//! In-process Rego evaluation via `regorus` — replaces the network hop to a
//! sidecar OPA.
//!
//! ## Design history (read before touching this file)
//!
//! Two iterations preceded this one:
//!
//! 1. A fixed 4-thread worker pool talking over `std::sync::mpsc` +
//!    `tokio::oneshot`, because plain `regorus::Engine` is `Rc`-based
//!    (`!Send`/`!Sync`).
//! 2. A thread-local `regorus::Engine` per tokio worker thread
//!    (architecture-directed fix for #1's `!Send` problem), each rebuilt
//!    independently when a shared `generation` counter advanced.
//!
//! Both were replaced by this design after two more findings:
//!
//! - **regorus has an `"arc"` Cargo feature** (`features = ["arc"]` in this
//!   crate's `Cargo.toml`) that swaps its internal `Rc` for `Arc`
//!   everywhere. Verified directly: `regorus::CompiledPolicy` is both
//!   `Send` and `Sync` under this feature. That removes the `!Send`
//!   problem at the root — there is no need for a thread-local engine, or
//!   even a pool, at all. One compiled policy, wrapped in an `Arc`, is
//!   callable concurrently from any number of threads.
//! - **`Engine::eval_query`/`eval_bool_query` (what iterations 1 and 2
//!   used) re-parse the query string and re-run
//!   `prepare_for_eval`/`clean_internal_evaluation_state`/
//!   `create_rule_prefixes` on *every call*** — regardless of engine
//!   reuse. That, not lock/channel contention, was the ~900µs-1ms/decision
//!   cost measured in both earlier iterations. `Engine::
//!   compile_with_entrypoint("data.mcp.authz.allow")` compiles the query
//!   ONCE into a `CompiledPolicy` (`prepared = true` is baked into the
//!   `Engine` `compile_with_entrypoint` hands back), and
//!   `CompiledPolicy::eval_with_input(&self, input)` — note `&self`, no
//!   mutation — skips all of that per call. Measured ~247µs/decision
//!   single-threaded (~4x faster) vs. ~930µs via `eval_bool_query`. See
//!   `benches/authz_bench.rs`.
//!
//! ## Current design
//!
//! `PolicyState` holds two pre-compiled entrypoints (`data.mcp.authz.allow`
//! and `data.mcp.authz.reasons`) plus a `generation` and the data-sync
//! clock, behind `RwLock<Arc<PolicyState>>`. A read is: acquire the lock,
//! clone the `Arc` (cheap — the `RwLock` is held only for the clone, not
//! for the eval), drop the lock, evaluate against the cloned `Arc`'s
//! `CompiledPolicy`s. `reasons` is only evaluated when `allow == false`
//! (when `allow == true`, `authz.rego`'s `allow` rule already required
//! `count(deny) == 0`, so `reasons` is guaranteed empty — evaluating it
//! again on the hot allow path would be pure waste).
//!
//! Both `data.mcp.authz.allow` and `data.mcp.authz.reasons` are compiled
//! from ONE `regorus::Engine` (`add_policy` + `add_data` once, then
//! `compile_with_entrypoint` called twice) — the second
//! `compile_with_entrypoint` call reuses the already-`prepare_for_eval`'d
//! engine and is cheap.
//!
//! Compilation happens synchronously inside `load_bundle`/`sync_data`
//! themselves (there is no lazy per-thread rebuild anymore — nothing to
//! rebuild per thread). This means a policy/data change is compiled
//! exactly ONCE, globally, at reload time — not once per worker thread —
//! and every worker thread sees the new compiled policy on its very next
//! evaluation with no staleness window at all (there is exactly one shared
//! `Arc<PolicyState>`, so there is no way for two threads to observe
//! different generations at the same wall-clock instant the way there was
//! with per-thread thread-locals).
//!
//! ## Fail-closed semantics
//!
//! - `load_bundle`/`sync_data` compile eagerly and return `Err` on failure
//!   **without swapping the shared state** — a broken reload is rejected
//!   atomically and the previously-loaded (already-validated) generation
//!   keeps serving every thread identically. This is a deliberate
//!   divergence from the thread-local design's "a bad reload denies this
//!   thread" behaviour: the danger that behaviour guarded against was
//!   *different threads enforcing different policies* (see design history
//!   above) — with a single global `Arc<PolicyState>` there is no such
//!   divergence possible, so "reject the bad push, keep the old good one
//!   live everywhere" is strictly safer, not a fallback that reintroduces
//!   the danger. If nothing has EVER loaded successfully, `PolicyState` is
//!   `NotLoaded` and every evaluation denies (see
//!   `no_bundle_loaded_denies_every_request`). Flagged for the architect to
//!   confirm this reasoning; `bundle_rejects_bad_reload_keeps_serving_old_good`
//!   below pins the current behaviour either way.
//! - No bundle loaded / data never synced / data older than
//!   `max_data_age` / rego eval error -> `PolicyError` -> `GateError::
//!   DependencyUnavailable(..)` -> `Decision::Deny`. Never `Allow`.

use crate::bundle::PolicyBundle;
use crate::cache::authz_cache_key;
use crate::error::PolicyError;
use arc_swap::ArcSwap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Default TTL ceiling on top of generation-scoping (see
/// `RegorusPolicyEngine::with_cache`'s docs for why this exists even
/// though `authz.rego` — audited, see the performance report — does not
/// itself read wall-clock time).
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(5);
const DEFAULT_CACHE_CAPACITY: u64 = 100_000;

/// The FINAL, merged decision: `authz.rego`'s own result combined with
/// (always-fresh, never-cached) anomaly structural deny reasons. This is
/// what `evaluate_raw` returns — it is NOT itself cached; see
/// [`AuthzResult`] for what actually sits in the cache.
#[derive(Debug, Clone, Default)]
pub struct EvalResult {
    pub allow: bool,
    pub reasons: Vec<String>,
}

/// `authz.rego`'s own decision, independent of anomaly — this is what
/// `evaluate_raw` caches, keyed by `authz_cache_key` (which excludes
/// `recent_calls`/`window_seconds` — see `cache.rs`). Anomaly results are
/// never cached at all: `anomaly_policy` is evaluated fresh on every call
/// and merged into the final `EvalResult` after a cache hit or miss here.
#[derive(Debug, Clone, Default)]
struct AuthzResult {
    allow: bool,
    reasons: Vec<String>,
}

enum PolicyState {
    NotLoaded,
    Loaded {
        generation: u64,
        rego_source: String,
        /// `anomaly.rego`, loaded into the SAME `regorus::Engine` as
        /// `authz.rego` so `data.mcp.anomaly.structural_deny_reasons`
        /// resolves — see `bundle.rs::anomaly_rego_source`'s doc comment
        /// for why this is optional (backward compatibility).
        anomaly_rego_source: Option<String>,
        data: serde_json::Value,
        allow_policy: regorus::CompiledPolicy,
        reasons_policy: regorus::CompiledPolicy,
        /// `data.mcp.anomaly.structural_deny_reasons`, compiled as its OWN
        /// prepared entrypoint and evaluated against the SAME unmodified
        /// `input` — never via `authz.rego`'s (removed) `with input as
        /// {...}` indirection, which is broken under regorus's prepared
        /// evaluation path for any composite-valued rule. See `authz.rego`'s
        /// "ANOMALY STRUCTURAL DENY RULES" section for the full writeup and
        /// `compile_entrypoints`/`evaluate_raw` below for how the result is
        /// merged into the final decision. `None` when no `anomaly.rego`
        /// was in the loaded bundle (backward compatibility).
        anomaly_policy: Option<regorus::CompiledPolicy>,
        data_synced_at: Option<Instant>,
    },
}

impl PolicyState {
    fn generation(&self) -> u64 {
        match self {
            PolicyState::NotLoaded => 0,
            PolicyState::Loaded { generation, .. } => *generation,
        }
    }
}

pub struct RegorusPolicyEngine {
    // `ArcSwap` instead of `RwLock<Arc<PolicyState>>`: a plain `RwLock`
    // read lock showed real, measured contention under concurrent
    // `evaluate_raw` load (see the performance report — swapping this in
    // took measured 12-thread throughput from ~8.6k to ~11.1k decisions/
    // sec with no other change). `ArcSwap::load()` is designed exactly for
    // "many frequent readers, rare atomic pointer swap" and avoids the
    // lock entirely on the read path.
    state: ArcSwap<PolicyState>,
    /// Serializes `load_bundle`/`sync_data` against each other (reloads are
    /// rare/administrative; a plain `Mutex` here has zero effect on the
    /// `evaluate_raw` hot path, which never touches it).
    write_lock: Mutex<()>,
    max_data_age: Duration,
    /// Total number of successful (policy, data) compiles — a legitimate
    /// reload/health metric, and what the "compile once, not per request"
    /// tests assert against.
    compile_count: AtomicU64,
    /// Total number of times the underlying `authz.rego` evaluation was
    /// actually invoked (authz cache misses) — what the cache-hit tests
    /// assert against. Never incremented on an authz cache hit, and never
    /// incremented for a call that fails before reaching the engine
    /// (`NotLoaded`/`DataStale`/etc. short-circuit earlier). NOTE: does
    /// NOT count `anomaly_policy` evaluations — anomaly runs on every call
    /// regardless of the authz cache, by design (see `cache.rs`'s module
    /// doc) — so this counter is authz-specific, not "any rego eval
    /// happened."
    eval_count: AtomicU64,
    /// Decision cache for `authz.rego`'s OWN result only (never the final
    /// merged `EvalResult` — anomaly is never cached, see `cache.rs`'s
    /// module doc for why). Key = `authz_cache_key` (generation + canonical
    /// input, minus `recent_calls`/`window_seconds`). Only ever populated
    /// with the engine's own successful `AuthzResult`; an `Err` is never
    /// written here (the `.insert()` call sits strictly after the
    /// `?`-guarded eval calls below, so an error return path can't reach
    /// it). Bounded by `max_capacity` (moka's default eviction under
    /// pressure is an approximated-LRU / TinyLFU admission policy — see
    /// moka's docs; we don't hand-roll an eviction policy) and by
    /// `time_to_live`.
    cache: moka::sync::Cache<[u8; 32], AuthzResult>,
    /// The operator-configured anomaly score cutoff (`GlobalLimits::
    /// anomaly_cutoff_threshold` in `mcphub-store`; the admin UI's
    /// "anomaly sensitivity" slider) — `f64` bits stored in an `AtomicU64`
    /// for lock-free read on the hot path (`anomaly_score.rs`'s score
    /// computation runs on EVERY call, never cached, same as
    /// `anomaly_policy`). Updated by `set_anomaly_cutoff`, which
    /// `bin/mcphubd`'s periodic policy-data refresh calls — NOT a per-
    /// request DB read. Deliberately NOT part of the Rego `data` document
    /// or the authz cache key: the score-threshold check happens entirely
    /// in Rust, in the always-fresh path, so a cutoff change takes effect
    /// on literally the next call with no cache-invalidation/generation
    /// bump needed at all (there is nothing cached to invalidate).
    anomaly_cutoff_bits: AtomicU64,
}

/// Matches `proxy/app/services/anomaly.py`'s `ANOMALY_ALERT_THRESHOLD`
/// default and `authz.rego`'s former `default anomaly_cutoff := 0.85`.
const DEFAULT_ANOMALY_CUTOFF: f64 = 0.85;

/// Compile both entrypoints from one prepared `regorus::Engine`. The
/// second `compile_with_entrypoint` call is cheap — `prepare_for_eval`
/// short-circuits once `Engine.prepared` is `true`, which the first call
/// already set.
type CompiledEntrypoints = (regorus::CompiledPolicy, regorus::CompiledPolicy, Option<regorus::CompiledPolicy>);

fn compile_entrypoints(
    rego_source: &str,
    anomaly_rego_source: Option<&str>,
    data: &serde_json::Value,
) -> Result<CompiledEntrypoints, PolicyError> {
    let mut engine = regorus::Engine::new();
    engine
        .add_policy("authz.rego".to_string(), rego_source.to_string())
        .map_err(|err| PolicyError::BundleMalformed(format!("rego compile failed: {err}")))?;
    let has_anomaly = anomaly_rego_source.is_some();
    if let Some(anomaly_source) = anomaly_rego_source {
        // Loaded as a second module into the SAME engine — `add_policy`
        // parses exactly one `package` per call (verified against
        // regorus 0.11's source), so `authz.rego`'s `package mcp.authz`
        // and `anomaly.rego`'s `package mcp.anomaly` cannot be
        // concatenated into one source string; they must be two
        // `add_policy` calls sharing this `Engine` instance.
        engine
            .add_policy("anomaly.rego".to_string(), anomaly_source.to_string())
            .map_err(|err| PolicyError::BundleMalformed(format!("anomaly.rego compile failed: {err}")))?;
    }
    engine
        .add_data(regorus::Value::from(data.clone()))
        .map_err(|err| PolicyError::BundleMalformed(format!("data push rejected: {err}")))?;
    let allow_policy = engine
        .compile_with_entrypoint(&regorus::Rc::from("data.mcp.authz.allow"))
        .map_err(|err| PolicyError::BundleMalformed(format!("compile of allow entrypoint failed: {err}")))?;
    let reasons_policy = engine
        .compile_with_entrypoint(&regorus::Rc::from("data.mcp.authz.reasons"))
        .map_err(|err| PolicyError::BundleMalformed(format!("compile of reasons entrypoint failed: {err}")))?;
    // Compiled as its OWN prepared entrypoint — NOT reached via authz.rego's
    // internal `with input as {...}` (removed; see authz.rego's "ANOMALY
    // STRUCTURAL DENY RULES" section for why that construct is broken under
    // regorus's prepared evaluation path for composite-valued rules).
    // Evaluated separately in `evaluate_raw` against the SAME unmodified
    // input and merged into the final decision there.
    let anomaly_policy = if has_anomaly {
        Some(
            engine
                .compile_with_entrypoint(&regorus::Rc::from("data.mcp.anomaly.structural_deny_reasons"))
                .map_err(|err| PolicyError::BundleMalformed(format!("compile of anomaly entrypoint failed: {err}")))?,
        )
    } else {
        None
    };
    Ok((allow_policy, reasons_policy, anomaly_policy))
}

impl RegorusPolicyEngine {
    /// Builds with the default decision-cache TTL (5s) and capacity
    /// (100,000 entries) — see `with_cache` for why those exist and how to
    /// override them.
    pub fn new(max_data_age: Duration) -> Self {
        Self::with_cache(max_data_age, DEFAULT_CACHE_TTL, DEFAULT_CACHE_CAPACITY)
    }

    /// `cache_ttl`: a ceiling on top of generation-scoped invalidation.
    /// Generation-scoping (the key includes the bundle/data generation)
    /// already guarantees a cached decision can never survive a policy or
    /// data reload — but if `authz.rego` itself ever reads wall-clock time
    /// (grant expiry, time-of-day conditions), a cached `allow` could
    /// outlive its validity *within* one generation. Audited: the current
    /// `authz.rego` does not reference any `time.*` builtin at all (grepped
    /// `time\.` across the embedded policy — zero matches), so today this
    /// TTL is pure defense-in-depth, not covering a real live risk. If a
    /// future policy revision adds a time-based rule, this TTL is the
    /// bound on how stale a cached decision can be relative to it — keep it
    /// short. `cache_capacity`: max entries before moka's eviction kicks in
    /// (approximated-LRU under memory pressure — see moka's docs).
    pub fn with_cache(max_data_age: Duration, cache_ttl: Duration, cache_capacity: u64) -> Self {
        Self {
            state: ArcSwap::new(Arc::new(PolicyState::NotLoaded)),
            write_lock: Mutex::new(()),
            max_data_age,
            compile_count: AtomicU64::new(0),
            eval_count: AtomicU64::new(0),
            cache: moka::sync::Cache::builder()
                .max_capacity(cache_capacity)
                .time_to_live(cache_ttl)
                .build(),
            anomaly_cutoff_bits: AtomicU64::new(DEFAULT_ANOMALY_CUTOFF.to_bits()),
        }
    }

    /// Update the anomaly score cutoff. Lock-free, takes effect on the
    /// very next `evaluate_raw` call — see `anomaly_cutoff_bits`'s field
    /// doc for why this deliberately does NOT touch the policy generation
    /// or the authz cache.
    pub fn set_anomaly_cutoff(&self, cutoff: f64) {
        self.anomaly_cutoff_bits.store(cutoff.to_bits(), Ordering::Relaxed);
    }

    pub fn anomaly_cutoff(&self) -> f64 {
        f64::from_bits(self.anomaly_cutoff_bits.load(Ordering::Relaxed))
    }

    /// Kept for API continuity with earlier revisions — there is no
    /// "worker pool" or "thread-local set" to size anymore (see module
    /// docs), so this just forwards to `new`.
    pub fn with_workers(max_data_age: Duration, _worker_count: usize) -> Self {
        Self::new(max_data_age)
    }

    pub fn compile_count(&self) -> u64 {
        self.compile_count.load(Ordering::Relaxed)
    }

    /// Number of times the rego engine was actually invoked (cache
    /// misses). Exposed for tests and as a cache-effectiveness metric.
    pub fn eval_count(&self) -> u64 {
        self.eval_count.load(Ordering::Relaxed)
    }

    /// Verify and load a signed bundle. Compiles synchronously; on failure,
    /// returns `Err` and leaves the previously-loaded generation (if any)
    /// serving unchanged — see module docs' "Fail-closed semantics".
    pub fn load_signed_bundle(&self, path: &std::path::Path, signing_key: &[u8]) -> Result<(), PolicyError> {
        let bundle = PolicyBundle::load_signed(path, signing_key)?;
        self.load_bundle(&bundle)
    }

    pub fn load_bundle(&self, bundle: &PolicyBundle) -> Result<(), PolicyError> {
        let source = bundle.rego_source()?.to_string();
        let anomaly_source = bundle.anomaly_rego_source()?.map(str::to_string);
        // Serializes concurrent reloads against each other; never touched
        // by `evaluate_raw`.
        let _write_guard = self.write_lock.lock().map_err(|_| PolicyError::NotLoaded)?;
        let current = self.state.load();
        let prev_gen = current.generation();
        let prev_data = match &**current {
            PolicyState::Loaded { data, .. } => data.clone(),
            // regorus::Engine::add_data requires an object at the root; an
            // empty object is the correct "nothing pushed yet" placeholder
            // (Rego objects with no keys are simply empty, not an error).
            PolicyState::NotLoaded => serde_json::json!({}),
        };

        // A (re)load must be re-synced before it's usable — carrying
        // forward a staleness clock from a different policy version would
        // be a fail-open-by-accident. `data_synced_at: None` below is what
        // actually enforces that (not the placeholder data value above).
        let (allow_policy, reasons_policy, anomaly_policy) =
            compile_entrypoints(&source, anomaly_source.as_deref(), &prev_data)?;
        self.compile_count.fetch_add(1, Ordering::Relaxed);
        self.state.store(Arc::new(PolicyState::Loaded {
            generation: prev_gen + 1,
            rego_source: source,
            anomaly_rego_source: anomaly_source,
            data: prev_data,
            allow_policy,
            reasons_policy,
            anomaly_policy,
            data_synced_at: None,
        }));
        Ok(())
    }

    /// Push `data.mcp_grants` / `data.mcp.tools` / `data.mcp.injection_phrases`.
    /// Requires a policy to already be loaded (there is nothing to compile
    /// data against otherwise). Compiles synchronously; same fail-closed
    /// "reject bad push, keep old good state" semantics as `load_bundle`.
    pub fn sync_data(
        &self,
        grants: serde_json::Value,
        tools: serde_json::Value,
        injection_phrases: serde_json::Value,
    ) -> Result<(), PolicyError> {
        let data = serde_json::json!({
            "mcp_grants": grants,
            "mcp": { "tools": tools, "injection_phrases": injection_phrases },
        });
        let _write_guard = self.write_lock.lock().map_err(|_| PolicyError::NotLoaded)?;
        let current = self.state.load();
        let (prev_gen, rego_source, anomaly_rego_source) = match &**current {
            PolicyState::Loaded { generation, rego_source, anomaly_rego_source, .. } => {
                (*generation, rego_source.clone(), anomaly_rego_source.clone())
            }
            PolicyState::NotLoaded => return Err(PolicyError::NotLoaded),
        };

        let (allow_policy, reasons_policy, anomaly_policy) =
            compile_entrypoints(&rego_source, anomaly_rego_source.as_deref(), &data)?;
        self.compile_count.fetch_add(1, Ordering::Relaxed);
        self.state.store(Arc::new(PolicyState::Loaded {
            generation: prev_gen + 1,
            rego_source,
            anomaly_rego_source,
            data,
            allow_policy,
            reasons_policy,
            anomaly_policy,
            data_synced_at: Some(Instant::now()),
        }));
        Ok(())
    }

    /// Evaluate `authz.rego` against `input`. Synchronous, cheap (no
    /// compilation on the hot path), and safe to call concurrently from
    /// any number of threads — `ArcSwap::load()` is lock-free on the read
    /// side (see module docs).
    pub fn evaluate_raw(&self, input: serde_json::Value) -> Result<EvalResult, PolicyError> {
        let state = self.state.load();
        let (allow_policy, reasons_policy, anomaly_policy, data_synced_at, generation) = match &**state {
            PolicyState::NotLoaded => return Err(PolicyError::NotLoaded),
            PolicyState::Loaded {
                allow_policy,
                reasons_policy,
                anomaly_policy,
                data_synced_at,
                generation,
                ..
            } => (allow_policy, reasons_policy, anomaly_policy, *data_synced_at, *generation),
        };

        match data_synced_at {
            None => return Err(PolicyError::DataNeverSynced),
            Some(t) if t.elapsed() > self.max_data_age => return Err(PolicyError::DataStale),
            Some(_) => {}
        }

        // Convert `serde_json::Value` -> `regorus::Value` ONCE (this walks
        // the whole tree and is the single most expensive step per
        // decision after the eval itself) and reuse it for every query
        // below — `regorus::Value`'s `Clone` is Rc/Arc-sharing, not a deep
        // copy, so cloning it per call is cheap even though cloning the
        // original `serde_json::Value` would not have been.
        //
        // authz cache key computed from the ORIGINAL `serde_json::Value`
        // (before the regorus conversion) — `generation` is bumped by
        // every `load_bundle`/`sync_data` call, so folding it into the key
        // makes a reload invalidate every prior entry for free (see
        // `cache.rs`). This key covers ONLY `authz.rego`'s own decision —
        // `recent_calls`/`window_seconds` are deliberately excluded (see
        // `cache.rs`'s module doc); anomaly is handled entirely separately
        // below and is never cached.
        let authz_key = authz_cache_key(&input, generation);

        // Extracted BEFORE `input` is consumed below — feeds the numeric
        // anomaly-score check (`anomaly_score.rs`), which — like
        // `anomaly_policy` — runs fresh on every call and is never cached,
        // so pulling these three fields out here doesn't touch the authz
        // cache key at all.
        let recent_call_tool_names: Vec<String> = input
            .get("recent_calls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| c.get("tool_name").and_then(|t| t.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let is_testing = input.get("is_testing").and_then(|v| v.as_bool()).unwrap_or(false);
        let is_ping = input.get("tool_name").and_then(|v| v.as_str()) == Some("ping");

        let regorus_input = regorus::Value::from(input);

        let authz_result: AuthzResult = match self.cache.get(&authz_key) {
            Some(cached) => cached,
            None => {
                self.eval_count.fetch_add(1, Ordering::Relaxed);
                let allow_value = allow_policy
                    .eval_with_input(regorus_input.clone())
                    .map_err(|e| PolicyError::Eval(e.to_string()))?;
                let authz_allow = matches!(allow_value.as_bool(), Ok(true));

                // authz.rego's `allow` requires `count(deny) == 0`, so when
                // `authz_allow == true`, authz's own `reasons` are
                // guaranteed empty — skip that second evaluation when we
                // don't need it.
                let authz_reasons = if authz_allow {
                    Vec::new()
                } else {
                    reasons_policy
                        .eval_with_input(regorus_input.clone())
                        .ok()
                        .and_then(|v| serde_json::to_value(v).ok())
                        .and_then(|v| v.as_array().cloned())
                        .map(|arr| {
                            arr.into_iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default()
                };

                let computed = AuthzResult {
                    allow: authz_allow,
                    reasons: authz_reasons,
                };
                // Only the engine's own successful authz result is ever
                // cached — this line is reachable only after the
                // `?`-guarded `eval_with_input` call above succeeded. Every
                // early `return Err(..)` in this function (not-loaded,
                // stale data, eval error) exits before this point.
                self.cache.insert(authz_key, computed.clone());
                computed
            }
        };

        // Anomaly structural deny reasons: evaluated as their OWN prepared
        // entrypoint against the SAME unmodified input, on EVERY call —
        // never cached, regardless of whether the authz lookup above was a
        // hit or a miss. This is what makes excluding `recent_calls`/
        // `window_seconds` from `authz_key` safe: there is no cache entry
        // for an anomaly verdict to go stale in, because anomaly is never
        // read from a cache at all. Must run even when `authz_result.allow`
        // is true: an anomaly-triggered deny has to fire even when
        // authz.rego's own rules would have allowed. A genuine eval error
        // here is `?`-propagated (fail-closed), same as `allow_policy`'s.
        let anomaly_reasons: Vec<String> = match anomaly_policy {
            None => Vec::new(),
            Some(anomaly_policy) => {
                let value = anomaly_policy
                    .eval_with_input(regorus_input)
                    .map_err(|e| PolicyError::Eval(e.to_string()))?;
                serde_json::to_value(value)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .map(|arr| arr.into_iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default()
            }
        };

        // Numeric anomaly-score threshold check — see `anomaly_score.rs`'s
        // module doc for why this lives here in Rust rather than in Rego
        // (matches the Python original's own architecture). `not
        // is_testing`/`not is_ping` mirror the removed `authz.rego` deny
        // rule's exemptions verbatim (R-4: `ping` is a liveness probe and
        // must stay observable under an anomaly lockout from other tools).
        let (anomaly_score, _pattern) = crate::anomaly_score::score_window(&recent_call_tool_names);
        let mut anomaly_reasons = anomaly_reasons;
        if anomaly_score > self.anomaly_cutoff() && !is_testing && !is_ping {
            anomaly_reasons.push("anomaly_score_threshold_exceeded".to_string());
        }

        let allow = authz_result.allow && anomaly_reasons.is_empty();
        let mut reasons = authz_result.reasons;
        reasons.extend(anomaly_reasons);

        Ok(EvalResult { allow, reasons })
    }

    /// Are the shared preconditions (bundle loaded, data fresh) met right
    /// now?
    pub fn is_ready(&self) -> bool {
        match &**self.state.load() {
            PolicyState::NotLoaded => false,
            PolicyState::Loaded { data_synced_at, .. } => {
                data_synced_at.is_some_and(|t| t.elapsed() <= self.max_data_age)
            }
        }
    }
}

// DELIBERATELY no `impl mcphub_gateway::traits::PolicyEngine for
// RegorusPolicyEngine` here — see "Why there is no `PolicyEngine` trait
// impl on this type" below.
//
// A previous version of this file had one, and it was a security bug
// waiting to be triggered rather than an active one: the trait's
// `evaluate(&self, identity, tool, input)` signature makes `input` look
// like the caller-controlled request body, so the old impl did exactly
// that — `_identity`/`_tool` were ignored, and `input` (attacker-supplied
// JSON) was forwarded VERBATIM as the entire Rego `input` object.
// `authz.rego` reads `input.client_roles`, `input.tool_status`,
// `input.tool_risk_level`, etc. straight off that object with no further
// trust boundary — so any code that plugged `RegorusPolicyEngine` in as
// the `PolicyEngine` implementation (the natural, obvious thing to write
// for a `Gates` construction) would have let a caller assert their own
// `client_roles: ["admin"]` and sail through. `default allow := false`
// meant this was invisible in testing (nothing wired that way had been
// built yet, so it only ever denied) — fail-closed-shaped, but one field
// away from fail-open the moment someone supplied a matching request body.
//
// Flagged by the architect during review of `bin/mcphubd/src/wiring/
// policy.rs`, which had already worked around it correctly: it builds the
// real `authz.rego` input from the resolved `Identity`/`ToolRef` plus a
// Postgres tool lookup, and calls `RegorusPolicyEngine::evaluate_raw`
// (below) directly — never through the trait. That adapter is the only
// place a full input should ever be assembled; it needs data (server-scoped
// tool status/risk level from Postgres) this crate deliberately does not
// have, so this crate cannot safely rebuild the trait impl "correctly"
// without either duplicating that lookup here or accepting an injected
// tool-metadata provider — neither of which existed a moment ago and both
// of which are new scope, not a fix. Deleting the impl was preferred over
// trying to make it safe: it turns "plug this in and get a silent bypass"
// into a compile error for anyone who tries the natural thing. The only
// sanctioned way to get a decision out of this type is `evaluate_raw`,
// which takes the FULLY-CONSTRUCTED input and trusts it completely — that
// is correct and intentional for a low-level primitive; the trust boundary
// belongs at the one call site that builds that input from authenticated
// identity, not inside this crate.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RAW_ALLOW_TRUE: &str = r#"
package mcp.authz
default allow := false
allow if { input.ok == true }
reasons := set()
"#;

    fn engine_with(source: &str) -> RegorusPolicyEngine {
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let bundle = PolicyBundle::unsigned_for_tests(source);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();
        e
    }

    #[test]
    fn deny_by_default_on_empty_input() {
        let e = engine_with(RAW_ALLOW_TRUE);
        let r = e.evaluate_raw(json!({})).unwrap();
        assert!(!r.allow, "empty input must not be allowed");
    }

    #[test]
    fn allows_when_the_policy_says_so() {
        let e = engine_with(RAW_ALLOW_TRUE);
        let r = e.evaluate_raw(json!({"ok": true})).unwrap();
        assert!(r.allow);
    }

    #[test]
    fn no_bundle_loaded_denies_every_request() {
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let err = e.evaluate_raw(json!({"ok": true})).unwrap_err();
        assert!(matches!(err, PolicyError::NotLoaded));
        assert!(!e.is_ready());
    }

    #[test]
    fn stale_data_denies() {
        let e = RegorusPolicyEngine::new(Duration::from_millis(1));
        let bundle = PolicyBundle::unsigned_for_tests(RAW_ALLOW_TRUE);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let err = e.evaluate_raw(json!({"ok": true})).unwrap_err();
        assert!(matches!(err, PolicyError::DataStale));
    }

    #[test]
    fn grant_for_tool_a_does_not_grant_tool_b() {
        // Real authz.rego semantics: a client with allowed_tools=["A"] must
        // not be authorized to invoke "B".
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let bundle = PolicyBundle::unsigned_for_tests(PolicyBundle::EMBEDDED_AUTHZ_REGO);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(
            json!({
                "alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}
            }),
            json!({}),
            json!([]),
        )
        .unwrap();

        let base = |tool: &str| {
            json!({
                "client_id": "alice",
                "client_roles": ["user"],
                "tool_id": "t1",
                "tool_name": tool,
                "tool_status": "active",
                "tool_risk_level": "low",
                "tool_server_id": "",
                "owned_server_ids": [],
                "owner_max_risk_level": "medium",
                "params": {},
                "anomaly_score": 0.0,
                "is_testing": false,
            })
        };

        let allowed = e.evaluate_raw(base("tool_a")).unwrap();
        assert!(allowed.allow, "grant for tool_a must allow tool_a");
        assert!(allowed.reasons.is_empty());

        let denied = e.evaluate_raw(base("tool_b")).unwrap();
        assert!(!denied.allow, "grant for tool_a must NOT allow tool_b");
        assert!(!denied.reasons.is_empty(), "a deny must carry a reason for audit");
    }

    #[test]
    fn compile_happens_once_per_load_not_per_evaluation() {
        let e = engine_with(RAW_ALLOW_TRUE);
        let before = e.compile_count();
        // Many evaluations against the same (unchanged) generation.
        for _ in 0..50 {
            e.evaluate_raw(json!({"ok": true})).unwrap();
        }
        assert_eq!(
            e.compile_count(),
            before,
            "evaluate_raw must never compile — only load_bundle/sync_data do"
        );
    }

    #[test]
    fn sync_data_recompiles_exactly_once() {
        let e = engine_with(RAW_ALLOW_TRUE);
        let after_setup = e.compile_count();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();
        assert_eq!(e.compile_count(), after_setup + 1);
    }

    #[test]
    fn bundle_rejects_bad_reload_keeps_serving_old_good() {
        let e = engine_with(RAW_ALLOW_TRUE);
        let good = e.evaluate_raw(json!({"ok": true})).unwrap();
        assert!(good.allow);
        let compiles_before = e.compile_count();

        let broken = PolicyBundle::unsigned_for_tests("package mcp.authz\n this is not valid rego {{{");
        let err = e.load_bundle(&broken).unwrap_err();
        assert!(matches!(err, PolicyError::BundleMalformed(_)));

        // The bad reload must not have been adopted: no new compile
        // recorded, and the OLD good policy keeps serving identically.
        assert_eq!(e.compile_count(), compiles_before);
        let still_good = e.evaluate_raw(json!({"ok": true})).unwrap();
        assert!(still_good.allow, "a rejected bad reload must not disturb the previously-good policy");
    }

    // ------------------------------------------------------------------
    // Decision cache — tested as a security control (does the key cover
    // the whole security argument?), not just a perf feature.
    // ------------------------------------------------------------------

    fn base_input(tool: &str) -> serde_json::Value {
        json!({
            "client_id": "alice",
            "client_roles": ["user"],
            // Role provenance (`fix-identity`'s `GrantedRole.asserted_by`,
            // ARCHITECTURE.md): `bin/mcphubd/src/wiring/policy.rs` now
            // includes this alongside the flat `client_roles` list. Present
            // in this fixture so `every_top_level_input_field_participates_
            // in_the_cache_key`'s generic mutation loop (below) proves it's
            // covered by the cache key automatically — no new hand-written
            // test needed, matching "derive the key from the input value,
            // never a field list."
            "client_granted_roles": [{"role": "user", "asserted_by": "platform"}],
            "tool_id": "t1",
            "tool_name": tool,
            "tool_status": "active",
            "tool_risk_level": "low",
            "tool_server_id": "",
            "owned_server_ids": [],
            "owner_max_risk_level": "medium",
            "params": {"arg": "value"},
            "anomaly_score": 0.0,
            "is_testing": false,
        })
    }

    fn engine_with_real_policy() -> RegorusPolicyEngine {
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let bundle = PolicyBundle::unsigned_for_tests(PolicyBundle::EMBEDDED_AUTHZ_REGO);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(
            json!({
                "alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}
            }),
            json!({}),
            json!([]),
        )
        .unwrap();
        e
    }

    /// Flip/perturb a JSON leaf value into something guaranteed different,
    /// preserving its rough type where that matters for the policy not to
    /// itself error out (arrays/objects get an extra harmless element so
    /// the shape survives `walk`/`is_string` checks in authz.rego).
    fn perturb(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Null => json!("was-null"),
            serde_json::Value::Bool(b) => json!(!b),
            serde_json::Value::Number(n) => json!(n.as_f64().unwrap_or(0.0) + 1.0),
            serde_json::Value::String(s) => json!(format!("{s}-perturbed")),
            serde_json::Value::Array(a) => {
                let mut a = a.clone();
                a.push(json!("perturbed"));
                serde_json::Value::Array(a)
            }
            serde_json::Value::Object(o) => {
                let mut o = o.clone();
                o.insert("__perturbed__".to_string(), json!(true));
                serde_json::Value::Object(o)
            }
        }
    }

    #[test]
    fn identical_input_is_a_cache_hit_engine_invoked_once() {
        let e = engine_with_real_policy();
        let input = base_input("tool_a");

        let before = e.eval_count();
        let r1 = e.evaluate_raw(input.clone()).unwrap();
        let after_first = e.eval_count();
        assert_eq!(after_first, before + 1, "first call must be a real evaluation");

        let r2 = e.evaluate_raw(input).unwrap();
        assert_eq!(e.eval_count(), after_first, "identical input must be a cache hit — no new evaluation");
        assert_eq!(r1.allow, r2.allow);
        assert_eq!(r1.reasons, r2.reasons);
    }

    /// Every field of the input struct must be part of the cache key. This
    /// is a security property, not a perf nicety: if any field were
    /// omitted, two requests differing only in that field would
    /// (incorrectly) share a cached verdict. Loop over every top-level key
    /// rather than spot-checking one.
    #[test]
    fn every_top_level_input_field_participates_in_the_cache_key() {
        let e = engine_with_real_policy();
        let base = base_input("tool_a");
        let obj = base.as_object().unwrap().clone();

        // Prime the cache with the baseline so the loop below measures
        // deltas cleanly.
        e.evaluate_raw(base.clone()).unwrap();
        let primed = e.eval_count();
        e.evaluate_raw(base.clone()).unwrap();
        assert_eq!(e.eval_count(), primed, "baseline repeat must hit the cache");

        for key in obj.keys() {
            let mut mutated = base.clone();
            let mutated_obj = mutated.as_object_mut().unwrap();
            let new_value = perturb(&obj[key]);
            mutated_obj.insert(key.clone(), new_value);

            let before = e.eval_count();
            // Result may legitimately differ (e.g. mutating tool_status);
            // what we're proving is that the ENGINE WAS INVOKED, i.e. the
            // field is part of the key.
            let _ = e.evaluate_raw(mutated);
            assert_eq!(
                e.eval_count(),
                before + 1,
                "mutating field '{key}' must be a cache miss — it is not covered by the key"
            );
        }
    }

    #[test]
    fn bundle_generation_bump_invalidates_prior_cache_entries() {
        let e = engine_with_real_policy();
        let input = base_input("tool_a");
        e.evaluate_raw(input.clone()).unwrap();
        let after_first = e.eval_count();
        e.evaluate_raw(input.clone()).unwrap();
        assert_eq!(e.eval_count(), after_first, "must have been a cache hit before reload");

        // Reload with byte-identical rego source — still a NEW generation.
        let bundle = PolicyBundle::unsigned_for_tests(PolicyBundle::EMBEDDED_AUTHZ_REGO);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(
            json!({"alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}}),
            json!({}),
            json!([]),
        )
        .unwrap();

        let before_after_reload = e.eval_count();
        e.evaluate_raw(input).unwrap();
        assert_eq!(
            e.eval_count(),
            before_after_reload + 1,
            "a bundle reload must invalidate the prior generation's cache entries"
        );
    }

    #[test]
    fn data_generation_bump_invalidates_prior_cache_entries() {
        let e = engine_with_real_policy();
        let input = base_input("tool_a");
        e.evaluate_raw(input.clone()).unwrap();
        let after_first = e.eval_count();
        e.evaluate_raw(input.clone()).unwrap();
        assert_eq!(e.eval_count(), after_first, "must have been a cache hit before the data sync");

        // Re-sync identical grants — still a NEW generation.
        e.sync_data(
            json!({"alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}}),
            json!({}),
            json!([]),
        )
        .unwrap();

        let before_after_sync = e.eval_count();
        e.evaluate_raw(input).unwrap();
        assert_eq!(
            e.eval_count(),
            before_after_sync + 1,
            "a data sync must invalidate the prior generation's cache entries"
        );
    }

    #[test]
    fn cache_entry_expires_after_ttl() {
        let e = RegorusPolicyEngine::with_cache(Duration::from_secs(120), Duration::from_millis(15), 1000);
        let bundle = PolicyBundle::unsigned_for_tests(RAW_ALLOW_TRUE);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();

        let input = json!({"ok": true});
        e.evaluate_raw(input.clone()).unwrap();
        let after_first = e.eval_count();
        e.evaluate_raw(input.clone()).unwrap();
        assert_eq!(e.eval_count(), after_first, "must be a cache hit within the TTL");

        std::thread::sleep(Duration::from_millis(60));
        e.evaluate_raw(input).unwrap();
        assert_eq!(e.eval_count(), after_first + 1, "an entry past its TTL must be re-evaluated");
    }

    #[test]
    fn eval_error_is_never_cached() {
        // `input.x + 1` errors at eval time when `input.x` is not a number
        // — a genuine rego evaluation error, not a fail-closed short
        // circuit (those — NotLoaded/DataStale — return before the cache
        // lookup and are covered by other tests).
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let source = "package mcp.authz\ndefault allow := false\nallow if { input.x + 1 > 0 }\nreasons := set()\n";
        let bundle = PolicyBundle::unsigned_for_tests(source);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();

        let bad_input = json!({"x": {"nested": true}});

        let before = e.eval_count();
        assert!(e.evaluate_raw(bad_input.clone()).is_err());
        let after_first = e.eval_count();
        assert!(after_first > before, "the failing call itself must reach the engine");

        assert!(e.evaluate_raw(bad_input).is_err());
        assert!(
            e.eval_count() > after_first,
            "an Err result must never be cached — the identical failing input must re-evaluate every time"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn reload_takes_effect_on_every_worker_thread_with_no_divergence_window() {
        let e = std::sync::Arc::new(RegorusPolicyEngine::new(Duration::from_secs(120)));
        let bundle = PolicyBundle::unsigned_for_tests(RAW_ALLOW_TRUE);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let e = e.clone();
            handles.push(tokio::spawn(async move { e.evaluate_raw(json!({"ok": true})) }));
        }
        for h in handles {
            assert!(h.await.unwrap().unwrap().allow);
        }

        // Reload to a deny-all policy — every worker thread must observe
        // it on the very next evaluation. There is exactly one shared
        // `Arc<PolicyState>`, so unlike the earlier thread-local design
        // there is no per-thread staleness window to even test for.
        let deny_all =
            PolicyBundle::unsigned_for_tests("package mcp.authz\ndefault allow := false\nreasons := set()\n");
        e.load_bundle(&deny_all).unwrap();
        e.sync_data(json!({}), json!({}), json!([])).unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let e = e.clone();
            handles.push(tokio::spawn(async move { e.evaluate_raw(json!({"ok": true})) }));
        }
        for h in handles {
            assert!(
                !h.await.unwrap().unwrap().allow,
                "every worker thread must see the reloaded (deny-all) policy"
            );
        }
    }

    /// Sanity check that `anomaly.rego`'s rules work correctly standalone,
    /// evaluated directly (no `authz.rego` indirection at all) via the
    /// UNPREPARED `Engine::eval_bool_query`/`eval_query` API. This used to
    /// be a diagnostic isolating a since-fixed regorus limitation (see
    /// `anomaly_bundle_structural_rule_fires_and_denies`'s doc comment for
    /// the full writeup and the fix); the original version of this test
    /// exercised `authz.rego`'s (now-removed) `with input as {...}`
    /// indirection, which no longer exists to test. Kept, retargeted at
    /// `data.mcp.anomaly.structural_deny_reasons` directly, as a second,
    /// independent confirmation that `anomaly.rego`'s own rule logic is
    /// correct — separate from whether the prepared-entrypoint plumbing
    /// around it works, which `anomaly_bundle_structural_rule_fires_and_denies`
    /// below covers.
    #[test]
    fn anomaly_structural_rule_evaluates_correctly_via_unprepared_query_api() {
        let mut engine = regorus::Engine::new();
        engine.add_policy("anomaly.rego".to_string(), PolicyBundle::EMBEDDED_ANOMALY_REGO.to_string()).unwrap();
        engine.add_data(regorus::Value::from(json!({}))).unwrap();
        let recent_calls: Vec<_> = (0..11).map(|i| json!({"tool_name": format!("file_read_{i}"), "timestamp": 1000.0 + i as f64})).collect();
        engine.set_input(regorus::Value::from(json!({
            "recent_calls": recent_calls, "window_seconds": 300,
        })));

        let reasons = engine.eval_query("data.mcp.anomaly.structural_deny_reasons".to_string(), false).unwrap();
        let reasons_set = reasons.result[0].expressions[0].value.as_set().unwrap();
        let has_bulk_spike = reasons_set.iter().any(|v| v.as_string().map(|s| s.as_ref() == "bulk_file_read_spike").unwrap_or(false));
        assert!(has_bulk_spike, "expected 'bulk_file_read_spike' among reasons, got {reasons_set:?}");
    }

    /// FIXED — was `#[ignore]`d as known-failing; see the previous test's
    /// doc comment for the original repro writeup, and `authz.rego`'s
    /// "ANOMALY STRUCTURAL DENY RULES" section / `engine.rs`'s
    /// `anomaly_policy` field for the root cause (regorus's prepared
    /// evaluation path breaks on any composite-valued rule referenced from
    /// inside a `with input as {...}` scope) and the workaround (the
    /// anomaly package is compiled and evaluated as its own separate
    /// prepared entrypoint, merged into the decision in `evaluate_raw`,
    /// rather than reached via `authz.rego`'s internal `with` indirection).
    #[test]
    fn anomaly_bundle_structural_rule_fires_and_denies() {
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let bundle =
            PolicyBundle::unsigned_for_tests_with_anomaly(PolicyBundle::EMBEDDED_AUTHZ_REGO, PolicyBundle::EMBEDDED_ANOMALY_REGO);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(
            json!({"alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}}),
            json!({}),
            json!([]),
        )
        .unwrap();

        let mut input = base_input("tool_a");
        // bulk_read_spike: > 10 "file"-containing tool names in the window.
        let recent_calls: Vec<_> = (0..11).map(|i| json!({"tool_name": format!("file_read_{i}"), "timestamp": 1000.0 + i as f64})).collect();
        input["recent_calls"] = json!(recent_calls);
        input["window_seconds"] = json!(300);

        let denied = e.evaluate_raw(input).unwrap();
        assert!(!denied.allow, "a bulk_read_spike window must be denied by the anomaly structural rule");
        assert!(
            denied.reasons.iter().any(|r| r == "bulk_file_read_spike"),
            "expected 'bulk_file_read_spike' in reasons, got {:?}",
            denied.reasons
        );

        // Sanity: a benign window (well under the threshold) with the same
        // otherwise-valid grant must still allow — proves this isn't just
        // "anomaly.rego always denies now".
        let mut benign_input = base_input("tool_a");
        benign_input["recent_calls"] = json!([{"tool_name": "ping", "timestamp": 1000.0}]);
        benign_input["window_seconds"] = json!(300);
        let allowed = e.evaluate_raw(benign_input).unwrap();
        assert!(allowed.allow, "a benign window must not trip the anomaly rule");
    }

    /// THE property the rejected two-tier design (see `PERFORMANCE.md`)
    /// could not guarantee, and this design can, by construction: an
    /// anomaly-triggering `recent_calls` must still deny even when the
    /// AUTHZ portion of the decision is served from cache. Proves it by
    /// watching `eval_count` (authz cache misses only, per its doc comment)
    /// stay flat across the second call while the final decision still
    /// flips to deny.
    #[test]
    fn anomaly_denies_through_an_authz_cache_hit() {
        let e = RegorusPolicyEngine::new(Duration::from_secs(120));
        let bundle =
            PolicyBundle::unsigned_for_tests_with_anomaly(PolicyBundle::EMBEDDED_AUTHZ_REGO, PolicyBundle::EMBEDDED_ANOMALY_REGO);
        e.load_bundle(&bundle).unwrap();
        e.sync_data(
            json!({"alice": {"allowed_tools": ["tool_a"], "allowed_tags": [], "max_risk_level": "medium"}}),
            json!({}),
            json!([]),
        )
        .unwrap();

        // First call: benign window. Allowed, and this is what populates
        // the authz cache entry (client_id/tool_name/... match what the
        // second call below will use).
        let mut benign_input = base_input("tool_a");
        benign_input["recent_calls"] = json!([{"tool_name": "ping", "timestamp": 1000.0}]);
        benign_input["window_seconds"] = json!(300);
        let first = e.evaluate_raw(benign_input).unwrap();
        assert!(first.allow, "benign window must allow");
        let eval_count_after_first = e.eval_count();
        assert_eq!(eval_count_after_first, 1, "first call must be a real authz evaluation");

        // Second call: IDENTICAL everything except `recent_calls` (now a
        // bulk_read_spike window) — since `recent_calls` is excluded from
        // the authz cache key, this MUST be an authz cache hit (eval_count
        // unchanged)...
        let mut spike_input = base_input("tool_a");
        let recent_calls: Vec<_> = (0..11).map(|i| json!({"tool_name": format!("file_read_{i}"), "timestamp": 1000.0 + i as f64})).collect();
        spike_input["recent_calls"] = json!(recent_calls);
        spike_input["window_seconds"] = json!(300);
        let second = e.evaluate_raw(spike_input).unwrap();

        assert_eq!(
            e.eval_count(),
            eval_count_after_first,
            "the authz portion must be served from cache — recent_calls alone must not force a re-evaluation"
        );
        // ...but the FINAL decision must still deny, because anomaly is
        // evaluated fresh on every call regardless of the authz cache.
        assert!(
            !second.allow,
            "an anomaly-triggering recent_calls must still deny even when authz itself is a cache hit"
        );
        assert!(
            second.reasons.iter().any(|r| r == "bulk_file_read_spike"),
            "expected 'bulk_file_read_spike' in reasons, got {:?}",
            second.reasons
        );
    }

    /// Proves the admin anomaly-cutoff control (`GlobalLimits::
    /// anomaly_cutoff_threshold`, wired via `set_anomaly_cutoff`) actually
    /// changes a decision — the concrete gap this whole feature was built
    /// to close (a working UI + a persisted value that changed nothing).
    #[test]
    fn moving_the_anomaly_cutoff_changes_the_decision() {
        let e = engine_with_real_policy();
        assert_eq!(e.anomaly_cutoff(), 0.85, "default cutoff must match the Python original's 0.85");

        // A window that scores 0.535 (rapid_successive_invocations: 11
        // calls -> 0.5 + 1*0.035) — see anomaly_score.rs's tests for the
        // exact formula. Well under the 0.85 default, well over a tightened
        // 0.1 cutoff.
        let mut input = base_input("tool_a");
        let recent_calls: Vec<_> = (0..11).map(|i| json!({"tool_name": format!("t{i}"), "timestamp": i as f64})).collect();
        input["recent_calls"] = json!(recent_calls);

        let at_default_cutoff = e.evaluate_raw(input.clone()).unwrap();
        assert!(at_default_cutoff.allow, "score 0.535 must be under the default 0.85 cutoff");

        e.set_anomaly_cutoff(0.1);
        let at_tightened_cutoff = e.evaluate_raw(input).unwrap();
        assert!(
            !at_tightened_cutoff.allow,
            "the SAME window must now deny once the operator tightens the cutoff below the score"
        );
        assert!(
            at_tightened_cutoff.reasons.iter().any(|r| r == "anomaly_score_threshold_exceeded"),
            "expected 'anomaly_score_threshold_exceeded' in reasons, got {:?}",
            at_tightened_cutoff.reasons
        );
    }

    #[test]
    fn anomaly_score_check_exempts_is_testing_and_ping_liveness_probe() {
        let e = engine_with_real_policy();
        e.set_anomaly_cutoff(0.0); // any nonzero score now exceeds cutoff

        let recent_calls: Vec<_> = (0..11).map(|i| json!({"tool_name": format!("t{i}"), "timestamp": i as f64})).collect();

        let mut testing_input = base_input("tool_a");
        testing_input["recent_calls"] = json!(recent_calls.clone());
        testing_input["is_testing"] = json!(true);
        testing_input["client_roles"] = json!(["admin"]);
        // is_testing alone isn't sufficient for `allow` (authz.rego's
        // testing-bypass path has its own requirements) — this test only
        // asserts the anomaly reason is absent, not that the whole call
        // is allowed.
        let testing_result = e.evaluate_raw(testing_input).unwrap();
        assert!(
            !testing_result.reasons.iter().any(|r| r == "anomaly_score_threshold_exceeded"),
            "is_testing must exempt the anomaly-score check, got {:?}",
            testing_result.reasons
        );

        let mut ping_input = base_input("ping");
        ping_input["recent_calls"] = json!(recent_calls);
        let ping_result = e.evaluate_raw(ping_input).unwrap();
        assert!(
            !ping_result.reasons.iter().any(|r| r == "anomaly_score_threshold_exceeded"),
            "ping (R-4 liveness probe) must be exempt from the anomaly-score check, got {:?}",
            ping_result.reasons
        );
    }

    // `trait_evaluate_never_maps_ok_to_allow_on_error` (tested `PolicyEngine
    // ::evaluate`'s `Result<Decision, GateError>` mapping) removed along
    // with the trait impl it exercised — see the removal note above
    // `#[cfg(test)] mod tests`. `evaluate_raw`'s own `Result<EvalResult,
    // PolicyError>` has no `Decision`/`Allow` variant to accidentally map an
    // `Err` into in the first place, and `no_bundle_loaded_denies_every_
    // request` above already pins "nothing loaded -> Err, never a usable
    // result" — nothing left to duplicate.
}
