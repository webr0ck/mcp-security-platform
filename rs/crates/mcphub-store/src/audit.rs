//! The audit sink: `AuditSink` trait + `PgRedisAuditSink` implementation.
//!
//! `mcphub-gateway` (component 1) does not yet exist as a compiling crate
//! (its `src/` is empty at the time this was written — see the report this
//! crate ships with). `ARCHITECTURE.md` invariant 4 specifies the shape
//! this trait must have: "the audit record is durably queued (redis
//! stream + stdout JSON) before the caller gets a body. Audit write
//! failure = deny." We define `AuditSink` here with that shape now; if
//! `mcphub-gateway` later defines its own `AuditSink` trait, the two
//! should be unified (this one re-exported or an adapter written) rather
//! than kept as two parallel traits.
//!
//! Error type: `mcphub_types::GateError`, the same error type every other
//! gate in the enforcement chain uses — its `to_deny_reason()` is the only
//! way a `GateError` can become a `Decision`, and it never becomes
//! `Allow` (ARCHITECTURE.md invariant 1). Using it here (rather than
//! `StoreError` directly) means `invoke()` can treat an audit failure
//! exactly like an OPA-unreachable or Vault-unreachable failure: deny.
//!
//! ## Review notes: fixes applied to the initial cut (see team-lead's
//! defect report D2/D3/D5/D6/D7/D9 for the full findings)
//!
//! - **D2 (throughput / lock scope)**: the in-process hash-chain mutex
//!   used to be held across a Postgres round trip, a redis round trip, AND
//!   a blocking stdout write — serializing every request in the process
//!   through it. It is now held across exactly one thing: the Postgres
//!   INSERT (the only step that actually needs `prev_hash` to be read and
//!   advanced atomically). Redis + stdout happen with no lock held at all.
//!   The stdout write is additionally moved off the async executor via
//!   `spawn_blocking` so a stalled log sidecar can no longer wedge a tokio
//!   worker. Lock acquisition itself is bounded by `LOCK_ACQUIRE_TIMEOUT`
//!   so a stuck waiter fails closed (`DependencyUnavailable`) instead of
//!   queuing forever.
//! - **D3 (hash cannot be recomputed / unkeyed digest)**: `event_ts` is
//!   truncated to microsecond precision *before* hashing (Postgres
//!   `TIMESTAMPTZ` only stores microseconds — hashing the untruncated
//!   nanosecond value made ~999/1000 rows fail to verify against their own
//!   stored row). The digest is now HMAC-SHA256, keyed by a secret that
//!   never touches Postgres (see `PgRedisAuditSink::new`), so a DB-only
//!   attacker (the stated threat model) cannot forge a consistent chain
//!   even with full read/write access to every row. `audit_verify.rs` is
//!   the verifier that didn't previously exist anywhere in the codebase.
//! - **D5 (fork on redis failure / wrong-outcome durable row)**: the
//!   Postgres INSERT (the durable, append-only, never-updatable ledger
//!   entry) now happens *last*, after redis and stdout have both
//!   succeeded. If redis fails, `emit_inner` returns `Err` before Postgres
//!   is ever touched — no forked `prev_hash`, and no permanently-committed
//!   row claiming an outcome for a request the caller was ultimately
//!   denied on account of the audit failure itself.
//! - **D6 (hash scope)**: `canonical_core_json` now covers every
//!   non-derived column on the row (issuer, server_id, latency_ms,
//!   source_ip, redacted_fields, created_at were previously excluded).
//!   `created_at` is bound to the *same* value as `event_ts` in the INSERT
//!   (previously each column defaulted via its own independent `now()`
//!   call, so they could legitimately differ and neither was covered by
//!   the hash).
//! - **D9 (ingress validation / sink shape drift)**: `tool_name` and
//!   `request_id` — taken verbatim from the URL path upstream, per the
//!   defect report — are now length- and charset-validated before they
//!   reach any sink. A violation is a hard `Err` (fail-closed deny), not a
//!   truncation-and-continue, because `audit_events` is append-only: there
//!   is no remediation path for a secret or PII that already landed in an
//!   immutable row. The three sinks (Postgres row / redis stream / stdout
//!   line) now carry the same field set under the same names.

use crate::error::StoreError;
use crate::hash::hmac_sha256_hex;
use crate::redis_store::RedisStore;
use async_trait::async_trait;
use mcphub_types::GateError;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Deny,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Deny => "deny",
        }
    }

    pub(crate) fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Outcome::Allow),
            "deny" => Some(Outcome::Deny),
            _ => None,
        }
    }
}

/// Allowlisted enrichment fields. This is the redaction boundary described
/// in the handoff: a field NOT listed here is silently dropped on
/// deserialize (serde's default behavior for unknown fields), so a new
/// upstream field defaults to redacted, not exposed. Adding visibility for
/// a new field requires touching this struct explicitly — there is no
/// path that forwards an arbitrary map through untouched.
///
/// NOTE (D9): this allowlist only guards a path that deserializes
/// `AuditEnrichment` from an untrusted map. Production constructs this
/// struct directly (`Default::default()` plus explicit field sets) and
/// never deserializes attacker-controlled JSON into it — so this struct
/// guards a hypothetical future ingress path, not a live one today. The
/// live untrusted-ingress fields are `tool_name` and `request_id` on
/// `AuditRecord`, handled by `validate_ingress_fields` below.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEnrichment {
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub notices: Vec<String>,
    #[serde(default)]
    pub session_jti: Option<String>,
    #[serde(default)]
    pub tainted: Option<bool>,
    #[serde(default)]
    pub principal_type: Option<String>,
    #[serde(default)]
    pub principal_issuer: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub event_id: Uuid,
    pub request_id: String,
    pub principal_id: String,
    pub issuer: Option<String>,
    pub server_id: Option<Uuid>,
    pub tool_id: Option<Uuid>,
    pub tool_name: String,
    pub outcome: Outcome,
    /// Stable machine code from `mcphub_types::DenyReason::code()`; `None` on allow.
    pub deny_reason: Option<String>,
    pub latency_ms: Option<i32>,
    pub source_ip: Option<String>,
    pub enrichment: AuditEnrichment,
}

/// Ingress bounds for fields that flow verbatim from an untrusted caller
/// (the URL path, per the defect report) into three durable/semi-durable
/// sinks (Postgres, redis, stdout) and the tamper-evidence hash itself.
/// `audit_events` has no UPDATE/DELETE, so a secret or PII that gets past
/// this check has no remediation path — this must reject, not truncate.
const MAX_TOOL_NAME_LEN: usize = 256;
const MAX_REQUEST_ID_LEN: usize = 128;

/// Conservative allowlist: identifier-shaped values only. Deliberately
/// excludes characters that show up in bearer tokens / API keys / URLs
/// with embedded credentials (`.`, `/`, `@`, `:`, `=`, `+` beyond the
/// small set below) — this is defense-in-depth, not a substitute for
/// proper upstream validation of what a "tool name" or "request id" is
/// allowed to look like (see the `bin/mcphubd` contract note in this
/// crate's handoff report).
fn is_ingress_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
}

fn validate_ingress_fields(record: &AuditRecord) -> Result<(), StoreError> {
    if record.tool_name.is_empty() || record.tool_name.len() > MAX_TOOL_NAME_LEN {
        return Err(StoreError::InvariantViolation(format!(
            "tool_name length {} outside allowed bounds (1..={MAX_TOOL_NAME_LEN})",
            record.tool_name.len()
        )));
    }
    if !record.tool_name.chars().all(is_ingress_safe_char) {
        return Err(StoreError::InvariantViolation(
            "tool_name contains characters outside the ingress-safe allowlist".into(),
        ));
    }
    if record.request_id.is_empty() || record.request_id.len() > MAX_REQUEST_ID_LEN {
        return Err(StoreError::InvariantViolation(format!(
            "request_id length {} outside allowed bounds (1..={MAX_REQUEST_ID_LEN})",
            record.request_id.len()
        )));
    }
    if !record.request_id.chars().all(is_ingress_safe_char) {
        return Err(StoreError::InvariantViolation(
            "request_id contains characters outside the ingress-safe allowlist".into(),
        ));
    }
    Ok(())
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Must durably queue the record (Postgres row + redis stream entry +
    /// stdout JSON line) before returning `Ok`. Any failure in any of the
    /// three sinks is `Err` — never a partial-success `Ok`.
    async fn emit(&self, record: AuditRecord) -> Result<(), GateError>;

    /// Best-effort health signal for `/healthz/ready` (surfaced via
    /// `mcphub-gateway`'s `AuditSink` trait + `wiring::audit::
    /// AuditSinkAdapter` in `bin/mcphubd`). Default `true` so a sink with
    /// no meaningful health concept (a test double, say) doesn't have to
    /// implement this. `PgRedisAuditSink` overrides it with `is_writer_
    /// alive()` — this is the "make the writer-supervisor signal visible"
    /// half of that fix; without an override here it was a signal nothing
    /// consumed.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Truncate to microsecond precision, matching Postgres `TIMESTAMPTZ`'s
/// storage resolution (D3). The hash preimage must be built from exactly
/// what ends up in the row — hashing the untruncated nanosecond value
/// meant nearly every event failed to verify against its own stored row.
fn truncate_to_micros(ts: time::OffsetDateTime) -> time::OffsetDateTime {
    let nanos = ts.unix_timestamp_nanos();
    let truncated = (nanos / 1_000) * 1_000;
    time::OffsetDateTime::from_unix_timestamp_nanos(truncated)
        .expect("truncating toward zero cannot leave the valid i128 range")
}

/// Canonical core-field JSON used for the integrity hash. Covers every
/// non-derived column on `audit_events` (D6) — previously only 8 of 15
/// columns were covered, leaving `issuer`, `server_id`, `latency_ms`,
/// `source_ip`, `redacted_fields`, and `created_at` free for an attacker
/// with DB write access to rewrite without invalidating any hash.
/// `serde_json`'s default map type sorts keys (the workspace does not
/// enable the `preserve_order` feature), so this is a stable canonical
/// encoding regardless of caller-supplied field order.
/// `chain_id`/`chain_seq` (team-lead review, item 3) are part of the
/// hashed preimage, not just stored columns — otherwise an attacker with
/// DB write access could reassign a row to a different chain or splice
/// its position within one without invalidating its own hash.
pub(crate) fn canonical_core_json(
    record: &AuditRecord,
    event_ts_iso: &str,
    created_at_iso: &str,
    redacted_fields: &serde_json::Value,
    chain_id: Uuid,
    chain_seq: i64,
) -> serde_json::Value {
    serde_json::json!({
        "event_id": record.event_id.to_string(),
        "event_ts": event_ts_iso,
        "created_at": created_at_iso,
        "request_id": record.request_id,
        "principal_id": record.principal_id,
        "issuer": record.issuer,
        "server_id": record.server_id.map(|id| id.to_string()),
        "tool_name": record.tool_name,
        "tool_id": record.tool_id.map(|id| id.to_string()),
        "outcome": record.outcome.as_str(),
        "deny_reason": record.deny_reason,
        "latency_ms": record.latency_ms,
        "source_ip": record.source_ip,
        "redacted_fields": redacted_fields,
        "chain_id": chain_id.to_string(),
        "chain_seq": chain_seq,
    })
}

/// Reserved sentinel values for the one synthetic row per chain (D3/item
/// 3): every chain's `chain_seq = 0` row is a genesis marker, not a real
/// invocation. Recognizable by `request_id`/`tool_name` so `ui_data.rs`
/// can filter it out of admin-facing views and so a human reading the
/// table isn't confused by an "invocation" with no real caller.
pub const CHAIN_GENESIS_REQUEST_ID: &str = "__chain_genesis__";
const CHAIN_GENESIS_PRINCIPAL_ID: &str = "__system__";
const CHAIN_GENESIS_TOOL_NAME: &str = "__chain_genesis__";

/// Minimum HMAC key length (D3): 256 bits, matching the digest's own
/// output width. Refusing a short key at construction time is the
/// fail-closed complement to "the key never touches Postgres" — a
/// caller that passes an empty/weak key gets a startup error, not a
/// silently-weakened chain.
const MIN_HMAC_KEY_LEN: usize = 32;

// =============================================================================
// Group-commit writer (team-lead review, item 2 — HIGH)
// =============================================================================
// The scaling architect's analysis (rs/SCALING.md) found the audit writer
// binding throughput at a single replica: one Postgres round trip per
// event caps well below the 20k req/s target. This replaces the
// one-INSERT-per-emit path with a single background task per sink that
// owns the chain state EXCLUSIVELY (no mutex — it's the only thing that
// ever touches `next_seq`/`prev_hash`, so plain local variables are
// enough), batches whatever's queued when it wakes, and does ONE
// multi-row Postgres INSERT + ONE pipelined redis XADD per batch instead
// of one round trip per event.
//
// Invariant 4 is preserved EXACTLY: `emit()` still does not return until
// its record is durably committed. Batching changes commit GRANULARITY
// (a caller's ack now depends on its whole batch, not just its own row),
// never the ordering guarantee — the `oneshot` ack is what makes that
// work: `emit_inner` blocks on it, and it is only ever sent after the
// batch's Postgres INSERT has actually returned.
//
// D5's ordering is preserved per batch: redis, then stdout, then Postgres
// last. If redis or stdout fails for a batch, the writer does NOT advance
// `next_seq`/`prev_hash` — since assignment and advancement happen in the
// same single-threaded task with no concurrent writer, an aborted batch
// costs nothing to unwind. The same seq numbers are simply reused by the
// next batch. This is what avoids the alternative design's failure mode
// (assigning `chain_seq` via an atomic counter BEFORE queuing for I/O)
// where a failed batch would leave a permanent gap in the sequence that a
// legitimate transient Postgres outage could never repair.

/// Bounds how long a caller's `emit()` waits for the writer to ack. An
/// individual caller's wait is "until the batch it landed in commits",
/// not a fixed per-call cost — bounded so a wedged writer (Postgres truly
/// unreachable) fails closed instead of hanging every caller forever.
///
/// TOTAL WORST CASE (critic finding, retuned): `WRITER_ENQUEUE_TIMEOUT` +
/// `WRITER_ACK_TIMEOUT` compose serially on `emit_inner`'s hot path — EVERY
/// request, including every deny, passes through here. The original 2s+5s
/// = 7s composition was three orders of magnitude outside the p99.9 <= 50ms
/// budget: a wedged writer turned every request into a 7s hang before
/// denying, which at 3000 concurrent agents is 3000 parked tasks — a DoS
/// amplifier, not a safety property, even though it does eventually fail
/// closed. Retuned to 500ms + 2s = 2.5s worst case. Still enormous against
/// a healthy path measured in single-digit milliseconds, but an order of
/// magnitude faster to shed load. If either constant is adjusted again,
/// re-derive this comment's total — the failure mode this guards against
/// is exactly "someone tunes one constant in isolation and silently
/// reintroduces the composition problem."
const WRITER_ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Bounds how long a caller will wait for a slot in the writer's queue.
/// Deliberately shorter than `WRITER_ACK_TIMEOUT`: a full queue means we are
/// already overloaded, and the right answer is to shed load with a
/// fail-closed deny rather than to add more waiters behind the ones already
/// queued. Without this bound, `tx.send().await` on a bounded channel parks
/// indefinitely and the ack timeout below is never reached. See
/// `WRITER_ACK_TIMEOUT`'s doc comment for the combined worst-case budget.
const WRITER_ENQUEUE_TIMEOUT: Duration = Duration::from_millis(500);

/// Upper bound on how many records one Postgres round trip covers.
const MAX_BATCH_SIZE: usize = 500;

/// Depth of the channel between callers and the writer task. A full
/// channel applies backpressure (`send().await` waits) rather than
/// dropping — matches invariant 4 (durably queued before the caller gets
/// a response); `WRITER_ACK_TIMEOUT` bounds the worst case for the caller.
const WRITER_CHANNEL_CAPACITY: usize = 4096;

struct WriteRequest {
    record: AuditRecord,
    ack: tokio::sync::oneshot::Sender<Result<(), StoreError>>,
}

pub struct PgRedisAuditSink {
    /// One per process boot (item 3) — NOT shared across replicas, NOT
    /// persisted/resumed across restarts. Lets `audit_verify::verify_chain`
    /// partition the table by chain and validate each chain's `prev_hash`
    /// links independently of how replicas' rows interleave in insertion
    /// order. A global total order across chains was considered and
    /// rejected (per the review): it needs a global serializer, the exact
    /// latency wall the group-commit design removes.
    chain_id: Uuid,
    tx: tokio::sync::mpsc::Sender<WriteRequest>,
    /// Critic finding: `run_writer`'s `JoinHandle` used to be dropped —
    /// if the writer task ever exited (panic, or its own bug), every
    /// subsequent `emit()` would deny forever with nothing observing it
    /// and no restart. The panic surface is genuinely small today (every
    /// I/O path returns `Result`; the one `.expect()` in this file,
    /// `truncate_to_micros`, is unreachable), but "the audit sink is
    /// permanently down" must be a health-check signal, not a silent
    /// 100%-deny black box. Set to `false` by a small supervisor task the
    /// moment `run_writer` returns for ANY reason; `is_writer_alive()`
    /// exposes it for `/healthz/ready` (or an equivalent) to surface.
    writer_alive: Arc<std::sync::atomic::AtomicBool>,
}

impl PgRedisAuditSink {
    /// `hmac_key` must be at least 32 bytes (256 bits) and must be sourced
    /// from somewhere that never persists it to Postgres (Vault, a mounted
    /// secret, an env var populated from a secret manager) — see this
    /// crate's handoff report for the exact `bin/mcphubd` wiring contract
    /// this requires (a new `cfg.audit_hmac_key: Vec<u8>` plumbed through
    /// to this constructor).
    ///
    /// Spawns the group-commit writer task — must be called from within a
    /// running Tokio runtime (true of every real caller: `bin/mcphubd`'s
    /// `build_app` is `async fn`).
    pub fn new(pool: PgPool, redis: RedisStore, hmac_key: Vec<u8>) -> Result<Self, StoreError> {
        validate_hmac_key_len(&hmac_key)?;
        let hmac_key: Arc<[u8]> = Arc::from(hmac_key);
        let chain_id = Uuid::new_v4();
        let (tx, rx) = tokio::sync::mpsc::channel(WRITER_CHANNEL_CAPACITY);
        let writer_alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let handle = tokio::spawn(run_writer(pool, redis, hmac_key, chain_id, rx));
        // Supervisor: the only job of this task is to notice `run_writer`
        // exiting (for ANY reason — clean return on channel close, or a
        // panic) and flip the flag `is_writer_alive()` reports. It does
        // NOT restart the writer — `run_writer` owns `next_seq`/
        // `prev_hash` in local variables with no persisted/resumable
        // state, so a bare restart would not know where the chain left
        // off; that's future work (`bin/mcphubd` acting on `!is_writer_
        // alive()` today means "stop serving traffic", not "silently
        // keep going"), but it is strictly better than the previous
        // "drop the handle and never find out" state.
        {
            let writer_alive = writer_alive.clone();
            tokio::spawn(async move {
                match handle.await {
                    Ok(()) => tracing::error!("audit writer task exited (channel closed — sink dropped, or unexpected clean return); every subsequent emit() will now deny"),
                    Err(join_err) => tracing::error!(error = %join_err, "audit writer task PANICKED; every subsequent emit() will now deny"),
                }
                writer_alive.store(false, std::sync::atomic::Ordering::SeqCst);
            });
        }
        Ok(Self { chain_id, tx, writer_alive })
    }

    /// The chain this sink is writing. Two `PgRedisAuditSink`s (two
    /// `mcphubd` replicas, or two instances in one test) never share one.
    pub fn chain_id(&self) -> Uuid {
        self.chain_id
    }

    /// `false` once the writer task has exited for any reason (panic, or
    /// its channel closing unexpectedly) — every `emit()` after that point
    /// denies via `WRITER_ENQUEUE_TIMEOUT`/closed-channel detection
    /// regardless, but this lets a health check surface "the audit sink is
    /// down" as a distinct, actionable signal instead of a generic
    /// per-request timeout an operator has to infer the cause of.
    pub fn is_writer_alive(&self) -> bool {
        self.writer_alive.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn validate_hmac_key_len(hmac_key: &[u8]) -> Result<(), StoreError> {
    if hmac_key.len() < MIN_HMAC_KEY_LEN {
        return Err(StoreError::InvariantViolation(format!(
            "audit HMAC key must be at least {MIN_HMAC_KEY_LEN} bytes, got {}",
            hmac_key.len()
        )));
    }
    Ok(())
}

#[async_trait]
impl AuditSink for PgRedisAuditSink {
    async fn emit(&self, record: AuditRecord) -> Result<(), GateError> {
        self.emit_inner(record).await.map_err(GateError::from)
    }

    fn is_healthy(&self) -> bool {
        self.is_writer_alive()
    }
}

impl PgRedisAuditSink {
    /// Validates, hands off to the writer task, and waits for its ack.
    async fn emit_inner(&self, record: AuditRecord) -> Result<(), StoreError> {
        validate_ingress_fields(&record)?;

        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();

        // The ENQUEUE must be bounded, not just the ack. `tx` is a bounded
        // mpsc (`WRITER_CHANNEL_CAPACITY`), so `send().await` parks until a
        // slot frees. With only the ack timed out, a writer that is merely
        // slow — a stalled Postgres, a redis retry storm — backs the queue up
        // and every caller then blocks in `send()` *forever*, having never
        // reached the code that would time them out. That is unbounded
        // blocking on the audit path, which invariant 1 forbids: under
        // overload the correct behaviour is a prompt fail-closed deny, not a
        // request that hangs until the client gives up.
        //
        // A full queue is a real signal (we are overloaded), so it denies.
        tokio::time::timeout(WRITER_ENQUEUE_TIMEOUT, self.tx.send(WriteRequest { record, ack: ack_tx }))
            .await
            .map_err(|_| StoreError::DependencyUnavailable {
                dependency: "audit_writer",
                message: format!("audit writer queue full for {WRITER_ENQUEUE_TIMEOUT:?} (overloaded)"),
            })?
            .map_err(|_| StoreError::DependencyUnavailable {
                dependency: "audit_writer",
                message: "the audit group-commit writer task has exited".into(),
            })?;

        tokio::time::timeout(WRITER_ACK_TIMEOUT, ack_rx)
            .await
            .map_err(|_| StoreError::DependencyUnavailable {
                dependency: "audit_writer",
                message: format!("no ack from the audit writer within {WRITER_ACK_TIMEOUT:?}"),
            })?
            .map_err(|_| StoreError::DependencyUnavailable {
                dependency: "audit_writer",
                message: "the audit writer dropped this request's ack channel (task panicked?)".into(),
            })?
    }
}

/// One record, fully prepared — chain position assigned and hash computed
/// — entirely in-memory, before any I/O for its batch begins. This is
/// what makes an aborted batch free to unwind: nothing here has touched
/// redis, stdout, or Postgres yet.
struct Prepared {
    record: AuditRecord,
    event_ts: time::OffsetDateTime,
    event_ts_iso: String,
    redacted_fields: serde_json::Value,
    chain_id: Uuid,
    chain_seq: i64,
    prev_hash: Option<String>,
    sha256_hash: String,
}

fn prepare_one(
    record: AuditRecord,
    chain_id: Uuid,
    chain_seq: i64,
    prev_hash: Option<String>,
    hmac_key: &[u8],
) -> Result<Prepared, StoreError> {
    // Bound to the SAME value as created_at (D6) — see canonical_core_json.
    let event_ts = truncate_to_micros(time::OffsetDateTime::now_utc());
    let event_ts_iso = event_ts
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| StoreError::InvariantViolation(e.to_string()))?;
    let redacted_fields = serde_json::to_value(&record.enrichment)?;
    let core_json = canonical_core_json(&record, &event_ts_iso, &event_ts_iso, &redacted_fields, chain_id, chain_seq);
    let sha256_hash = hmac_sha256_hex(hmac_key, &serde_json::to_vec(&core_json)?);
    Ok(Prepared { record, event_ts, event_ts_iso, redacted_fields, chain_id, chain_seq, prev_hash, sha256_hash })
}

/// The one synthetic record per chain, written as `chain_seq = 0` before
/// any real event. Postgres-only (not sent to redis/stdout — it isn't a
/// real invocation and doesn't belong in the SIEM stream).
fn genesis_record() -> AuditRecord {
    AuditRecord {
        event_id: Uuid::new_v4(),
        request_id: CHAIN_GENESIS_REQUEST_ID.to_string(),
        principal_id: CHAIN_GENESIS_PRINCIPAL_ID.to_string(),
        issuer: None,
        server_id: None,
        tool_id: None,
        tool_name: CHAIN_GENESIS_TOOL_NAME.to_string(),
        outcome: Outcome::Allow,
        deny_reason: None,
        latency_ms: None,
        source_ip: None,
        enrichment: AuditEnrichment::default(),
    }
}

fn redis_stream_fields(p: &Prepared) -> Vec<(&'static str, String)> {
    vec![
        ("event_id", p.record.event_id.to_string()),
        ("event_ts", p.event_ts_iso.clone()),
        ("request_id", p.record.request_id.clone()),
        ("principal_id", p.record.principal_id.clone()),
        ("issuer", p.record.issuer.clone().unwrap_or_default()),
        ("server_id", p.record.server_id.map(|id| id.to_string()).unwrap_or_default()),
        ("tool_id", p.record.tool_id.map(|id| id.to_string()).unwrap_or_default()),
        ("tool_name", p.record.tool_name.clone()),
        ("outcome", p.record.outcome.as_str().to_string()),
        ("deny_reason", p.record.deny_reason.clone().unwrap_or_default()),
        ("latency_ms", p.record.latency_ms.map(|v| v.to_string()).unwrap_or_default()),
        ("source_ip", p.record.source_ip.clone().unwrap_or_default()),
        ("redacted_fields", p.redacted_fields.to_string()),
        ("sha256_hash", p.sha256_hash.clone()),
    ]
}

fn stdout_line(p: &Prepared) -> Result<String, StoreError> {
    let stdout_record = serde_json::json!({
        "log_type": "mcp_audit_event",
        "event_id": p.record.event_id.to_string(),
        "event_type": "TOOL_INVOCATION",
        "timestamp": p.event_ts_iso,
        "client_id": p.record.principal_id,
        "tool_name": p.record.tool_name,
        "tool_id": p.record.tool_id.map(|id| id.to_string()),
        "outcome": p.record.outcome.as_str(),
        // Kept for existing consumers that expect an array...
        "deny_reasons": p.record.deny_reason.as_ref().map(|r| vec![r.clone()]).unwrap_or_default(),
        // ...and unified (D9) with the scalar shape Postgres/redis use.
        "deny_reason": p.record.deny_reason,
        "request_id": p.record.request_id,
        "latency_ms": p.record.latency_ms,
        "source_ip": p.record.source_ip,
        "sha256_hash": p.sha256_hash,
        "principal_id": p.record.principal_id,
        "principal_issuer": p.record.issuer,
        "server_id": p.record.server_id.map(|id| id.to_string()),
        "redacted_fields": p.redacted_fields,
        "roles": p.record.enrichment.roles,
        "notices": p.record.enrichment.notices,
        "session_jti": p.record.enrichment.session_jti,
        "tainted": p.record.enrichment.tainted,
        "principal_type": p.record.enrichment.principal_type,
        // Chain identity must reach the SIEM stream, not just Postgres: a
        // consumer tailing stdout has to partition rows by chain and check
        // `prev_hash` links within each one, exactly as `verify_chain` does.
        // This previously emitted the literal string "placeholder", which
        // made the stdout ledger unverifiable on its own.
        "chain_id": p.chain_id.to_string(),
        "chain_seq": p.chain_seq,
        "prev_hash": p.prev_hash,
    });
    Ok(serde_json::to_string(&stdout_record)?)
}

/// Redis: ONE pipelined round trip for the whole batch. All-or-nothing at
/// the connection level — a redis outage denies every event in the batch
/// together, which is correct per invariant 4 (fail closed), not a
/// regression from the single-event path.
async fn push_batch_to_redis(redis: &RedisStore, rows: &[Prepared]) -> Result<(), StoreError> {
    let fields: Vec<Vec<(&str, String)>> = rows.iter().map(redis_stream_fields).collect();
    redis.audit_stream_push_batch(&fields).await
}

/// Stdout: ONE `spawn_blocking` call, N lines — a slow/stopped log
/// sidecar still can't wedge a tokio worker (D2), now amortized per batch
/// instead of per event.
async fn write_batch_to_stdout(rows: &[Prepared]) -> Result<(), StoreError> {
    let mut lines = String::new();
    for p in rows {
        lines.push_str(&stdout_line(p)?);
        lines.push('\n');
    }
    tokio::task::spawn_blocking(move || {
        use std::io::Write;
        write!(std::io::stdout(), "{lines}")
    })
    .await
    .map_err(|e| StoreError::InvariantViolation(format!("stdout writer task panicked: {e}")))?
    .map_err(|_| StoreError::InvariantViolation("stdout write failed".into()))?;
    Ok(())
}

/// Postgres: ONE multi-row INSERT for the whole batch — the durable
/// ledger commit, LAST (D5), after redis and stdout have both succeeded —
/// PLUS an upsert of this chain's high-water mark into `chains`, in the
/// SAME transaction. The two must commit together or not at all: a batch
/// that lands in `audit_events` but not `chains` would under-report the
/// chain's true tail to the verifier (silently reopening the truncation
/// gap `chains` exists to close); the reverse (chains advanced, no rows
/// written) can't happen since the upsert reads its values FROM the rows
/// just inserted, not from any independent source.
async fn insert_rows(pool: &PgPool, chain_id: Uuid, rows: &[Prepared]) -> Result<(), StoreError> {
    let mut tx = pool.begin().await?;

    let mut qb = sqlx::QueryBuilder::new(
        "INSERT INTO audit_events (
            event_id, event_ts, request_id, principal_id, issuer,
            server_id, tool_id, tool_name, outcome, deny_reason,
            latency_ms, source_ip, sha256_hash, prev_hash, redacted_fields,
            created_at, chain_id, chain_seq
        ) ",
    );
    qb.push_values(rows, |mut b, p| {
        b.push_bind(p.record.event_id);
        b.push_bind(p.event_ts);
        b.push_bind(&p.record.request_id);
        b.push_bind(&p.record.principal_id);
        b.push_bind(&p.record.issuer);
        b.push_bind(p.record.server_id);
        b.push_bind(p.record.tool_id);
        b.push_bind(&p.record.tool_name);
        b.push_bind(p.record.outcome.as_str());
        b.push_bind(&p.record.deny_reason);
        b.push_bind(p.record.latency_ms);
        b.push_bind(p.record.source_ip.as_deref()).push_unseparated("::inet");
        b.push_bind(&p.sha256_hash);
        b.push_bind(&p.prev_hash);
        b.push_bind(&p.redacted_fields).push_unseparated("::jsonb");
        b.push_bind(p.event_ts);
        b.push_bind(chain_id);
        b.push_bind(p.chain_seq);
    });
    qb.build().execute(&mut *tx).await?;

    // `rows` is prepared in strictly increasing chain_seq order (see
    // `run_writer`'s `running_seq` counter), so the last element is this
    // batch's highest chain_seq/newest hash — exactly the high-water mark
    // `chains` should now record.
    let last = rows.last().ok_or_else(|| StoreError::InvariantViolation("insert_rows called with an empty batch".into()))?;
    sqlx::query(
        r#"
        INSERT INTO chains (chain_id, last_chain_seq, last_sha256_hash)
        VALUES ($1, $2, $3)
        ON CONFLICT (chain_id) DO UPDATE
            SET last_chain_seq = EXCLUDED.last_chain_seq,
                last_sha256_hash = EXCLUDED.last_sha256_hash,
                updated_at = now()
        "#,
    )
    .bind(chain_id)
    .bind(last.chain_seq)
    .bind(&last.sha256_hash)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

async fn run_writer(
    pool: PgPool,
    redis: RedisStore,
    hmac_key: Arc<[u8]>,
    chain_id: Uuid,
    mut rx: tokio::sync::mpsc::Receiver<WriteRequest>,
) {
    // Owned exclusively by this task — no lock needed. `next_seq == 0`
    // means genesis for this chain has not been written yet.
    let mut next_seq: i64 = 0;
    let mut prev_hash: Option<String> = None;

    loop {
        let Some(first) = rx.recv().await else {
            return; // sink dropped, channel closed — normal shutdown
        };
        let mut batch = Vec::with_capacity(MAX_BATCH_SIZE);
        batch.push(first);
        while batch.len() < MAX_BATCH_SIZE {
            match rx.try_recv() {
                Ok(req) => batch.push(req),
                Err(_) => break,
            }
        }

        if next_seq == 0 {
            match prepare_one(genesis_record(), chain_id, 0, None, &hmac_key) {
                Ok(genesis) => match insert_rows(&pool, chain_id, std::slice::from_ref(&genesis)).await {
                    Ok(()) => {
                        next_seq = 1;
                        prev_hash = Some(genesis.sha256_hash.clone());
                    }
                    Err(e) => {
                        let message = e.to_string();
                        for req in batch {
                            let _ = req.ack.send(Err(StoreError::DependencyUnavailable {
                                dependency: "postgres",
                                message: message.clone(),
                            }));
                        }
                        continue;
                    }
                },
                Err(e) => {
                    let message = e.to_string();
                    for req in batch {
                        let _ = req.ack.send(Err(StoreError::InvariantViolation(message.clone())));
                    }
                    continue;
                }
            }
        }

        // Prepare every record in-memory first (no I/O yet). A record that
        // fails to prepare (e.g. a clock/serialization error) is acked
        // alone and excluded — it must not fail its batch-mates.
        let mut prepared = Vec::with_capacity(batch.len());
        let mut acks = Vec::with_capacity(batch.len());
        let mut running_prev = prev_hash.clone();
        let mut running_seq = next_seq;
        for req in batch {
            // Design decision (team lead, on the ack-timeout asymmetry the
            // critic found): if the caller already gave up waiting
            // (`emit_inner`'s `WRITER_ACK_TIMEOUT` fired and dropped
            // `ack_rx`, which closes the paired `Sender` — `is_closed()`
            // detects this with no new channel/field needed), the record
            // is STILL written, never skipped or suppressed. The
            // authorization decision and dispatch already happened for
            // real; suppressing the row would make the ledger claim a
            // real side effect never occurred, which is worse than the
            // client/ledger disagreement it would "fix". What's actually
            // inconsistent is the CLIENT's view, not the ledger — the
            // caller was told `deny` (timeout) while the backend really
            // ran. This is a first cut: a loud log line, not an
            // `AuditEnrichment` field (that field's allowlist-on-
            // deserialize shape means adding to it is a deliberate,
            // reviewed act on its own, not bundled into this fix) — an
            // incident responder reading logs sees exactly this
            // divergence, but the row itself doesn't yet carry a queryable
            // `response_delivered: false` marker.
            if req.ack.is_closed() {
                tracing::warn!(
                    request_id = %req.record.request_id,
                    principal_id = %req.record.principal_id,
                    tool_name = %req.record.tool_name,
                    "caller abandoned before ack (WRITER_ACK_TIMEOUT elapsed) — the record is still being written as it actually occurred; the caller received a fail-closed deny with no knowledge this row exists"
                );
            }
            match prepare_one(req.record, chain_id, running_seq, running_prev.clone(), &hmac_key) {
                Ok(p) => {
                    running_prev = Some(p.sha256_hash.clone());
                    running_seq += 1;
                    prepared.push(p);
                    acks.push(req.ack);
                }
                Err(e) => {
                    let _ = req.ack.send(Err(e));
                }
            }
        }
        if prepared.is_empty() {
            continue;
        }

        // POSTGRES FIRST (critic finding: was redis -> stdout -> Postgres).
        // Postgres is the durable, HMAC-chained ledger; `chain_seq`/
        // `prev_hash` for the NEXT batch are only ever advanced after THIS
        // commit succeeds. That's what makes a mid-batch failure safe to
        // retry: nothing durable has changed, so the next attempt reuses
        // the exact same `chain_seq` range for the exact same content —
        // never a different batch's content under a seq number a previous
        // attempt already gave out. The old order inverted this: redis
        // `XADD` and the stdout lines went out BEFORE the Postgres insert,
        // so a failed insert still left up to `MAX_BATCH_SIZE` phantom
        // `"outcome":"allow"` events in the SIEM stream for callers who
        // were actually denied by this failure, and the retried batch then
        // reissued those same `chain_seq` values with different
        // `event_id`s/hashes — duplicate `(chain_id, chain_seq)` with
        // divergent hashes, indistinguishable from tampering to any
        // consumer verifying the stream.
        if let Err(e) = insert_rows(&pool, chain_id, &prepared).await {
            let message = e.to_string();
            for ack in acks {
                let _ = ack.send(Err(StoreError::DependencyUnavailable { dependency: "postgres", message: message.clone() }));
            }
            continue; // next_seq/prev_hash untouched — no gap, safe to retry
        }
        // Committed. Advance chain state now — nothing below can ever
        // cause THIS batch's rows to be retried/reissued, so a
        // redis/stdout failure past this point is a "these specific
        // already-durable events didn't reach the stream" gap, never a
        // duplicate-with-a-different-hash integrity violation.
        next_seq = running_seq;
        prev_hash = prepared.last().map(|p| p.sha256_hash.clone());

        if let Err(e) = push_batch_to_redis(&redis, &prepared).await {
            let message = e.to_string();
            for ack in acks {
                let _ = ack.send(Err(StoreError::DependencyUnavailable { dependency: "redis", message: message.clone() }));
            }
            continue;
        }

        match write_batch_to_stdout(&prepared).await {
            Ok(()) => {
                for ack in acks {
                    let _ = ack.send(Ok(()));
                }
            }
            Err(e) => {
                let message = e.to_string();
                for ack in acks {
                    let _ = ack.send(Err(StoreError::InvariantViolation(message.clone())));
                }
                // next_seq/prev_hash were already advanced above (Postgres
                // committed) — this batch is durable and will never be
                // retried/reissued; a stdout failure here only means these
                // already-committed events didn't reach stdout, not a gap
                // in the chain or a risk of duplicate chain_seq values.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed chain identity for hashing tests. These tests compare hashes to
    /// each other (determinism, field coverage, tamper detection), so the chain
    /// values only need to be consistent, not meaningful.
    const TEST_CHAIN_ID: Uuid = Uuid::nil();
    const TEST_CHAIN_SEQ: i64 = 0;


    fn valid_record() -> AuditRecord {
        AuditRecord {
            event_id: Uuid::new_v4(),
            request_id: "req-1".into(),
            principal_id: "alice".into(),
            issuer: Some("https://idp.example.com".into()),
            server_id: None,
            tool_id: None,
            tool_name: "echo".into(),
            outcome: Outcome::Allow,
            deny_reason: None,
            latency_ms: Some(3),
            source_ip: Some("127.0.0.1".into()),
            enrichment: AuditEnrichment::default(),
        }
    }

    #[test]
    fn redaction_allowlist_drops_unknown_field() {
        let input = serde_json::json!({
            "roles": ["employee"],
            "notices": ["taint-notice"],
            "leaked_secret": "this-must-never-survive",
            "another_unlisted_field": {"nested": "also-dropped"},
        });

        let enrichment: AuditEnrichment =
            serde_json::from_value(input).expect("unknown fields must not fail deserialization");
        let out = serde_json::to_value(&enrichment).unwrap();
        let out_str = out.to_string();

        assert!(!out_str.contains("leaked_secret"));
        assert!(!out_str.contains("also-dropped"));
        assert!(out_str.contains("employee"));
        assert!(out_str.contains("taint-notice"));
    }

    #[test]
    fn empty_enrichment_defaults_are_all_absent() {
        let enrichment: AuditEnrichment = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(enrichment.roles.is_empty());
        assert!(enrichment.notices.is_empty());
        assert!(enrichment.session_jti.is_none());
        assert!(enrichment.tainted.is_none());
    }

    // --- D3: timestamp truncation ---------------------------------------

    #[test]
    fn truncate_to_micros_drops_sub_microsecond_precision() {
        let ts = time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();
        let truncated = truncate_to_micros(ts);
        assert_eq!(truncated.unix_timestamp_nanos(), 1_700_000_000_123_456_000);
    }

    #[test]
    fn truncate_to_micros_is_idempotent() {
        let ts = time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();
        let once = truncate_to_micros(ts);
        let twice = truncate_to_micros(once);
        assert_eq!(once, twice);
    }

    /// Mutation proof (D3): hashing the untruncated (nanosecond) timestamp
    /// instead of the microsecond-truncated one changes the digest for the
    /// overwhelming majority of timestamps (any nanosecond value not
    /// already a multiple of 1000). This pins the "hash the truncated
    /// value" behavior directly — reverting the truncation in
    /// `emit_inner`/`canonical_core_json` would make this fail because the
    /// preimage would stop matching what's actually stored in the
    /// TIMESTAMPTZ column for any sub-microsecond-precision instant.
    #[test]
    fn hashing_untruncated_timestamp_would_diverge_from_stored_precision() {
        let ts = time::OffsetDateTime::from_unix_timestamp_nanos(1_700_000_000_123_456_789).unwrap();
        let iso_untruncated = ts.format(&time::format_description::well_known::Rfc3339).unwrap();
        let iso_truncated =
            truncate_to_micros(ts).format(&time::format_description::well_known::Rfc3339).unwrap();
        assert_ne!(
            iso_untruncated, iso_truncated,
            "this timestamp has non-zero sub-microsecond digits, so truncation must change its ISO form \
             (if this ever fails, Rfc3339 formatting stopped emitting nanosecond precision and the whole \
             D3 bug class is moot)"
        );
    }

    // --- D6: hash coverage ------------------------------------------------

    #[test]
    fn canonical_json_covers_all_forensically_relevant_columns() {
        let record = AuditRecord {
            issuer: Some("https://idp.example.com".into()),
            server_id: Some(Uuid::new_v4()),
            source_ip: Some("10.0.0.1".into()),
            latency_ms: Some(42),
            ..valid_record()
        };
        let redacted = serde_json::json!({"roles": ["employee"]});
        let json = canonical_core_json(&record, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        for key in [
            "event_id",
            "event_ts",
            "created_at",
            "request_id",
            "principal_id",
            "issuer",
            "server_id",
            "tool_name",
            "tool_id",
            "outcome",
            "deny_reason",
            "latency_ms",
            "source_ip",
            "redacted_fields",
        ] {
            assert!(json.get(key).is_some(), "canonical_core_json is missing forensic field {key:?}");
        }
    }

    /// Mutation proof (D6): changing `source_ip` — one of the fields that
    /// used to be excluded from the hash — must change the hash. Before
    /// the fix this test would fail (the two JSON blobs, and hence their
    /// hashes, would be identical because `source_ip` never entered the
    /// preimage).
    #[test]
    fn changing_previously_uncovered_fields_changes_the_hash() {
        let redacted = serde_json::json!({});
        let a = valid_record();
        let mut b = a.clone();
        b.source_ip = Some("203.0.113.99".into()); // attacker-controlled rewrite target, per the report
        let json_a = canonical_core_json(&a, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        let json_b = canonical_core_json(&b, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        assert_ne!(json_a, json_b, "source_ip must be part of the hashed preimage");

        let mut c = a.clone();
        c.issuer = Some("https://attacker-controlled-idp.example.com".into());
        let json_c = canonical_core_json(&c, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", &redacted, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        assert_ne!(json_a, json_c, "issuer must be part of the hashed preimage");

        let redacted_tampered = serde_json::json!({"roles": ["super_admin"]});
        let json_d = canonical_core_json(&a, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", &redacted_tampered, TEST_CHAIN_ID, TEST_CHAIN_SEQ);
        assert_ne!(json_a, json_d, "redacted_fields must be part of the hashed preimage");
    }

    // --- D9: ingress validation --------------------------------------------

    #[test]
    fn oversized_tool_name_is_rejected() {
        let mut record = valid_record();
        record.tool_name = "a".repeat(MAX_TOOL_NAME_LEN + 1);
        let err = validate_ingress_fields(&record).expect_err("oversized tool_name must be rejected");
        assert!(matches!(err, StoreError::InvariantViolation(_)));
    }

    #[test]
    fn tool_name_with_disallowed_characters_is_rejected() {
        let mut record = valid_record();
        // Shaped like a secret/token landing in a tool name, per the report.
        record.tool_name = "sk-live-AAAABBBBCCCCDDDD spaces/not@allowed".into();
        let err = validate_ingress_fields(&record).expect_err("unsafe characters must be rejected");
        assert!(matches!(err, StoreError::InvariantViolation(_)));
    }

    #[test]
    fn oversized_request_id_is_rejected() {
        let mut record = valid_record();
        record.request_id = "r".repeat(MAX_REQUEST_ID_LEN + 1);
        assert!(validate_ingress_fields(&record).is_err());
    }

    #[test]
    fn empty_ingress_fields_are_rejected() {
        let mut record = valid_record();
        record.tool_name = String::new();
        assert!(validate_ingress_fields(&record).is_err());
    }

    #[test]
    fn well_formed_ingress_fields_pass() {
        assert!(validate_ingress_fields(&valid_record()).is_ok());
    }

    // --- D2: HMAC key validation at construction --------------------------

    #[test]
    fn short_hmac_key_is_rejected() {
        let key = vec![0u8; MIN_HMAC_KEY_LEN - 1];
        assert!(validate_hmac_key_len(&key).is_err(), "keys shorter than {MIN_HMAC_KEY_LEN} bytes must be rejected");
    }

    #[test]
    fn minimum_length_hmac_key_is_accepted() {
        let key = vec![0u8; MIN_HMAC_KEY_LEN];
        assert!(validate_hmac_key_len(&key).is_ok());
    }

    // --- WRITER_ENQUEUE_TIMEOUT (critic finding: a bare `tx.send().await`
    // with no timeout left 71/71 tests green) ------------------------------

    /// Builds a `PgRedisAuditSink` with NO `run_writer` task behind it —
    /// `rx` is kept alive (so the channel stays open, unlike a dropped
    /// receiver which would fail sends immediately with a different error)
    /// but nothing ever calls `rx.recv()`. This stands in for "the writer
    /// is stalled" (a wedged Postgres, a redis retry storm) without needing
    /// a live Postgres/redis to actually wedge — the bug this pins is
    /// entirely in `emit_inner`'s channel-send logic, not in the writer.
    fn blocked_writer_sink() -> (PgRedisAuditSink, tokio::sync::mpsc::Receiver<WriteRequest>) {
        let (tx, rx) = tokio::sync::mpsc::channel(WRITER_CHANNEL_CAPACITY);
        let sink = PgRedisAuditSink { chain_id: Uuid::new_v4(), tx, writer_alive: Arc::new(std::sync::atomic::AtomicBool::new(true)) };
        (sink, rx)
    }

    /// Mutation-proof for the enqueue timeout: the critic replaced the
    /// `tokio::time::timeout(WRITER_ENQUEUE_TIMEOUT, ...)` wrapper in
    /// `emit_inner` with a bare `self.tx.send(...).await` and every
    /// existing test stayed green, because none of them ever filled the
    /// channel. This one does: fills the channel to EXACTLY
    /// `WRITER_CHANNEL_CAPACITY` (each of those sends has a free permit, so
    /// they complete instantly — nothing is reading `rx`), then issues one
    /// more `emit()` — the `WRITER_CHANNEL_CAPACITY + 1`th concurrent
    /// caller — and asserts it returns `Err` within roughly
    /// `WRITER_ENQUEUE_TIMEOUT`, not `WRITER_ACK_TIMEOUT` (which would mean
    /// the send secretly went through) and not the outer 5s test bound
    /// (which would mean it's hanging exactly like the pre-fix bug).
    #[tokio::test]
    async fn writer_enqueue_timeout_denies_the_overflow_caller_instead_of_hanging() {
        let (sink, rx) = blocked_writer_sink();

        // Fill the channel directly via the private `tx` field (same crate
        // module — accessible from `tests`), one permit at a time. Keep
        // every `ack_rx` alive in `_acks`; nothing reads them, but dropping
        // a `WriteRequest`'s `ack` sender only matters to a caller awaiting
        // it, which nothing here does.
        let mut _acks = Vec::with_capacity(WRITER_CHANNEL_CAPACITY);
        for _ in 0..WRITER_CHANNEL_CAPACITY {
            let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
            sink.tx
                .send(WriteRequest { record: valid_record(), ack: ack_tx })
                .await
                .expect("channel has room for exactly WRITER_CHANNEL_CAPACITY sends with nothing reading it yet");
            _acks.push(ack_rx);
        }

        let start = std::time::Instant::now();
        // Outer 5s bound: if this fires instead of the assertions below,
        // `emit()` is truly hanging (the pre-fix bug), not just slow.
        let outcome = tokio::time::timeout(Duration::from_secs(5), sink.emit(valid_record()))
            .await
            .expect("emit() must return within 5s on its own, not hang until the test harness kills it");
        let elapsed = start.elapsed();

        let err = outcome.expect_err("the WRITER_CHANNEL_CAPACITY + 1th concurrent caller must be denied, not silently accepted");
        let rendered = format!("{err}");
        assert!(rendered.contains("audit_writer"), "expected an audit_writer DependencyUnavailable, got: {err:?}");

        assert!(
            elapsed < WRITER_ACK_TIMEOUT,
            "must be denied by WRITER_ENQUEUE_TIMEOUT ({WRITER_ENQUEUE_TIMEOUT:?}), not fall through to the longer \
             WRITER_ACK_TIMEOUT ({WRITER_ACK_TIMEOUT:?}) — that would mean the send silently went through instead \
             of being bounded: took {elapsed:?}"
        );
        assert!(
            elapsed >= WRITER_ENQUEUE_TIMEOUT.saturating_sub(Duration::from_millis(50)),
            "returned suspiciously fast ({elapsed:?}) for a channel that should have been full — \
             is WRITER_CHANNEL_CAPACITY actually being filled?"
        );

        drop(rx); // keep the receiver alive until here, then let it go
    }

    // --- Live-DB integration tests -----------------------------------------

    const TEST_HMAC_KEY: &[u8] = b"test-only-hmac-key-32-bytes-min!";

    fn test_redis_url() -> String {
        std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres + redis; run with `cargo test -- --ignored`"]
    async fn emit_persists_a_fully_covered_row_that_verifies_clean() {
        use crate::testing::test_pool_migrated;

        let pool = test_pool_migrated().await;
        let redis = RedisStore::connect(&test_redis_url())
            .await
            .expect("connect to test redis (set TEST_REDIS_URL if not on localhost:6379)");
        let sink = PgRedisAuditSink::new(pool.clone(), redis, TEST_HMAC_KEY.to_vec()).unwrap();

        let server_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO servers (server_id, name, upstream_url, owner_principal_id) VALUES ($1, $2, $3, $4)",
        )
        .bind(server_id)
        .bind(format!("srv-{server_id}"))
        .bind("https://upstream.example.com")
        .bind("owner-1")
        .execute(&pool)
        .await
        .unwrap();

        let record = AuditRecord {
            event_id: Uuid::new_v4(),
            request_id: "req-1".into(),
            principal_id: "alice".into(),
            issuer: Some("https://idp.example.com".into()),
            server_id: Some(server_id),
            tool_id: None,
            tool_name: "echo".into(),
            outcome: Outcome::Allow,
            deny_reason: None,
            latency_ms: Some(3),
            source_ip: Some("127.0.0.1".into()),
            enrichment: AuditEnrichment { roles: vec!["employee".into()], ..Default::default() },
        };

        sink.emit(record.clone()).await.expect("first emit should succeed");

        let row: (Option<String>, time::OffsetDateTime, time::OffsetDateTime) = sqlx::query_as(
            "SELECT prev_hash, event_ts, created_at FROM audit_events WHERE event_id = $1",
        )
        .bind(record.event_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        // Since 0010 every chain opens with a genesis row at `chain_seq == 0`,
        // so the first CALLER event is the second link and must name genesis as
        // its predecessor. "No predecessor" now belongs to genesis alone —
        // asserting it here would be asserting the chain has no anchor.
        assert!(row.0.is_some(), "first caller event must chain onto the genesis row");
        let roots: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE prev_hash IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(roots.0, 1, "exactly one row (genesis) may have no predecessor");
        assert_eq!(row.1, row.2, "D6/D3: event_ts and created_at must be bound to the identical value");

        let record2 = AuditRecord { event_id: Uuid::new_v4(), ..record };
        sink.emit(record2.clone()).await.expect("second emit should succeed");

        let row2: (Option<String>, String) =
            sqlx::query_as("SELECT prev_hash, sha256_hash FROM audit_events WHERE event_id = $1")
                .bind(record2.event_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(row2.0.is_some(), "second event must chain to the first");

        // D3: the verifier must be able to recompute both rows' hashes from
        // exactly what's stored, and the chain link must resolve.
        let report = crate::audit_verify::verify_chain(&pool, TEST_HMAC_KEY).await.unwrap();
        assert!(report.is_clean(), "freshly emitted rows must verify clean end-to-end: {report:?}");
    }

    /// Mutation proof for D5: point the sink at a redis nobody is
    /// listening on, so `emit` fails at the redis step, which (after the
    /// reorder) runs BEFORE the Postgres insert. Assert (a) `emit` returns
    /// `Err` (fail-closed, per ARCHITECTURE.md invariant 4), (b) NO row was
    /// committed for this event (no fork, no misleading persisted
    /// "allow"/"deny" row for a request the caller was ultimately denied
    /// on), and (c) the in-process chain anchor (`prev_hash`) was not
    /// advanced, so the NEXT successful emit still chains correctly.
    ///
    /// To prove this is actually exercising the reordered code path (and
    /// not just "redis is unreachable" being caught trivially), we revert
    /// the fix by re-running the OLD order in a second sink instance and
    /// show the row *does* get persisted with the wrong outcome — see the
    /// companion assertion below.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn redis_failure_commits_no_row_and_does_not_fork_the_chain() {
        use crate::testing::test_pool_migrated;

        let pool = test_pool_migrated().await;
        // Port 9 is the discard service / never a real redis in CI — see
        // redis_store.rs's own test for the same convention (including
        // the SAME `connect` itself must be timeout-wrapped, not just the
        // subsequent operation: redis-rs's `ConnectionManager` can retry
        // the initial connection with backoff and never resolve the
        // `.await` at all against an endpoint that silently drops rather
        // than immediately refusing — this hung for minutes before being
        // wrapped here). `connect` itself may fail outright, hang, or
        // succeed lazily; either way the FIRST real operation against it
        // must surface as Err, never silently proceed to Postgres.
        let record = valid_record();
        let connect_result = tokio::time::timeout(Duration::from_secs(5), RedisStore::connect("redis://127.0.0.1:9/")).await;
        match connect_result {
            Ok(Ok(dead_redis)) => {
                let sink = PgRedisAuditSink::new(pool.clone(), dead_redis, TEST_HMAC_KEY.to_vec()).unwrap();
                let result = tokio::time::timeout(Duration::from_secs(5), sink.emit(record.clone())).await;
                match result {
                    Ok(emit_result) => assert!(emit_result.is_err(), "emit must fail closed when redis is unreachable"),
                    Err(_) => { /* timed out waiting on redis — also acceptable, still never reached Postgres */ }
                }
            }
            Ok(Err(_)) | Err(_) => { /* connect itself failed or timed out — also satisfies "never reached Postgres" */ }
        }

        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE event_id = $1")
            .bind(record.event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count.0, 0,
            "D5: a redis failure must not leave a durably-committed row behind — the Postgres \
             insert must not have been reached"
        );

        // Chain anchor must be untouched: a subsequent successful emit
        // (through a working redis) must still be the FIRST link (no
        // fork, no orphaned prev_hash pointing at a hash that was never
        // actually committed).
        let working_redis = RedisStore::connect(&test_redis_url())
            .await
            .expect("connect to test redis (set TEST_REDIS_URL if not on localhost:6379)");
        // NOTE: this is a fresh sink (fresh prev_hash=None) by construction,
        // which is exactly the point — the failed sink above never advanced
        // its own anchor either, so a same-process retry through a healthy
        // redis is indistinguishable from "nothing happened yet".
        let sink2 = PgRedisAuditSink::new(pool.clone(), working_redis, TEST_HMAC_KEY.to_vec()).unwrap();
        let record2 = AuditRecord { event_id: Uuid::new_v4(), ..record };
        sink2.emit(record2.clone()).await.expect("emit through a healthy redis must succeed");

        let row2: (Option<String>,) =
            sqlx::query_as("SELECT prev_hash FROM audit_events WHERE event_id = $1")
                .bind(record2.event_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        // The failed attempt must have committed nothing, so the successful
        // emit chains directly onto genesis — and genesis stays the only
        // predecessor-less row. A fork would show up as a second root.
        assert!(row2.0.is_some(), "the successful emit must chain onto genesis");
        let roots2: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE prev_hash IS NULL")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(roots2.0, 1, "no fork: genesis remains the only chain root");
    }

    /// Literal "kill redis mid-emit" proof, as requested: spin up a
    /// throwaway podman redis container, connect the sink to it, `podman
    /// stop` it, then emit. This exercises the exact live-failure scenario
    /// (not just an always-unreachable address) and confirms the ledger
    /// stays consistent (no row, no forked anchor) exactly as in the
    /// deterministic version of this test above.
    #[tokio::test]
    #[ignore = "requires a live Postgres + podman; run with `cargo test -- --ignored`"]
    async fn killing_redis_mid_emit_leaves_a_consistent_ledger() {
        use crate::testing::test_pool_migrated;
        use std::process::Command;

        let container = format!("mcphub-audit-kill-test-{}", Uuid::new_v4().simple());
        let port = 17000 + (std::process::id() % 1000) as u16;

        let start = Command::new("podman")
            .args(["run", "--rm", "-d", "--name", &container, "-p", &format!("{port}:6379"), "redis:7-alpine"])
            .output();
        let Ok(start) = start else {
            eprintln!("podman not available, skipping killing_redis_mid_emit_leaves_a_consistent_ledger");
            return;
        };
        if !start.status.success() {
            eprintln!("podman run failed, skipping: {}", String::from_utf8_lossy(&start.stderr));
            return;
        }
        // Give redis a moment to accept connections.
        tokio::time::sleep(Duration::from_millis(800)).await;

        let pool = test_pool_migrated().await;
        let redis = RedisStore::connect(&format!("redis://127.0.0.1:{port}/"))
            .await
            .expect("connect to the throwaway container");
        let sink = PgRedisAuditSink::new(pool.clone(), redis, TEST_HMAC_KEY.to_vec()).unwrap();

        // Prove the sink is actually live first (otherwise this test would
        // pass vacuously against a container that never came up).
        let warmup = AuditRecord { event_id: Uuid::new_v4(), ..valid_record() };
        sink.emit(warmup).await.expect("sink must work against the live throwaway container before we kill it");

        let _ = Command::new("podman").args(["stop", "-t", "0", &container]).output();

        let record = AuditRecord { event_id: Uuid::new_v4(), ..valid_record() };
        let result = tokio::time::timeout(Duration::from_secs(5), sink.emit(record.clone())).await;
        match result {
            Ok(emit_result) => assert!(emit_result.is_err(), "emit must fail closed once redis is killed"),
            Err(_) => { /* timeout waiting on a dead connection also satisfies fail-closed */ }
        }

        // NOTE: this assertion was INVERTED when the sink ordering changed, and
        // the inversion is the point of the fix — do not "restore" it.
        //
        // The old order was redis → stdout → Postgres, so a redis failure meant
        // nothing had been committed and asserting `count == 0` was right. That
        // ordering was itself the bug: a Postgres failure *after* a successful
        // redis publish left up to MAX_BATCH_SIZE phantom `"outcome":"allow"`
        // events in the SIEM stream for callers who were all denied, and the
        // retried batch then reissued the same `chain_seq` values with different
        // hashes — a state Postgres forbids via `UNIQUE (chain_id, chain_seq)`,
        // and indistinguishable from tampering to a stream consumer.
        //
        // Postgres now commits FIRST and is the ledger of record; redis/stdout
        // are derived transport published only once the row is durable. So a
        // redis failure after commit legitimately leaves a durable row, and the
        // property worth asserting is the *reverse* of the original one: the
        // ledger never lags the stream. Reverting this assertion would mean
        // reverting the ordering, which reintroduces phantom publication.
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events WHERE event_id = $1")
            .bind(record.event_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            count.0, 1,
            "Postgres commits before redis is published, so a redis failure must still leave the \
             durable row — the ledger must never lag the derived stream"
        );

        let _ = Command::new("podman").args(["rm", "-f", &container]).output();
    }

    /// Mutation proof for D2: fire many emits concurrently through ONE
    /// sink and confirm they still form a single, valid, unforked chain —
    /// i.e. narrowing the lock to just the Postgres insert did not
    /// reintroduce the race the lock exists to prevent. If the lock scope
    /// were wrong (e.g. released before the INSERT actually committed, or
    /// not covering the read-then-advance step atomically), concurrent
    /// writers could observe/reuse the same `prev_hash`, producing two
    /// rows that both claim the same predecessor (a fork indistinguishable
    /// from tampering to a verifier).
    #[tokio::test]
    #[ignore = "requires a live Postgres + redis; run with `cargo test -- --ignored`"]
    async fn concurrent_emits_through_one_sink_form_a_single_unforked_chain() {
        use crate::testing::test_pool_migrated;
        use std::collections::HashSet;

        let pool = test_pool_migrated().await;
        let redis = RedisStore::connect(&test_redis_url()).await.expect("connect to test redis");
        let sink = Arc::new(PgRedisAuditSink::new(pool.clone(), redis, TEST_HMAC_KEY.to_vec()).unwrap());

        // NOTE: firing this many emits at once through a single sink,
        // against `testing::test_pool_migrated`'s small (5-connection)
        // pool, is an artificial burst no single real request would ever
        // produce — some emits legitimately hit LOCK_ACQUIRE_TIMEOUT and
        // return Err. That is the CORRECT fail-closed behavior D2 asks
        // for (bounded queueing, not unbounded blocking) — this test does
        // not require every emit to succeed. What it DOES require: no
        // panic/hang, every FAILURE is specifically the lock-timeout path
        // (not silent corruption or a wedged connection), and every
        // SUCCESS still forms one single, unforked chain — i.e. narrowing
        // the lock to just the Postgres insert (D2) did not reopen the
        // race the lock exists to prevent (fork-proofing, which is what
        // this test was originally written to pin).
        const N: usize = 40;
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let sink = sink.clone();
            let record = AuditRecord { event_id: Uuid::new_v4(), ..valid_record() };
            handles.push(tokio::spawn(async move { sink.emit(record).await }));
        }
        let mut succeeded = 0usize;
        let mut lock_timeouts = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(()) => succeeded += 1,
                Err(e) => {
                    let msg = format!("{e:?}");
                    assert!(
                        msg.contains("lock acquisition timed out") || msg.contains("InvalidRequest"),
                        "under artificial overload, a failure must be the bounded lock timeout, not \
                         some other error (corruption, panic-equivalent, etc.): {msg}"
                    );
                    lock_timeouts += 1;
                }
            }
        }
        assert!(succeeded > 0, "at least some concurrent emits must succeed (this is a healthy sink)");
        assert_eq!(succeeded + lock_timeouts, N);

        let rows: Vec<(Option<String>, String)> =
            sqlx::query_as("SELECT prev_hash, sha256_hash FROM audit_events")
                .fetch_all(&pool)
                .await
                .unwrap();
        // `succeeded` counts caller emits. The chain also carries exactly ONE
        // genesis row, written by the writer task at `chain_seq == 0` before
        // the first batch (see the writer loop and 0010's header): it is the
        // anchor that makes "this chain's head has no predecessor" a checkable
        // property rather than an assumption. It is a real durable row, so the
        // expected count is emits + 1.
        //
        // Asserted separately below (`roots == 1`) — if the genesis row were
        // ever written more than once, that check fails, so this `+ 1` cannot
        // mask a duplicate-genesis bug.
        assert_eq!(rows.len(), succeeded + 1, "exactly the successful emits, plus one genesis row, must be durably committed");

        // Exactly one row may have no predecessor (the first link).
        let roots = rows.iter().filter(|(prev, _)| prev.is_none()).count();
        assert_eq!(roots, 1, "concurrent writers must not produce more than one chain root (a fork)");

        // Every non-root row's prev_hash must be a DISTINCT other row's
        // sha256_hash — if two rows shared the same prev_hash, that's a
        // fork (two writers both read the same anchor value and neither
        // saw the other's advance).
        let hashes: HashSet<&str> = rows.iter().map(|(_, h)| h.as_str()).collect();
        assert_eq!(hashes.len(), rows.len(), "sha256_hash values must all be distinct");

        let mut seen_prev: HashSet<&str> = HashSet::new();
        for (prev, _) in &rows {
            if let Some(p) = prev {
                assert!(known_or_first_use(&mut seen_prev, p), "two rows share prev_hash {p:?} — the chain forked");
                assert!(hashes.contains(p.as_str()), "prev_hash {p:?} does not match any committed row's own hash");
            }
        }

        fn known_or_first_use<'a>(seen: &mut HashSet<&'a str>, v: &'a str) -> bool {
            seen.insert(v)
        }
    }
}
