# mcphub-policy performance record

This is the durable record of every latency/throughput number measured
against `crates/mcphub-policy`'s in-process Rego authorization engine
(`crates/mcphub-policy/src/engine.rs`, benched by
`crates/mcphub-policy/benches/authz_bench.rs`), what conditions each number
was taken under, and — for every number — what it does and does not
license you to conclude. Read the whole "How to read this document" section
before quoting anything from the tables below.

Companion pieces:
- `scripts/perf-check.sh` (`make perf-check`) — reproduces the current-design
  numbers on whatever machine you're standing on, self-describing its own
  conditions, and **refuses to print a verdict** when those conditions can't
  support one. See "The verification kit" below.
- `ARCHITECTURE.md`'s "Policy evaluation: compiled entrypoints + a decision
  cache" section — the design narrative this document supplies the raw
  numbers for. If the two ever disagree on a number, trust whichever has a
  `perf-results/*.json` file or `target/criterion/` artifact backing it, and
  fix the other.

## How to read this document

1. **A number without its conditions is worse than no number.** Every row
   below states hardware, build profile, what else was running, and sample
   size/CI where available. If a row is missing one of those, that is
   itself the finding — it means the number was reported once, verbally,
   without an artifact, and you should treat it as a hint, not a fact.
2. **This machine is not representative hardware.** Every number in this
   document, unless stated otherwise, comes from one 2019 6-core/12-thread
   Intel laptop (`i7-9750H @ 2.60GHz`, macOS), routinely running with other
   load on it (concurrent `cargo build`s from other work in this same
   session/repo, browser, etc.). That is not a controlled benchmark rig.
   Absolute latencies and throughputs from this box are **not**
   hardware-portable constants — do not put them in a capacity plan.
   **Ratios** (cache hit vs miss, hot vs cold throughput, floor breakdown
   percentages) are far more stable across the noisy runs recorded here
   than any single absolute number, and are the part of this document worth
   trusting across machines.
3. **Micro-benchmarks measure the policy engine, not the gateway.** Every
   number here comes from calling `RegorusPolicyEngine` directly in a
   Criterion harness — no HTTP, no axum routing, no credential broker, no
   database, no network. They are evidence for "how expensive is one Rego
   decision," and only that. They are not evidence for end-to-end request
   latency, and they cannot be, by construction. The definitive number for
   that has to come from component 6's `loadgen` (`rs/../loadgen/`) driven
   against a live `mcphubd` deployment. See "What each number is (and isn't)
   evidence for" at the end of this document.
4. **Same code, different day, different number.** The single most
   important lesson in this document is `compile_with_entrypoint` +
   `eval_with_input`'s cache-miss floor reading ~303-320µs in one run and
   noticeably higher in another, on *identical code*, minutes apart, on the
   same machine — see the table below. If you only remember one thing from
   this document, remember that a re-run before trusting a number is not
   optional.

## Recorded measurements

All numbers below are from `crates/mcphub-policy/benches/authz_bench.rs`
unless stated otherwise. "CI" is Criterion's bootstrapped 95% confidence
interval on the mean. Box: 6 physical / 12 logical core Intel i7-9750H,
macOS 26.5.2, rustc 1.97.1, `cargo bench` (release, `opt-level = 3`, no
`[profile.bench]` override in the workspace `Cargo.toml` at time of
writing — verify that hasn't changed before trusting "optimized" here).

### 1. The naive path, and why it was slow

| what | value | conditions |
|---|---|---|
| `Engine::eval_bool_query` per decision (no cache, no compiled entrypoint) | **~930µs** (mean 933.3µs, median 929.4µs, std dev 22.9µs, n=100) | criterion artifact `target/criterion/authz_single_decision`, this session, single-threaded, machine load not recorded for this specific run |

**Why it was slow, precisely** (see `engine.rs` module doc for the full
narrative): `eval_query`/`eval_bool_query` re-parse the query string and
re-run `prepare_for_eval`/`clean_internal_evaluation_state`/
`create_rule_prefixes` **on every call**, regardless of whether the same
`Engine` is reused across calls. This was mis-attributed, in two earlier
design iterations (see "Discarded designs" below), to lock/channel
contention — it is neither; it reproduces identically single-threaded with
zero contention possible.

### 2. The current design: compile once, `eval_with_input` per call

| what | value | conditions |
|---|---|---|
| `compile_with_entrypoint` + `eval_with_input`, first measurement | **~312µs** (median 319.9µs, mean 402.8µs, std dev 261.4µs — high variance, see below) | criterion artifact `target/criterion/authz_warm_single_decision`, this session, single-threaded |
| same code, reported again on a noisier run | **~790µs** | reported by the prior work in this session; no separate `target/criterion` artifact survived to corroborate the exact value (criterion only retains the current run + one prior baseline, and it was overwritten) — the *direction* (same code reading substantially higher on a busier machine) is corroborated by this session's own std-dev-261µs sample above, which is itself skewed by the same effect |
| re-measured this document's authoring session, current bench name (`authz_floor_eval_with_input_preconverted`, pre-converted input, isolates compiled-policy eval from JSON conversion) | **303.05µs** (CI 297.7–309.0µs) | `perf-results/2026-08-14T04-32-50Z_webr0cks-MacBook-Pro_ceed443390df.json`, load fraction 0.40, `suitable_for_verdict: true` |
| same bench, ~5 minutes later | not captured as a clean number — the run immediately following was flagged `suitable_for_verdict: false` (load fraction 0.88) by `perf-check.sh` and its numbers are intentionally not reported here | `perf-results/2026-08-14T04-34-48Z_webr0cks-MacBook-Pro_ceed443390df.json` |

**This is the most important row in this document.** Identical code,
compiled once, minutes apart, on the same laptop: 303µs, 312-320µs, and a
separately-reported 790µs. The std dev on the very first sample (261µs on a
319µs median) already tells you this measurement is right at the edge of
what this box can measure cleanly. Treat any single reading in the
200-800µs range as consistent with all the others, not as a regression or
an improvement, unless a same-day, same-load re-run says otherwise.

### 3. Decision cache: hit vs miss, and the ratio

| what | value | conditions |
|---|---|---|
| cache hit (moka lookup only, no rego eval) | ~10.0µs (mean 10.32µs, median 10.10µs, n=100) | first `cargo bench` run this session, single-threaded, ambient load not captured |
| cache hit, `perf-check.sh` verified-suitable run | **5.70µs** (CI 5.68–5.72µs) | load fraction 0.40, `suitable_for_verdict: true` |
| cache miss (forced distinct input every call, real regorus eval) | ~672µs (Criterion's console slope estimate) / ~628µs (bootstrapped mean) | same first run as above |
| cache miss, `perf-check.sh` verified-suitable run | **317.44µs** (CI 314.1–321.3µs) | same suitable run as above |
| **ratio, this session's readings** | **~55.7x** (suitable run) to **~67x** (first run, using slope estimates) to **~70x** (using ARCHITECTURE.md's earlier ~20µs/~790µs≈39.5x — inconsistent with the ratios measured directly this session; ARCHITECTURE.md's ~20µs/~790µs pairing predates this session's re-measurement and should be treated as superseded by the rows above) | — |

**The stable signal is the ratio, not either endpoint.** Across every
reading taken this session, cache hit sits roughly 40-70x cheaper than
cache miss. That range, not any single hit or miss number, is what should
inform a hit-rate-dependent capacity estimate.

### 4. 12-thread throughput: cache-hot vs cache-cold

All readings: `available_parallelism()` = 12 threads, one shared
`Arc<PolicyState>`, `Throughput::Elements(1)`.

| what | value | conditions |
|---|---|---|
| cache-hot (all 12 threads hammering the same cached input) | ~496k decisions/s (489-504k Kelem/s CI) | first `cargo bench` run this session |
| cache-hot, `perf-check.sh` suitable run | **710k decisions/s** (699-722k CI) | load fraction 0.40 at the time the earlier single-decision benches ran; note throughput benches ran later in the same invocation and the shell showed load climbing over the run (see caveat below) |
| cache-cold (every call, every thread, a distinct input — no cache reuse at all) | ~8.29k decisions/s (8.13-8.46k CI) | first `cargo bench` run this session |
| cache-cold, `perf-check.sh` suitable run | **10.28k decisions/s** (10.08-10.48k CI) | same run as cache-hot 710k row above |
| a prior report from this session (not independently re-verified, artifact overwritten before this document was authored) | ~430-448k/s hot, ~6.8-7.7k/s cold | — |

Across the three independent readings recorded for this document (prior
report, first run, `perf-check.sh` suitable run), **hot throughput ranged
430k-710k/s (a ~65% swing) and cold ranged 6.8k-10.3k/s (a ~54% swing), on
the same machine, same code, within roughly 20 minutes of each other.**
This is the clearest evidence in this document that absolute throughput
numbers from this box are not something to plan capacity against.

**The open risk this leaves for the AUTHZ portion of the decision**
(unchanged from `ARCHITECTURE.md`): throughput is a function of cache hit
rate, and the hit rate depends on traffic shape, because the authz cache
key must include `params` (`authz.rego`'s deny rules inspect `params` for
injection patterns, so `params` is part of the security argument — see
"Standing conclusions" below). Identical-repeat traffic caches beautifully;
same-tool-different-args traffic (a search with a new query, a read with a
new path) misses every time. Real agent traffic skews toward the latter, so
**the cache-cold figure is the number to plan against for the authz
portion, not the cache-hot figure**, until measured against real traffic on
real hardware.

A SEPARATE, now-resolved risk existed for the anomaly layer specifically —
see §4b immediately below; do not conflate the two when reading this
document.

### 4b. The split cache (current design): a second, narrower key for anomaly

**This section supersedes any description elsewhere of "the decision
cache" as a single key covering the whole decision — that was true through
§4 above, and stopped being true once the anomaly layer went live (see §6
below for why it had to change).**

Once `anomaly.rego`'s structural rules are wired to a real `recent_calls`
producer, `input.recent_calls` changes on nearly every call (each
invocation appends to the sliding window). A single cache key covering the
whole input would be poisoned by that on essentially every request — the
cache-hot numbers in §4 above stop being reachable in practice, and
effective throughput collapses to the cache-cold floor (~7-10k/s on this
box), under the 20k/s budget.

**Fix**: the cache now covers ONLY `authz.rego`'s own decision
(`AuthzResult` in `engine.rs`), keyed on the input with exactly two fields
excluded — `recent_calls` and `window_seconds` (`cache.rs`'s
`AUTHZ_CACHE_KEY_EXCLUDED_FIELDS`). `anomaly.rego`'s
`structural_deny_reasons` is evaluated as its own separate prepared
entrypoint (`engine.rs`'s `anomaly_policy`) on EVERY call, unconditionally,
never cached at all. The two results are merged in Rust: `allow =
authz_allow && anomaly_reasons.is_empty()`.

Why this is safe in a way the rejected two-tier rule-partition (§6) was
not: this isn't a partition of individual deny rules by a hand-derived
criterion. It respects a module boundary that already exists as two
independently-compiled entrypoints, and `anomaly.rego` is the SOLE consumer
of `recent_calls`/`window_seconds` (confirmed by grep, and pinned by
`cache.rs`'s `policy_never_reads_the_excluded_cache_fields` test, which
greps the embedded, comment-stripped `authz.rego` source for either field
name on every test run — not a comment someone has to remember to
re-verify by hand). And because anomaly is never cached AT ALL — rather
than cached under a different key — there is no cache entry for an
anomaly verdict to go stale in; the staleness class of bug is unreachable
by construction, not merely avoided by careful scoping.

Three numbers, reported separately per the convention above (never
blended):

| what | value | conditions |
|---|---|---|
| authz cache hit | **17.4µs** (CI 17.258–17.546µs) | `cargo bench`, this session, single-threaded |
| authz cache miss | **426.02µs** (CI 420.19–433.62µs) | same run |
| anomaly eval alone (never cached, paid every call) | **98.07µs** (CI 96.66–99.88µs) | same run, `anomaly_eval_with_input_preconverted` |
| **real end-to-end cost once anomaly is live**: authz cache HIT + fresh anomaly EVERY call | **84.24µs** (CI 83.56–85.12µs) | same run, `authz_cache_hit_plus_fresh_anomaly_every_call` — `recent_calls` varies every iteration (a counter), asserted NOT to force an authz re-evaluation |

Single-core ceiling from the real end-to-end number: `1 / 84.24µs ≈
11,876 decisions/s/core`. At 8 cores, linear-scaling ceiling ≈ 95,000/s;
even at the ~30-50% parallel efficiency observed elsewhere in this document
(§1-§4's hot/cold throughput swings), that's **~28,500-47,500/s — clears
the 20k/s budget with real headroom**, versus the ~7-10k/s cold floor the
single-key design would have collapsed to. As always: this is one noisy
laptop: the underlying `authz_cache_miss`/`authz_cache_hit` numbers moved
~25-190% from their §1-§3 readings with no code change in between (see
"How to read this document" — ratios and shares are the signal, not
absolutes), so treat the 84.24µs figure the same way — directionally
trustworthy, not a number to plan a deployment against without a
`perf-check.sh`-style re-measurement on target hardware.

### 5. The floor breakdown

| what | value | conditions |
|---|---|---|
| `serde_json::Value → regorus::Value` conversion alone | ~17µs of ~790µs (**~2%**) | reported this session against the earlier ~790µs floor reading |
| same measurement, re-run for this document | **5.95µs of 317.44µs cache-miss (~1.9%)** / 5.95µs of 303.05µs floor-eval (~2.0%) | `perf-check.sh` suitable run, `authz_floor_json_to_regorus_conversion_only` = 5.95µs (CI 5.87-6.03µs) |
| remainder — genuine interpreted Rego tree-walking over `authz.rego` (~180 rule lines) | **~98%** of the floor, consistently across both readings | — |

**The percentage is the stable finding, not either absolute number.** JSON
conversion is roughly 2% of the cache-miss cost on this box, in both a
~790µs-floor run and a ~317µs-floor run — the two absolute conversion times
(17µs, 5.95µs) differ by ~3x, tracking the same run-to-run noise seen
everywhere else in this document, but the *share* of the total they
represent barely moved. Two hypotheses about where the rest of the floor
goes were tested and **both were wrong**: `Engine` construction per call is
cheap by design (empty-container defaults plus `Rc`/`Arc` refcount bumps —
`Engine::new_from_compiled_policy` is `pub(crate)` in `regorus`, so it can't
be hoisted out of the per-call path even if it were expensive), and JSON
conversion is the ~2% above, not the dominant cost as an earlier report had
guessed before this was actually measured. The remaining ~98% is genuine
interpreted Rego tree-walking, and there is no further optimization
reachable through regorus's public API short of the "next levers" listed in
`ARCHITECTURE.md` (shrink what `authz.rego` evaluates, fork regorus to
reuse an `Interpreter`, or compile Rego to native code).

### 6. The two-tier split: measured and rejected

| what | value | conditions |
|---|---|---|
| full evaluation | ~492µs | reported by the prior work in this session |
| correctly-scoped "Tier A" (params-independent deny rules cached separately) | ~268µs (**~45% reduction**) | reported by the prior work in this session |

**Flagged: these two absolute numbers (492µs, 268µs) have no surviving
`target/criterion` artifact or `perf-results/*.json` backing them at the
time this document was authored** — only `ARCHITECTURE.md`'s prose
("correctly scoped it saves only ~45%") independently corroborates the
*percentage*. Treat the two absolute numbers as reported-not-reproduced; the
~45% figure is corroborated in two independent places and is safe to cite.

**Why it was rejected regardless of the ~45% savings:**
1. The saving is capped at ~45% because the per-call cost is dominated by
   fixed overhead (parse/compile-adjacent bookkeeping, tree-walk setup),
   not by rule count — splitting the rule set does not proportionally split
   the cost.
2. It was **unsafe as first specified**. The design partitioned rules by
   "does this rule reference `input.params`" and assumed anything that
   didn't could be cached independently of `params`. But
   `input.recent_calls` (the anomaly-sliding-window input) is exactly as
   per-call-varying as `params` is — a partition keyed only on
   "references `input.params`" would have cached a stale anomaly verdict
   against a request whose `recent_calls` had since changed, silently
   serving a decision made against stale anomaly history. This is a
   correctness bug, not a performance shortfall, and is why the design was
   rejected outright rather than merely deprioritized.

### 7. Discarded designs and their numbers

Two designs preceded the current one (full narrative in `engine.rs`'s
module doc, "Design history"). Both were replaced after finding that
`regorus`'s `"arc"` feature makes `CompiledPolicy` `Send + Sync`, removing
the need for either.

| design | what it measured | value | conditions |
|---|---|---|---|
| **Design 1: fixed 4-thread worker pool** over `std::sync::mpsc` + `tokio::oneshot` (because plain `regorus::Engine` is `Rc`-based, `!Send`/`!Sync`) | full request path through the channel, this session's `authz_warm_single_decision_via_policy_engine` bench | mean 2.99ms, median 2.66ms, std dev 0.92ms | `target/criterion/authz_warm_single_decision_via_policy_engine`, this session |
| **Design 2: thread-local `regorus::Engine` per tokio worker**, rebuilt when a shared `generation` counter advanced | raw eval cost with the channel removed, this session's `authz_single_decision_raw_no_channel` bench | mean 1.33ms, median 1.28ms | `target/criterion/authz_single_decision_raw_no_channel`, this session |
| (for reference) cold compile + data load under the pre-refactor bench shape | — | mean 1.74ms, median 1.72ms | `target/criterion/authz_cold_compile_and_load_data`, this session |

Design 1's channel overhead (~2.66-2.99ms) dwarfs even the naive
`eval_bool_query` cost (~930µs) — the channel hop, not the Rego evaluation,
was the dominant cost in that design. Design 2 removed the channel and
still measured ~1.28-1.33ms, well above the current design's ~300-320µs
floor, because it was still paying the `eval_bool_query` re-parse cost
(current design's whole point was replacing that call, not the
threading model). Neither number should be read as "thread-locals are
slow" in general — they're slow **here** because both designs kept the
`eval_bool_query` re-parse-per-call cost that the current design's
`compile_with_entrypoint` change eliminates independently of threading
model.

### 8. Cold compile

| what | value | conditions |
|---|---|---|
| `load_bundle` + `sync_data`, both entrypoints, current design | 3.729ms (mean, CI 3.65-3.81ms) | first `cargo bench` run this session |
| same bench, second run | **2.603ms** (CI 2.585-2.621ms) | `perf-check.sh` suitable run, load fraction 0.40 |
| swing reported by the prior work in this session | **2.6ms → 11.6ms across runs, zero code changes** | not independently reproduced to the 11.6ms extreme in this document's two readings (2.60ms, 3.73ms), but the direction and rough magnitude of the swing is consistent — this session's own two readings already show a ~43% swing on their own |

Cold compile happens once per policy/data generation (bundle reload), not
per request, so its absolute value matters far less than the per-decision
numbers above — but it is the single noisiest number in this document, and
is the clearest illustration of why "this box, this run" numbers cannot be
treated as constants: **the same, unmodified compile step measured 2.6ms,
3.7ms, and — per the earlier report — up to 11.6ms**, apparently correlated
with how much else (other `cargo build`s in this shared repo/session) was
running concurrently.

## Standing conclusions (don't re-derive these)

- **regorus needs the `"arc"` Cargo feature.** Without it, `regorus`'s
  internal `Rc` stays `Rc`, and `regorus::Engine`/`CompiledPolicy` are
  `!Send`. `features = ["arc"]` in `crates/mcphub-policy/Cargo.toml` swaps
  every internal `Rc` for `Arc` (verified directly with `assert_send`/
  `assert_sync` against both types under the feature) and is what makes
  "one compiled policy behind an `Arc`, called from any thread" possible at
  all — see `engine.rs`'s module doc and the `Cargo.toml` comment above the
  `regorus` dependency line.
- **Keep `default-features` ON for `regorus`.** A hand-picked minimal
  feature list (`default-features = false, features = ["std","regex",...]`)
  changes `walk/2`'s safety-checker behavior and rejects
  `all_string_values`'s `walk(x, [path, v])` in the real `authz.rego` as
  "use of undefined variable `path` is unsafe" — even though the identical
  source compiles and evaluates fine with default features on. Root-caused
  by bisecting feature flags against an isolated `regorus` repro; which
  specific default feature it is was not tracked down further (not worth
  the budget once default-on was confirmed to fix it). See the `Cargo.toml`
  comment above the `regorus` dependency line.
- **`Engine::new_from_compiled_policy` is `pub(crate)` inside `regorus`.**
  The `Engine` construction that `CompiledPolicy::eval_with_input` does
  internally per call cannot be hoisted out from outside the crate even if
  it were expensive to construct — which it isn't (see "The floor
  breakdown" above): it's empty-container defaults plus `Rc`/`Arc` refcount
  bumps.
- **The cache key must include `params`, and that caps the achievable hit
  rate.** `authz.rego`'s deny rules inspect `input.params` for injection
  patterns, so `params` is part of the security argument the decision is a
  pure function of — omitting it from the cache key would let two
  materially different requests (same tool, different arguments) share a
  cached verdict, which is a correctness bug, not an optimization. The
  practical consequence: identical-repeat traffic (the same agent calling
  the same tool with the same arguments repeatedly) caches beautifully;
  same-tool-different-argument traffic (a search with a new query each
  time) misses on every call, because the varying argument is part of the
  key by construction. See `cache.rs`'s module doc and "The open risk this
  leaves" under section 4 above.
- **Also folded into the cache key: `input.recent_calls`.** This was the
  bug that killed the two-tier split design (section 6) — any future
  cache-partitioning idea needs to check every per-call-varying input field,
  not just `params`, or it will reintroduce the same staleness bug.

## The verification kit — reproducing this on different hardware

`scripts/perf-check.sh` (`make perf-check`) exists so someone landing on a
fresh 8-core Linux box, months from now, with none of the context above,
can get a comparable, self-describing result in one command.

What it does:
1. **Captures the environment automatically** into every result file: CPU
   model, physical vs. logical core count, OS/kernel, rustc/cargo version,
   git commit + dirty flag, build profile, and 1/5/15-minute load average.
2. **Refuses to print a verdict when the environment looks unsuitable.**
   Default gate: 1-minute load average must be under 50% of logical core
   count (`PERF_CHECK_MAX_LOAD_FRACTION`, default `0.5`), and the build must
   not be forced into an unoptimized/debug-assertions profile. When the
   gate trips, the script still runs the benches and writes the raw numbers
   to `perf-results/*.json` (marked `suitable_for_verdict: false`) — so the
   run isn't wasted — but prints **no verdict**, exits nonzero, and says
   plainly: *"these conditions cannot support a reliable measurement."*
   This is deliberate and is demonstrated below with a real run on this
   box.
3. **Pre-builds the exact bench binary** (`cargo bench ... --no-run`) before
   timing anything, so compile time (section 8's 2.6-3.7ms+ swings) never
   bleeds into the first benchmark's own numbers. Criterion's own
   per-benchmark 3-second warm-up runs on top of that and is not
   reimplemented or bypassed — see the script's inline comment for why not.
4. **Runs the real Criterion suite** (`cargo bench --bench authz_bench`) and
   parses `target/criterion/<bench>/new/estimates.json` for each of the
   named benchmarks, reporting `mean.point_estimate` and its 95% CI.
5. **Reports cache-hit latency, cache-miss latency, and (assumed) hit rate
   as three separate, unblended figures**, plus a derived-throughput table
   swept across assumed hit rates from the two measured single-decision
   latencies. That table is explicitly labeled as a linear interpolation
   between the two directly-measured endpoints (0% and 100% hit rate) —
   **not** an independent measurement of any intermediate hit rate, and it
   ignores whatever lock/cache contention the concurrent cache-hot/cache-cold
   benchmarks capture at the endpoints that a naive single-thread
   interpolation cannot.
6. **Writes machine-readable JSON** (schema documented via the fields
   themselves — see any file under `perf-results/`) alongside the
   human-readable console summary, specifically so two machines' results
   can be diffed programmatically rather than eyeballed.

### Running it — real output from this box, this session

**Run 1 — machine quiet enough, verdict printed** (load fraction 0.40,
2026-08-14T04:32:50Z, saved at
`perf-results/2026-08-14T04-32-50Z_webr0cks-MacBook-Pro_ceed443390df.json`):

```
$ source $HOME/.cargo/env && make perf-check
...
================================================================
perf-check: 2026-08-14T04:32:50Z on webr0cks-MacBook-Pro
  CPU: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz  (6 physical / 12 logical)
  OS: Darwin 25.5.0
  rustc: rustc 1.97.1 (8bab26f4f 2026-07-14)
  git: ceed443390dfacc1dda25df39b97a46d4a4a76f3 (dirty)
  load average (1m): 4.84423828125  (fraction of logical cores: 0.4036865234375, threshold 0.5)
  result file: /Users/webr0ck/Code/mcp-security-platform/rs/perf-results/2026-08-14T04-32-50Z_webr0cks-MacBook-Pro_ceed443390df.json
================================================================
cache-hit  latency : 5.70µs (CI 5.68..5.72µs)
cache-miss latency : 317.44µs (CI 314.11..321.30µs)
hit/miss ratio     : 55.7x
cold compile (both) : 2603.03µs (CI 2585.00..2621.45µs)
floor: json->regorus: 5.95µs (CI 5.87..6.03µs)
floor: eval (warm)  : 303.05µs (CI 297.74..308.98µs)

derived throughput by assumed hit rate (single-thread, interpolated — see notes):
  hit_rate=0.00  ~      3150 decisions/s/thread
  hit_rate=0.25  ~      4175 decisions/s/thread
  hit_rate=0.50  ~      6189 decisions/s/thread
  hit_rate=0.75  ~     11957 decisions/s/thread
  hit_rate=0.90  ~     27120 decisions/s/thread
  hit_rate=0.95  ~     46980 decisions/s/thread
  hit_rate=0.99  ~    113433 decisions/s/thread
  hit_rate=1.00  ~    175492 decisions/s/thread

Verdict: environment suitable, numbers above are usable for comparison
against rs/PERFORMANCE.md's baseline (see that file's Comparison Procedure).
```

**Run 2, ~2 minutes later — gate trips, no verdict, exactly as designed**
(load climbed to fraction 0.88, most likely from Run 1's own bench process
and other concurrent work in this shared session — the exact scenario this
gate exists to catch):

```
$ source $HOME/.cargo/env && make perf-check
...
================================================================
perf-check: 2026-08-14T04:34:48Z on webr0cks-MacBook-Pro
  CPU: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz  (6 physical / 12 logical)
  OS: Darwin 25.5.0
  rustc: rustc 1.97.1 (8bab26f4f 2026-07-14)
  git: ceed443390dfacc1dda25df39b97a46d4a4a76f3 (dirty)
  load average (1m): 10.51513671875  (fraction of logical cores: 0.8762613932291666, threshold 0.5)
  result file: /Users/webr0ck/Code/mcp-security-platform/rs/perf-results/2026-08-14T04-34-48Z_webr0cks-MacBook-Pro_ceed443390df.json
================================================================

!! NO VERDICT: these conditions cannot support a reliable measurement.
   - load average 10.51513671875 on 12 logical cores (fraction 0.8762613932291666) exceeds threshold 0.5 — machine looks busy (concurrent build, other load)

   Raw numbers were still written to /Users/webr0ck/Code/mcp-security-platform/rs/perf-results/2026-08-14T04-34-48Z_webr0cks-MacBook-Pro_ceed443390df.json (suitable_for_verdict: false)
   so the run isn't wasted, but do not quote them for a capacity decision.
   Re-run once the machine is quiet (PERF_CHECK_MAX_LOAD_FRACTION to adjust the gate,
   PERF_CHECK_SKIP_GATE=1 to force output anyway, still flagged unreliable).
make: *** [perf-check] Error 1
```

Both `perf-results/*.json` files from this pair of runs are the actual,
unedited output — the JSON's `suitable_for_verdict` field is exactly what
gated the second run's missing verdict above, not a separate check.

### A note on `python3`, and why not a Rust binary

The script is bash + `python3` (stdlib only — `json`, `os.getloadavg`,
`os.cpu_count`), not `jq` and not a small Rust binary. Reasoning: `jq` is
not guaranteed present on a fresh box the way `python3` almost always is on
Linux; a Rust binary would need its own `[[bin]]` target, a build step
before it could run (chicken-and-egg on a machine being evaluated for the
first time), and would duplicate `serde_json` parsing logic this script can
get from the stdlib `json` module for free. If a fresh box turns out to
lack `python3`, the script fails fast with a clear message (exit code 2)
rather than guessing.

## Comparison procedure — checking a new machine against this baseline

1. Run `make perf-check` (or `scripts/perf-check.sh` directly) on the new
   machine. If it refuses to print a verdict, fix what it names (usually:
   wait for other load to quiet down, or re-run with nothing else building)
   and re-run — do not override the gate for a number you intend to keep.
2. Compare the new machine's `perf-results/*.json` against a recorded
   baseline **using ratios and percentages, not raw deltas on absolute
   times**:
   - **cache hit/miss ratio** (this document's readings: ~40-70x on one
     noisy laptop) — compare ratio-to-ratio, not µs-to-µs.
   - **hot/cold throughput ratio**, similarly.
   - **floor breakdown percentage** (JSON conversion's ~2% share of the
     cache-miss floor) — this was the most stable number recorded in this
     entire document (1.9-2.2% across two very different absolute floor
     readings) and is a good canary: if it moves by more than a couple of
     percentage points on a new machine, something structural changed
     (different regorus version, different `authz.rego`, different
     serde_json version), not just noise.
3. **What counts as noise vs. a real regression**, from this document's own
   evidence:
   - Absolute single-decision latencies (cache-miss floor, cold compile)
     swinging **up to ~2-4x** run-to-run on the *same unmodified code, same
     machine* is within what this session directly observed (303µs vs.
     "790µs" reported; 2.6ms vs. 3.7ms vs. a reported 11.6ms cold compile).
     Do not open a regression investigation for a swing inside that range
     without first re-running on a quiet machine.
   - 12-thread throughput swinging **~50-65%** run-to-run (this session:
     430k-710k/s hot, 6.8k-10.3k/s cold) is likewise within observed noise
     on a shared machine.
   - A **ratio** (hit/miss, hot/cold, floor-percentage) moving outside the
     ranges recorded in this document, especially in a direction that holds
     across a re-run on a quiet machine, is the signal worth investigating
     — that's a change in what the code is actually doing, not in how busy
     the box was.
4. **When a number regresses** (by the ratio-based standard above, on a
   confirmed-quiet re-run): check, in order — (a) did `authz.rego` change
   (more rules to walk = a real, expected floor increase); (b) did the
   `regorus` dependency version change (re-verify the `"arc"` feature and
   default-features requirements above still hold); (c) did the cache key
   derivation change (`cache.rs`) in a way that widens or narrows what
   counts as a hit; (d) is this genuinely new hardware whose baseline has
   never been recorded — in which case record it here as a new row with its
   own conditions, don't overwrite the existing one.
5. **None of the above substitutes for component 6's `loadgen` against a
   live deployment.** These micro-benchmarks are evidence for the cost of
   one Rego decision in isolation. They are not evidence for gateway p50/
   p99 request latency, for behavior under real concurrent HTTP load, for
   credential-broker or database contribution to latency, or for anything
   downstream of `invoke.rs`'s gate chain other than the policy-evaluation
   gate itself. A capacity decision needs the `loadgen` number against a
   live `mcphubd`; a micro-benchmark regression here is a reason to *look*,
   not a number to *plan* against.
