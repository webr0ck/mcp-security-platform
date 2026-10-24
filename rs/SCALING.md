# Horizontal scaling — N-replica design for `mcphubd`

Status: design, not implemented. Companion to `ARCHITECTURE.md` (which stays the
governing spec; nothing here weakens its invariants). Every number below is
tagged **[measured]** (came from a bench/critic run recorded in ARCHITECTURE.md
or the audit critic report) or **[reasoned]** (derived arithmetic or judgment —
verify before betting on it).

## 0. The problem, restated from the measurements

- Cache-cold policy decision: **~790µs** [measured]. Irreducible via regorus's
  public API [measured — two hypotheses tested and rejected, see
  ARCHITECTURE.md "Measured reality"].
- Cache key must include `params` (deny rules inspect params), and real agent
  traffic varies params per call → plan against the **~7.7k decisions/s
  cache-cold floor** per 12-thread/6-core box [measured], not the 430k/s hot
  number.
- Target: **20,000 req/s from 3000 agents** (ARCHITECTURE.md performance
  budget).
- Audit emit: the per-process `Mutex` in `crates/mcphub-store/src/audit.rs`
  now (post-D2) covers only the Postgres INSERT — but that still serializes
  every request in the process through one PG round trip. At 0.7–2ms per
  round trip that is **~500–1500 events/s per process** [measured by critic] —
  the wall long before policy is.

Two consequences frame everything below:

1. **Replicas ≈ hosts.** The 7.7k/s cold floor is CPU-bound Rego
   interpretation. N `mcphubd` processes on the *same* host share the same
   cores and do not multiply policy throughput [reasoned — obvious but easy to
   miss; verify with a 2-process same-host bench before provisioning].
   Horizontal scaling here means more hosts (or more cores), with a small
   per-host process count only for availability/deploy reasons.
2. **The audit path must be fixed in code, not scaled around.** 20k req/s ÷
   1.5k events/s/process = 14 replicas just to absorb audit — absurd when a
   group-commit writer fixes it inside one process (§4). Scaling N up to paper
   over a serialized write path is the anti-pattern.

## 1. State classification

| State | Today | Multi-replica classification | Why |
|---|---|---|---|
| Policy decision cache (`mcphub-policy/src/cache.rs`, moka in `engine.rs`) | per-process moka, 5s TTL | **Local. Do not share.** | §2.1 — a shared tier costs a Redis RTT comparable to the eval it saves, and the hit rate is structurally low anyway |
| Policy bundle + compiled entrypoints | per-process, loaded from signed file | **Local copy, shared source of truth + shared activation epoch** | §5 — replicas must converge on one digest inside a bounded, observable window |
| Grants/tools data (`sync_data`) | per-process snapshot from PG, `max_data_age` fail-closed | **Local snapshot, shared source (PG), bounded staleness — already correct** | staleness is already bounded and fail-closed; digest goes into health for observability |
| Rate limit (`mcphub-policy/src/rate_limit.rs`, governor) | per-process keyed GCRA | **Shared (Redis GCRA).** | §2.2 — per-replica limits are a security control silently loosening N× |
| Anomaly cutoff / `recent_calls` sliding window | per-process (feeds Rego input) | **Shared (Redis).** | same argument as rate limit; a per-replica window sees 1/N of a client's behaviour and under-detects [reasoned — confirm where `recent_calls` is actually populated before implementing] |
| Audit hash chain (`mcphub-store/src/audit.rs` `prev_hash`) | per-process `Mutex<Option<String>>`, fresh each boot | **Deliberately per-replica chains, made partitionable via a durable `chain_id`.** | §4 — a global chain requires a global serializer, recreating the wall |
| PKCE pending flows (`mcphub-identity/src/pkce.rs` `PendingFlowStore`) | in-memory HashMap | **Shared (Redis, TTL 600s, single-use via `GETDEL`).** | §2.3 — sticky sessions rejected |
| JWKS cache (`mcphub-identity/src/jwks.rs`) | per-process moka | **Local. Never share.** | public keys, TTL-bounded, N independent fetches per rotation is noise |
| Token-exchange cache (`mcphub-identity/src/exchange.rs`) | per-process moka | **Local. Must never be shared.** | values are live downstream bearer tokens; putting them in Redis creates a new secret-at-rest surface. Cost: up to N× exchange calls per (sub, server) — acceptable at small N [reasoned] |
| Quarantine flags, entitlements, server registry, IDP config, credentials | Postgres | **Already shared (PG). No change.** | read per request via `EntitlementStore`; if anyone later adds a local `tool_meta` cache, its TTL becomes the quarantine-propagation lag and must be ≤ the stated quarantine SLO — or don't cache |
| Credential broker KEK / Vault | Vault | Already shared. No change. | |
| Dedicated-port allocations | in-memory `DedicatedPortAllocator` (`mcphub-identity/src/ports.rs`) | **Shared (PG registry is the allocator; in-memory struct becomes a read-through view).** | §7 — and note ports.rs currently allocates per **ServerId**, contradicting ARCHITECTURE.md's resolved per-**IDP** model; fix that first |

Rule of thumb that falls out: **caches of public/recomputable facts stay
local; security *controls* with cross-request memory (limits, windows,
single-use flows) go shared; secrets never go shared.**

## 2. The contested items, argued

### 2.1 Decision cache: keep it local, and stop expecting it to save you

The trap in the brief is real: with random LB distribution, a repeat of the
same (identity, tool, params, generation) within the 5s TTL lands on the same
replica with probability 1/N, so per-replica hit rate on repeat traffic drops
by ~N. Three options:

- **Shared Redis cache tier.** A loopback/LAN Redis GET is ~100–500µs
  [reasoned — measure on the target hardware]; the thing it saves costs 790µs.
  Best case ~2–8× win per hit, worst case near-parity — for a cache whose hit
  rate on real agent traffic is low *regardless of sharing*, because `params`
  vary per call. It also puts a serialized full-input SHA-256 key and a Redis
  RTT on the hot path of every request, and forces the generation story (§5)
  to be solved first (a decision cached under replica A's generation must
  never serve under B's different one). Cost/benefit fails. **Rejected.**
- **Affinity routing on the cache key.** The key includes `params`, so true
  key-affinity is per-request-unique — meaningless. The useful approximation
  is affinity on **client identity** (consistent-hash on `sub`/mTLS CN at
  nginx): a client's repeats land on one replica, restoring the single-process
  hit rate for whatever repeat traffic exists, and as a bonus keeping that
  client's token-exchange cache and (if we ever fell back to it) local rate
  bucket on one replica. Cheap to add (`hash $ssl_client_s_dn consistent` /
  `hash $remote_addr consistent` in the nginx upstream). **Adopt as LB
  default** — it costs nothing and strictly helps every local cache.
- **Accept local caches and size for the cold floor.** This is the honest
  planning posture either way: ARCHITECTURE.md already concluded the cold
  floor is the number to plan against. The cache remains what it is — a free
  win on identical-repeat traffic, not a capacity mechanism.

**Decision: local caches + identity-affinity LB routing + all sizing done at
the cold floor.** Any capacity plan that only closes at an assumed hit rate is
wrong.

One required change regardless: the cache generation is currently a
per-process monotonic counter. For cross-replica *observability* (not for
sharing), replace/augment it with content digests — see §5.

### 2.2 Rate limiting: shared Redis GCRA, and why fail-closed doesn't get worse

Per-replica governor with limit L means the fleet enforces up to N×L —
a security control loosening silently as you scale. With random LB it's ≈L in
expectation but N×L under adversarial burst-splitting [reasoned]. Not
acceptable for a security platform.

The decisive observation: **invariant 4 already puts a Redis round trip
(audit XADD) on every allowed request, and audit failure already denies.**
Redis is already on the hot path and already coupled to availability. Moving
rate limiting to Redis therefore adds one RTT of latency (~0.2ms, or ~0 if
pipelined with other per-request Redis work) and **zero new availability
coupling**. This is the same conclusion Envoy reached: local per-proxy limits
multiply, so Envoy's production answer is a global rate limit service backed
by Redis (lyft/ratelimit) [reasoned-from-memory — pattern is well known, exact
implementation details unverified here].

Design: atomic GCRA/token-bucket as a Redis Lua script (EVALSHA), keyed
`rl:{sub}`, with per-client overrides read from PG as today’s plan. Redis
error or script failure → `GateError::RateLimited`-equivalent deny
(`DependencyUnavailable("rate_limit")`), never allow. Keep the governor
implementation behind the same `RateLimiter` trait as the single-node/lab
configuration (config-selected), documented as "correct only at N=1".

Interim (before the Lua limiter exists): configure each replica at
`quota / N`. This is *approximately* correct under random LB and strictly
conservative under identity-affinity routing (each client's bucket lives on
one replica, which then enforces quota/N — too tight, i.e. fail-safe in the
right direction) [reasoned]. Acceptable as a stopgap only.

Anomaly cutoff: same treatment. Whatever populates the sliding window that
becomes `input.recent_calls`/`anomaly_score` must read/write a shared Redis
structure (sorted set per sub, trimmed by time), or a client can spread
behaviour across replicas to stay under every local window. **Flagged: I did
not locate the recent_calls producer in the rs tree — verify whether it is
implemented yet; if not, implement it shared from day one.**

### 2.3 PKCE pending flows: shared Redis store, not sticky sessions

Pick: **shared store.** Reasons:

- The code already anticipates it: `PendingFlowStore`'s doc comment says
  "Production wiring backs this with Redis (short TTL) via `mcphub-store`".
- The natural key (`state`) is opaque, high-entropy, and single-use —
  `SET state → serialized PendingFlow, EX 600` on start; `GETDEL` on callback
  gives single-use semantics atomically across replicas.
- Sticky sessions would have to survive a *cross-site redirect through the
  IDP and back*, possibly minutes later, from clients that are not always
  browsers (MCP clients doing RFC 7591 + PKCE). Cookie/affinity stickiness
  across that boundary is fragile, dies with the replica mid-login, and adds
  LB configuration that must never be wrong for a security flow. Rejected.
- Login is low-rate and latency-tolerant; a Redis RTT is irrelevant there.
- Fail-closed: Redis down → logins fail → correct (they'd be denied at audit
  anyway).

Keep `MAX_PENDING_FLOWS` semantics globally: bound with a counter or accept
the Redis-side bound via per-key TTL + a `SCARD`-style cap check; the DoS
concern (unauthenticated `/login` growing state) becomes "unauthenticated
`/login` writes to Redis" — bound it with the existing edge rate limit on
`/login` at nginx plus the capacity cap.

Note the `PendingFlow` contains the PKCE **verifier** — a short-lived secret.
Storing it in Redis is acceptable (600s TTL, single-use, Redis is inside the
data network and already holds audit content), but it must go into the store
under the same no-log/no-Display discipline as every other `Secret<T>`.

## 3. What each replica looks like (target shape)

Homogeneous replicas: every replica runs the identical binary, listens on the
shared port **and every dedicated IDP port**, loads the same signed bundle,
syncs the same PG data. No leader, no special replica. Scheduling and LB in §8.

## 4. The audit path: group commit + per-replica chains

### 4.1 Throughput: group-commit writer (fix before scaling)

Current shape (`audit.rs::emit_inner`): per event — Redis XADD (RTT) →
stdout line → mutex → PG INSERT (RTT) → advance `prev_hash`. The mutex
serializes the whole process at one PG RTT per event: ~500–1500 events/s
[measured by critic].

Fix: a per-replica **group-commit audit writer** (WAL-style), preserving
invariant 4 exactly:

- `emit()` sends `(record, oneshot::Sender)` into an mpsc channel and awaits
  the oneshot. The response is still not sent until the oneshot resolves —
  audit remains synchronous-before-response.
- A single writer task drains the channel up to `MAX_BATCH` (e.g. 128) or
  `MAX_WAIT` (e.g. 2ms), computes the hash chain for the batch **in memory**
  (sequential, no lock needed — the writer task *is* the serialization),
  then: one pipelined Redis XADD for the batch → one multi-row
  `INSERT ... SELECT FROM unnest(...)` for the batch → resolve every oneshot
  with the batch outcome. Redis-fail → whole batch resolves Err before PG is
  touched (preserves the D5 ordering); PG-fail → whole batch Err, chain
  anchor not advanced.
- Bounded channel; a full channel is `DependencyUnavailable("audit_sink")` →
  deny (replaces `LOCK_ACQUIRE_TIMEOUT` as the back-pressure valve).

Expected: ~128 events per ~2–3ms round trip ≈ **40–60k events/s per replica**
[reasoned arithmetic — bench it]; added latency ≤ `MAX_WAIT` + one RTT, inside
the p99 budget. This single change removes audit from the bottleneck table
entirely.

One semantic change to state honestly: within a batch, all-or-nothing means a
request can be denied because a *neighbouring* record's batch failed. That is
strictly fail-closed (over-denying, never over-allowing) and identical in kind
to today's "audit dependency down = deny".

### 4.2 Correctness: chains an auditor can partition

With N replicas, per-process chains interleave in one `audit_events` table
and `prev_hash` becomes unverifiable (multiple roots, cross-linked hashes —
today's verifier would report tampering on a healthy system). A single global
chain would require a global serializer (PG advisory lock around
read-last-hash-then-insert), putting every replica's hottest write behind one
lock — recreating, fleet-wide, the exact wall §4.1 removes. **Rejected.**

Design: **explicit per-replica-boot chains.**

- New columns: `chain_id UUID NOT NULL` (minted fresh at every sink
  construction = every process boot), `chain_seq BIGINT NOT NULL`
  (monotonic within the chain, assigned by the writer task), unique index
  `(chain_id, chain_seq)`.
- `chain_id` and `chain_seq` join `canonical_core_json` — they are part of
  the hashed preimage, so a row cannot be silently moved between chains or
  reordered within one.
- A **genesis record** (`chain_seq = 0`, `event_type = chain_genesis`) binds
  `chain_id` to `(hostname, replica_ordinal, boot timestamp, mcphubd build
  digest, active bundle digest)` and is HMAC'd like any row. The auditor
  partitions by `chain_id`, verifies each chain independently (root =
  genesis, links = `prev_hash`, density = gapless `chain_seq`), and gets an
  inventory of which replica produced what, when.
- Cross-chain total order is **explicitly not provided** — per-event HMAC +
  per-chain links + gapless sequence is the tamper-evidence model, same
  posture the Python platform took (per-event HMAC, chain scoped
  out) but now formalized instead of accidental. What an attacker gains from
  N chains vs 1: nothing new — deleting a whole chain's tail is detectable
  via `chain_seq` gaps against the genesis + the neighbouring chains'
  timestamps; deleting an entire chain including genesis is detectable only
  operationally (a replica that booted, per deploy logs/systemd journal, but
  has no chain). State that residual honestly in `audit_verify.rs`'s report.
- `audit_verify.rs::verify_chain` regrows a `verify_all_chains` that groups
  by `chain_id`; the existing single-chain logic becomes the per-group body.

### 4.3 Audit volume at target load

20k req/s ≈ 20k rows/s ≈ ~20MB/s ≈ **1.7TB/day** [reasoned: ~1KB/row].
Sustained target load makes retention a first-order problem: partition
`audit_events` by day (`chain_id`-agnostic), archive-and-detach old
partitions (this coexists with the append-only guard: the guard forbids
UPDATE/DELETE on rows; partition detach is a DDL archival operation that must
be an explicitly-audited operator action, exporting to MinIO/object storage
before drop — same model the Python platform's MinIO archival tier uses).
Not designed further here; listed in §11 as a prerequisite for sustained
target-load operation.

## 5. Policy-generation consistency across replicas

Two replicas enforcing different policy simultaneously is a correctness
violation to bound, observe, and alarm on — not eliminate at any price.

**Identity, not counters.** Replace the meaning of "generation" with content
digests: `bundle_digest = SHA-256(signed bundle bytes)` and
`data_digest = SHA-256(canonical grants/tools/phrases snapshot)`. The local
monotonic `generation: u64` stays as the cache-key epoch inside a process
(cheap), but the *reported* identity of what a replica enforces is the digest
pair. Each replica exposes it in `/healthz` and as a metric label.

**Distribution.** One activation record, one place:
`policy_activations(bundle_digest, signed_bundle_bytes_ref, activated_at,
not_after_grace)` in Postgres (PG, not Redis: policy activation must survive
a Redis flush, and PG is already the config source of truth). Replicas learn
of it by poll (interval `T_poll`, e.g. 5s) plus an optional Redis pub/sub
nudge for fast-path propagation; the poll is the correctness mechanism, the
nudge is latency sugar — never rely on pub/sub delivery for a security
property.

**The bound, enforced fail-closed.** After a new activation at time `t`, a
replica that has not successfully loaded+compiled the new digest by
`t + T_poll + grace` (grace ≈ compile time + margin, e.g. 10s total) marks
itself **unready**: `/healthz` fails, the LB drains it, and — because
readiness gates serving, and an unready replica's `evaluate` path can also be
made to return `DependencyUnavailable("policy_epoch")` — a straggler denies
rather than enforcing the old policy indefinitely. The divergence window is
therefore ≤ `T_poll + grace`, observable (digest metric disagreement), and
alarmed (any two replicas reporting different digests for > window fires).
During the window, both digests are individually valid, signed, operator-
approved policies — the exposure is "old approved policy served a few seconds
longer on some replicas", which is exactly the exposure a single process has
between the operator's push and its own reload.

**Why not eliminate the window entirely?** True simultaneous flip needs
two-phase activation: phase 1 pushes + compiles everywhere (replicas hold
both compiled states), phase 2 flips a shared epoch that every request reads.
The epoch read must be consistent per request → either a Redis/PG read per
request (new hot-path RTT and availability coupling for marginal benefit) or
a local watch of an epoch key with the same propagation delay you started
with. The bounded window with fail-closed straggler handling gets the entire
correctness value (no replica *ever* enforces a stale policy beyond a known,
small, alarmed bound) without a new hot-path dependency. This mirrors how OPA
itself handles distributed PDPs: bundle polling with `revision` reported in
decision logs/status — staleness bounded and observed, not eliipsed
[reasoned-from-memory — OPA bundle/status API semantics, unverified here].

**Data (grants) sync** already has this structure: per-replica snapshot,
`max_data_age` fail-closed staleness bound. Add the `data_digest` to health
for the same observability. Divergence between replicas' grant snapshots is
bounded by the sync interval — same as the Python platform's OPA data sync.

**Cache interaction.** Cached decisions are keyed on the local generation
counter which bumps on every load — a replica can never serve a cached
decision across a digest change. No cross-replica cache exists (§2.1), so no
cross-replica invalidation problem exists.

## 6. Redis, fail-closed, and the honest availability story

Facts first: **Redis is already on the critical path of every single allowed
request** (audit XADD, invariant 4). Redis down today = every invoke denied.
This design adds: rate-limit check, anomaly window, PKCE flows. None of these
change the worst case — it was already "Redis down = platform denies".

What actually changes is *blast radius per feature*:

| State | Redis down → | Is a local fallback safe? |
|---|---|---|
| Audit stream | deny everything (unchanged, invariant 4) | **No.** Un-audited allows are the definitional fail-open. |
| Rate limit | deny (moot — request dies at audit anyway) | A governor fallback would be *arguable* in isolation, but it is unreachable in practice: no request that passes a degraded rate limiter can complete, because audit denies it 3 gates later. Don't build dead code. |
| Anomaly window | deny (same reasoning) | No, same. |
| PKCE flows | logins fail | No fallback (a local flow store recreates the exact A-starts/B-finishes bug). Acceptable: sessions already issued keep working until token expiry. |
| Decision cache | n/a — cache is local | n/a. If a shared cache tier is ever built despite §2.1, a read failure there is the one place local fallback (just evaluate) is safe, because the cache is an optimization, not a control. |

So the honest answer to "is there any state where a local fallback is safe
without violating fail-closed": **effectively no** — the only safe candidate
(decision cache) is one we deliberately keep local anyway, and every other
candidate is dominated by the audit invariant.

Therefore the availability work goes into **Redis itself**, not into
fallbacks:

- Single-host tier: Redis as a quadlet with `Restart=always`, AOF
  `everysec`, outage = restart time (seconds). Denials during that window are
  the designed behaviour; alarm on the deny-spike, don't engineer around it.
- Multi-host tier: Redis with a replica + Sentinel (or a managed equivalent),
  client-side `connection-manager` reconnect (already in the pinned redis
  crate features). Failover window (~seconds of denies) is accepted and
  documented, same as today.
- The new Lua scripts (rate limit, flow store ops) must be `EVALSHA` with
  reload-on-NOSCRIPT so a failover to a script-less replica self-heals
  instead of hard-denying until an operator loads scripts.

Same story for Postgres (audit INSERT + entitlement reads are per-request):
PG down = deny everything, unchanged from today. Multi-replica adds only
connection-count pressure (§8), not new coupling.

## 7. `dedicated_port` × N replicas × LB

**Pre-existing defect to fix first:** `mcphub-identity/src/ports.rs`
(`DedicatedPortAllocator`) allocates per `ServerId`. ARCHITECTURE.md
explicitly resolved this the other way: the port belongs to the **IDP**
(`idp_configs.dedicated_port`); servers with `auth_mode = dedicated_port`
share their IDP's listener. Per-server allocation burns the 100-port range N×
faster and stands up duplicate listeners with identical metadata. Rekey the
allocator (and its restore path) by `IdpId` before any of the below.

Multi-replica model:

- **Allocation is a registry fact, not a process fact.** The allocation lives
  on the `idp_configs` row in PG (already the ARCHITECTURE.md rule:
  "register the allocation with the platform *before* opening and routing the
  port"). The in-memory allocator becomes a read-through view of that table;
  allocation itself is an `INSERT ... ON CONFLICT` against a
  `dedicated_port UNIQUE` constraint so two replicas (or a replica and the
  Ansible provisioning playbook) can never double-allocate. First-writer
  wins; everyone else reads.
- **Every replica listens on every dedicated port** (homogeneous replicas).
  A port is an IDP identity, not a replica identity. Replica startup reads
  `idp_configs`, binds each allocated port, and serves that IDP's RFC 9728 +
  RFC 8414 metadata on it. Runtime allocation of a *new* IDP port propagates
  like a config epoch (§5 pattern): replicas poll the registry and bind new
  listeners; the port is not routed at the edge until all ready replicas
  report it (below), so no client ever sees a port that only some replicas
  serve.
- **LB:** nginx `stream {}` (TCP passthrough — mTLS/TLS terminates at
  `mcphubd` for dedicated ports, or `http {}` per-port server blocks if the
  edge terminates; follow whatever the shared port does today) with one
  `listen <port>` + one `upstream` per dedicated port, generated by the
  Ansible `gateway` role from the same registry query the provisioning
  playbook uses (`playbooks/provision-dedicated-port.yml` already exists —
  extend it to render the per-port upstream across all replica hosts).
  Identity-affinity hashing (§2.1) applies per upstream.
- **Health:** the LB health-checks each replica *per dedicated port* by
  fetching `/.well-known/oauth-protected-resource` on that port and (cheaply)
  checking it parses. A replica healthy on the shared port but failing to
  bind port 9007 must be out of rotation *for port 9007 only* — per-upstream
  health, not one global bit. `mcphubd`'s own `/healthz` additionally
  reports the set of bound dedicated ports + the IDP config epoch, so
  "replica missing a listener" is observable before the LB notices.
- **Metadata consistency:** metadata is a pure function of the `IdpConfig`
  row. Replicas serve identical documents as long as they hold the same
  config epoch — covered by the same bounded-staleness + health-epoch
  machinery as §5. Two replicas briefly serving different `jwks_uri` during
  a config change is bounded by the epoch window and harmless in kind (both
  are operator-approved configs), same argument as policy.

## 8. Sizing arithmetic

> **SUPERSEDED IN PART — re-measured after the split cache and the anomaly
> layer landed.** The table below was computed against a single-key decision
> cache and a policy engine with no anomaly evaluation. Both changed:
>
> - `anomaly.rego` is now evaluated as its own prepared entrypoint on **every**
>   call (never cached), and it reads `recent_calls`, which changes on every
>   invocation.
> - The decision cache was therefore split: authz is cached on a key that
>   **excludes** `recent_calls`/`window_seconds`; anomaly is always fresh.
>   Without that split a whole-input key could essentially never hit, and
>   throughput would have collapsed to the cold floor — the interaction
>   ARCHITECTURE.md predicted.
>
> **Re-measured end to end, with `recent_calls` varying every iteration (i.e.
> the real traffic shape, not a warm-cache best case):**
>
> | | measured |
> |---|---|
> | authz cache hit | ~17.4µs |
> | authz cache miss | ~426µs |
> | anomaly eval (never cached) | ~98.1µs |
> | **real end-to-end per decision** | **~84.2µs** |
>
> That is **~11,876 decisions/s per core** → ~95k/s at 8 cores linear, and
> **~28,500–47,500/s at the 30–50% parallel efficiency observed on this box**.
>
> Net effect on the plan of record: policy is comfortably *not* the binding
> constraint, and the "replicas for 20k req/s" column below is pessimistic —
> **1–2 replicas now carry 20k on policy alone.** The wall ordering in the
> second table is unchanged and is what still matters: the audit writer and
> the Postgres write path bind long before policy does. Do not use the h=0 row
> as a planning number any more; use the 84.2µs figure, and re-measure with
> `make perf-check` on real hardware before committing to a fleet size.
>
> Everything below is retained because the *method* is still correct — only
> the per-decision cost changed.

All per-replica numbers assume an 8-core host per the ARCHITECTURE.md budget;
the measured 7.7k/s was 12 threads on 6 physical cores, so per-core cold ≈
1/790µs ≈ 1,266 decisions/s [measured→reasoned].

**Policy throughput per 8-core replica** at hit rate *h*
(cost = h·20µs + (1−h)·790µs per decision, ×8 cores):

| hit rate h | µs/decision | per-replica req/s | replicas for 20k req/s |
|---|---|---|---|
| 0% (planning number) | 790 | ~10,100 | **2 exactly, 3 with headroom** |
| 25% | 597 | ~13,400 | 2 |
| 50% | 405 | ~19,800 | 2 (1 has no headroom) |
| 75% | 212 | ~37,700 | 1 (+1 for availability) |
| 90% | 97 | ~82,500 | 1 (+1) |

**Plan of record: 3 × 8-core replica hosts** — carries 20k req/s at h=0 with
~1.5× headroom, survives one replica loss at ~10k/s degraded (or 20k at
h≥50%), and N≥2 is required for zero-downtime deploys anyway (§9).

**Where the bottleneck moves once policy stops being it** (at 20k req/s):

| Path | Per-replica capacity | Fleet demand at 20k | Binding at |
|---|---|---|---|
| Audit, today's serialized writer | 0.5–1.5k ev/s [measured] | 20k ev/s | **already binding at N=1 — fix per §4.1, do not scale around** |
| Audit, group-commit writer | ~40–60k ev/s [reasoned] | 20k ev/s | not binding at any sane N |
| Postgres write path | ~150–300 batched INSERTs/s of 128 rows ≈ 20–40k rows/s on decent NVMe [reasoned — bench] | 20k rows/s | roughly at target — PG needs its own headroom check + the §4.3 partitioning; this is the **next real wall** after the writer fix |
| Postgres read path (`tool_meta` + `list_visible` = 2 queries/req) | pool of ~15 conns × ~2k q/s | 40k q/s | ~40k indexed point-reads/s is feasible but not free [reasoned]; add a per-replica *bounded* read-through cache **only** with TTL ≤ quarantine SLO, or precompute `list_visible` per (identity, grants-digest) keyed by the §5 `data_digest` — which makes it correctly invalidated shared-state-derived, not a staleness hole |
| PG connections | ~15/replica pool | 3 replicas ≈ 45 + workers | fine to ~10 replicas; beyond that, pgbouncer |
| Redis ops (XADD batched, rate-limit Lua, exchange/flows) | single Redis ~100k+ ops/s [reasoned] | ~20k Lua + ~150 pipelined XADD batches + noise ≈ 25k ops/s | not binding below ~8–10 replicas; then Redis needs its own core or cluster |
| Token exchange (`shared_exchange` servers) | IDP-bound | ×N cold exchanges per (sub,server) | watch IDP rate limits; identity-affinity routing (§2.1) reduces to ×1 in practice |

Order of walls: **audit writer (now) → PG audit-write headroom + retention →
PG read path → Redis**. Policy stops being the constraint at N=3.

## 9. Deployment

Building on `deploy/ansible/` + `deploy/quadlets/` as they exist (health-gated
`deploy.yml` with automatic rollback, quadlet units, nginx gateway role).

- **Scheduling:** replicas are inventory entries, not an orchestrator's
  decision. `mcp_gateway` group grows to 3 hosts (per §8); each host runs one
  `mcphubd.container` quadlet (one process per host — §0 point 1; a second
  process per host buys availability-during-deploy only if the host has spare
  cores, otherwise nothing). The `gateway` (nginx) role runs on one edge host
  (or two with keepalived — out of scope, listed in §12) and gains `upstream
  mcphubd_shared { hash <client identity> consistent; server hostA:8001; … }`
  plus the per-dedicated-port upstreams of §7, all rendered from inventory +
  the IDP registry.
- **Rolling deploys without a split-policy window:** the deploy artifact is
  (image digest, bundle digest) — **pin the bundle digest in the deploy
  vars** just like `mcphubd_image_digest`, and have `deploy.yml` serialize
  over hosts (`serial: 1`): drain via LB health, deploy, health-check
  (which now asserts the replica reports the expected `bundle_digest` +
  `data_digest` — extend the `health_check` role), rejoin, next host.
  Policy-only changes ride the §5 activation mechanism and don't need a
  binary deploy at all. Mixed-version windows during a rolling image deploy
  are bounded by the same health assertions: a replica whose reported bundle
  digest differs from the activation record past the §5 window is unready and
  stays drained — the LB never routes to a straggler.
- **Network isolation stays honest:** the quadlet table already encodes it —
  `mcp-backend.container` publishes **no ports** and sits on the internal
  `backend` network; only `mcphubd` joins both `backend` and `gateway`
  networks. Adding replica hosts multi-host means the backend network becomes
  a cross-host network; the invariant to preserve verbatim: **backends are
  reachable from gateway replicas and from nothing else** — no published
  backend ports, no backend membership in any externally-routable network,
  and the existing `check_network_isolation`-style verification extended to
  every host in the group (add to the `health_check`/`smoke-test` playbooks).
  If backends stay single-host, gateway replicas on other hosts reach them
  over WireGuard/vxlan into the backend network — never over published ports.
- **Rollback:** unchanged mechanism (`rollback` role records/restores
  digests), now per-host under `serial: 1`; a mid-rollout failure leaves
  earlier hosts on the new digest and later on old — both healthy, both
  policy-converged (policy is decoupled from the image), and `deploy.yml`'s
  existing rescue reporting states which hosts sit where.

## 10. Comparable systems (what transfers, what doesn't)

All three are cited from working knowledge, not re-verified against current
docs for this design — **[reasoned-from-memory]**; verify before quoting
outward.

- **OPA's distributed-PDP guidance:** PDP colocated with the PEP (sidecar/
  embedded — exactly what regorus-in-process is), policy distributed as
  versioned bundles from a central control plane, staleness *observed* via
  status/decision-log reporting of the bundle revision rather than eliminated.
  §5 is this pattern with the observation made fail-closed (staleness past
  the bound → unready → drained), which OPA leaves to the operator.
- **Envoy global rate limiting (lyft/ratelimit):** per-proxy local limits
  multiply with fleet size, so the production pattern is a shared Redis-backed
  limit service consulted per request. Transfers directly (§2.2); our
  fail-closed twist (limit-service unreachable → deny) is the opposite of
  Envoy's common default (failure_mode_deny=false) — that default is exactly
  the pattern that does **not** fit this platform and is rejected explicitly.
- **linkerd2-proxy:** per-proxy policy cache fed by a central policy
  controller over a watch, with the proxy holding a versioned index —
  local-enforce/central-distribute, identity bound to trust anchor. Matches
  §2.1 + §5. Its "fail-open until first policy load" bootstrap default does
  not transfer — `PolicyState::NotLoaded → deny` stays.
- **Classic PDP/PEP/PAP/PIP split (XACML lineage):** PEP local (invoke gate
  chain), PDP colocated (regorus), PAP central (signed bundle + activation
  record), PIP shared (PG grants, Redis windows). This design is that split;
  naming it in docs helps auditors place each component.

## 11. Migration path from today's single-process design

Ordered so every step is independently shippable and N=1 keeps working:

1. **Audit group-commit writer + chain columns** (§4) — fixes the N=1
   bottleneck *and* is the hard prerequisite for N≥2 (interleaved chains are
   broken today, not just suboptimal). Migration adds `chain_id`/`chain_seq`;
   verifier grows `verify_all_chains`.
2. **Digest-based policy identity + `/healthz` reporting** (§5) — pure
   additive observability at N=1.
3. **Redis-backed PKCE flow store** (§2.3) — behind the existing store trait;
   N=1 behaviour unchanged.
4. **Redis GCRA rate limiter + shared anomaly window** (§2.2) — config-
   selected implementation of the existing `RateLimiter` trait; governor
   stays for lab/N=1.
5. **`ports.rs` per-IDP rekey + PG-backed allocation** (§7) — a correctness
   fix even at N=1 (matches ARCHITECTURE.md).
6. **Policy activation record + poll + fail-closed epoch staleness** (§5).
7. **Ansible: multi-host inventory, nginx upstreams with identity-affinity
   hashing, per-port health checks, `serial: 1` deploy, digest assertions in
   `health_check`, isolation checks per host** (§9).
8. **Load-test the fleet** (loadgen, component 6): confirm the §8 table on
   real hardware — especially the group-commit audit ceiling, PG write
   headroom at 20k rows/s, and the actual cache hit rate under recorded agent
   traffic. Every [reasoned] number above graduates or dies here.
9. **Audit partitioning/retention** (§4.3) — before sustained target-load
   production, not before the load test.

## 12. What this design does NOT solve

- **The 790µs floor itself.** Unchanged; we buy hosts instead. The escape
  hatches (shrink the policy, fork regorus, compile to native) remain in
  ARCHITECTURE.md, still gated on real-traffic measurement.
- **Cross-chain total ordering of audit events.** Deliberately out (§4.2);
  tamper evidence is per-chain + per-event HMAC + sequence density. Deleting
  an *entire* chain including its genesis is detectable only against external
  boot records — a stated residual, not a solved one.
- **Edge (nginx) high availability.** One LB host is a SPOF this document
  does not remove (keepalived/VRRP or DNS-level failover is follow-on work).
- **Redis/Postgres HA beyond restart-and-deny.** Sentinel/replica topology is
  sketched (§6) but not designed; the platform's answer to a datastore outage
  remains "deny until it's back", by invariant.
- **Multi-region / geo distribution.** Nothing here addresses WAN latency
  between replica and PG/Redis; the design assumes one LAN.
- **Backend MCP server scaling.** Backends stay single-instance behind the
  isolation boundary; scaling *them* is a separate problem.
- **Per-client rate-limit overrides from PG** — still the pre-existing TODO
  in `rate_limit.rs`; the Redis limiter must land with override support or
  inherit the TODO.
- **The actual cache hit rate of real traffic.** Unknown until step 11.8.
  Every capacity claim above is stated at h=0 for exactly this reason.

## 13. Code-change index (hand-off to implementers)

| File | Change |
|---|---|
| `rs/crates/mcphub-store/src/audit.rs` | Replace per-emit mutex+INSERT with bounded-mpsc group-commit writer task (§4.1): batch hash-chain in-memory, pipelined XADD, multi-row INSERT via `unnest`, oneshot acks; Redis-before-PG ordering preserved; full channel ⇒ `DependencyUnavailable("audit_sink")`. Add `chain_id`/`chain_seq` to `AuditRecord`, `canonical_core_json`, and the INSERT; emit genesis record at construction. |
| `rs/crates/mcphub-store/src/audit_verify.rs` | `verify_all_chains`: group rows by `chain_id`, verify each (genesis root, links, gapless `chain_seq`), report per-chain + inventory of chains. |
| `rs/migrations/` | New migration: `ALTER TABLE audit_events ADD chain_id UUID NOT NULL, ADD chain_seq BIGINT NOT NULL` (backfill existing rows into a synthetic legacy chain per distinct root), `UNIQUE (chain_id, chain_seq)`. Later: daily partitioning (§4.3). |
| `rs/crates/mcphub-policy/src/engine.rs` | Add `bundle_digest()`/`data_digest()` (SHA-256 of bundle bytes / canonical data snapshot) exposed alongside `generation`; keep the local counter for cache keys. Epoch-staleness check: if an activation record newer than `T_poll+grace` isn't loaded, `evaluate_raw` ⇒ `Err(PolicyError::EpochStale)` (new variant, maps to deny) and `is_ready()` ⇒ false. |
| `rs/crates/mcphub-policy/src/cache.rs` | No change (key derivation stays input+generation; document that generation is process-local by design). |
| `rs/crates/mcphub-policy/src/rate_limit.rs` | New `RedisRateLimiter` implementing the same `RateLimiter` trait: GCRA Lua via EVALSHA (reload on NOSCRIPT), keyed by `sub`, per-client overrides; any Redis/script error ⇒ `GateError::DependencyUnavailable("rate_limit")`. Keep `GovernorRateLimiter`, documented "N=1 only", config-selected. |
| `rs/crates/mcphub-identity/src/pkce.rs` | Extract a `PendingFlowStore` trait (insert/consume); keep the in-memory impl for tests; add serde derives on `PendingFlow` (verifier under `Secret<T>` discipline). |
| `rs/crates/mcphub-store/src/redis_store.rs` | `RedisPendingFlowStore`: `SET state EX 600 NX` / `GETDEL`; the rate-limit + anomaly-window Lua helpers; pipelined XADD batch helper for the audit writer. |
| `rs/crates/mcphub-identity/src/ports.rs` | Rekey `DedicatedPortAllocator` by IDP id (not `ServerId`) per ARCHITECTURE.md; back allocate/restore with the `idp_configs` row (`INSERT ... ON CONFLICT` on a `UNIQUE dedicated_port`); in-memory map becomes a view. |
| `rs/crates/mcphub-gateway/src/app.rs` / `state.rs` / `routers/` | `/healthz` reports `{bundle_digest, data_digest, idp_config_epoch, bound_dedicated_ports, chain_id}`; readiness gates on §5 epoch freshness. |
| `rs/bin/mcphubd/` | Wire: Redis flow store + Redis limiter selection by config; activation-record poller (PG) + optional pub/sub nudge; replica identity (hostname+ordinal) into the audit sink for the genesis record. |
| `rs/crates/mcphub-store/src/repo/` (policy) | `policy_activations` table accessors: publish activation (super-admin path), read latest for the poller. |
| `deploy/ansible/` | Inventory: multiple `mcp_gateway` hosts. `gateway` role: shared-port upstream with `hash <client id> consistent`, per-dedicated-port `listen`+`upstream` rendered from the IDP registry, per-port health checks. `deploy.yml`: `serial: 1`, drain/rejoin, `health_check` asserts expected digests. `smoke-test`/`health-check` playbooks: isolation verification on every host. `provision-dedicated-port.yml`: render port across all replica hosts + edge, registry-first ordering unchanged. |
| `rs/loadgen/` | Scenarios for: cold-floor fleet throughput, group-commit audit ceiling, PG write headroom, recorded-traffic cache hit rate (graduates §8's [reasoned] numbers). |
