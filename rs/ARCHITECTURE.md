# Rust rewrite — shared contract

Binding for all builders. If your component needs to change something here, say so in
your report; do not silently diverge.

Reference standard: **linkerd2-proxy** (tower/tokio layering, per-request identity+policy,
no allocation on the hot path, `tracing` spans everywhere, fail-closed defaults).

## Workspace

```
rs/
  Cargo.toml            # [workspace] resolver = "2"
  crates/
    mcphub-types/       # shared types, errors, no I/O deps    (component 1 owns)
    mcphub-gateway/     # axum app, tower layers, invocation   (component 1)
    mcphub-identity/    # OIDC, JWKS, token exchange, ports    (component 2)
    mcphub-policy/      # regorus, RBAC eval, entitlement      (component 3)
    mcphub-creds/       # AES-256-GCM broker, Vault KMS        (component 3)
    mcphub-store/       # sqlx Postgres, redis, audit sink     (component 4)
    mcphub-ui/          # askama templates + static            (component 5)
  bin/mcphubd/          # the single binary; wires everything  (component 1)
  migrations/           # sqlx migrations                      (component 4)
  loadgen/              # 3000-agent harness                   (component 6)
deploy/
  ansible/              # roles, playbooks, inventories        (component 6)
  quadlets/             # podman systemd units                 (component 6)
```

Rust edition 2021, MSRV stable. Pinned major deps (do not substitute):
`axum 0.7`, `tower`, `tower-http`, `tokio 1` (rt-multi-thread), `hyper 1`,
`sqlx 0.8` (postgres, rustls, macros off — use runtime queries, no DATABASE_URL at build),
`redis 0.27` (aio, connection-manager), `serde`/`serde_json`, `thiserror`, `anyhow` (bins only),
`tracing` + `tracing-subscriber` (json), `openidconnect 3`, `jsonwebtoken 9`,
`aws-lc-rs` (aead + hkdf), `regorus 0.11` (in-process Rego — **enable the `arc` feature**: it swaps regorus's
internal `Rc` for `Arc`, making `CompiledPolicy` both `Send` and `Sync`, so one
compiled policy behind an `Arc` serves every worker thread. Without it `Engine`
is `!Send` and cannot be held across an `.await`, which forces either
thread-local engines or a worker pool — both strictly worse. Otherwise keep
default features: a hand-picked feature list silently changes `walk/2`'s safety
checker and breaks the real `authz.rego`), `askama 0.12`, `reqwest 0.12` (rustls, no default-features),
`governor` (rate limit), `moka` (async cache), `uuid`, `time`.

## Non-negotiable invariants (ported from the Python platform)

1. **Fail-closed.** Any dependency error (DB, redis, Vault, JWKS, policy) → `Deny`. There is
   no `unwrap_or(Allow)`. `Result<Decision, E>` must never be mapped to allow on `Err`.
2. **Single choke point.** Both the REST path (`POST /api/v1/tools/{id}/invoke`) and the
   MCP path (`POST /mcp`, `tools/call`) call exactly one function:
   `mcphub_gateway::invocation::invoke(ctx, req) -> Result<InvokeOutcome, DenyReason>`.
   No second enforcement path. Ever.
3. **Discovery == invoke.** A tool that does not appear in this identity's `tools/list` must
   be rejected on `tools/call` with the same reason. Enforced in `invoke`, not in the lister.
4. **Audit is synchronous and precedes the response.** The audit record is durably queued
   (redis stream + stdout JSON) before the caller gets a body. Audit write failure = deny.
5. **No secret ever enters a log, a span field, an error `Display`, or a response body.**
   Credentials are `Secret<T>` wrappers with `Debug`/`Display` redacted.
6. **Backends are network-isolated.** Only the gateway may reach a backend MCP server.
   Enforced at the network/deployment layer (container/podman network policy that makes
   a backend genuinely unreachable except via the gateway), verified out-of-band by
   `scripts/check_network_isolation.py` / deploy's `verify_isolation.py` — **not** a
   per-request Rust check. `mcphub-gateway`'s `ToolMeta` briefly carried a
   `network_isolated: bool` field feeding a per-invoke gate; it was removed
   (integration pass, critic finding) because `bin/mcphubd`'s wiring had no per-tool/
   per-server data source for it and hardcoded it to `true` for every tool — a gate
   that can never fire is worse than no gate, since it reads as enforcement in both the
   code and this doc. If a real per-backend isolation signal is ever persisted (e.g. by
   the deploy-time verifier), a live check can be reintroduced against that data; until
   then, this invariant's enforcement lives entirely outside the request path.

## Core types (`mcphub-types`) — component 1 defines these first, exactly

```rust
pub struct Identity {
    pub sub: String,
    pub issuer: IssuerId,          // which configured IDP minted this
    pub email: Option<String>,
    pub roles: Vec<GrantedRole>,   // resolved, not raw claims — see below
    pub groups: Vec<String>,
    pub token_ref: TokenRef,       // opaque handle for downstream exchange
}

pub enum Role { SuperAdmin, ServerOwner, SecurityAnalyst, Employee }

/// A role is NEVER a bare `Role`. It is always paired with the issuer that
/// asserted it, and that provenance survives all the way to the authorization
/// decision.
pub struct GrantedRole { pub role: Role, pub asserted_by: IssuerId }
```

**Why (this was an architecture bug, found by mutation-testing critique):** the
first cut of this document specified `roles: Vec<Role>` — a flat enum with no
issuer binding — and every IDP profile was given the *same* default role-name
table. The platform is required to serve Entra + Keycloak + Zitadel
simultaneously, and those tenants are not equally trusted: a partner realm or a
contractor org is exactly where a lab or an outside admin lives. That admin
creates a role named `mcphub-super-admin` in **their own** tenant, grants it to
themselves, and signs in. The token is cryptographically flawless — right `iss`,
right `aud`, valid signature under that IDP's real JWKS, unexpired — so every
cryptographic control passes, correctly, and the resolved `SuperAdmin` reaches
RBAC with no record of who vouched for it. No `sub` collision required.

Rules that follow, and none of them are optional:

1. **Role provenance is part of the value.** Claim resolution takes the
   `IdpConfig`/`IssuerId` as input and stamps every resolved role with it.
   A function that maps claims → roles without receiving the issuer is a bug.
2. **Privileged roles are issuer-gated.** Each `IdpConfig` declares the maximum
   role it may assert (`max_assertable_role`). Only an IDP explicitly marked as
   the platform's trusted admin source may assert `SuperAdmin`. Anything above
   an IDP's ceiling is dropped and logged, never clamped silently.
3. **No shared default role table.** Role-name → `Role` mapping is per-IDP
   config with no cross-IDP default. Two configured IDPs mapping the same role
   string must be an explicit, reviewed operator decision — and startup must
   refuse to boot on an unintended collision rather than resolve it by
   last-write-wins.
4. **Authorization sees the pair.** RBAC and the Rego input receive
   `(role, asserted_by)`. A policy that can't tell a contractor tenant's
   `SuperAdmin` from the corporate IDP's isn't enforcing anything.

`linkerd2-proxy` gets this right and it's the lesson to copy: identity is a
typed value bound to the trust anchor that vouched for it, never a bare string
compared against a global table.

The remaining core types:

```rust
pub struct ToolRef { pub server: ServerId, pub tool: String }

pub enum Decision { Allow { obligations: Obligations }, Deny(DenyReason) }

pub enum DenyReason {
    Unauthenticated, NoGrant, Quarantined, PolicyDenied { rule: String },
    EntitlementMissing, RateLimited, TaintFloor, DependencyUnavailable(&'static str),
}
```

`DenyReason` **must** carry a stable machine code for the audit record and must not leak
internal detail into the HTTP body (map to a short public string separately).

## Enforcement order in `invoke` (do not reorder)

```
authenticate → resolve identity → ingress (server enabled) → SSRF guard
→ rbac (role has server) → quarantine gate → entitlement (discovery==invoke)
→ rate limit / anomaly cutoff → policy (regorus) → taint floor
→ credential injection → dispatch to backend → response filter → audit emit
```

## Multi-IDP architecture (the user's explicit question — this is the answer)

Every registered MCP server has an `auth_mode`:

| mode | when | how |
|---|---|---|
| `shared_passthrough` | backend accepts the platform IDP's token as-is | forward caller token (audience-checked) |
| `shared_exchange` | backend needs its own IDP, and the platform IDP **supports RFC 8693** | gateway performs token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`) caller-token → downstream token, cached per (sub, server) with TTL < token exp |
| `dedicated_port` | backend needs its own IDP and **no token exchange is available** | that server gets its **own listener port**; that port publishes its own RFC 9728 protected-resource metadata + RFC 8414 AS metadata pointing at *that server's* IDP. The client does a normal PKCE flow against that IDP. The shared port is unaffected. |

`dedicated_port` is the isolation valve: one weird IDP never degrades auth for every other
MCP server on the shared port.

**Which entity owns the port — resolved, after two components implemented this
differently.** `auth_mode` is per **server** (it describes how *this* backend is
reached). The `dedicated_port` itself is per **IDP**, because the port's entire
job is to publish one IDP's RFC 9728 + RFC 8414 metadata. Several servers that
share an awkward IDP therefore share that IDP's listener — allocating a port per
server would stand up N identical listeners advertising identical metadata.

So: `servers.auth_mode` + `servers.idp_id`; `idp_configs.dedicated_port`. A server
with `auth_mode = dedicated_port` is reached on the port belonging to its IDP.
Ports are allocated from a configured range (`listeners.dedicated_range =
9000..9100`) and recorded on the **IDP** row, not the server row. Provisioning is
keyed by IDP, and must register the allocation with the platform *before* opening
and routing the port — the reverse order leaves a port listening on 0.0.0.0,
routed to the gateway, that the registry has no record of.
All three modes go through the **same** `invoke` choke point — only identity resolution and
credential injection differ.

IDP configuration is settable **two ways**, both landing in the same
`config::IdpConfig` struct:
- at install time (`ansible-playbook … -e @idp.yml`, or the interactive installer), and
- at runtime via `POST /api/v1/admin/idps` (super-admin only), persisted to Postgres.
Runtime config wins; if the DB is unreachable at startup, boot from the file config; if
neither is present, **refuse to start** (fail-closed).

## UI direction (component 5)

Server-rendered askama templates, progressive enhancement, no SPA, no build step.
**No neon, no glow, no gradients.** Restrained: one neutral gray scale, one accent hue,
system font stack, 4px spacing grid, borders over shadows. Four personas, one nav that
filters by role: super-admin, server owner/admin, security team, employee.
Light + dark via `prefers-color-scheme` with CSS custom properties. WCAG AA contrast.

## Policy evaluation: compiled entrypoints + a decision cache

Rego evaluation is the hot path's dominant cost and needs three things, in order
of how much they buy:

1. **Never call `eval_query`/`eval_bool_query` per request.** Both re-parse the
   query string and rerun `prepare_for_eval` on every call — ~930µs for the real
   436-line `authz.rego`. Use `Engine::compile_with_entrypoint(...)` once at
   bundle load and `CompiledPolicy::eval_with_input(&self, input)` per request
   (~312µs, and `&self` means no mutable state to synchronize).
2. **Only evaluate `reasons` on a deny.** Reasons exist for the audit record;
   `allow` implies `count(deny) == 0`, so the second query is pure waste on the
   hot path.
3. **Cache the decision.** Rego evaluation is a pure deterministic function, so
   memoizing it changes no semantics. The cache key is the whole security
   argument and must be derived **from the input value handed to regorus**, plus
   the bundle generation and data generation — never from a hand-maintained list
   of fields, because any omitted field means two materially different requests
   share a verdict. Generation-scoping makes a reload's prior entries
   structurally unreachable rather than merely stale. Cap with a short TTL (5s)
   so any wall-clock-dependent rule can't be pinned, never cache an `Err` or a
   fallback-path decision, and bound the size.

### Anomaly evaluation is a separate prepared entrypoint (regorus limitation)

`anomaly.rego` is compiled as its **own** prepared entrypoint and evaluated
directly against the same unmodified `input`, then merged:
`allow = authz_allow && anomaly_reasons.is_empty()`.

It is NOT reached through `authz.rego` via `with input as {...}`, and must not be.
Root cause: regorus's `Interpreter::apply_with_modifiers` does
`self.data = self.with_document["data"].clone()` on entering **any** `with` scope —
even one that only overrides `input` and never touches `data`. Under the unprepared
`eval_query` API that is harmless. Under the prepared
`compile_with_entrypoint`/`eval_with_input` path (the ~3x faster one we rely on),
any rule whose value is a composite type — array or set, including a plain static
literal — evaluated inside that reset scope fails with
`"previous value is not an object"`. It fires on **every** input, including a benign
one, so loading such a bundle denies 100% of traffic.

This is an upstream limitation, not a bundle mistake. Reproduces in ~15 lines.

### Decision cache: authz only, anomaly always fresh

The cache key is derived from the canonical input **minus `recent_calls` and
`window_seconds`**, plus the bundle and data generations. `anomaly.rego` is
evaluated fresh on every call and never cached.

Those two exclusions are safe only because `authz.rego` does not reference either
field — a structural fact (one module reads them, and it is not the cached one),
not a heuristic. **If a future `authz.rego` rule reads `recent_calls`, the exclusion
becomes a correctness bug**, so that absence should be asserted by a test, not
assumed.

Why this is safe where an earlier design was not: a rejected proposal tried to
partition individual deny rules *within* one module by "does it reference
`input.params`" — a criterion that proved incomplete (it missed `recent_calls`) and
would have served stale anomaly verdicts. This splits along an existing module
boundary instead, and anomaly is never cached **at all** rather than cached under a
different key, so staleness is unreachable by construction.

Without the split, `recent_calls` changes on every call (each invocation appends to
the window), so a whole-input key can essentially never hit and throughput collapses
to the cold floor.

### Role ceilings apply to BOTH role sources

`IdpConfig.max_assertable_role` must be enforced on the claim-derived path *and* the
DB-derived path. This was originally missed: the authenticator discarded the
ceiling-checked roles from `resolve()` and rebuilt them from a bare
`SELECT ... FROM role_grants`, so the ceiling was dead code on the only path that
mattered and the escalation simply moved from "forge a role claim" to "insert a
grant row". Both paths now share one rank comparison (`role_exceeds_ceiling`) so they
cannot drift, and `grant_role` rejects any issuer that is not a configured IDP.

Enforcement is at **read** time, on every authenticated request — which also means
lowering a ceiling takes effect immediately rather than waiting for grants to be
rewritten.

### Audit: what the ledger records when the caller is denied

If the audit ack times out, the caller is denied **but dispatch already happened**.
The `allow` row stays, and is marked (`response_delivered: false`) rather than
suppressed or rewritten.

The row is factually true: the authorization decision was allow and the backend
really executed, with whatever side effects that implies. What diverges is the
*client's* view, not the ledger's. Deleting the record would make an append-only
compliance ledger claim a real side effect never occurred — the worst answer for
anyone reconstructing "did this tool actually run against production?".

Related ordering rule: **nothing is published to redis or stdout until it is durable
in Postgres.** Postgres is the ledger of record; the streams are derived SIEM
transport. Publishing first meant a failed insert left phantom `"outcome":"allow"`
events for callers who were denied, and the retried batch reissued the same
`chain_seq` with different hashes — a state Postgres forbids via
`UNIQUE (chain_id, chain_seq)`, and indistinguishable from tampering to a stream
consumer.

### Measured reality, and the open risk

**`rs/PERFORMANCE.md` is the canonical record — do not quote numbers from this
file.** It tags every figure as reproduced-with-artifact vs reported-without, and
`make perf-check` re-measures on any machine (and refuses to print a verdict when
the box is too loaded or the build isn't optimized).

Indicative only, on a 6-physical-core dev box. Later runs measured the hit/miss
pair at ~5.7µs/~317µs and the 12-thread figures across 430k–710k/s hot and
6.8k–10.3k/s cold — i.e. the absolutes moved by 2x between runs with no code
change, which is itself the point:

| | indicative |
|---|---|
| cache hit | ~6-20µs |
| cache miss (the floor) | ~320-790µs |
| hit:miss ratio | ~40-56x ← the portable signal |
| 12-thread throughput, cache hot | ~430-710k decisions/s |
| 12-thread throughput, cache cold | ~7-10k decisions/s |

Two hypotheses about that floor were tested and **both were wrong**:
`Engine` construction per call is cheap by design (empty-container defaults plus
`Rc`/`Arc` refcount bumps — and `new_from_compiled_policy` is `pub(crate)`, so it
can't be hoisted anyway), and the `serde_json → regorus::Value` conversion is
**~2%** of the cost (~17µs of ~790µs). The remaining ~770µs is genuine interpreted
Rego tree-walking over this ~180-line policy. There is no further optimization
reachable through regorus's public API.

**The open risk this leaves.** Throughput is now a function of cache hit rate, and
the hit rate depends on traffic shape, because the cache key must include `params`
(deny rules inspect params for injection patterns, so params are part of the
security argument). Identical-repeat traffic caches beautifully; same-tool-
different-args traffic — a search with a new query, a read with a new path — misses
every time. Real agent traffic skews toward the latter, so the **~7.7k/s cold floor
is the number to plan against, not the 430k/s hot figure**, until measured against
real traffic on real hardware.

A two-tier split (caching params-independent deny rules separately) was designed,
measured, and **rejected**: correctly scoped it saves only ~45%, because the cost is
per-call fixed overhead rather than rule count. It also proved unsafe as first
specified — `input.recent_calls` (the anomaly sliding window) is just as per-call
varying as `params`, so a partition keyed on "references `input.params`" would have
cached stale anomaly verdicts.

If the cold floor proves insufficient against real traffic, the remaining levers are,
in order of cost: shrink what `authz.rego` evaluates per call; fork regorus to reuse
an `Interpreter` across calls; or compile the policy to native code instead of
interpreting it. Do not reach for any of them before component 6 measures a real
deployment on real hardware.

## Self-service: grants ∧ profiles

`profiles` is a principal's own per-MCP narrowing on top of `grants`. The two
compose as an AND and the direction is not symmetric:

- **`grants`** (and the SuperAdmin branch) decide what a principal is entitled
  to at all. Only an admin flow writes these.
- **`profiles`** may only ever NARROW that set — disable an MCP, or restrict
  which of its functions are reachable. A profile row **cannot** grant access
  `grants` did not already allow, because it is applied as a *filter over the
  granted set*, never as an alternative source of entitlement.

It is enforced inside `EntitlementStore::list_visible` — deliberately, because
that is the single method both `tools/list` and `invoke`'s entitlement gate
call. A profile exclusion therefore narrows discovery and invocation *together*
and cannot drift. Adding it as a separate gate would have created a second
enforcement path, which invariant 2 forbids, and would have allowed a tool to be
hidden from discovery while still invocable.

Fail-closed: a profiles lookup failure denies. It never degrades to "no profile
found, allow everything". Migration 0013 created the table without granting the
least-privilege runtime role on it, and this property is what surfaced the
omission immediately (every request denied with `dependency_unavailable`) rather
than silently widening access — fixed in 0014. **Every new table needs its
grants in the same migration that creates it**; `mcphubd` connects as a
non-owner role by design, so an ungranted table is invisible to it.

### Self-lockout

`repo::profiles` refuses to disable the self-service MCP in your own profile,
and `disable_function` refuses to narrow your own recovery functions out of it.
The guard lives in the **repo layer**, not at the callers, for the reason the
Python platform documented: many call sites route through one function, so
guarding each caller leaves the next one unprotected.

## Backend dispatch contract

Every backend MCP server the gateway calls receives this, and every future
backend inherits it.

**Body — a real MCP JSON-RPC `tools/call` request, never bare arguments:**

```json
{"jsonrpc":"2.0","id":"<request_id>","method":"tools/call",
 "params":{"name":"<tool>","arguments":<caller params>}}
```

Backends *speak MCP* — they are FastMCP apps, including everything the SDK
scaffolder generates — so a bare arguments object is a protocol none of them
implement. This also makes multi-tool backends work: the tool name travels in
`params.name`, where the spec says it lives, so a server with N tools under one
`server_id` can route. It is deliberately NOT a side-channel header; a header
naming the method alongside an MCP-shaped body would be two sources of truth for
one fact, free to disagree. `request_id` doubles as the JSON-RPC `id` so a
backend's logs correlate with our audit record.

**Identity — gateway-set headers, matching what `mcphub-sdk` already reads:**

| header | contents |
|---|---|
| `X-User-Sub` | the resolved subject |
| `X-User-Role` | highest-rank role (compat shim for the Python single-role model) |
| `X-User-Roles` | `role@issuer` pairs, comma-separated |

Two rules, both non-negotiable:

1. **The gateway strips any inbound copy of these headers before setting its
   own** — strip first, then set, never merge. If a client can send
   `X-User-Sub: someone-else` and have it survive, that is identity spoofing
   against every backend at once. Today this is structurally guaranteed as well:
   the header map handed to the dispatcher originates from
   `CredentialBroker::inject`, a fresh map, so client headers never reach it.
   The explicit strip stays as defence in depth against that ever changing.
2. **Roles carry provenance.** `X-User-Roles` sends `(role, asserted_by)` pairs,
   never bare names. A backend receiving `admin` with no idea which IDP vouched
   for it reproduces the cross-IDP escalation described under "Core types" — one
   layer further out, where the gateway can no longer help.

**Credentials are keyed per (principal, server, tool).** `CredentialSource::lookup`
uses the tool name as the credential `purpose`, and the AAD binds the ciphertext
to that triple. Note the consequence: an absent credential row is a hard **deny**,
not "this tool needs no credential" — so every invocable tool needs a row, even a
placeholder. `cargo run -p mcphub-creds --example seal` writes one.

## Credential AAD — a requirement on future service-account support

Credential ciphertexts bind AAD over `(principal_id, server_id, purpose)`, matching
the `credentials` uniqueness constraint. That is sufficient **today** only because
service-account credentials are not yet modelled.

The Python original distinguished `owner_type='user'` from `owner_type='service'`,
where service rows used a `__service__` sentinel plus `tool_id` while user rows used
the real sub — two ownership models sharing one lookup shape. If service credentials
are added and both kinds can land on the same `(principal_id, server_id, purpose)`
triple, the AAD stops distinguishing them and **a ciphertext becomes replayable
across owner types**.

Requirement for whoever adds them: encode ownership into `principal_id` itself at
write time — store the literal `user:<sub>` or `service:<tool_id>`. Both the
uniqueness constraint and the AAD then stay correct with no schema or crypto change.
Do not add a fourth AAD field later and assume old ciphertexts re-bind; they won't.

## Performance budget (component 6 verifies)

3000 concurrent agent clients, steady-state `tools/call`. Targets, measured at the gateway,
excluding backend time:
- p50 ≤ 3 ms, p99 ≤ 15 ms, p99.9 ≤ 50 ms added latency
- ≥ 20 000 req/s sustained on 8 cores
- zero allocations in the deny-fast-path beyond the audit record
- memory steady-state < 512 MB RSS

## Ground rules for builders

- Every crate compiles on its own (`cargo check -p <crate>`) and has at least one real test
  that fails if the invariant it guards breaks. No `todo!()`, no `unimplemented!()`.
- No `unwrap()`/`expect()` outside tests and `main()` startup.
- `#![forbid(unsafe_code)]` at the top of every lib.
- Do not create files outside your component's directories listed above.
