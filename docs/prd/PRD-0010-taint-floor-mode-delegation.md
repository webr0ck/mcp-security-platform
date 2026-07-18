# PRD-0010 — Taint-Floor Enforcement Modes + Delegated Configuration

- **Status:** Phase 0 SHIPPED 2026-07-18 (minimal notify-only change, implemented directly by
  the product owner outside this document). Phase 1+ below is DESIGN v1 — architecture only,
  no implementation yet. This PRD is the "why we need this and how it should be built" record
  for the full roadmap; do not infer that Phase 1+ is live from the fact that Phase 0 shipped.
- **Date:** 2026-07-18
- **Author:** system-architect (design task)
- **Depends on:** RFC-0001 §8.1 (B-coarse taint floor), PRD-0001 M2 (binary integrity /
  taint-floor enforcement, `TAINT_FLOOR_ENABLED`), PRD-0001 M3 (`TRUST_ENVELOPE_ENABLED`,
  independent — not assumed co-enabled anywhere in this design).
- **Scope:** (a) **Phase 0 (shipped today, MVP):** the taint floor's deny path becomes
  notify-only, platform-wide, no configuration surface. (b) **Phase 1+ (roadmap, this PRD's
  main deliverable):** three enforcement modes — `enabled` / `disabled` / `disclaimer` — for
  the taint floor, configurable now per-profile, with the full schema/API shape for tenant-
  and user-granularity configuration plus an admin delegation ladder, specified now but gated
  off until implemented.
- **Non-goals:** changing the binary-integrity collapse itself (`binary_integrity()`,
  `_TRUSTED_FLOOR_RANK`), changing `result_taints_session`/tracking semantics, a generic
  platform-wide settings KV store (this follows the existing per-purpose-table convention).

## 0a. Phase 0 — shipped 2026-07-18 (current actual state)

**What changed today (implemented separately/minimally by the product owner, described here
for continuity with the roadmap below — this section documents, it does not prescribe code):**
the taint floor's Step 1.6 gate in `invocation.py` stops denying. A call is **always allowed**
regardless of taint state. In place of the deny, the response carries a disclaimer/flag
whenever either of these is true for this call:

- the session was **already tainted** before this call (`is_tainted_for_principal` — prior
  ingestion of an untrusted result earlier in the session), **or**
- **this call's own result** came from an untrusted source, i.e. `binary_integrity(trust_tier)
  == 0` for the server just invoked (`trust_tier < 2` — untrustedPublic/trustedPublic).

**Scope:** platform-wide, single behavior, not configurable per profile/user/tenant. No mode
switch, no delegation, no admin panel surface. This is the degenerate case of Phase 1's
`disclaimer` mode, applied unconditionally everywhere `TAINT_FLOOR_ENABLED` would previously
have gated a deny.

**Why:** same-day MVP requirement from the product owner — ship *something* observable today
(callers/agents can see they're operating on untrusted data) without waiting for the full
configurable-mode + delegation design below.

**What this replaces:** the pre-Phase-0 behavior described in §0b — a hard deny
(`TaintFloorDenyError`, JSON-RPC `-32003`) on any `required_integrity >= 1` sink in a tainted
session.

**⚠️ Known, accepted gap — read before treating Phase 0 as secure-by-default:** Phase 0's
"never deny, always allow" is unconditional. It does **not** carve out an exception for the
credential-injection case that §1 SI-1/INV-016 below treats as non-negotiable in the target
design — because INV-016 doesn't exist in the codebase yet; it is a Phase 1+ invariant this PRD
is proposing, not one being retrofitted onto Phase 0. Concretely: today, a tainted session
calling a credential-injecting tool **succeeds** where it previously would have been denied
(if `TAINT_FLOOR_ENABLED` was ever turned on anywhere) — the platform's most serious taint-floor
protection is currently off, platform-wide, with only an unsigned disclaimer flag as a
compensating control. This is called out again as risk callout #1 in §9. Recommendation: treat
Phase 0 as a time-boxed exception and prioritize Phase 1 (§8) promptly — Phase 1's
implementation must fold INV-016 in as a replacement for Phase 0's blanket allow, not layer on
top of it, since Phase 0 and Phase 1 will otherwise both be touching the same Step 1.6 block.

**Response shape:** reuses the same flat, unsigned `meta` dict `trust_tier`/`sensitivity_label`
already live in (see §0b) — Phase 1 §6's `meta.taint_disclaimer` shape is designed to be exactly
what Phase 0 already emits today in simplified form, so Phase 1 does not need a response-shape
migration, only added configurability of *whether* it fires.

## 0b. Background — behavior before Phase 0 (superseded today, kept for context)

Before Phase 0, `taint_floor.py` was pure/deterministic; `taint_store.py` was a fail-closed
Redis bit keyed on `client_id` (LOGIC-005: identity-stable, not auth-method-stable);
`invocation.py` Step 1.6 gated every call with `required_integrity >= 1` against
`is_tainted_for_principal`, denying with `TaintFloorDenyError` when tainted; write-before-forward
marked the session tainted immediately after an untrusted result returned, before the
response-injection screen. That was a single global always-on **binary deny** gate — no way to
disable, weaken, or annotate it per caller. Phase 0 (§0a) replaces the deny with notify-only.
Phase 1+ (below) is how deny-vs-notify-vs-off becomes a real, auditable, delegatable choice
again, without regressing the parts of this design (INV-016, tracking-is-never-mode-gated) that
Phase 0's minimal patch does not implement.

## 1. Shared design invariants (Phase 1+ target state — not yet implemented)

- **SI-1 INV-016 (new, Phase 1+): the credential-injection absolute floor is never mode-gated.**
  A tainted session calling a credential-injecting tool (`effective_injection_mode(...) !=
  "none"`) is denied under **every** mode value, including `disabled`. This is evaluated
  strictly before mode is even consulted. See §9 risk callout #2 for the full rationale, and
  §0a for why this is **not** true of Phase 0 as shipped today.
- **SI-2 Tracking is never mode-gated.** `mark_tainted_for_principal` stays governed solely by
  `TAINT_FLOOR_ENABLED` (today's flag), never by the resolved taint mode. A mode only changes
  what happens when a tainted session is *evaluated*, never whether taint is *recorded*. (This
  one already holds true for Phase 0 as shipped — Phase 0 doesn't touch write-before-forward.)
- **SI-3 Fail-closed direction is `enabled`, never `disabled`/`disclaimer`.** Once Phase 1 ships
  configurable modes, any DB error, cache miss+DB error, unknown mode string, or
  scope-resolution ambiguity resolves to `"enabled"` — the safe default *at that point*. Unlike
  `_lookup_profile_with_cache`'s INV-015 (fails the whole request, 503), this fails toward a
  *usable* safe value, so the request completes normally under `enabled` semantics rather than
  erroring. Not applicable to Phase 0 (no modes exist yet to fail between).
- **SI-4 Admin-gated + audited.** Every mutation (mode, granularity, delegation grant/revoke)
  requires `platform_admin` at minimum (Phase 1: **only** `platform_admin`, no delegation
  exists yet) and calls `services/admin_audit.py::emit_admin_config_event` — the existing
  convention (`admin_llm.py`, `admin_limits.py`, `admin_prompts.py`, `admin_git.py`), not a
  bespoke audit path.
- **SI-5 Schema-complete now, API-gated later.** All three scope types (`tenant`, `user`,
  `profile`) and the full delegation shape exist in the **single** migration that ships with
  Phase 1. Phase 2 adds routers and authorization logic against that same schema — **no
  second migration, no column/table rewrite.**
- **SI-6 Tenant scope is never delegatable.** `taint_mode_delegations.scope_type` CHECK
  constraint permits only `'user'` and `'profile'` — never `'tenant'`. An admin may set the
  tenant-wide default directly; that specific power can never be handed to a delegate.
- **SI-7 Granularity selection is permanently non-delegatable.**
  `taint_mode_delegations.capability` CHECK constraint permits only `'set_mode'`. The column
  is shaped to allow a future `'set_granularity'` value without a migration, but the API layer
  will reject any attempt to grant it — see §9 for why this is a deliberate, permanent
  tightening of the PRD ask, not an oversight.

## 2. Data model (Phase 1+ roadmap — no migration exists yet)

One migration, `infra/db/migrations/V078__taint_mode_governance.sql` (next free number as of
2026-07-18; verify against `ls infra/db/migrations` before actually cutting it, since Phase 0's
own change may or may not need a migration of its own — check with the product owner):

```sql
-- V078__taint_mode_governance.sql
-- Taint-floor enforcement MODE + GRANULARITY + delegation (PRD-0010 Phase 1+; RFC-0001 §8.1;
-- PRD-0001 M2 follow-on). Schema ships complete (all 3 scope types); Phase 1 wires
-- only the profile-scope API surface (SI-5). See docs/prd/PRD-0010-taint-floor-mode-delegation.md.

-- 1. Platform-wide granularity governance (singleton). Admin/platform_admin write-only,
--    NEVER delegatable (SI-7). Phase 1 ships this fixed at 'profile' with a read-only GET;
--    the PUT router lands in Phase 2.
CREATE TABLE IF NOT EXISTS taint_governance (
    id                  SMALLINT    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    active_granularity  TEXT        NOT NULL DEFAULT 'profile'
                                     CHECK (active_granularity IN ('tenant', 'user', 'profile')),
    updated_by          TEXT        NOT NULL DEFAULT 'system',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO taint_governance (id, active_granularity, updated_by)
    VALUES (1, 'profile', 'system')
    ON CONFLICT (id) DO NOTHING;

-- 2. Per-scope taint-mode configuration. Absence of a row for a scope = 'enabled'
--    (the Phase 1 target default — see SI-3), same absence-means-default convention as
--    mcp_profiles / wizard_prompts / client_limits.
CREATE TABLE IF NOT EXISTS taint_mode_config (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_type      TEXT        NOT NULL CHECK (scope_type IN ('tenant', 'user', 'profile')),
    profile_uuid    UUID        REFERENCES profiles(id) ON DELETE CASCADE,
    user_client_id  TEXT,       -- same logical identity key as taint_store.py's client_id
    mode            TEXT        NOT NULL DEFAULT 'enabled'
                                 CHECK (mode IN ('enabled', 'disabled', 'disclaimer')),
    updated_by      TEXT        NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT taint_mode_config_scope_shape CHECK (
        (scope_type = 'tenant'  AND profile_uuid IS NULL     AND user_client_id IS NULL) OR
        (scope_type = 'user'    AND profile_uuid IS NULL     AND user_client_id IS NOT NULL) OR
        (scope_type = 'profile' AND profile_uuid IS NOT NULL AND user_client_id IS NULL)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_taint_mode_config_tenant_singleton
    ON taint_mode_config ((scope_type)) WHERE scope_type = 'tenant';
CREATE UNIQUE INDEX IF NOT EXISTS idx_taint_mode_config_user
    ON taint_mode_config (user_client_id) WHERE scope_type = 'user';
CREATE UNIQUE INDEX IF NOT EXISTS idx_taint_mode_config_profile
    ON taint_mode_config (profile_uuid) WHERE scope_type = 'profile';

-- 3. Delegation grants. Append-only (INV-011 style), mirrors role_assignments
--    (V050__role_assignments_append_only_revoke.sql): grant = INSERT active row,
--    revoke = INSERT tombstone row (revoked=true), never UPDATE/DELETE the original.
--    'tenant' excluded from scope_type by design (SI-6); 'set_granularity' excluded
--    from capability by design (SI-7).
CREATE TABLE IF NOT EXISTS taint_mode_delegations (
    event_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_type          TEXT        NOT NULL CHECK (scope_type IN ('user', 'profile')),
    profile_uuid         UUID        REFERENCES profiles(id) ON DELETE CASCADE,
    user_client_id        TEXT,
    delegate_client_id     TEXT        NOT NULL,
    capability              TEXT        NOT NULL DEFAULT 'set_mode' CHECK (capability IN ('set_mode')),
    granted_by               TEXT        NOT NULL,
    revoked                    BOOLEAN     NOT NULL DEFAULT false,
    revoked_by                  TEXT,
    expires_at                    TIMESTAMPTZ,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT taint_mode_deleg_scope_shape CHECK (
        (scope_type = 'user'    AND profile_uuid IS NULL     AND user_client_id IS NOT NULL) OR
        (scope_type = 'profile' AND profile_uuid IS NOT NULL AND user_client_id IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_taint_deleg_profile  ON taint_mode_delegations (profile_uuid, revoked);
CREATE INDEX IF NOT EXISTS idx_taint_deleg_user      ON taint_mode_delegations (user_client_id, revoked);
CREATE INDEX IF NOT EXISTS idx_taint_deleg_delegate ON taint_mode_delegations (delegate_client_id, revoked);

-- INV-011: explicit GRANT/REVOKE, append-only enforced at the DB role level (not just app logic).
GRANT SELECT, INSERT, UPDATE ON taint_governance TO proxy_app;
REVOKE TRUNCATE, DELETE ON taint_governance FROM proxy_app;
GRANT SELECT, INSERT, UPDATE ON taint_mode_config TO proxy_app;
REVOKE TRUNCATE, DELETE ON taint_mode_config FROM proxy_app;
GRANT SELECT, INSERT ON taint_mode_delegations TO proxy_app;
REVOKE UPDATE, DELETE, TRUNCATE ON taint_mode_delegations FROM proxy_app;

COMMENT ON TABLE taint_governance IS
    'Singleton: which scope granularity is the active taint-mode configuration surface. '
    'Admin/platform_admin write-only, permanently non-delegatable (PRD-0010 SI-7).';
COMMENT ON TABLE taint_mode_config IS
    'Per-scope taint-floor enforcement mode. Absent row for a scope = enabled (Phase 1 '
    'target default). Never overrides INV-016.';
COMMENT ON TABLE taint_mode_delegations IS
    'Append-only set_mode delegation grants. Never UPDATE/DELETE — revoke is a tombstone '
    'INSERT (revoked=true). scope_type excludes tenant by design (SI-6).';
```

Resolution precedence (most specific wins), implemented in a new pure-ish resolver
`proxy/app/services/taint_mode.py::resolve_taint_mode()`:

1. `taint_mode_config` row where `scope_type='profile'` and `profile_uuid` = the caller's
   session-bound named profile (if any) — reuses the `profile_uuid` local variable
   `invocation.py` already resolves earlier in the request (used today at the
   `_lookup_profile_with_cache(..., profile_uuid=profile_uuid)` call, before Step 1.5).
2. Else `taint_mode_config` row where `scope_type='user'` and `user_client_id` = `client_id`.
3. Else `taint_mode_config` row where `scope_type='tenant'` (singleton).
4. Else `"enabled"` (hardcoded terminal default).

Cached with the same 30s-TTL config-cache convention as `llm_config.py`/`prompt_store.py`
(bounds the DB read on the hot invocation path); a cache-miss + DB-error resolves to
`"enabled"` per SI-3 rather than serving stale data or raising.

```python
# Design sketch (not implementation) — proxy/app/services/taint_mode.py
async def resolve_taint_mode(*, client_id: str | None, profile_uuid: str | None) -> str:
    """Resolve the effective taint-floor mode for this call. NEVER raises.

    Fail-closed direction is 'enabled' (SI-3) — the caller can always trust the
    return value is a valid mode string and can proceed without a try/except.
    Precedence: profile > user > tenant > 'enabled'. See PRD-0010 §2.
    """
```

## 3. API surface (Phase 1+ roadmap)

Conventions match this repo's routers as observed (`server_registry.py`, `admin_grants.py`,
`admin_llm.py`): `HTTPException(status_code=..., detail=...)` for errors,
`JSONResponse({...})` for success, `_require_platform_admin` / role-check helpers at the top
of each handler, admin routes under `/api/v1/admin/...`.

**New router `proxy/app/routers/taint_mode.py`:**

| Method | Path | Auth (Phase 1) | Auth (Phase 2 adds) | Notes |
|---|---|---|---|---|
| `GET` | `/api/v1/admin/taint-mode/governance` | `admin`/`platform_admin`/`auditor` (read) | unchanged | Returns `{active_granularity: "profile"}`. |
| `PUT` | `/api/v1/admin/taint-mode/governance` | **501** (not implemented in Phase 1 — the endpoint exists and returns a structured "roadmap" error, not a 404, so clients can detect the capability rather than guess) | `platform_admin` only, never delegatable (SI-7) | Body `{"granularity": "tenant"\|"user"\|"profile"}`. |
| `GET` | `/api/v1/admin/taint-mode/config` | `admin`/`platform_admin`/`auditor` (read); optional `?scope_type=&scope_id=` filter | unchanged | Lists all configured scopes (not the resolved default — explicit rows only). |
| `GET` | `/api/v1/admin/taint-mode/config/profile/{profile_uuid}` | same as above | unchanged | Single-scope read; 404 shape = `{mode: "enabled", explicit: false}` (no row = default, not an error). |
| `PUT` | `/api/v1/admin/taint-mode/config/profile/{profile_uuid}` | `platform_admin` only | `platform_admin` **OR** an active `set_mode` delegate for that `profile_uuid` (§4) | Body `{"mode": "enabled"\|"disabled"\|"disclaimer"}`. Audited via `emit_admin_config_event(action="set_taint_mode", ...)` **and** a raw `audit_events` insert with `event_type='TAINT_MODE_CHANGED'` (mirrors `SERVER_TRUST_TIER_CHANGED` — this is a security-relevant escalation/de-escalation, so it belongs in the same queryable audit stream server-trust changes do, not only the generic admin log). |
| `PUT` | `/api/v1/admin/taint-mode/config/user/{client_id}` | **501** in Phase 1 | `platform_admin` **OR** active delegate | Schema-ready, gated off (SI-5). |
| `PUT` | `/api/v1/admin/taint-mode/config/tenant` | **501** in Phase 1 | `platform_admin` only — never delegatable (SI-6) | Schema-ready, gated off. |
| `GET` | `/api/v1/admin/taint-mode/delegations` | **501** in Phase 1 | `admin`/`platform_admin`/`auditor` | Lists active (non-revoked, non-expired) grants. |
| `POST` | `/api/v1/admin/taint-mode/delegations` | **501** in Phase 1 | `platform_admin` only | Body `{"scope_type": "profile"\|"user", "scope_id": "...", "delegate_client_id": "...", "expires_at": null}`. `capability` is not a request field — always `'set_mode'` (SI-7); rejects `scope_type='tenant'` with 422 (SI-6, belt-and-braces on top of the DB CHECK). |
| `DELETE` | `/api/v1/admin/taint-mode/delegations/{event_id}` | **501** in Phase 1 | `platform_admin` only | Inserts a tombstone row (`revoked=true`), same convention as `DELETE /api/v1/admin/roles/{client_id}/{role}` in `admin_grants.py` — the HTTP verb is DELETE, the DB operation is an INSERT. |

**New self-service read, alongside the existing named-profile endpoints in
`proxy/app/routers/profiles.py`:**

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/v1/profiles/named/{name}/taint-mode` | same read-check as the existing `GET /api/v1/profiles/named/{name}` | Returns the *resolved* effective mode for that profile (not raw config rows) — low-sensitivity transparency, not a security boundary, so no admin gate. |

Why a 501 rather than simply not registering the route in Phase 1: a client (or `qa-engineer`,
or the admin panel) probing capability should get a structured, documented "not yet" rather
than an ambiguous 404 that's indistinguishable from a typo'd path. `detail` on the 501 body
points at this PRD's phase table.

## 4. Delegation model (designed now, phased to Phase 2 — SI-5)

**Who can grant/revoke:** `platform_admin` **only** — not plain `admin`. This follows the
IDOR-005 precedent already established in this codebase
(`profiles.py::_CROSS_PROFILE_WRITE_ROLES`): any write that reaches into *another principal's*
state, or in this case *hands another principal a new capability over a security control*, is
narrowed to the specifically-provisioned `platform_admin` role rather than the broader
KC-issued `admin` alias. Same rationale, same narrowing.

**What is delegated:** exactly one capability, `set_mode`, scoped to exactly one `(scope_type,
scope_id)` pair — either a specific `profile_uuid` or a specific `user_client_id`. A delegate
can set the mode for *that scope only*; they cannot grant further delegations (no re-delegation
— `taint_mode_delegations` has no "can this delegate also grant" column, deliberately), cannot
change granularity, and cannot touch tenant scope.

**Default on a fresh install:** `taint_mode_delegations` is empty. `taint_governance` seeds to
`active_granularity='profile'`. Every `taint_mode_config` scope is absent → resolves to
`"enabled"` everywhere. So a fresh install is "only Admin can set anything" by construction —
there is no delegate until a `platform_admin` explicitly `POST`s one, and Phase 1 doesn't even
expose that endpoint yet (it 501s), so a fresh Phase-1 install is *stricter* than the PRD's own
"most restrictive default" ask: nobody but `platform_admin` can change taint mode at all until
Phase 2 ships.

**How it's audited:** every grant/revoke calls `emit_admin_config_event(actor, action=
"grant_taint_delegation"|"revoke_taint_delegation", client_id=<delegate_client_id>, details=
{scope_type, scope_id, capability, expires_at})`, in addition to the append-only
`taint_mode_delegations` row itself serving as the durable state/history (same dual-recording
`update_server`'s `SERVER_TRUST_TIER_CHANGED` insert already does alongside the state UPDATE).

**How it interacts with the existing role vocabulary:** it deliberately does **not** reuse
`role_assignments`/`server_owner`. `server_owner` in this codebase is explicitly documented
(ARCHITECTURE.md §6.5) as "ownership is enforced per-row via `owner_sub` checks in the handler"
— i.e., it's a role *label*, not itself a grant of a specific capability over a specific
resource. Modeling taint-mode delegation as its own narrow grant table (rather than overloading
`server_owner` or minting a new platform role) keeps the blast radius of a grant exactly as
narrow as the PRD asks: one scope, one capability, one delegate, revocable independently of any
role change.

**Authorization check at the `PUT .../config/profile/{profile_uuid}` handler (Phase 2):**

```python
# Design sketch — proxy/app/routers/taint_mode.py
async def _may_set_mode(request: Request, profile_uuid: str) -> None:
    if _is_platform_admin(request):
        return
    if await _has_active_delegation(
        scope_type="profile", profile_uuid=profile_uuid,
        delegate_client_id=request.state.client_id,
    ):
        return
    raise HTTPException(status_code=403, detail="not authorized to set taint mode for this profile")
```

`_has_active_delegation` reads `taint_mode_delegations` with the same "latest event wins,
`revoked=false`, unexpired" query shape as `admin_grants.py::_ACTIVE_ROLE_ASSIGNMENTS_SQL`.

## 5. Enforcement changes (Phase 1+ roadmap — `taint_floor.py` + `invocation.py`)

**Important implementation note:** whoever picks up Phase 1 must reconcile with whatever
minimal patch Phase 0 (§0a) already landed in `invocation.py` Step 1.6 — this section's design
*replaces* Phase 0's blanket allow, it does not layer on top of it. In particular, Phase 1 is
where INV-016 (the credential-injection absolute floor) actually starts being enforced again;
until Phase 1 ships, the gap described in §0a/§9#1 remains open.

**New pure function in `taint_floor.py`** (additive — every existing function is unchanged):

```python
# Design sketch — proxy/app/services/taint_floor.py
def effective_taint_action(
    *, tainted: bool, required_integrity: int, credential_injecting: bool, mode: str,
) -> str:
    """PRD-0010 Phase 1+. Returns "allow" | "deny" | "disclaimer".

    INV-016 (credential-injection absolute floor) is evaluated FIRST and is never
    downgradeable by `mode` — this is the one branch no mode value can escape.
    """
    if tainted and credential_injecting:
        return "deny"
    if taint_floor_decision(tainted=tainted, required_integrity=required_integrity) != "deny":
        return "allow"
    if mode == "disabled":
        return "allow"
    if mode == "disclaimer":
        return "disclaimer"
    return "deny"  # mode == "enabled", or any unrecognized mode string (fail-closed)
```

**`invocation.py` Step 1.6 changes** (today's — i.e. pre-Phase-0's — block ran ~line
1145-1163; Phase 0 has already modified this block minimally; Phase 1 extends/replaces it
further):

- After computing `_required` and `_tainted`, also compute
  `_credential_injecting = _eff_injection not in _NON_INJECTING_MODES` (the same
  `_eff_injection` value already computed for `effective_required_integrity` — no new lookup)
  and `_mode = await resolve_taint_mode(client_id=client_id, profile_uuid=profile_uuid)`.
- Compute `_action = effective_taint_action(tainted=_tainted, required_integrity=_required,
  credential_injecting=_credential_injecting, mode=_mode)`.
- `_action == "deny"`: deny path, with the audit `deny_reasons` distinguishing the two cases so
  QA/appsec can assert on them independently:
  - credential-injection absolute case → `deny_reasons=["taint_floor:credential_injection_absolute"]`
  - general mode=enabled case → `deny_reasons=[f"taint_floor:required_integrity={_required}"]`
  - Both raise the **same** `TaintFloorDenyError` (no new exception type needed — the
    router-side mapping to `-32003` is identical either way, and QA only needs the audit
    `deny_reasons` tag to differentiate, not a new code path).
- `_action == "allow"`: no deny, no annotation. Stash `_taint_disclaimer = None` for the
  meta-enrichment step below.
- `_action == "disclaimer"`: no deny. Stash
  `_taint_disclaimer = {"tainted": True, "mode": "disclaimer", "would_deny_required_integrity":
  _required, "reason": "session_tainted_by_prior_untrusted_result"}`.

**Write-before-forward:** **unchanged from pre-Phase-0** — `mark_tainted_for_principal` stays
gated only on `TAINT_FLOOR_ENABLED` (SI-2). Mode is never consulted here.

**Meta enrichment (the flat `upstream_response["meta"][...]` block):** add one line:

```python
if _taint_disclaimer is not None:
    upstream_response["meta"]["taint_disclaimer"] = _taint_disclaimer
```

Placed alongside the existing `meta["trust_tier"]` / `meta["sensitivity_label"]` assignments —
using the same flat, unsigned `meta` dict those already live in (not the separate signed
`_meta[TRUST_ENVELOPE_KEY]` envelope, which is independently feature-flagged by
`TRUST_ENVELOPE_ENABLED` and must not be assumed present). Absence of `taint_disclaimer` =
nothing noteworthy — same absence-means-default convention used throughout this codebase's
config surfaces. This is the same field Phase 0 already populates today in simplified,
non-configurable form (§0a) — Phase 1 does not change the response shape, only adds
configurability of whether/when it fires.

## 6. Disclaimer-mode response shape (target shape; Phase 0 already emits a simplified version)

```json
{
  "jsonrpc": "2.0",
  "id": 42,
  "result": {
    "content": [ /* ...tool output, unmodified... */ ],
    "meta": {
      "audit_id": "b6f...",
      "latency_ms": 118,
      "trust_tier": 3,
      "server_id": "8f2a...",
      "sensitivity_label": "medium",
      "taint_disclaimer": {
        "tainted": true,
        "mode": "disclaimer",
        "would_deny_required_integrity": 1,
        "reason": "session_tainted_by_prior_untrusted_result"
      }
    }
  }
}
```

`would_deny_required_integrity` is included (not just a boolean) so a client/agent can
reason about *why* — it's the `required_integrity` value that would have triggered a deny
under `enabled` mode, letting a sophisticated caller correlate it against the tool's own
declared `required_integrity` without a second lookup. Phase 0's simplified version may omit
`would_deny_required_integrity`/`reason` and just carry a boolean-ish flag — that's an
acceptable MVP simplification; Phase 1 standardizes on this fuller shape.

## 7. Admin panel UX sketch (Phase 1+ roadmap — no admin surface ships in Phase 0)

Per PRD-0004 D-1, the canonical admin UI is the **HTMX portal**
(`proxy/app/routers/portal.py`, `fragment_admin_*` server-rendered fragments) — the React
`ui/src/components/**` tree is frozen and out of scope. This follows that convention, not the
frozen React one.

New fragment `fragment_admin_taint_mode`, nested as a sub-section of the existing **Access**
tab (`fragment_admin_access`, portal.py:4884) rather than a new top-level nav tab — same
placement rationale ARCHITECTURE.md §6.6 gives for the RBAC role-assignments panel: this is an
RBAC-adjacent control-plane surface (governs who can weaken a security control), not a
server-registry or submissions concern.

Phase 1 view (profile scope only):
- A table of profiles with an explicit `taint_mode_config` row: profile name, current mode
  (pill: green `enabled`, red `disabled`, amber `disclaimer` — reusing the existing
  `pill-approved`/`pill-pending`/`pill-quarantined` CSS class family's visual language, new
  classes `pill-taint-enabled`/`pill-taint-disabled`/`pill-taint-disclaimer`), updated-by,
  updated-at.
- A "Set mode" action per row (dropdown + confirm), `platform_admin`-gated identically to the
  existing trust-tier PATCH control on the Servers tab.
- An attention-band entry (reusing the `adm-attention` pattern already on `fragment_admin_servers`)
  surfacing any profile currently in `disabled` mode — since that's the state that silently
  removes a safety net, it deserves the same "needs your attention" visual treatment pending
  quarantine/approval items already get.

Phase 2 additions (same fragment, once granularity/delegation ship):
- A "Configuration granularity" selector (tenant/user/profile radio group), `platform_admin`
  only, with the current selection visibly locked/greyed for anyone else.
- A "Delegations" sub-table: delegate, scope, granted-by, granted-at, expires-at, revoke button
  — directly modeled on the existing RBAC role-assignments table in the same Access tab, so an
  admin reviewing "who can do what" sees both role grants and taint-mode delegations in one
  place without context-switching tabs.

## 8. Phased rollout

**Phase 0 — shipped 2026-07-18 (recap; see §0a for the full description):** notify-only,
platform-wide, no configuration, implemented directly by the product owner outside this
document. INV-016 does not apply yet (§0a/§9#1).

**Phase 1 — next, not started:**
- Migration `V078__taint_mode_governance.sql` — **all three tables, full shape**, per SI-5.
- `resolve_taint_mode()` + `effective_taint_action()` + the `invocation.py` Step 1.6 rewrite —
  fully live enforcement of `enabled`/`disabled`/`disclaimer`, but resolution only ever
  consults `scope_type='profile'` rows (governance is hardcoded to `'profile'` for now; the
  `user`/`tenant` precedence steps in `resolve_taint_mode` are implemented but structurally
  unreachable since no `user`/`tenant` row can be written yet).
- INV-016 (credential-injection absolute floor) — live from the start of Phase 1, closing the
  §0a/§9#1 gap Phase 0 deliberately accepted.
- `GET/PUT /api/v1/admin/taint-mode/config/profile/{profile_uuid}`, `GET
  /api/v1/admin/taint-mode/governance`, `GET /api/v1/profiles/named/{name}/taint-mode` —
  `platform_admin`-only writes, no delegation.
- Admin panel: profile-mode table + attention band (§7 Phase 1 view).
- New ARCHITECTURE.md §10 row: **INV-016**. (Doc update, not code — flagged for whoever
  implements, per "keep this doc matched to code.")

**Phase 2 — later, not started, schema/API shape already fixed by Phase 1 — no rewrite needed:**
- `PUT /api/v1/admin/taint-mode/governance` (granularity picker) — un-501, `platform_admin`
  only, permanently non-delegatable (SI-7).
- `PUT /api/v1/admin/taint-mode/config/user/{client_id}` and `.../config/tenant` — un-501.
- `taint_mode_delegations` grant/revoke endpoints — un-501, plus the `_may_set_mode` delegate
  check wired into the profile/user PUT handlers.
- Admin panel: granularity selector + delegations sub-table (§7 Phase 2 additions).

**Decisions locked now that Phase 1/2 must not revisit:**
- The polymorphic scope shape (`scope_type` + one nullable FK/text column per type + a shape
  CHECK) — adding a fourth scope type later is an `ALTER TABLE ... ADD COLUMN` + CHECK swap,
  not a redesign.
- `capability` as its own column, fixed to `'set_mode'` today — a real value already exists in
  the row shape if a future PRD ever wants a second delegatable capability; SI-7 is a policy
  decision enforced at the API layer, not a schema limitation, so lifting it later needs no
  migration.
- INV-016's absolute-floor placement (evaluated before mode, using the exact same
  `effective_injection_mode` the current codebase already computes for the floor bump) — Phase
  2 cannot introduce a "disabled means fully disabled" escape hatch without an explicit new PRD
  reopening this specific decision, because the resolver signature
  (`effective_taint_action(..., credential_injecting: bool, mode: str)`) makes the ordering
  structural, not incidental.

## 9. Security risk callouts

1. **[Phase 0, live now] Phase 0 removes the credential-injection absolute-deny path entirely.**
   Because Phase 0's scope is "never deny, always allow," a tainted session calling a
   credential-injecting tool succeeds today where it previously would have been denied (if
   `TAINT_FLOOR_ENABLED` was ever turned on) — there is no INV-016-equivalent carve-out in
   Phase 0, because INV-016 is a Phase 1+ target invariant, not a Phase-0 retrofit. This is a
   deliberate, PO-accepted, time-boxed MVP trade-off, not an oversight — but it should not be
   treated as a stable security posture. Recommendation: prioritize Phase 1 promptly; until
   then, this gap is the single highest-priority item this PRD identifies. (See §0a.)
2. **Does `disabled` mode (Phase 1+) weaken the credential-injection floor bump?** No — this is
   SI-1's central decision for the *target* design. INV-016 is evaluated before mode is even
   read, once Phase 1 ships. A `disabled` scope will still hard-deny a tainted session calling
   a credential-injecting tool. This was the single most important design call in the Phase 1+
   roadmap and is called out three separate times in this document (§1, §5, §8) so it cannot be
   silently dropped during implementation review.
3. **Can a compromised/over-trusted profile-owner (Phase 2) grant themselves broader
   taint-disable than intended?** No re-delegation exists (§4) — a delegate holds `set_mode`
   for exactly the one scope they were granted, cannot grant it onward, cannot touch
   governance, cannot touch tenant scope (SI-6 DB CHECK, belt-and-braces API-layer 422). The
   narrowest possible blast radius is "this one profile's mode," which is also the *existing*
   blast radius of a `disabled` misconfiguration if an admin sets it directly — delegation
   doesn't create a new risk class, it only moves *who* can trigger the existing one, under
   audit.
4. **Can `disabled` mode (Phase 1+) cause taint history to "reset" if flipped back to
   `enabled`?** No — SI-2. Tracking is unconditional on `TAINT_FLOOR_ENABLED` alone (true for
   Phase 0 too — Phase 0 does not touch write-before-forward). A session that ingested
   untrusted content while `disabled` is still correctly tainted the moment the scope flips
   back to `enabled` or `disclaimer`.
5. **Can granularity-switching (Phase 2) be used to escalate a narrow delegation?** This is why
   SI-7 makes granularity permanently non-delegatable, and why it's a *deliberate tightening*
   beyond what the PRD's literal text implied ("mode AND granularity both admin-locked" as the
   *default* reads as if both could eventually be opened up). Recommendation to the PO: keep
   this tightening — the alternative (a delegate who can also widen the configuration surface
   they were delegated *within*) is a privilege-escalation primitive with no compensating
   control, and nothing in the stated requirement actually needs granularity to be delegatable
   to satisfy "delegate the ability to change taint-mode."
6. **KC-resync-style tension with delegation revocation (Phase 2)?** Unlike `role_assignments`
   (which has the documented KC-resync-reinstates-a-revoked-role tension, ARCHITECTURE.md
   §6.6), `taint_mode_delegations` has no external identity-provider sync path — a revoke is
   final until a `platform_admin` re-grants it. No equivalent footgun exists here; noted only
   to confirm it was checked, not because a mitigation is needed.
7. **`disclaimer` mode (Phase 0 and Phase 1+) and prompt-injection risk:** the
   `taint_disclaimer` block is plain metadata, not part of `content` — it is never mixed into
   the text an LLM consumes as tool output, so it cannot itself become an injection vector. It
   is appended in the same flat `meta` dict as `trust_tier`/`sensitivity_label`, which already
   carry this property today.
