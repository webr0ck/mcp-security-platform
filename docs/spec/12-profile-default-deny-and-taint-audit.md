# 12 — Named-profile default-deny + audit taint semantics

Status: **Implemented (2026-07-18)**
Source: `docs/spec/11-server-lifecycle-and-hardening-batch.md` §1 and §7
(external acceptance run findings 1 and 7).

Proxy-side only. No `authz.rego` change was needed for either fix — both are
implemented entirely in `proxy/app/services/invocation.py` plus the audit
SDK / Wazuh syslog path for Fix 7.

## Fix 1 — Named-profile default-deny

### Problem

Named profiles (bound at OIDC login via `?profile=<name>`, see Task 4.3 /
`docs/spec/11-...md` and `proxy/tests/unit/test_named_profiles.py`) are meant
to be the access-restriction mechanism for session-bound logins. In
`invoke_tool` Step 2.5, `_lookup_profile_with_cache(client_id, tool_name,
profile_uuid=...)` queries the `mcp_profiles` table filtered by
`(profile_uuid, mcp_name)`. When no row exists for a given tool under that
profile, the function returns `None`, and the caller set
`profile_data = {}` — which OPA's `authz.rego` treats as "no restriction",
i.e. default-allow. That is the same behavior as the legacy per-identity
path (`profile_uuid is None`), which defeats the purpose of a named
profile: once an admin has started configuring one, every tool that hasn't
been explicitly bound should be denied, not silently allowed.

### Fix

A new helper, `_named_profile_has_any_binding(profile_uuid: str) -> bool`
(`proxy/app/services/invocation.py`), counts rows in `mcp_profiles WHERE
profile_uuid=:uuid` (no `mcp_name` filter — any row for the profile at
all). In Step 2.5, when `_lookup_profile_with_cache` returns `None` AND
`profile_uuid` is set:

- If the profile has **≥1 binding row anywhere** → synthesize
  `profile_data = {"enabled": False, "allowed_functions": []}` so OPA
  denies with `mcp_disabled_for_profile` (the same reason code an explicit
  `enabled=False` row would produce).
- If the profile has **zero binding rows** (freshly created, not yet
  configured) → keep `profile_data = {}` (default-allow), so a
  newly-created profile isn't bricked before an admin adds the first
  binding.

The **legacy per-identity path** (`profile_uuid is None`) is untouched —
`_named_profile_has_any_binding` is never called on that path, and the
no-row → `{}` (default-allow) behavior is unchanged.

### Fail-closed semantics

`_named_profile_has_any_binding` mirrors `_lookup_profile_with_cache`'s
fail-closed + Redis last-known-state caching discipline (Task 1.10 /
SELF-F2) — a restriction mechanism must never silently default-allow on a
DB error:

| Condition | Behavior |
|---|---|
| DB success | use the row count + write Redis cache (TTL 300s, key `mcp_profile:uuid:{profile_uuid}:__has_bindings__`) |
| DB error + cache hit | use cached bool (last-known-state) |
| DB error + cache miss | raise `ProfileLookupError` → caller converts to `OPAUnavailableError` → HTTP 503 |

This exception is caught by the *same* `except ProfileLookupError` block
that already wraps `_lookup_profile_with_cache` in Step 2.5 — no new
error-handling path was introduced.

## Fix 7 — Audit taint semantics

### Problem

The taint-floor NOTIFY-ONLY path (Phase 0, PRD-0010 — see the code comment
at `invoke_tool` Step 1.6) previously called:

```python
await _emit_audit_event(
    ...,
    outcome="allow",
    deny_reasons=[f"taint_floor_notice:required_integrity={_required}"],
    ...,
)
```

Putting advisory text in `deny_reasons` on an `outcome="allow"` event is
misleading: anything (a dashboard, a SIEM rule, a human reviewer) that
treats a non-empty `deny_reasons` as "this call was denied" would
misclassify the event.

### Fix

- **`observability/mcp-audit-logger/mcp_audit_logger/schema.py`** —
  `AuditEvent` gets a new field, `notices: list[str] = field(default_factory=list)`.
  Default empty list — fully backward compatible with every existing
  caller. Included in `to_dict()`, so it flows into the stdout structured
  JSON log line (the stable SIEM integration seam per `CLAUDE.md`).
- **`proxy/app/services/invocation.py`** — `_emit_audit_event` gains an
  optional `notices: list[str] | None = None` parameter, passed through to
  `AuditEvent(..., notices=notices or [])`. The taint notify-only call site
  now passes `deny_reasons=[]` and `notices=["taint_floor_notice:required_integrity=N"]`.
  Verified (source-level regression test) that no other `outcome="allow"`
  call site in the file passes a non-empty literal `deny_reasons`.
- **`proxy/app/services/wazuh_syslog.py`** — `emit()` gains an optional
  `notices: list[str] | None = None` parameter; included in the JSON
  payload under a `notices` key (separate from `deny_reasons`) when
  non-empty.

### Adjacent bug fixed while wiring this

The Wazuh syslog secondary-path call site in `_emit_audit_event` was
passing `principal_id=principal_id` to `wazuh_syslog.emit()`, but `emit()`
never declared that parameter. Every call raised `TypeError`, silently
swallowed by the wrapping `except Exception: pass` (by design — the
secondary path must never affect INV-001) — meaning the Wazuh syslog path
has been fully non-functional (zero events reaching Wazuh) since
`principal_id` was added at that call site. Removed the stray kwarg as
part of this change so the path (and the new `notices` plumbing) actually
executes. No `emit()` signature change was needed for `principal_id`
itself since it was never part of the documented Wazuh payload contract.

### Scope note: not persisted to PostgreSQL

`notices` is **not** added to the `audit_events` table / INSERT in this
change — that's a DB-engineer-owned migration, out of this workstream's
file ownership, and the spec text ("audit SDK + SIEM/wazuh path") did not
require it. Today `notices` is visible in: the stdout structured audit log
line, and the Wazuh syslog UDP payload. It is **not** queryable via the
compliance API / `audit_events` table or any UI built on top of it. If
that's needed, a follow-up migration (`ALTER TABLE audit_events ADD COLUMN
notices JSONB`) plus a wiring change in the `_emit_audit_event` INSERT
block would be required.

## Testing

- `proxy/tests/unit/services/test_invocation_profile_default_deny.py` —
  named profile w/ bindings denies an unbound tool; named profile w/ zero
  bindings still allows; legacy path never calls the new helper;
  DB-error-no-cache → 503; plus direct cache/DB-tier tests for
  `_named_profile_has_any_binding`.
- `proxy/tests/unit/services/test_invocation_taint_notices.py` — `notices`
  plumbed to `AuditEvent` and Wazuh syslog with `deny_reasons` left
  untouched; the taint notify-only call site emits `deny_reasons=[]` +
  the notice in `notices` end-to-end through `invoke_tool`; a source-level
  regression guard against any future `outcome="allow"` call site smuggling
  content into `deny_reasons`.
