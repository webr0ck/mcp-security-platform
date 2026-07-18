# 13 — Entitlement principal validation + submission data_categories hardening

Status: **Implemented (2026-07-18)**
Source: `docs/spec/11-server-lifecycle-and-hardening-batch.md` §2 (fix 2) and
§4 (fix 4), from the external acceptance run findings.

Scope: `proxy/app/routers/entitlements.py`, `proxy/app/routers/submission.py`,
and their unit tests. No schema migration was needed for either fix — no
`V079__*.sql` was added.

## Fix 2 — entitlement principal_id shape validation

### Problem

`POST /api/v1/servers/{id}/entitlements` (`grant_entitlement`) accepted any
non-empty string as `principal_id`, including a bare username like
`human:keycloak:alice`. But the invoke-time identity computed by
`middleware/auth.py::_build_principal_id` for a verified-email OIDC session
is `human:{OIDC_ISSUER_ID}:{verified_email}` — e.g.
`human:keycloak:alice@corp`. A grant made against the bare-username form
returned 201 and looked successful, but it never matched anything at invoke
time: `entitlement` lookups compare `principal_id` for exact equality, so
the grant silently authorized nothing. There was no server-side signal that
the grant was inert.

### Fix

`EntitlementGrantBody.principal_id` now has a `model_validator(mode="after")`
(`entitlements.py`, `principal_id_shape`) that:

1. Splits `principal_id` into exactly 3 parts via `principal_id.split(":", 2)`
   — `type`, `issuer`, `subject`. Splitting with a `maxsplit` of 2 (not an
   unbounded split) is deliberate: the subject segment may itself contain
   `:` (e.g. a nested service-account subject), and an unbounded split would
   truncate it.
2. Requires all 3 segments to be non-empty after stripping.
3. Requires the `type` segment to be one of the existing
   `_VALID_PRINCIPAL_TYPES` (`human`, `agent`, `kc_group` — matches the DB's
   `principal_type_enum`, see `infra/db/migrations/V013__principal_type_enum.sql`).
4. Requires the `type` segment to equal the request's own `principal_type`
   field (e.g. a `principal_type="human"` request cannot carry a
   `principal_id` starting with `agent:`).

On any violation, this raises inside pydantic validation → FastAPI returns
**422** automatically, with a message that states the required shape and a
concrete example (`type:issuer:subject`, e.g. `human:keycloak:alice@corp`).

**Explicitly out of scope**: this is shape validation only. It does **not**
resolve `principal_id` against a live identity store (Keycloak, an LDAP
directory, etc.) to confirm the principal actually exists — that is a larger
change (would need a network call or a cached identity index at grant time)
and is not part of this fix. A syntactically well-formed but non-existent
subject (e.g. `human:keycloak:nobody@corp`) still grants successfully; it
simply never matches any real caller, which is a much smaller blast radius
than the original bug (a *systematically wrong* format that could
plausibly be typed by every admin who didn't know the exact invoke-time
shape).

**Deviation from the fix-2 task note**: the task description mentioned a
type namespace of `{human, agent, kc_group, service}`. The DB's
`principal_type_enum` (V013) and this router's own `principal_type: Literal[...]`
field only define `human | agent | kc_group` — there is no `service`
principal type anywhere in this codebase (a service credential is a
`principal_type="human"` `auth_method="api_key"` caller, per
`_build_principal_id`). Validating against a `service` value that can never
appear in `principal_type` would be dead code, so the shape validator
reuses the existing `_VALID_PRINCIPAL_TYPES` frozenset instead of
introducing a fourth value. Flagged here for the architect to confirm — if
a `service` principal type is intended for a future change, it needs to
land in the DB enum and the `principal_type` `Literal` first.

### Tests

`proxy/tests/unit/test_entitlement_api.py::TestEntitlementGrantBody` —
extended with: bare-username rejection (the exact original bug), missing
subject segment, empty subject segment (trailing colon), principal_id
type/principal_type mismatch, unknown type segment, subject containing
extra colons (verifies the `maxsplit=2` behavior), and the canonical
well-formed shape. Pre-existing tests in the same class and in
`TestINV001AuditBeforeResponse` that constructed `EntitlementGrantBody`
with bare/unshaped principal_ids were updated to use well-formed
`type:issuer:subject` values — those tests exercise audit/INV-001 behavior,
not principal_id shape, so they were adapted rather than left encoding the
now-fixed bug.

## Fix 4 — data_categories enum + non-name-consuming validation failure

### Problem statement (as reported)

"Unknown category fails submission after claiming the name permanently (no
resubmit — a stuck draft holds the name forever)." `submission.py:_VALID_CATEGORIES`
was also undeclared in the tool-facing schema — a caller had to guess valid
values.

### What was verified

`server_registry.name` is claimed at `POST /api/v1/submissions` /
`create_draft` time — this INSERT happens under a
`name`+`owner_sub`+`deleted_at IS NULL` uniqueness check
(`create_draft`, `submission.py`), and is unconditional: it does not (and,
before this fix, could not) validate `data_categories`, because
`DraftCreate` never had that field — `data_categories` is only ever
collected later, via `PATCH /api/v1/submissions/{id}` / `update_draft`
(`DraftUpdate.data_categories`, wizard steps 2-3).

`DraftUpdate.data_categories` already carries a `field_validator` (`valid_cats`).
Pydantic validates a request body **before** FastAPI calls the route
handler, so an unknown category in a PATCH body already raised a 422 at
parse time, before `update_draft()` — and therefore before any DB
read/write — ever ran. Re-reading the create/update code confirms there is
no code path where a name is claimed *because of* a data_categories
failure, nor any partial commit inside `update_draft` that a
data_categories rejection could leave half-applied (the mode/idp
compatibility check earlier in the function has the same property: it
raises before the `UPDATE` statement is even built). **This part of fix
4(a) already held** — no reordering of validation vs. DB write was needed
for the `PATCH` endpoint itself.

What was **not** already covered: `DraftCreate` and `DraftUpdate` used
pydantic's default `extra="ignore"` behavior. A caller that (reasonably)
tried to send `data_categories` directly on `POST /api/v1/submissions`
— since nothing in the API surface documented that the field only exists on
the PATCH model — had it silently dropped: the draft was created (201, name
claimed) with no validation of the categories ever run and no categories
ever recorded, no error surfaced at all. This is the actual "silent
claim with no useful signal" failure mode consistent with the report, even
though the *original* claimed row itself is always still editable via a
follow-up PATCH (the name is never unrecoverably stuck — see Tests below).

### Fix

1. **`extra="forbid"` on `DraftCreate` and `DraftUpdate`** (`model_config`).
   Any field not declared on the model — including `data_categories` sent
   at create time, or a typo'd field name — now raises 422 immediately
   instead of being silently dropped. This turns the "claimed a name,
   captured nothing, no error" failure mode into a loud, immediate,
   non-name-consuming (nothing is written to `server_registry` when
   pydantic parsing itself fails) 422.
2. **Enum surfaced in the error**: `valid_cats`'s `ValueError` now lists the
   full sorted `_VALID_CATEGORIES` set alongside the bad values, instead of
   only the bad values.
3. **Enum surfaced in the schema**: `DraftUpdate.data_categories` now
   carries `json_schema_extra={"items": {"enum": sorted(_VALID_CATEGORIES)}}`
   and a `description` listing the valid values, so the enum is
   discoverable via the generated OpenAPI schema (`/docs`, or any
   schema-introspecting client/tool) — not just after a failed guess.
   `injection_mode`'s existing `valid_mode` validator error was similarly
   extended to list `_VALID_MODES` for the same reason (`unknown
   injection_mode` errors previously named only the bad value).

### Tests

New file `proxy/tests/unit/test_submission_data_categories.py`:

- `DraftUpdate(data_categories=[...bad...])` raises at construction
  (parse-time, pre-DB) and the error message contains every valid category.
- An end-to-end sequence: `create_draft` claims a name → a
  `DraftUpdate(data_categories=["not_real"])` construction fails (no DB call
  reachable) → the **same** `server_id`/name is re-PATCHed with a corrected,
  valid `data_categories` list and succeeds — demonstrating the name is
  never permanently stuck.
- `DraftCreate(name=..., data_categories=[...])` — an unknown field at
  create time — now raises 422 (previously silently dropped).
- `DraftUpdate(unexpected_field=...)` — same, for the update model.

## Files changed

- `proxy/app/routers/entitlements.py` — `EntitlementGrantBody` shape
  validator (Fix 2).
- `proxy/app/routers/submission.py` — `extra="forbid"` on `DraftCreate` /
  `DraftUpdate`, enum surfaced in `data_categories` / `injection_mode`
  errors and in the `data_categories` field schema (Fix 4).
- `proxy/tests/unit/test_entitlement_api.py` — new + updated
  `EntitlementGrantBody` shape tests.
- `proxy/tests/unit/test_submission_data_categories.py` — new file, Fix 4
  coverage.

No migration was added — neither fix required a schema change.
