# 15 — Profile naming clarity + credential-upload discoverability (Fixes 5 & 6)

Status: **Implemented 2026-07-18**
Source: `docs/spec/11-server-lifecycle-and-hardening-batch.md`, findings 5 and 6 (from
`ExternalTestResults/2026-07-18_21_40_results.md`).

This document records what changed for Fix 5 and Fix 6 and why, as the durable reference —
`11-server-lifecycle-and-hardening-batch.md` stays the point-in-time batch tracking doc.

## Fix 6 — credential-upload discoverability

**Finding:** `PUT /api/v1/admin/credentials/{tool_id}` existed and worked, but was only
discoverable by reading a test file — no UI, and the admin docs only showed curl.

**Status found:** `ui/src/components/Servers/CredentialsPanel.tsx` already implemented the full
form (tool picker via expand-per-row, credential type, owner type service/user, secret input,
description) wired to `credentials.upload()` in `ui/src/services/api.ts`, and was already mounted
as the "Credentials" tab in `ServersSection.tsx` (admin-only, gated the same way as "Registry").
No code changes were needed for the UI itself — it was already a discoverable, working form.

**What this change adds:** a documentation cross-link. `docs/admin/credential-provisioning.md`'s
"Upload or rotate a credential" section now leads with the UI path (Servers → Credentials tab)
before the curl reference, so someone reading the admin docs finds the UI first.

**Body shape** (`CredentialUploadBody` in `ui/src/services/api.ts`, matches the backend contract
exactly):

```ts
{
  secret: string            // the raw secret value; never echoed back after upload
  credential_type: string   // api_key | oauth2_refresh | entra_client_secret | service_account_jwt | basic_auth
  owner_type: 'service' | 'user'
  user_sub?: string         // required when owner_type === 'user'
  username?: string         // required when credential_type === 'basic_auth' (RFC 7617)
  description?: string
}
```

## Fix 5 — "profile" naming collision

**Finding:** two unrelated systems both call themselves "profile":

1. Per-identity self-service meta-tools (`get_profile`/`enable_mcp`/`disable_mcp`/
   `enable_function`/`disable_function`, `target_profile` argument) — Task 4.2, rows in
   `mcp_profiles`/`profile_mcp_bindings`, keyed by principal.
2. Session-bound **named** profiles — Task 4.3, admin-only, REST-only
   (`POST /api/v1/profiles/named`, `PUT /api/v1/profiles/named/{name}/mcps/{tool_name}`), bound at
   OIDC login via `?profile=<name>`. No MCP tool exists for this system by design.

Nothing in-repo previously explained the distinction, so it was easy to build against the wrong
one (e.g. assume `enable_mcp` affects a named profile's session-wide bindings — it does not).

**What changed:**

- **New:** `docs/troubleshooting/profile-naming.md` — the disambiguation doc. Explains what each
  system is, how to reach it, storage, and a "which one do I want" table.
- **`infra/db/migrations/V081__clarify_self_service_profile_tool_descriptions.sql`** — appends a
  one-line disambiguator to the `tool_registry.description` of the 5 self-service meta-tools seeded
  by V078, so the distinction is visible directly in `tools/list` output, not just in docs someone
  has to go find. Idempotent `UPDATE ... SET description = description || '...'`, guarded by a
  `NOT LIKE` check so re-running the migration doesn't duplicate the suffix. No schema change, no
  DELETE (tool_registry rows are audit-linked and can only be soft-deleted — see the guard notes in
  V078 itself).
- **Explicitly out of scope, tracked as a follow-up:** the external `self-service-mcp` server (the
  actual process behind these tool calls, living outside this repo at
  `http://self-service:8000/mcp`) has its own docstrings baked into its tool schema that predate
  this fix. Those are not editable from this repo. `profile-naming.md` notes this explicitly so
  nobody mistakes the V081 description suffix for the whole fix.

## Role-based access note

Neither fix changes any RBAC boundary:

- Fix 6's UI form was already gated identically to the rest of the "Servers" registry admin surface
  (`isAdmin` in `ServersSection.tsx` — role must be exactly `admin`, matching the backend's
  `admin`-role gate on `/admin/credentials/*`, not `security_reviewer`/`platform_admin`).
- Fix 5 is documentation + a description-text migration only; it does not touch any endpoint,
  role check, or OPA policy.
