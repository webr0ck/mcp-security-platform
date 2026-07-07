# RBAC roles and client grants

**Audience:** `admin`/`platform_admin` operators managing who can do what.

> Commands below assume you're either going through the real gateway/mTLS path, or (for a lab
> walkthrough) running inside the `mcp-proxy` container — see
> [../user/self-service-onboarding.md's Prerequisites](../user/self-service-onboarding.md#prerequisites).

## Roles

| Role | Can do |
|---|---|
| `admin`, `platform_admin` | Everything below — reviewer actions, credential management, grants, limits, provider profiles. |
| `security_reviewer` | Approve/reject/request-changes on submissions (not credential management, not grants). |
| `security_auditor`, `auditor` | Read-only: view the review queue, audit log, SBOM/scan reports. Cannot mutate anything. |
| `server_owner` | Owns their own submitted servers — can `PATCH`/`submit`/`provide-url` their own, cannot review anyone's (including their own — segregation of duties). |
| `manager` | Portal "my access" / profile management for their reports (see `routers/portal.py` fragments). |
| `user`, `agent` | Ordinary tool-calling principal, no admin surface. |
| `readonly` | Portal read access, no mutation, no admin surface. |

Role assignments are **append-only** (`role_assignments` table, V050) — a grant/revoke is its own
inserted event row, not an in-place update. "Current" role state is the most recent event per
`(client_id, role)`; nothing is ever destructively edited, so the full grant/revoke history is
always available for audit.

## Assigning a role

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/roles \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id": "bob", "role": "security_reviewer"}'
```

## Revoking a role

```bash
curl -sf -X DELETE "http://localhost:8000/api/v1/admin/roles/bob/security_reviewer" \
  -H "Authorization: Bearer $TOKEN"
```

## Listing principals

```bash
curl -sf http://localhost:8000/api/v1/admin/principals -H "Authorization: Bearer $TOKEN"
```

Returns the union of everyone with a live role assignment, an explicit MCP profile toggle, or an
active session — not a Keycloak-wide user sync (out of scope; see the router's own docstring).

## Client grants (per-client tool allowlists)

Grants are what actually reach OPA — they are the enforced authorization data, independent of the
role labels above. A client's `allowed_tools`/`allowed_tags`/`max_risk_level` here is what
`tools/list` and `invoke_tool` check against.

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/grants \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id": "bob", "allowed_tools": ["echo-ping"], "allowed_tags": [], "max_risk_level": "low"}'
```

**Every grant/revoke mutation calls `push_grants()` before returning** — OPA's in-memory data is
updated as part of the same request, not eventually-consistent. If you ever suspect OPA has drifted
(e.g. after a manual DB edit, which you should not do), force a resync:

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/sync-grants -H "Authorization: Bearer $TOKEN"
```

## API keys

```bash
curl -sf -X POST http://localhost:8000/api/v1/admin/api-keys \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"client_id": "ci-bot", "description": "CI pipeline key"}'
```

**Expected output:** the raw key is returned **exactly once**, in this response — it is hashed
(HMAC-SHA-256) before storage and can never be retrieved again; losing it means issuing a new one
(`DELETE /api/v1/admin/api-keys/{key_id}` to revoke the old one).
