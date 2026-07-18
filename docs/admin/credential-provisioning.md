# Credential management

**Audience:** `admin` operators uploading/rotating the secrets a `service`/`basic_auth`/
`service_account`/`entra_*` tool needs to authenticate to its upstream.

> Commands below assume you're either going through the real gateway/mTLS path, or (for a lab
> walkthrough) running inside the `mcp-proxy` container — see
> [../user/self-service-onboarding.md's Prerequisites](../user/self-service-onboarding.md#prerequisites).

All endpoints below require the `admin` role (not `security_reviewer`/`platform_admin` — see
[rbac-and-grants.md](rbac-and-grants.md) for the full role matrix). Every mutation is encrypted
with AES-256-GCM before storage and emits an audit event; **the platform never returns a stored
secret's plaintext value in any subsequent read** — only upload/rotate is possible, never "view".

## Upload or rotate a credential

**UI path (Fix 6, `docs/spec/11-server-lifecycle-and-hardening-batch.md`):** this same endpoint is
also reachable from the portal — **Servers → Credentials tab** — so `entra_client_credentials`-style
servers can get a credential without reading this file or a test. Pick the tool, click
"Manage credential", fill in credential type / owner / secret, save. The UI form posts the exact
body shape shown below (`ui/src/components/Servers/CredentialsPanel.tsx`,
`credentials.upload()` in `ui/src/services/api.ts`); the curl form remains the reference for
scripting/CI.

```bash
curl -sf -X PUT http://localhost:8000/admin/credentials/$TOOL_ID \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"secret": "sk_live_...", "credential_type": "api_key", "owner_type": "service",
       "description": "Acme API key, rotated 2026-07-07"}'
```

**Expected output:** `200 OK` with a JSON body confirming `credential_id` — never the secret you
just sent.

`credential_type` values in use: `api_key`, `oauth2_refresh`, `entra_client_secret`,
`basic_auth`, `client_secret` (generic external OAuth). `owner_type` is `service` (one credential
shared by every caller of this tool — the common case) or `user` (per-user; requires `user_sub`,
mostly used by enrollment flows rather than this direct upload path).

**`basic_auth`** additionally requires `username` (RFC 7617 — the secret field is the password).

## Revoke a credential

```bash
curl -sf -X DELETE http://localhost:8000/admin/credentials/$TOOL_ID -H "Authorization: Bearer $TOKEN"
```

The tool immediately stops being able to authenticate upstream — any in-flight or new invocation
using `service`/`service_account`/etc. injection fails closed
(`CredentialInjectionError` → a JSON-RPC error, never a silent unauthenticated forward — see
[../troubleshooting/credential-injection.md](../troubleshooting/credential-injection.md)).

## Microsoft Entra ID setup

Entra needs three values together, not just one secret:

```bash
curl -sf -X PUT http://localhost:8000/admin/credentials/$TOOL_ID/entra \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"tenant_id": "<entra-tenant-guid>", "client_id": "<app-registration-client-id>",
       "client_secret": "<app-registration-secret>",
       "scope": "https://graph.microsoft.com/.default"}'
```

## Setting the injection mode directly (admin path)

```bash
curl -sf -X PUT http://localhost:8000/admin/credentials/$TOOL_ID/injection-mode \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"injection_mode": "service"}'
```

Accepts the full mode set (`auth_modes.py::all_mode_values()`, including admin-only
`passthrough`) — wider than what a self-service submitter can choose. See
[../reference/auth-modes.md](../reference/auth-modes.md) for the complete list and which modes are
admin-only.

## External OAuth (per-server) client secret

A self-service-onboarded `external_oauth_*`/`entra_*` server's client_secret is stored the same
way (`PUT /admin/credentials/{tool_id}`, `credential_type: "client_secret"`, `owner_type:
"service"`) against any one tool belonging to that server — the broker resolves it via
`tool_registry.credential_id` at invoke time. See
[oauth-provider-setup.md](oauth-provider-setup.md) for the provider-profile side of this.

## Enrollment-based credentials (per-user OAuth)

`entra_user_token`, `external_oauth_user_token`, and `kc_token_exchange` don't use this upload
path at all — the END USER enrolls themselves (`GET /auth/status/{service}` →
`enrollment_url` if not yet enrolled). Nothing for an admin to upload per-user; the admin's job for
these modes is approving the provider config (see
[submission-review.md](submission-review.md)), not uploading a shared secret.
