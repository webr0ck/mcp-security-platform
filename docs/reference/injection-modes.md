# Injection modes — technical reference

**Audience:** engineers building or reviewing an MCP server against this platform, or debugging a
credential-injection failure.

For the non-expert "which mode do I pick" version, see
[../user/auth-mode-decision-guide.md](../user/auth-mode-decision-guide.md). For the generated
status table, see [auth-modes.md](auth-modes.md). This document explains what each mode actually
does at invoke time.

Every mode ultimately produces a `{header_name: header_value}` dict that
`credential_broker/dispatcher.py` merges into the outbound request to your upstream server.
`inject_header` (default `Authorization`) and `inject_prefix` (default `Bearer`) are per-tool
configurable — most modes format the header as `f"{inject_prefix} {token}"`.

| Mode | What's injected | Token lifecycle |
|---|---|---|
| `none` | Nothing. | N/A |
| `service` | A static, platform-stored bearer token/API key. | Never expires from the platform's perspective — rotate via [../admin/credential-provisioning.md](../admin/credential-provisioning.md). |
| `basic_auth` | `Authorization: Basic <base64(username:password)>` — `inject_prefix` is ignored (RFC 7617 mandates `Basic`). | Static, same rotation path as `service`. |
| `user` | Nothing credential-shaped; `X-User-Sub` carries the caller's identity. Your server manages its own per-user auth/session. | N/A |
| `service_account` | A Keycloak `client_credentials` access token for a registered KC client. | Minted per call (cached briefly), platform-managed. |
| `kc_token_exchange` | An RFC 8693-exchanged token: the caller's own platform sign-in token, exchanged for one scoped to your registered audience. | Minted per call from the caller's live session; **your server must independently validate** issuer/audience/expiry/signature — the platform does not do this for you (see below). |
| `entra_client_credentials` | An app-only Microsoft Graph token (Azure `client_credentials`). | Minted/refreshed by the platform. |
| `entra_user_token` | A delegated Microsoft Graph token acting as the signed-in user. | Requires the user to have completed enrollment once (`GET /auth/status/entra`); refreshed automatically thereafter. |
| `external_oauth_client_credentials` | An app-only token from a generic (non-KC, non-Entra) OAuth 2.0 `client_credentials` grant. | Platform-managed refresh. |
| `external_oauth_user_token` | A per-user delegated token from a generic OAuth 2.0 authorization-code + refresh flow. | Requires per-user enrollment once; the platform stores the encrypted refresh token and mints a fresh access token per call — your server never sees the refresh token. |
| `passthrough` (admin-only) | The caller's own inbound `Authorization` header, forwarded verbatim. | Whatever the caller presented — no platform-side lifecycle. |

## What your server must validate for `kc_token_exchange`

This is the one mode where the platform's guarantee stops at "delivered a token that came from a
real exchange" — **your server is responsible for validating it**, exactly like any OIDC resource
server would:

1. Issuer matches the platform's Keycloak realm issuer.
2. Audience matches the one you registered (see
   [../admin/submission-review.md](../admin/submission-review.md)).
3. Not expired (`exp`).
4. Signature valid against the platform's JWKS.
5. Use `sub` as the calling user's identity for any per-user authorization you do.

`services/same_idp_verify.py::run_same_idp_verify_probe` (platform-side) is an automated check
against a deployed server for exactly this — it confirms missing/wrong-audience/expired tokens are
all rejected. See [../admin/post-approval-activation.md](../admin/post-approval-activation.md).

## Failure behavior (important for debugging)

**Every mode fails closed.** If credential injection cannot produce a valid header (revoked
credential, failed refresh, no enrollment yet, policy violation), the dispatcher raises
`CredentialInjectionError` — the request is **never forwarded upstream without the intended
credential**. This surfaces to the caller as a JSON-RPC `error` in an HTTP 200 response (not a
silent pass-through) — see [../troubleshooting/credential-injection.md](../troubleshooting/credential-injection.md).

## The `ServiceAdapter` contract (advanced)

For external OAuth services that need more than "call the API with a bearer token" — resolving a
tenant/site id after enrollment, exposing a specific safe verification endpoint —
`credential_broker/adapters/service_adapter.py` defines a `ServiceAdapter` `Protocol`:
`required_oauth_fields()`, `default_scopes()`, `validate_provider_config()`,
`post_enrollment_discovery()`, `select_resource()`, `build_runtime_context()`, `verify_access()`,
`safe_probe_endpoint()`. `adapters/generic_service_adapter.py::GenericServiceAdapter` is the
reference "no extra discovery needed" implementation most services should use unmodified.
A `ServiceAdapter` **never** sees or stores a refresh token or client secret — only a short-lived
access token for the duration of one discovery/verify call; its output
(`server_registry.service_context`) is always non-secret and separate from `credential_store`.
