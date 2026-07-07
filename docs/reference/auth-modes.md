# Auth mode reference

**Audience:** admins reviewing a submission's requested auth mode, engineers building an MCP
server against this platform, and anyone debugging why a tool call was rejected.

This table is **generated** from `proxy/app/services/auth_modes.py` — the single canonical
source of truth for every auth/credential-injection mode the platform knows about (WP-A5 /
CR-02). It is never hand-edited between the markers below; run
`python3 scripts/generate_auth_modes_doc.py` after changing `auth_modes.py`, and
`proxy/tests/unit/test_auth_modes_doc_current.py` fails CI if anyone forgets.

- **Mode value** — the exact string stored in `server_registry.injection_mode` /
  `tool_registry.injection_mode` and accepted by the submission API's `injection_mode` field.
- **Status** — ✅ supported and self-service selectable today, 🔒 admin-only (exists, but a
  self-service submitter cannot choose it — an admin must set it via the registry API),
  ⚠️ a deprecated alias kept for backward compatibility with existing rows (choose the
  canonical name instead for new servers), or 🚧 roadmap (the enum value exists but no
  dispatcher branch implements it yet — do not choose it, nothing will happen at invoke time).

For what each mode actually does when a tool is invoked (headers injected, token lifecycle,
failure behavior), see [injection-modes.md](injection-modes.md). For a non-expert decision tree
("which mode should I pick?"), see
[../user/auth-mode-decision-guide.md](../user/auth-mode-decision-guide.md).

<!-- BEGIN GENERATED AUTH MODE TABLE -->
| Mode value | Label | Status | Description |
|---|---|---|---|
| `none` | No credential injection | ✅ Supported (self-service selectable) | The upstream requires no authentication from the platform. |
| `service` | Shared service credential | ✅ Supported (self-service selectable) | A platform-managed shared API key or static bearer token, the same for every caller. |
| `basic_auth` | Basic auth | ✅ Supported (self-service selectable) | Shared or per-user HTTP Basic auth (RFC 7617). |
| `user` | Per-user identity (no credential injection) | ✅ Supported (self-service selectable) | No credential is injected beyond X-User-Sub; the upstream manages its own per-user state. |
| `service_account` | Keycloak service account | ✅ Supported (self-service selectable) | A Keycloak client_credentials access token for the tool's registered KC client. |
| `kc_token_exchange` | Same-IdP token exchange | ✅ Supported (self-service selectable) | RFC 8693 token exchange — the caller's Keycloak token is exchanged for an upstream-audience token. Only works when the upstream trusts this same Keycloak realm. |
| `oauth_user_token` | Same-IdP token exchange (deprecated name) | ⚠️ Deprecated alias (accepted, do not choose for new servers) | Alias for kc_token_exchange, kept for backward compatibility with existing rows. |
| `entra_client_credentials` | Microsoft Entra app-only | ✅ Supported (self-service selectable) | An app-only Microsoft Graph token via Azure client_credentials grant. |
| `entra_user_token` | Microsoft Entra delegated (per-user) | ✅ Supported (self-service selectable) | A delegated Microsoft Graph token acting as the signed-in user; requires per-user enrollment. |
| `external_oauth_client_credentials` | External OAuth, app-only | ✅ Supported (self-service selectable) | Generic external OAuth 2.0 client_credentials grant for a non-Keycloak, non-Entra IdP. |
| `external_oauth_user_token` | External OAuth, per-user | ✅ Supported (self-service selectable) | Generic external OAuth 2.0 per-user delegated/refresh flow for a non-Keycloak, non-Entra IdP (e.g. Atlassian Jira Cloud OAuth 2.0 3LO). |
| `passthrough` | Passthrough (admin-only) | 🔒 Admin-only (not self-service selectable) | Forwards the caller's own inbound Authorization header verbatim to the upstream. |
<!-- END GENERATED AUTH MODE TABLE -->

## Where this is enforced

- **Self-service submission wizard**: only modes with status "supported" are offered
  (`auth_modes.py::self_service_mode_values()`), enforced server-side in
  `routers/submission.py` regardless of what the client UI sends.
- **Admin server registration** (`routers/server_registry.py`): accepts the full set including
  admin-only and alias modes (`auth_modes.py::all_mode_values()`).
- **Dispatch** (`credential_broker/dispatcher.py`): `InjectionMode` is a direct alias of
  `AuthMode` (`InjectionMode = AuthMode`) — there is exactly one enum, not two that could drift.
