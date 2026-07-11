# Troubleshooting: credential injection and tool invocation

**Audience:** anyone debugging a tool call that isn't working once a server is already active and
released. Read
[../user/using-approved-server.md#important-http-200-does-not-mean-success](../user/using-approved-server.md#important-http-200-does-not-mean-success)
first — the HTTP status code alone will mislead you. For a submission/review-stage problem, see
[onboarding.md](onboarding.md) instead.

## Tool invocation errors

The proxy speaks JSON-RPC over HTTP — **every** gate failure in the invoke path (auth, network/SSRF,
entitlement, OPA policy, credential injection) returns an HTTP 200 with a JSON-RPC `error` object,
not an HTTP 4xx. Always check the response body's `error` key.

| `error.code` / message pattern | Cause | Fix |
|---|---|---|
| Tool absent from `tools/list` entirely | Quarantined, or you're not entitled to it, or it's `disabled`. | Ask an admin to check `tool_registry.status` and release it if appropriate (see [../admin/submission-review.md](../admin/submission-review.md)); check your client's grants (see [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md)). |
| `"Tool '<name>' (<id>) is quarantined and cannot be invoked."` | Explicitly calling a quarantined tool by name. | Same as above — needs an admin release, not a client-side fix. |
| `-32001 "Downstream authorization required."` | The upstream itself (a foreign IdP, e.g. Entra) is challenging — a delegated/`passthrough` mode where the caller isn't enrolled or their token expired. | Follow the `data.www_authenticate`/`downstream_challenge` in the error, or re-enroll via `GET /auth/status/{service}`. |
| `-32603 "Upstream MCP server error."` | The upstream server itself errored, timed out, or the invoke/init handshake failed. | Check the upstream server's own health/logs — this is downstream of the platform's own gates, not a platform-side auth failure. |
| Deny audited with reason `"not_entitled:<reason>"` | Your client's grants don't cover this tool/tag/risk-level. | See [../admin/rbac-and-grants.md](../admin/rbac-and-grants.md) — an admin needs to add a grant. |
| `CredentialInjectionError` (surfaces as a `-32603`-shaped error, always DENY-audited) | The configured auth mode couldn't produce a credential: not enrolled yet, revoked/missing secret, an OAuth policy violation at dispatch time, or the credential broker itself is unreachable. | Check [../reference/injection-modes.md](../reference/injection-modes.md) for what that mode needs; for per-user modes (`entra_user_token`, `external_oauth_user_token`, `kc_token_exchange`) the caller usually just needs to (re-)enroll. **This never means the request went through unauthenticated** — the platform fails closed rather than forwarding without the intended credential. |
| `ValueError`/deny: `"SSRF blocked upstream URL at invoke time: ..."` | The upstream host re-resolved to a different/private IP since registration (DNS-rebind guard) or genuinely violates the SSRF policy. | If legitimate (e.g. a lab-internal target), the server needs to be registered with the correct `UPSTREAM_PRIVATE_CIDR_ALLOWLIST` entry — an admin/infra concern, not something a caller can work around. |
| Called `invoke_tool` and got back a tool list instead of your tool's result, no error at all | You omitted `method` — it silently defaults to `"tools/list"`. | See [../user/using-approved-server.md](../user/using-approved-server.md#5-call-a-tool--via-the-invoke_tool-meta-tool-advanced) — either supply `"method": "tools/call"` (plus the nested `arguments.name`), or use the simpler direct `tools/call` form instead. |

## Credential-provisioning-side causes

Most `CredentialInjectionError`s trace back to something an admin needs to fix, not the caller:

| Auth mode | Likely fix |
|---|---|
| `service`, `basic_auth`, `service_account` | Credential missing/revoked/expired — see [../admin/credential-provisioning.md](../admin/credential-provisioning.md). |
| `entra_user_token`, `external_oauth_user_token` | The caller has not completed per-user enrollment (`GET /auth/status/{service}` → `enrollment_url`) — nothing for an admin to fix here, the CALLER needs to enroll. |
| `kc_token_exchange` | No `approved_token_audience` recorded, or the audience isn't in the platform's `KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES` ceiling — see [../admin/submission-review.md](../admin/submission-review.md). |
| `entra_client_credentials`, `external_oauth_client_credentials` | App-only client_secret missing/revoked, or (for external OAuth) no matching `oauth_provider_policy`/`oauth_provider_profile` — see [../admin/oauth-provider-setup.md](../admin/oauth-provider-setup.md). |
