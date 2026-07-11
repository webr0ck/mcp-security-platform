# MCP Server Examples

Five real, working reference implementations — one per distinct credential-injection
pattern this platform supports — for anyone building a new MCP server to submit via
self-service (`submit_mcp_server`) or admin onboarding.

These are copies of actual servers running in `lab/mcp-servers/` (not simplified toy
code), kept here unmodified so they stay a faithful reference. If you're starting a new
integration, also call the self-service `get_server_scaffold(injection_mode=...)` tool
first — it generates a minimal starter file; these examples show a complete, tested
implementation of the same pattern for when the scaffold isn't enough.

| Example | `injection_mode` | Pattern | Credential the server sees |
|---|---|---|---|
| [`none-catfacts`](none-catfacts/) | `none` | No auth at all — a genuinely public upstream API (catfact.ninja). The simplest possible server; start here if your upstream needs no credential. | Nothing — no header is injected. |
| [`service-grafana`](service-grafana/) | `service` | One shared credential for every caller (a Grafana service-account token). All invocations are attributed to the shared identity, not the individual user. | `Authorization: Bearer <shared-token>`, injected on every request. |
| [`user-netbox`](user-netbox/) | `user` | Per-user credential — each caller gets their own broker-injected token, so upstream logs show real per-user attribution. Requires each user to have their own credential enrolled. | `Authorization: Token <this-caller's-token>`, different per user. |
| [`entra-app-only-directory`](entra-app-only-directory/) | `entra_client_credentials` | App-only OAuth 2.0 client_credentials against Microsoft Graph. **The platform does the entire token exchange itself** and hands your server a ready-to-use Graph access token — your server never sees a client secret and never talks to `login.microsoftonline.com`. See the big comment at the top of `server.py` — this is the single most commonly misunderstood pattern (it looks like it needs its own token exchange; it doesn't). | `Authorization: Bearer <graph-access-token>`, exchanged and cached by the broker. |
| [`entra-delegated-m365`](entra-delegated-m365/) | `entra_user_token` (delegated) or `entra_client_credentials` (app-only fallback) | The most complex example: supports BOTH delegated (acts as the real signed-in user, via `/auth/enroll/m365` real interactive consent) and app-only fallback in one server, switching behavior based on whether a per-user token was actually injected. Read `REQUIRE_DELEGATED` and `_is_delegated()` in `server.py` before copying this pattern — the safe default refuses to silently fall back to app-only. | Delegated: `Authorization: Bearer <user's-token>`. App-only: same as entra-app-only-directory. |

## The one thing every example gets right that's easy to get wrong

**`stateless_http=True` is required** on the `FastMCP(...)` constructor for the broker-injected
header to actually reach your tool functions. In FastMCP's default stateful mode, tools run in a
long-lived session-init task group and the per-request context never propagates — you'll see the
credential header arrive at the ASGI layer but read as empty inside your `@mcp.tool()` functions.
This cost real debugging time building `entra-app-only-directory` — every example here already has
it set correctly; if you write a new server from scratch, don't skip it.

## Submitting a new server built from one of these

1. Adapt the example for your real upstream (change the base URL, tool names, response shaping).
2. Get it running somewhere reachable from the gateway (a container on the platform's network for
   testing, or your own real infrastructure for a genuine external submission).
3. Call `submit_mcp_server` (the self-service MCP tool) with your `injection_mode` matching the
   pattern you copied. **If you're using an OAuth-family mode** (`entra_client_credentials`,
   `entra_user_token`, `oauth_user_token`), you must also pass `upstream_idp_type`,
   `upstream_idp_issuer`, and `upstream_idp_client_id` in that same call — this cannot be added
   after submission (the submission becomes non-editable once scanned).
4. An admin approves, you `provide-url` with the real running address, an admin activates the
   discovered tools and uploads the actual credential value — then it's live.

If your IdP issuer has never been used on this platform before, an admin also needs to add an
`oauth_provider_policy` row for it before approval will succeed (fail-closed on unknown issuers —
a deliberate control, not a bug).
