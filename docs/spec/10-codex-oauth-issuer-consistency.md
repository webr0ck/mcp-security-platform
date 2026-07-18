# 10 — Codex-compatible OAuth: RFC 9207 issuer consistency

Status: **Design (approved approach), implementation pending live-Codex verification**
Date: 2026-07-18
Sources: `CodexOauth/2026-07-18-mcp-gateway-codex-oauth-diagnostics.md`;
rmcp PR #896 (SEP-2468); openai/codex #31573.

## Problem

Codex ≥ 0.143 fails MCP OAuth login against the gateway with:

```
Authorization server response missing required issuer: expected <issuer>
```

The failure is at **callback issuer validation**, before the authorization-code
exchange. Claude Code (more lenient) still works; older Codex (≤ 0.141) worked.

## Root cause — a real topology inconsistency, not only a client bug

rmcp PR #896 implements RFC 9207 / SEP-2468 issuer validation:

1. During the authorization request, the client **records the expected issuer
   from the authorization-server (AS) metadata** into its PKCE/CSRF state.
2. On the redirect callback, it validates the RFC 9207 `iss` query parameter:
   it must **equal** the recorded issuer, and must be **present** whenever the
   AS metadata advertises `authorization_response_iss_parameter_supported: true`
   (Keycloak does).

Our gateway advertises an **inconsistent issuer identity**:

| Value | Where | Current content |
|---|---|---|
| `authorization_servers[0]` | `/.well-known/oauth-protected-resource` | `https://<host>:8443` (proxy **origin**) |
| AS metadata `issuer` | `/.well-known/oauth-authorization-server` | `https://<host>:8443/realms/mcp` (Keycloak realm) |
| callback `iss` (RFC 9207) | Keycloak redirect | `https://<host>:8443/realms/mcp` (Keycloak realm) |

The proxy origin (`…:8443`) ≠ the realm issuer (`…:8443/realms/mcp`). A strict
RFC 9207 client keys on the AS it discovered from `authorization_servers` and
cannot reconcile the origin it was pointed at with the realm issuer in the
callback → "missing required issuer". Everything the platform emits is
individually valid; they are just not the **same** issuer string.

### Why the split exists (what we must not lose)

The proxy deliberately fronts AS metadata (points `authorization_servers` at
itself) for two reasons — see `proxy/app/routers/oauth_metadata.py`:

1. **Scope filtering** — Keycloak's native discovery lists every realm scope;
   MCP clients build the authorization request from `scopes_supported`, so an
   unfiltered list causes `invalid_scope`. The proxy overrides `scopes_supported`
   to only those enabled on the `claude-code` public client.
2. **Zero-credential DCR bridge** — the proxy injects
   `registration_endpoint = {proxy}/oauth/register`, which hands every client the
   static `claude-code` public client (PKCE S256, no secret) without real dynamic
   client registration against Keycloak.

Any fix must keep both.

## Recommended design — front the filtered metadata at the realm issuer path

Make one issuer identity — the Keycloak realm URL `{public}/realms/mcp` —
authoritative everywhere, while the proxy keeps serving the filtered metadata.

**Changes:**

1. **Protected-resource metadata** (`_protected_resource_metadata`): set
   `authorization_servers: ["{public}/realms/mcp"]` (the realm issuer), not the
   proxy origin. `issuer` (added in commit `60012d3`) stays `{public}/realms/mcp`.

2. **Serve the filtered AS metadata at the realm's well-known path.** Route
   `{public}/realms/mcp/.well-known/oauth-authorization-server` to the **proxy**
   (today the gateway sends `/realms/` to Keycloak). The proxy returns the same
   filtered document `oauth_server_metadata` already produces —
   `issuer = {public}/realms/mcp`, `registration_endpoint = {proxy}/oauth/register`,
   overridden `scopes_supported`, `code_challenge_methods_supported: ["S256"]` —
   with `authorization_endpoint`/`token_endpoint`/`jwks_uri` pointing at
   Keycloak's real realm endpoints.

3. Leave every other `/realms/mcp/*` path (openid-configuration, `/protocol/*`,
   JWKS, token, authorize) routed to Keycloak unchanged.

**Result:** `authorization_servers[0]` = AS-metadata `issuer` = callback `iss` =
`{public}/realms/mcp`. RFC 9207 validation passes for Codex ≥ 0.143; Claude Code
unaffected; scope filtering and the DCR bridge are preserved because the proxy
still serves the metadata — just at the realm path the client now discovers.

### Gateway routing (lab example)

`lab/nginx/conf.d/mcp-proxy-lab.conf` already has `location /.well-known/` → proxy
and `location /realms/` → Keycloak. Add a **more specific** exact/regex location
that wins over `location /realms/`:

```nginx
# Serve our filtered AS metadata at the realm issuer path so authorization_servers,
# AS-metadata issuer, and the RFC 9207 callback iss are all {public}/realms/mcp.
location = /realms/mcp/.well-known/oauth-authorization-server {
    proxy_pass http://mcp-proxy-upstream/.well-known/oauth-authorization-server;
    # (headers as for the other proxy locations)
}
```

The production gateway (`gateway/`) needs the equivalent route.

## Alternatives considered

- **Point `authorization_servers` directly at Keycloak's realm (no fronting).**
  Issuer becomes consistent, but Codex would fetch Keycloak's *raw* discovery —
  losing scope filtering (→ `invalid_scope`) and the DCR bridge (→ clients can't
  obtain the `claude-code` client). Rejected.
- **Make the proxy a full OAuth issuer facade** (issuer = proxy origin; proxy
  proxies `/authorize` + `/token` and rewrites the callback `iss`). Most flexible
  but far larger surface, and rewriting a loopback callback the AS sends straight
  to the client's `127.0.0.1` is not reliably possible. Rejected for MVP.
- **Do nothing / document the 0.141.0 downgrade.** The prior stopgap; the product
  owner has asked for a platform-side fix instead. Rejected.

## Implementation plan

1. `oauth_metadata.py` — `_protected_resource_metadata`: `authorization_servers`
   → `[_public_issuer()]`. Add a route (or reuse `oauth_server_metadata`) served
   at the realm well-known path.
2. Gateway: add the exact-match location above (lab + prod).
3. Tests: assert `authorization_servers[0] == issuer == {public}/realms/mcp` on
   both metadata docs; assert the realm-path AS metadata carries the proxy's
   `registration_endpoint` and filtered `scopes_supported`.
4. Regression: Claude Code OAuth flow unchanged; `scopes_supported` override and
   `/oauth/register` bridge intact.

## Verification (required before "fixed")

Unit/integration tests above **plus** a live handshake with a current Codex
(≥ 0.143, e.g. 0.144.5) completing `codex mcp login mcp-gateway` end-to-end:
token-endpoint POST, authenticated `POST /mcp` initialize → 200, tools listed.
This needs the real client host (the Windows machine in the diagnostics report);
CI cannot exercise it.

## Article

Publishable as a follow-up to the launch OAuth piece
(`Brain/Vault/00_AI/mcp-security-platform-launch/article_2_mcp-proxy-design.md`):
"Fronting an IdP without breaking RFC 9207 — how an MCP gateway keeps scope
filtering and a zero-credential DCR bridge while staying issuer-consistent for
strict clients like Codex." Draft after the implementation is verified live.
