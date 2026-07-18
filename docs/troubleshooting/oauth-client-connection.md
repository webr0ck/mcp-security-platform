# Troubleshooting: MCP client OAuth connection ("missing required issuer")

Applies when connecting an OAuth-backed MCP client (Codex, Claude Code, or any
rmcp/MCP client) to the gateway and login fails at the callback.

## Symptom

The client aborts OAuth **at the redirect callback, before the token exchange**,
with a message like:

```
Authorization server response missing required issuer: expected https://<host>/realms/mcp
```

`codex mcp login mcp-gateway` fails; no `mcp-gateway` tools load. Claude Code may
still connect fine against the *same* gateway — that does **not** mean the gateway
is compliant (see below).

## Root cause

RFC 9207 issuer validation (implemented in rmcp PR #896, shipped in Codex ≥ 0.143).
A strict client records the issuer from the authorization-server metadata and
requires the callback `iss` to match it. The failure means the gateway advertised
an **inconsistent issuer**: `authorization_servers` (in protected-resource
metadata), the AS-metadata `issuer`, and the IdP callback `iss` were not all the
same string. Lenient clients (Claude Code) skip this check, so "works in Claude
Code" hides the defect.

The platform fix (2026-07-18, `docs/spec/10-codex-oauth-issuer-consistency.md`)
makes all three equal the **realm issuer URL** (`{host}/realms/mcp`).

## Debug from the proxy logs

The proxy emits one greppable line per discovery request:

```bash
podman logs mcp-proxy 2>&1 | grep oauth.discovery
```

Expected — all issuer values identical (the realm URL), registration bridge present:

```
oauth.discovery protected_resource resource=https://<host>/mcp authorization_servers=['https://<host>/realms/mcp'] issuer=https://<host>/realms/mcp
oauth.discovery as_metadata issuer=https://<host>/realms/mcp registration_endpoint=https://<host>/oauth/register path=/.well-known/oauth-authorization-server/realms/mcp
```

**Red flag:** if `authorization_servers` is the proxy **origin** (`https://<host>`,
no `/realms/...`) while `issuer` is the realm URL, the split is back — a strict
client will reject it. They must match.

Cross-check the live documents directly (inside the proxy container, which is a
trusted ingress peer):

```bash
podman exec mcp-proxy python -c "import urllib.request,json; \
d=json.load(urllib.request.urlopen('http://localhost:8000/.well-known/oauth-protected-resource/mcp')); \
print('authorization_servers=',d['authorization_servers'],'issuer=',d['issuer'])"
```

`authorization_servers[0]` **must equal** `issuer`. Then confirm the IdP callback
`iss` (from the browser's redirect to `127.0.0.1:<port>?...&iss=...`) equals that
same value.

## Fix / workarounds

**Gateway side is already fixed and RFC 9207-compliant.** Verified empirically
(2026-07-18): a real authorization callback through the gateway carries
`iss=https://<host>/realms/mcp` — exactly the value the client expects — and
`authorization_servers == AS-issuer == callback iss == the realm URL`. See the log
check above. So the server sends a correct, present, matching issuer.

**Codex 0.144.x still fails anyway** — it rejects a valid, present `iss`
([openai/codex#31573](https://github.com/openai/codex/issues/31573); 0.144.x has
related OAuth-refresh bugs too, [#33403](https://github.com/openai/codex/issues/33403)).
No server change can fix a client that won't accept a compliant response. Two ways
to run **current** Codex against the gateway:

1. **Recommended — bearer-token config (no downgrade, bypasses the broken OAuth
   callback).** Codex's `bearer_token_env_var` sends `Authorization: Bearer <token>`
   directly; the gateway's OIDC bearer path validates it (a real Keycloak access
   token, not a static API key). Proven to reach `POST /mcp` initialize → 200.

   ```toml
   [mcp_servers.mcp-gateway]
   url = "https://<host>:8443/mcp"
   bearer_token_env_var = "MCP_GATEWAY_TOKEN"
   ```

   Set `MCP_GATEWAY_TOKEN` to a Keycloak access token for your user (obtain it via
   your normal login / a refresh; it is short-lived, so refresh when it expires).
   This keeps auth Keycloak-issued and validated — it just skips Codex's buggy
   interactive callback.

2. **Client downgrade** to a pre-regression Codex (0.141.0) — works, but pins you
   to an old client. Upgrade back once OpenAI ships the #31573 fix.

## Not this issue

- **`INGRESS_DENIED` / direct `:8000` calls** — SEC-05 ingress guard; go through
  the gateway (`:8443`), not the proxy port directly.
- **TLS trust / revocation errors** (`CRYPT_E_NO_REVOCATION_CHECK`) — a client
  cert-trust problem, unrelated to issuer validation. See the gateway TLS notes.
- **`OAUTH_POLICY_VIOLATION` at server approval** — that's the reviewer-time
  `oauth_provider_policy` gate for onboarding a server, not a client-login issue.
