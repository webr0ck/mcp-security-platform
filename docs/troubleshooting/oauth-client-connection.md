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

1. **Preferred (platform):** ensure the gateway runs the issuer-consistency fix
   (commit in `oauth_metadata.py` — `authorization_servers` = realm issuer; AS
   metadata served at the RFC 8414 path-insertion URL). Verify with the log check
   above.
2. **Client-side stopgap only** (if the gateway can't be updated yet): pin the
   client to a pre-regression version (Codex 0.141.0). This is a workaround, not a
   fix — the gateway should be made compliant.

## Not this issue

- **`INGRESS_DENIED` / direct `:8000` calls** — SEC-05 ingress guard; go through
  the gateway (`:8443`), not the proxy port directly.
- **TLS trust / revocation errors** (`CRYPT_E_NO_REVOCATION_CHECK`) — a client
  cert-trust problem, unrelated to issuer validation. See the gateway TLS notes.
- **`OAUTH_POLICY_VIOLATION` at server approval** — that's the reviewer-time
  `oauth_provider_policy` gate for onboarding a server, not a client-login issue.
