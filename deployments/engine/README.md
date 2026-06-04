# MCP Security Platform — Engine Tier

Minimal, self-contained deployment: gateway (nginx+ModSec) · security proxy · OPA policy engine · PostgreSQL · Redis · Vault · step-ca (mTLS CA).

**Requires:** Docker Compose v2.20+

## Quick start

```bash
cp deployments/engine/.env.example .env
# Edit .env — fill DB_PASSWORD, REDIS_PASSWORD, PROXY_SECRET_KEY, VAULT_TOKEN,
# API_KEY_HMAC_KEY, SBOM_SIGNING_KEY, AUDIT_LOG_HMAC_KEY, OAUTH_STATE_SECRET
bash scripts/init-engine.sh           # generates ADMIN_PASSWORD once
docker compose -f compose.engine.yml up -d
docker compose -f compose.engine.yml ps
```

## Admin panel

`https://localhost/admin` — **LAN-only** (RFC-1918 enforced by nginx).
Credentials: `admin` / value of `ADMIN_PASSWORD` from init-engine.sh output.

## Connect your IDP

Set in `.env`, then `docker compose -f compose.engine.yml restart proxy`:

```ini
OIDC_ENABLED=true
OIDC_ISSUER_URL=https://your-idp.example.com/realms/mcp
OIDC_CLIENT_ID=mcp-security-platform
OIDC_CLIENT_SECRET=<secret>
OIDC_AUDIENCE=mcp-security-platform
OIDC_REDIRECT_URI=https://your-host/api/v1/auth/oidc/callback
```

Any OIDC-compliant provider works: Keycloak, Okta, Auth0, Microsoft Entra, Dex.

## Ship audit logs to your SIEM

```bash
# Optional Filebeat sidecar overlay
FILEBEAT_OUTPUT_HOSTS=logstash:5044 \
  docker compose -f compose.engine.yml -f compose.logging-agent.yml up -d
```
