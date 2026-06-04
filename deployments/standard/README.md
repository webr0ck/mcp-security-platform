# MCP Security Platform — Standard Tier

Engine + Keycloak (OIDC) + Grafana + Loki. No users by default.

## Quick start

```bash
cp deployments/standard/.env.example .env
# Fill DB_PASSWORD, REDIS_PASSWORD, PROXY_SECRET_KEY, VAULT_TOKEN,
# API_KEY_HMAC_KEY, SBOM_SIGNING_KEY, AUDIT_LOG_HMAC_KEY, OAUTH_STATE_SECRET
bash scripts/init-standard.sh
docker compose -f compose.standard.yml up -d
```

## Creating users

1. Open `http://localhost:8082` → admin / `KC_ADMIN_PASSWORD`
2. Select realm **mcp** → Users → Add user
3. Set username + password → Groups → assign to `mcp-admin`, `mcp-editor`, `mcp-viewer`, or `mcp-analyst`

## Production considerations

**Keycloak dev mode:** `compose.standard.yml` uses `start-dev` with `KC_DB: dev-file` (in-memory H2).
All realm configuration and users are **lost on container restart**.
Before any production or long-lived deployment:

- Switch to `KC_DB: postgres` with a persistent external PostgreSQL database.
  See: <https://www.keycloak.org/server/db>
- Replace `start-dev` with `start` and configure all required production settings.
- Export your realm config and ensure it is re-imported on startup, or manage via GitOps.

**Alertmanager:** placeholder webhook URLs (`http://localhost:9999/alertmanager-placeholder`) are set in
`observability/alertmanager/alertmanager.yml`. Alerts are silently dropped until real endpoints are
configured (Slack webhook, PagerDuty, Telegram bot, or SMTP).

## Services

| Service | URL | Credentials |
|---|---|---|
| Admin panel | https://localhost/admin (LAN only) | admin / ADMIN_PASSWORD |
| Keycloak | http://localhost:8082 | admin / KC_ADMIN_PASSWORD |
| Grafana | http://localhost:3000 | SSO via Keycloak or admin / ADMIN_PASSWORD |
