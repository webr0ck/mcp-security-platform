# MCP Security Platform — Full POC Tier

Standard tier + Wazuh SIEM + three demo MCP servers + three demo users (alice/bob/carol).

## Quick start

```bash
cp deployments/poc/.env.example .env
# Fill DB_PASSWORD, REDIS_PASSWORD, PROXY_SECRET_KEY, VAULT_TOKEN,
# API_KEY_HMAC_KEY, SBOM_SIGNING_KEY, AUDIT_LOG_HMAC_KEY, OAUTH_STATE_SECRET
bash scripts/init-poc.sh
docker compose -f compose.poc.yml up -d
docker compose -f compose.poc.yml ps
```

## Demo users

| User  | Role    | Can access            | Password env var       |
|-------|---------|-----------------------|------------------------|
| alice | viewer  | echo tools only       | `POC_ALICE_PASSWORD`   |
| bob   | editor  | echo + notes          | `POC_BOB_PASSWORD`     |
| carol | agent   | echo + notes + search | `POC_CAROL_PASSWORD`   |
| admin | admin   | everything            | `ADMIN_PASSWORD`       |

Create alice/bob/carol in Keycloak (`http://localhost:8082`) after startup.
DB role assignments are applied automatically by `poc-seeder` on startup.

## Services

| Service          | URL                         | Notes                         |
|------------------|-----------------------------|-------------------------------|
| Admin panel      | https://localhost/admin      | LAN only                      |
| Keycloak         | http://localhost:8082        | Create users here             |
| Grafana          | http://localhost:3000        | SSO via Keycloak              |
| Wazuh dashboard  | http://localhost:5601        | admin / WAZUH_INDEXER_PASSWORD|

## MCP servers

| Server            | Upstream URL              | Allowed roles          |
|-------------------|---------------------------|------------------------|
| poc-echo-server   | http://mcp-echo:8000      | viewer, editor, analyst, admin |
| poc-notes-server  | http://mcp-notes:8000     | editor, analyst, admin |
| poc-search-server | http://mcp-search:8000    | analyst, admin         |

## Detection rules

Sigma rules in `detections/` define all threat detection logic.
Wazuh receives logs from `mcp-proxy` via the Filebeat sidecar.
