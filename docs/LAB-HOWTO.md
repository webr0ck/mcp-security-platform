# MCP Security Platform — Lab How-To Guide

Practical step-by-step instructions for running and using the lab. Every command in this guide runs against the actual lab stack.

- Proxy: `http://localhost:8000`
- Keycloak: `http://localhost:8082`
- DB: `localhost:5432`, user `mcp_app`, password `devpassword`, database `mcp_security`

---

## 1. Starting the Lab

The lab requires two compose files: the base stack (`docker-compose.yml`) and the lab overlay (`podman-compose.lab.yml`). The overlay adds Keycloak, the Keycloak seeder, lab-specific MCP servers, Grafana with Loki, NetBox, Gitea, and Vault.

### First-time setup (one-time)

```bash
# 1. Ensure Podman VM has enough memory
podman machine stop
podman machine set --memory 6144 --cpus 6
podman machine start

# 2. Create .env.lab from the template
cp .env.lab.example .env.lab
# Edit .env.lab — at minimum, set OIDC_ISSUER_URL to your machine's address:
#   OIDC_ISSUER_URL=http://localhost:8082/realms/mcp   (if running on localhost)
#   OIDC_ISSUER_URL=http://<YOUR_LAN_IP>:8082/realms/mcp  (if on LAN)

# 3. Start everything
make -f Makefile.lab lab-up
```

### Subsequent starts (after VM restart or lab-down)

```bash
make -f Makefile.lab lab-up
```

`lab-up` runs these steps in order:
1. `podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab up -d --build`
2. `bash lab/scripts/vault-init.sh` — seeds Vault KV with broker master secret + creates Gitea admin user
3. `podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab run --rm lab-seeder` — seeds DB tool registry, RBAC, service tokens
4. `lab-keycloak-seeder` container runs automatically — updates client secrets from `.env.lab`

### Verify the lab is healthy

```bash
make -f Makefile.lab lab-smoke
# Expected: 7/7 passed
```

Manual spot check:

```bash
# Proxy health
curl -s http://localhost:8000/health/ready | jq .

# Keycloak health
curl -s http://localhost:8082/health/ready | jq .

# List registered tools (as alice, using dev bypass header)
curl -s http://localhost:8000/api/v1/tools \
  -H "X-Client-Cert-CN: alice" | jq '[.data[].name]'
```

---

## 2. Keycloak Setup

Keycloak 24 is the primary OIDC IDP. The lab realm (`mcp`) is imported from `lab/keycloak/realm-mcp.json` on first start — it contains all users, clients, and role mappings. You should not need to re-configure it manually.

### Accessing the admin console

```
URL:      http://localhost:8082/admin
Username: admin
Password: adminpassword   (or KC_ADMIN_PASSWORD from .env.lab)
```

Navigate to **Keycloak → mcp realm** (dropdown in the top-left corner).

### Realm: mcp

- **Realm URL:** `http://localhost:8082/realms/mcp`
- **OIDC discovery:** `http://localhost:8082/realms/mcp/.well-known/openid-configuration`
- **Token endpoint:** `http://localhost:8082/realms/mcp/protocol/openid-connect/token`

### Test users

| Username | Password | Realm Role | Notes |
|---|---|---|---|
| `alice` | `labpassword` | `admin` | Full access including admin credentials UI |
| `bob` | `labpassword` | `agent` | Tool invocations, audit log read |
| `carol` | `labpassword` | `auditor` | Audit log, compliance reports, read-only |

Roles are mapped to the `roles` claim in the KC token via the **roles claim mapper** on the `mcp-proxy` client.

### Clients

| Client ID | Type | Notes |
|---|---|---|
| `mcp-proxy` | confidential, PKCE S256 | Browser login for the proxy |
| `grafana` | confidential | Grafana SSO via KC |

Client secrets are set by `lab-keycloak-seeder` from `KC_PROXY_CLIENT_SECRET` and `KC_GRAFANA_CLIENT_SECRET` in `.env.lab`.

---

## 3. Browser Login Flow (Keycloak)

This flow authenticates a human user to the proxy via their browser using Keycloak.

### Step by step

1. Open `http://localhost:8000/api/v1/auth/oidc/login` in a browser.
2. The proxy generates a PKCE `code_verifier` + `code_challenge` (S256), stores the state in the `oidc_sessions` DB table, and redirects your browser to Keycloak.
3. At `http://localhost:8082/realms/mcp/protocol/openid-connect/auth?…`, log in as `alice` / `labpassword`.
4. Keycloak redirects to `http://localhost:8000/api/v1/auth/oidc/callback?code=…&state=…`.
5. The proxy verifies the `state` against `oidc_sessions`, exchanges the code for KC tokens using the internal container URL (`OIDC_INTERNAL_ISSUER_URL`), and stores the KC tokens server-side.
6. The response contains:
   - `mcp_session` HttpOnly cookie (15 min TTL)
   - JSON body with `session_token` (internal HS256 JWT)

The `session_token` / cookie is what you use for subsequent API calls. It **never contains the raw Keycloak tokens** — those stay server-side.

### Using the session token in API calls

```bash
# Save the token from the callback response JSON
SESSION_TOKEN="<session_token from step 6>"

# Who am I?
curl -s http://localhost:8000/api/v1/auth/oidc/session \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq .

# List tools (requires agent or admin role)
curl -s http://localhost:8000/api/v1/tools \
  -H "Authorization: Bearer $SESSION_TOKEN" | jq '[.data[].name]'
```

### Session TTL and logout

The session JWT expires after `SESSION_JWT_EXPIRE_SECONDS` (default: 900 seconds / 15 min). To log out:

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/oidc/logout \
  -H "Authorization: Bearer $SESSION_TOKEN"
# Response: {"message": "Logged out."}
```

This revokes the session in the `oidc_sessions` table and clears the cookie.

---

## 4. Admin Credentials UI

The admin credentials UI provides a web interface for uploading, rotating, and revoking tool credentials without DB access. It requires the `admin` role (alice in the lab).

### Accessing the UI

1. Log in via Keycloak (section 3) as `alice` to get a session token or cookie.
2. Navigate to `http://localhost:8000/admin/credentials`.
   - If you have the `mcp_session` cookie from a browser login, the page loads directly.
   - If using curl, pass `Authorization: Bearer <session_token>`.

### Uploading a credential via API

```bash
SESSION_TOKEN="<token from Keycloak login>"

# 1. Find the tool ID you want to credential
TOOL_ID=$(curl -sf http://localhost:8000/admin/credentials/api \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  | jq -r '.tools[] | select(.name=="grafana-query") | .tool_id')

echo "Tool ID: $TOOL_ID"

# 2. Upload the credential (AES-256-GCM encrypted at rest)
curl -s -X PUT "http://localhost:8000/admin/credentials/${TOOL_ID}" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secret": "glsa_myGrafanaServiceAccountToken",
    "credential_type": "api_key",
    "owner_type": "service",
    "description": "Grafana SA token — service mode"
  }'

# 3. Set injection mode to "service" so all callers share this credential
curl -s -X PUT "http://localhost:8000/admin/credentials/${TOOL_ID}/injection-mode" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"injection_mode": "service"}'
```

### Verifying the upload

```bash
curl -s http://localhost:8000/admin/credentials/api \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  | jq '.tools[] | select(.tool_id=="'$TOOL_ID'") | {name, injection_mode, has_credential}'
```

Expected output:

```json
{
  "name": "grafana-query",
  "injection_mode": "service",
  "has_credential": true
}
```

### Revoking a credential

```bash
curl -s -X DELETE "http://localhost:8000/admin/credentials/${TOOL_ID}" \
  -H "Authorization: Bearer $SESSION_TOKEN"
```

---

## 5. Credential Injection Per Tool

Each tool in the registry has an `injection_mode` column (set via the admin credentials UI or DB migration). The mode determines how credentials are resolved and injected when the tool is invoked.

| Mode | What happens | When to use |
|---|---|---|
| `none` | No credential injected | Public tools, tools with no stored secret |
| `service` | Shared service credential decrypted (keyed by `__service__`) and injected | Grafana SA token shared across all callers |
| `user` | Per-user credential decrypted (keyed by caller's Keycloak `sub`) | Each user has their own personal API key for a tool |
| `service_account` | Keycloak `client_credentials` token fetched for `kc_client_id` | KC-managed service accounts (e.g. a KC client per tool) |
| `oauth_user_token` | RFC 8693 token exchange via Keycloak — exchanges caller's session token for a target-service token | Microsoft 365 or other OAuth-native services |

### Example: Grafana (service mode)

All callers share one Grafana SA token. The proxy decrypts it from `credential_store` (owner_type=service, user_sub=`__service__`) and injects it into the upstream Grafana API call.

1. Upload credential as shown in section 4.
2. Set `injection_mode=service`.
3. Invoke any Grafana tool — the SA token is injected automatically.

### Example: M365 (oauth_user_token mode)

Each caller gets a token exchanged from their own Keycloak session token via RFC 8693.

```bash
# Set the tool's KC audience for token exchange
curl -s -X PUT "http://localhost:8000/admin/credentials/${M365_TOOL_ID}/injection-mode" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "injection_mode": "oauth_user_token",
    "kc_client_id": "m365-tool",
    "kc_token_audience": "api://m365-tool"
  }'
```

> **Note:** `broker_instance` is initialized at proxy startup (`main.py` lifespan → `build_broker()`); it is only `None` when `VAULT_TOKEN` is empty, in which case tools with credential injection modes fail-closed at call time. Set `VAULT_TOKEN` in `.env.lab` to enable credential injection in the lab.

---

## 6. Running the Full Test Suite

```bash
# From the project root — ensure .env.lab is present and the stack is running
cd ~/Code/mcp-security-platform

# Run all tests
PYTHONPATH=proxy python3 -m pytest proxy/tests/ \
  -v \
  --tb=short \
  -x

# Expected output:
# 292 passed, 2 skipped, 1 xfailed in <N>s
```

### Environment requirements for tests

Most tests use mocked dependencies and do not require a running lab. The integration tests in `proxy/tests/integration/` require the stack. Set these env vars if you need them:

```bash
export DB_URL="postgresql+asyncpg://mcp_app:devpassword@localhost:5432/mcp_security"
export REDIS_URL="redis://:devpassword@localhost:6379/0"
export VAULT_ADDR="http://localhost:8201"
export VAULT_TOKEN="lab-root-token"
```

### Running a single test file

```bash
PYTHONPATH=proxy python3 -m pytest proxy/tests/test_oidc_browser.py -v
PYTHONPATH=proxy python3 -m pytest proxy/tests/test_admin_credentials.py -v
```

---

## 7. Connecting Claude Code to the MCP Endpoint

The proxy exposes a full MCP Streamable-HTTP endpoint at `POST http://localhost:8000/mcp`.

### Step 1: Get an API key

```bash
# Create an API key as bootstrap admin
API_RESPONSE=$(curl -s -X POST http://localhost:8000/api/v1/auth/apikey \
  -H "X-Client-Cert-CN: bootstrap" \
  -H "Content-Type: application/json" \
  -d '{"client_id": "alice", "description": "claude code key"}')

echo "$API_RESPONSE" | jq .
API_KEY=$(echo "$API_RESPONSE" | jq -r '.api_key')
echo "API Key: $API_KEY"
```

### Step 2: Add to `~/.mcp.json` — URL only, no credentials

**The MCP client stores only the gateway URL. No API key, no client secret, no token.**

```json
{
  "mcpServers": {
    "mcp-security-platform": {
      "type": "http",
      "url": "http://localhost:8000/mcp"
    }
  }
}
```

That's it. When Claude Code first hits the MCP endpoint, it:
1. Gets a `401` with `WWW-Authenticate: Bearer ... resource_metadata="http://localhost:8000/.well-known/oauth-protected-resource"`
2. Fetches `/.well-known/oauth-protected-resource` → discovers `authorization_servers: ["http://<YOUR_LAN_IP>:8082/realms/mcp"]`
3. Fetches `/.well-known/oauth-authorization-server` (proxied from Keycloak) → gets all OAuth2 endpoints
4. POSTs to `/oauth/register` → receives the static `claude-code` public-client ID (no secret)
5. Opens the browser to `http://localhost:8082/realms/mcp/protocol/openid-connect/auth`
6. User logs in (alice / bob / carol with `labpassword`)
7. Token is held in memory for the session — nothing persisted on disk

### Step 3: Verify the discovery chain

```bash
# 1. Confirm 401 + resource_metadata header
curl -sv http://localhost:8000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}' 2>&1 \
  | grep -E "HTTP|WWW-Authenticate"

# 2. Confirm protected-resource points at Keycloak
curl -s http://localhost:8000/.well-known/oauth-protected-resource | jq .

# 3. Confirm authorization-server discovery returns Keycloak endpoints
curl -s http://localhost:8000/.well-known/oauth-authorization-server | jq '{authorization_endpoint,token_endpoint,registration_endpoint}'

# 4. Confirm dynamic client registration returns claude-code with no secret
curl -s -X POST http://localhost:8000/oauth/register \
  -H "Content-Type: application/json" \
  -d '{"redirect_uris":["http://localhost:12345/callback"]}' | jq .
# → { "client_id": "claude-code", "token_endpoint_auth_method": "none", ... }
# No client_secret in the response.
```

### Available tools (via MCP)

| Tool name | Role required | What it does |
|---|---|---|
| `platform_info` | admin, agent, auditor | Platform version, environment, authenticated identity |
| `security_pulse_summary` | admin, agent | CVE digest and anomaly count |
| `list_registered_tools` | admin, agent | Tool registry with audit status and risk scores |
| `invoke_tool` | admin | Invoke any registered tool by name |

---

## 8. Keycloak Admin Tasks

### Creating a new user

1. Admin console → `http://localhost:8082/admin` → realm `mcp`
2. **Users** → **Create new user**
3. Fill username, set **Email verified** = on
4. **Credentials** tab → **Set password** → disable "Temporary"
5. **Role mappings** tab → **Assign role** → select `admin`, `agent`, or `auditor`

Or via the admin REST API:

```bash
# Get admin token
KC_TOKEN=$(curl -sf -X POST http://localhost:8082/realms/master/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=adminpassword" \
  | jq -r '.access_token')

# Create user
curl -s -X POST http://localhost:8082/admin/realms/mcp/users \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "dave",
    "email": "dave@example.com",
    "enabled": true,
    "emailVerified": true,
    "credentials": [{"type":"password","value":"labpassword","temporary":false}]
  }'

# Get user ID
USER_ID=$(curl -sf http://localhost:8082/admin/realms/mcp/users?username=dave \
  -H "Authorization: Bearer $KC_TOKEN" | jq -r '.[0].id')

# Get agent role ID
ROLE_ID=$(curl -sf http://localhost:8082/admin/realms/mcp/roles/agent \
  -H "Authorization: Bearer $KC_TOKEN" | jq -r '.id')

# Assign agent role
curl -s -X POST "http://localhost:8082/admin/realms/mcp/users/${USER_ID}/role-mappings/realm" \
  -H "Authorization: Bearer $KC_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\":\"${ROLE_ID}\",\"name\":\"agent\"}]"
```

After creating a user in Keycloak, the proxy syncs roles to `role_assignments` on first login. If the user needs immediate proxy access without logging in first, insert directly:

```bash
podman exec -i mcp-db psql -U mcp_app -d mcp_security -c \
  "INSERT INTO role_assignments (client_id, role, granted_by) VALUES ('dave@example.com', 'agent', 'manual') ON CONFLICT DO NOTHING;"
```

Flush the Redis role cache for the new user:

```bash
podman exec mcp-redis redis-cli -a devpassword DEL "roles:dave@example.com"
```

### Rotating a client secret

1. Admin console → realm `mcp` → **Clients** → `mcp-proxy`
2. **Credentials** tab → **Regenerate** → copy the new secret
3. Update `.env.lab`: `KC_PROXY_CLIENT_SECRET=<new_secret>` and `OIDC_CLIENT_SECRET=<new_secret>`
4. Restart the proxy: `podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab restart proxy`

---

## 9. Troubleshooting

### Keycloak slow to start (60s start_period)

Keycloak 24 performs schema migrations on first start, which can take 30–60 seconds. The compose healthcheck has a `start_period: 60s` — container transitions to `healthy` only after that. If `lab-up` fails because the seeder timed out waiting for Keycloak, re-run:

```bash
# Wait for Keycloak to be healthy
until podman healthcheck run lab-keycloak 2>/dev/null | grep -q healthy; do
  echo "Waiting for Keycloak..."
  sleep 5
done

# Re-run the seeder
podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab \
  run --rm lab-keycloak-seeder
```

Check Keycloak logs:

```bash
podman logs lab-keycloak --tail 50 -f
```

### Redis stale role cache after new user creation

The proxy caches role lookups for 5 minutes. After creating a Keycloak user or modifying DB roles, flush the cache:

```bash
# Flush a specific user
podman exec mcp-redis redis-cli -a devpassword DEL "roles:alice"

# Flush all role caches
podman exec mcp-redis redis-cli -a devpassword KEYS "roles:*" \
  | xargs -r podman exec -i mcp-redis redis-cli -a devpassword DEL
```

### DB migration status check

```bash
podman exec -i mcp-db psql -U mcp_app -d mcp_security \
  -c "SELECT version, description, installed_on, success FROM schema_version ORDER BY installed_rank;"
```

Expected: V001 through V012 all showing `success = t`.

If V010–V012 are missing (injection_mode column or oidc_sessions table absent):

```bash
for f in infra/db/migrations/V010*.sql infra/db/migrations/V011*.sql infra/db/migrations/V012*.sql; do
  echo "Applying $f..."
  podman exec -i mcp-db psql -U mcp_app -d mcp_security < "$f" || true
done
```

### OIDC login redirects to wrong host

`OIDC_ISSUER_URL` must be the address your **browser** can reach. If running on a remote machine, set it to `http://<LAN_IP>:8082/realms/mcp` (not the container-internal address). The container-internal URL is set separately as `OIDC_INTERNAL_ISSUER_URL=http://lab-keycloak:8080/realms/mcp`.

After updating `.env.lab`, restart the proxy:

```bash
podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab restart proxy
```

### Session JWT invalid / 401 after proxy restart

The proxy's `PROXY_SECRET_KEY` rotates on container restart in dev mode. Existing session JWTs are invalidated — log in again at `http://localhost:8000/api/v1/auth/oidc/login`. In production this key should be a stable secret in Vault.

### Stale OIDC discovery document cached in Redis

The proxy caches the Keycloak discovery document for 5 minutes in Redis. If you restarted Keycloak:

```bash
podman exec mcp-redis redis-cli -a devpassword DEL oidc:discovery
```

### 502 Bad Gateway after proxy restart

Nginx may have cached the old proxy container IP. Restart the gateway:

```bash
podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab \
  restart nginx-gateway
```

### Grafana SSO not working

1. Check that `KC_GRAFANA_CLIENT_SECRET` in `.env.lab` matches the Keycloak admin console → Clients → grafana → Credentials tab.
2. Re-run the seeder to push the updated secret to Keycloak:
   ```bash
   podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab \
     run --rm lab-keycloak-seeder
   ```
3. Restart Grafana:
   ```bash
   podman compose -f docker-compose.yml -f podman-compose.lab.yml --env-file .env.lab \
     restart lab-grafana
   ```

### NetBox OOM

```bash
podman machine stop
podman machine set --memory 6144 --cpus 6
podman machine start
make -f Makefile.lab lab-up
```

### Checking all container health at once

```bash
podman compose -f docker-compose.yml -f podman-compose.lab.yml ps --format "table {{.Name}}\t{{.Status}}"
```

All containers should show `Up` or `(healthy)`. A container stuck in `(starting)` more than 2 minutes after `lab-up` has a problem — check its logs with `podman logs <container-name> --tail 30`.
