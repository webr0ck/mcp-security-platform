# MCP Security Platform — Lab Guide

> **Learning and evaluation environment only.**
> The lab stack is intentionally misconfigured for convenience: Vault runs in dev mode (in-memory, data lost on restart), all passwords default to `labpassword`, and TLS is self-signed. None of these choices are safe for production.
> See [INSTALL.md](INSTALL.md) for the production deployment guide and [SECURITY.md](SECURITY.md) for the security model.

The lab lets you run the complete MCP Security Platform on a single machine — proxy, two OIDC IdPs, Vault, PostgreSQL, Redis, Grafana, NetBox, Gitea, nine MCP servers, and an egress proxy — using [Podman](https://podman.io/) (rootless, no daemon). The production tiers use Docker Compose; see [INSTALL.md](INSTALL.md).

---

## Contents

1. [What the lab gives you](#1-what-the-lab-gives-you)
2. [Prerequisites](#2-prerequisites)
3. [Bring up the lab](#3-bring-up-the-lab)
4. [Lab endpoints](#4-lab-endpoints)
5. [The two IdPs explained](#5-the-two-idps-explained)
6. [Connecting an MCP client (Claude Code)](#6-connecting-an-mcp-client-claude-code)
7. [Running the test suite](#7-running-the-test-suite)
8. [Lab lifecycle commands](#8-lab-lifecycle-commands)
9. [Troubleshooting](#9-troubleshooting)
10. [Further reading](#10-further-reading)

---

## 1. What the lab gives you

| Layer | What runs | Purpose |
|---|---|---|
| MCP proxy | `proxy/` (FastAPI, hot-reload) | OAuth 2.1 PKCE gateway, RBAC, credential injection, OPA policy enforcement |
| Primary IdP | Keycloak 24 (realm `mcp`) | Production-grade OIDC — browser login, PKCE, token exchange |
| Secondary IdP | Dex v2.38 + Mock IdP | Lightweight alternative OIDC flows, device flow, federation testing |
| Secret store | Vault (dev mode) | Credential broker; data is in-memory and lost on restart |
| Database | PostgreSQL 16 | Role assignments, tool registry, session store, audit log |
| Cache | Redis 7 | Rate limiting, role cache, OIDC discovery cache |
| Observability | Grafana + Loki + Promtail + Alertmanager | Log aggregation, dashboards, alert routing |
| IPAM | NetBox v4.2 | CMDB / inventory data for the NetBox MCP server |
| Git hosting | Gitea | Self-hosted repo for the Gitea MCP server |
| Egress proxy | Squid (allowlisting) | Controls outbound calls from the M365 MCP server |
| MCP servers | echo, notes, search, grafana, netbox, gitea, m365, self-service, rag-assistant | Nine distinct credential-injection scenarios |

**When to use the lab vs production:**
- Lab: evaluating the platform, running integration tests, local development, conference demos.
- Production: any environment that handles real credentials, real user data, or is network-accessible beyond a trusted LAN. Start from [INSTALL.md](INSTALL.md).

---

## 2. Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| Podman | 4.4+ | `podman --version` |
| podman-compose | 1.1+ | `podman-compose --version` |
| Python | 3.12+ | `python3 --version` |
| curl | any | `curl --version` |
| jq | any | `jq --version` |
| openssl | any | For token verification |

### Podman VM sizing

NetBox and Keycloak will OOM-kill if the Podman VM is under-resourced. Set the VM to at least 6 GB RAM and 6 CPUs before starting:

```bash
podman machine stop
podman machine set --memory 6144 --cpus 6
podman machine start
```

### Ollama model (optional — LLM risk scorer)

The proxy uses Ollama (`llama3.2`, ~2 GB) to score tool-call risk. Pull the model once after the stack is up:

```bash
make pull-model
```

This runs `ollama pull llama3.2` inside the Ollama container. If skipped, the risk scorer falls back to a heuristic and logs a warning.

---

## 3. Bring up the lab

### First time

```bash
# 1. Copy the env template
cp .env.lab.example .env.lab

# 2. Set OIDC_ISSUER_URL to the address your browser can reach
#    (localhost if running locally; LAN IP if Claude Code runs on another machine)
#    Edit .env.lab and set:
#      OIDC_ISSUER_URL=http://localhost:8082/realms/mcp
#    Or for a remote client:
#      OIDC_ISSUER_URL=http://<YOUR_LAN_IP>:8082/realms/mcp

# 3. Bring up the full stack (builds images, starts services, seeds Vault + DB + Keycloak)
make -f Makefile.lab lab-up
```

`lab-up` performs these steps in order:

1. `podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml up -d --build` — builds and starts all containers.
2. 10-second wait for services to reach their health checks.
3. `make -f Makefile.lab lab-init`, which runs:
   - `bash lab/scripts/vault-init.sh` — seeds Vault KV with the broker master secret and creates the Gitea admin user.
   - `podman-compose … run --rm lab-seeder` — populates the DB tool registry, RBAC assignments, and service tokens.
   - The `lab-keycloak-seeder` container (started as part of compose) waits for Keycloak to be healthy and then pushes client secrets from `.env.lab` into the realm.

Alternatively, `lab-setup` wraps `lab-up` plus DB migrations and a final smoke test:

```bash
make -f Makefile.lab lab-setup
```

### Subsequent starts

```bash
make -f Makefile.lab lab-up
```

### Verify the lab is healthy

```bash
make -f Makefile.lab lab-smoke
# Expected output: 7/7 passed
```

Manual spot checks:

```bash
# Proxy readiness
curl -s http://localhost:8000/health/ready | jq .

# Keycloak readiness
curl -s http://localhost:8082/health/ready | jq .

# List registered tools (dev bypass header — no auth required in dev mode)
curl -s http://localhost:8000/api/v1/tools \
  -H "X-Client-Cert-CN: alice" | jq '[.data[].name]'
```

---

## 4. Lab endpoints

### Core platform

| Service | URL | Credentials / notes |
|---|---|---|
| MCP proxy (API + MCP endpoint) | `http://localhost:8000` | OAuth 2.1 PKCE; see section 6 |
| Proxy MCP endpoint | `http://localhost:8000/mcp` | Streamable HTTP transport |
| Proxy health | `http://localhost:8000/health/ready` | No auth |
| Proxy admin credentials UI | `http://localhost:8000/admin/credentials` | Requires `admin` role (alice) |

### Identity providers

| Service | URL | Notes |
|---|---|---|
| Keycloak admin console | `http://localhost:8082/admin` | `admin` / `adminpassword` (or `KC_ADMIN_PASSWORD`) |
| Keycloak realm `mcp` | `http://localhost:8082/realms/mcp` | Primary OIDC IdP |
| Keycloak OIDC discovery | `http://localhost:8082/realms/mcp/.well-known/openid-configuration` | |
| Dex | `http://localhost:5556/dex` | Secondary OIDC IdP; see section 5 |
| Mock IdP | `http://localhost:8888` | Click-to-login; device flow; no passwords |

### Observability

| Service | URL | Credentials |
|---|---|---|
| Grafana (lab, with Keycloak SSO) | `http://localhost:3001` | `admin` / `labpassword` or SSO via Keycloak |
| Grafana (main observability stack) | `http://localhost:3000` | `admin` / see `GF_SECURITY_ADMIN_PASSWORD` |
| Loki (LogQL direct queries) | `http://localhost:3100` | No auth |

### Lab upstream services

| Service | URL | Credentials |
|---|---|---|
| NetBox | `http://localhost:8090` | `admin` / `labpassword` |
| Gitea | `http://localhost:3002` | `gitadmin` / `labpassword` |

### Secret store

| Service | URL | Notes |
|---|---|---|
| Vault (dev mode) | `http://localhost:8201` | Token: `lab-root-token` — **lab only, never reuse** — data lost on restart, re-run `lab-init` |

> **Note on Vault port:** The lab remaps Vault to `:8201` (container port 8200) to avoid colliding with other local Vault instances. The `.env.lab.example` ships `VAULT_ADDR=http://localhost:8200` — update it to `http://localhost:8201` if you query Vault directly from the host.

### Keycloak test users (realm `mcp`)

All three users share the password `labpassword` — **lab only, never reuse in production.**

| Username | Password | Realm role | Access |
|---|---|---|---|
| `alice` | `labpassword` | `admin` | Full access including admin credentials UI |
| `bob` | `labpassword` | `agent` | Tool invocations, audit log read |
| `carol` | `labpassword` | `auditor` | Audit log and compliance reports (read-only) |

Roles are mapped to the `roles` claim in Keycloak tokens via the **roles claim mapper** on the `mcp-proxy` client.

### Lab MCP servers

All nine lab MCP servers are registered in `mcps.yaml` and seeded into the proxy tool registry by `lab-seeder`. The proxy routes calls to them over per-server pairwise internal networks (MCP servers cannot reach each other or platform backends directly).

| MCP server | Internal URL | Host port | Credential scenario |
|---|---|---|---|
| `lab-echo` | `http://lab-mcp-echo:8000/mcp` | `127.0.0.1:8105` | No credential (auth verification target) |
| `lab-notes` | `http://lab-mcp-notes:8000/mcp` | `127.0.0.1:8106` | Per-user credential injection (approach A) |
| `lab-search` | `http://lab-mcp-search:8000/mcp` | `127.0.0.1:8107` | No credential |
| `lab-grafana` | `http://lab-mcp-grafana:8000/mcp` | `127.0.0.1:8100` | Shared service API key injection (approach B) |
| `lab-netbox` | `http://mcp-netbox:8000/mcp` | `127.0.0.1:8101` | Shared service API key injection (approach B) |
| `lab-gitea` | `http://lab-mcp-gitea:8000/mcp` | `127.0.0.1:8102` | Broker-injected token (approach B) |
| `lab-m365` | `http://lab-mcp-m365:8000/mcp` | `127.0.0.1:8103` | Entra client credentials via broker; egress via Squid |
| `lab-self-service` | `http://lab-mcp-self-service:8000/mcp` | `127.0.0.1:8108` | Proxy profile API (approach A, user-sub) |
| `lab-rag-assistant` | `http://lab-rag-assistant:8000/mcp` | `127.0.0.1:8104` | No credential; serves `docs/` read-only |

Host ports are bound to `127.0.0.1` only — MCP server containers are not directly reachable from the LAN; all external access goes through the proxy.

---

## 5. The two IdPs explained

The lab ships two OIDC identity providers by design. They serve different testing purposes and are both real — this is not a configuration error or a work in progress.

### Keycloak 24 — primary IdP

**Purpose:** production-grade OIDC flows. All browser-based logins, the Claude Code PKCE flow, token exchange (RFC 8693), and Grafana SSO run through Keycloak.

- Realm `mcp` is imported from `lab/keycloak/realm-mcp.json` on first start. It contains pre-configured users (alice/bob/carol), clients (`mcp-proxy`, `grafana`, `claude-code`), role mappers, and redirect URIs.
- The `mcp-proxy` client uses confidential PKCE S256. The `claude-code` client is public (no secret) to support Claude Code's dynamic-port redirect.
- Client secrets are pushed into the realm by the `lab-keycloak-seeder` container using values from `.env.lab` (`KC_PROXY_CLIENT_SECRET`, `KC_GRAFANA_CLIENT_SECRET`). The lab defaults are `mcp-proxy-secret` and `grafana-secret` — **lab only**.
- The proxy talks to Keycloak on the internal container URL (`http://lab-keycloak:8080`) for JWKS and token validation; the browser-facing URL (`http://localhost:8082` or `http://<YOUR_LAN_IP>:8082`) is set via `OIDC_ISSUER_URL` in `.env.lab`.

### Dex v2.38 + Mock IdP — secondary IdP

**Purpose:** lightweight, password-free OIDC flows for testing alternate authentication paths and protocol-level scenarios.

**Dex** (`lab/dex/config.lab.yaml`, port `5556`) is a pre-Keycloak carryover kept for backward compatibility. It runs in-memory with static passwords (`labpassword` for alice/bob/admin) and is used for testing Dex-specific OIDC adapter paths and federation token exchange.

**Mock IdP** (`lab/mock-idp/`, port `8888`) is a custom FastAPI OAuth 2.1 / OIDC server that implements click-to-login (no password form), device flow (RFC 8628), and dynamic client registration. It is the simplest way to test:
- Device authorization flow end-to-end.
- What the proxy does when the IdP returns an `access_denied` response.
- Dynamic client registration without a Keycloak admin console.

Users in the Mock IdP are `alice@corp` (analyst role), `bob@corp` (viewer role), and `admin@corp` (admin role). Login is a browser click — no password entry.

**Switching the proxy between IdPs** is done by changing `OIDC_ISSUER_URL` in `.env.lab` and restarting the proxy:

```bash
# Use Keycloak (default)
OIDC_ISSUER_URL=http://localhost:8082/realms/mcp

# Use Dex
OIDC_ISSUER_URL=http://localhost:5556/dex

# Use Mock IdP
OIDC_ISSUER_URL=http://localhost:8888
```

Restart the proxy after each change:

```bash
podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  restart proxy
```

---

## 6. Connecting an MCP client (Claude Code)

The proxy MCP endpoint at `http://localhost:8000/mcp` uses OAuth 2.1 PKCE — no static API keys or credentials go in the client config file.

### Step 1 — Set `PROXY_BASE_URL` in `.env.lab`

Required when the client runs on a different machine from the proxy:

```bash
PROXY_BASE_URL=http://<YOUR_LAN_IP>:8000
```

Leave it blank (or set to empty string) for localhost-only use — the proxy derives the base URL from the incoming `Host` header in that case (`OIDC_TRUST_FORWARDED_HOST=true` is set in the lab compose).

Restart the proxy after changing `PROXY_BASE_URL`.

### Step 2 — Add the gateway to `~/.claude/settings.json`

```json
{
  "mcpServers": {
    "mcp-gateway": {
      "type": "http",
      "url": "http://<YOUR_LAN_IP>:8000/mcp"
    }
  }
}
```

Use `http://localhost:8000/mcp` if client and proxy are on the same machine.

Two things that must be exactly right:
- `"type": "http"` — not `"sse"`, not `"streamable-http"`. Claude Code's string for Streamable HTTP transport is `"http"`. Using `"sse"` skips the OAuth flow and returns `-32000`.
- `"url"` — not `"command"`. The `"command"` field launches a local subprocess. A URL in `"command"` causes Claude Code to try to execute it as a process.

### What happens on first connection

1. Claude Code sends a request to `/mcp` and receives `401 Unauthorized` with `WWW-Authenticate: Bearer resource_metadata="http://<YOUR_LAN_IP>:8000/.well-known/oauth-protected-resource"`.
2. Claude Code fetches `/.well-known/oauth-protected-resource` — discovers `authorization_servers: ["http://<YOUR_LAN_IP>:8082/realms/mcp"]`.
3. Claude Code fetches `/.well-known/oauth-authorization-server` (proxied from Keycloak) — gets all OAuth 2 endpoints.
4. Claude Code POSTs to `/oauth/register` — receives the pre-registered `claude-code` public client ID (no secret).
5. Claude Code opens your browser to Keycloak at `http://<YOUR_LAN_IP>:8082`.
6. Log in as alice, bob, or carol with `labpassword`.
7. Keycloak redirects to a `localhost:<ephemeral-port>/callback` listener that Claude Code started — the token is captured in memory. Nothing is persisted to disk.

For the full verification command sequence and troubleshooting table, see the [Connecting Claude Code](README.md#connecting-claude-code-to-this-proxy) section of the README.

---

## 7. Running the test suite

> **`make` vs `make -f Makefile.lab`:** lab *lifecycle* targets (`lab-up`, `lab-down`, `lab-smoke`,
> `lab-init`, `lab-test`, …) live in `Makefile.lab` and need `-f Makefile.lab`. Everything else
> (`test-all`, `test-red-team`, `assign-role`, `pull-model`) lives in the root `Makefile` and is
> called as bare `make`.

### In-container test suite (unit + integration + security)

Requires the full lab stack to be running (`make -f Makefile.lab lab-up`).

```bash
make test-all
```

This runs inside the proxy container:

```
python -m pytest tests/unit/ tests/integration/ tests/security/ -v --tb=short
```

Expected result: all tests pass (292 pass, 2 skip, 1 xfail as of last baseline).

### Host-side pytest (unit tests only, no running stack needed)

Most unit tests mock their dependencies. You can run them from the host:

```bash
PYTHONPATH=proxy python3 -m pytest proxy/tests/ -v --tb=short -x
```

Integration tests in `proxy/tests/integration/` require a running stack. Export these variables if you want to run them from the host:

```bash
export DB_URL="postgresql+asyncpg://mcp_app:devpassword@localhost:5434/mcp_security"
export REDIS_URL="redis://:devpassword@localhost:6379/0"
export VAULT_ADDR="http://localhost:8201"
export VAULT_TOKEN="lab-root-token"
```

> Note: the lab compose maps the DB to host port `5434` (not `5432`) to avoid conflicts. The Vault host port is `8201`.

Single-file runs:

```bash
PYTHONPATH=proxy python3 -m pytest proxy/tests/test_oidc_browser.py -v
PYTHONPATH=proxy python3 -m pytest proxy/tests/test_admin_credentials.py -v
```

### Lab functional tests

End-to-end functional tests against the live lab stack:

```bash
make -f Makefile.lab lab-test
```

### Red-team (sandbox isolation)

Tests MCP server isolation: verifies that containers cannot reach platform backends (DB, Redis, Vault) directly, cannot reach each other, and cannot escape the sandbox.

```bash
make test-red-team
```

Requires: full lab stack running **and** `sandbox/` container running. The test script at `sandbox/tests/red_team/run_all.sh` also runs `test_mcp_platform_backend_isolation.sh` against the lab MCP servers.

---

## 8. Lab lifecycle commands

All targets use `Makefile.lab`. The underlying compose command is:

```
podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml
```

| Target | Command | What it does |
|---|---|---|
| First-time setup | `make -f Makefile.lab lab-setup` | Start + migrate DB + seed + smoke test (one-stop zero-to-usable) |
| Start stack | `make -f Makefile.lab lab-up` | Build + start + seed (Vault init + DB seeder) |
| Stop stack | `make -f Makefile.lab lab-down` | Stop all containers; volumes preserved |
| Full reset | `make -f Makefile.lab lab-reset` | `down -v` (destroys volumes) then `lab-up`; all data is wiped |
| Reset + setup | `make -f Makefile.lab lab-setup-reset` | Full reset then zero-to-usable setup |
| Seed only | `make -f Makefile.lab lab-init` | Re-run Vault init + DB seeder (after a restart that cleared Vault dev-mode data) |
| Rebuild changed | `make -f Makefile.lab lab-rebuild` | Rebuild proxy + Grafana + NetBox images, restart only those services, re-seed |
| Follow logs | `make -f Makefile.lab lab-logs` | Tail logs for proxy, Dex, Grafana, NetBox |
| Dex logs only | `make -f Makefile.lab lab-dex-logs` | Tail Dex logs only |
| Container status | `make -f Makefile.lab lab-ps` | Show running status of all lab containers |
| Proxy shell | `make -f Makefile.lab lab-proxy-shell` | `bash` shell inside the proxy container |
| NetBox shell | `make -f Makefile.lab lab-netbox-shell` | `sh` shell inside the NetBox container |
| Smoke test | `make -f Makefile.lab lab-smoke` | Run `lab/scripts/lab-smoke.sh` — expects 7/7 passed |
| Entra check | `make -f Makefile.lab lab-entra-check` | Verify Entra/Graph API connectivity (requires `ENTRA_*` vars) |

**Re-seeding after a restart:** Vault runs in dev mode — all data is in-memory and is lost whenever the Vault container restarts. After any restart that touches Vault, run:

```bash
make -f Makefile.lab lab-init
```

This re-seeds the broker master secret and Gitea admin credentials without restarting the rest of the stack.

---

## 9. Troubleshooting

### Keycloak slow to start

Keycloak 24 runs schema migrations on first boot (30–60 seconds). The compose health check has a `start_period: 60s`. If `lab-up` fails because the seeder timed out waiting for Keycloak to become healthy, wait for Keycloak and re-run the seeder manually:

```bash
until podman healthcheck run lab-keycloak 2>/dev/null | grep -q healthy; do
  echo "Waiting for Keycloak..."
  sleep 5
done
podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  run --rm lab-keycloak-seeder
```

Check Keycloak logs: `podman logs lab-keycloak --tail 50 -f`

### NetBox OOM

If NetBox is killed immediately after starting, the Podman VM is under-resourced:

```bash
podman machine stop
podman machine set --memory 6144 --cpus 6
podman machine start
make -f Makefile.lab lab-up
```

### OIDC login redirects to wrong host

`OIDC_ISSUER_URL` must be the address your **browser** can reach — not a container-internal address. If connecting from another machine on the LAN, set it to `http://<YOUR_LAN_IP>:8082/realms/mcp`.

The internal proxy-to-Keycloak address is set separately as `OIDC_INTERNAL_ISSUER_URL=http://lab-keycloak:8080/realms/mcp` and should not be changed.

After updating `.env.lab`, restart the proxy:

```bash
podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  restart proxy
```

### `PROXY_BASE_URL` not set — OAuth discovery returns `localhost`

If the MCP client is on a different machine and the browser redirect opens `localhost` instead of the LAN IP, `PROXY_BASE_URL` is either unset or set to `localhost`. Set it to `http://<YOUR_LAN_IP>:8000` in `.env.lab` and restart the proxy.

### `-32000` / no browser opens in Claude Code

| Cause | Fix |
|---|---|
| Wrong transport type (`"sse"`) | Change to `"type": "http"` in `~/.claude/settings.json` |
| `PROXY_BASE_URL` not set | Set it and restart the proxy |
| Keycloak not reachable on `:8082` | Check `OIDC_ISSUER_URL` and firewall |
| User has no role assigned | `make assign-role CLIENT_ID=<email> ROLE=agent` |
| Redis error (rate limit fails closed) | Check Redis: `make -f Makefile.lab lab-logs` |

### Session JWT invalid / 401 after proxy restart

The proxy's `PROXY_SECRET_KEY` rotates on container restart in dev mode. Existing session JWTs are invalidated — log in again at `http://localhost:8000/api/v1/auth/oidc/login`.

### Redis stale role cache

The proxy caches role lookups for 5 minutes. After creating a Keycloak user or modifying DB roles:

```bash
# Flush a specific user
podman exec mcp-redis redis-cli -a devpassword DEL "roles:alice"

# Flush all role caches
podman exec mcp-redis redis-cli -a devpassword KEYS "roles:*" \
  | xargs -r podman exec -i mcp-redis redis-cli -a devpassword DEL
```

### Stale OIDC discovery document

The proxy caches the Keycloak discovery document for 5 minutes in Redis. If you restarted Keycloak:

```bash
podman exec mcp-redis redis-cli -a devpassword DEL oidc:discovery
```

### 502 Bad Gateway after proxy restart

Nginx may have cached the old proxy container IP. Restart the gateway:

```bash
podman-compose -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  restart gateway
```

### DB migration status check

```bash
podman exec -i mcp-db psql -U mcp_app -d mcp_security \
  -c "SELECT version, description, installed_on, success FROM schema_version ORDER BY installed_rank;"
```

Expected: V001 through V012 all showing `success = t`. If migrations are missing, re-run `make db-migrate`.

### Checking all container health at once

```bash
make -f Makefile.lab lab-ps
```

All containers should show `Up` or `(healthy)`. A container stuck in `(starting)` more than 2 minutes after `lab-up` has a problem — check its logs:

```bash
podman logs <container-name> --tail 30
```

---

## 10. Further reading

| Document | Contents |
|---|---|
| [INSTALL.md](INSTALL.md) | Production deployment (Docker Compose, Vault HA, TLS, hardening) |
| [SECURITY.md](SECURITY.md) | Security model, threat boundaries, responsible disclosure |
| [README.md](README.md) | Platform overview, architecture summary, feature matrix |
| [docs/LAB-HOWTO.md](docs/LAB-HOWTO.md) | Detailed lab how-to: Keycloak admin tasks, credential injection per mode, admin credentials UI, OAuth session lifecycle |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Reality-annotated architecture (supersedes v1) |
| [docs/RBAC.md](docs/RBAC.md) | Role model, assignment API, OPA policy details |
| [docs/API.md](docs/API.md) | Full proxy REST API reference |
