# DevOps Log — Lab Bring-Up
Date: 2026-05-01

## Environment
- Podman version: 5.8.2
- Machine: podman-machine-default (applehv, 6 CPUs, 2GiB RAM, 100GiB disk)
- Machine status: running
- Compose provider: /usr/local/bin/docker-compose (external, called via podman compose)
- Project root: /Users/webr0ck/Code/mcp-security-platform

---

## .env.lab Audit

### Missing variables added
The following variables were absent or needed correction:

| Variable | Value Added |
|----------|-------------|
| `LAB_NETBOX_SECRET_KEY` | `lab-netbox-secret-key-minimum-50-chars-change-in-prod` (replaced too-short default) |
| `GRAFANA_ADMIN_TOKEN` | `placeholder` (was empty/whitespace — filled by lab-init after Grafana SA creation) |
| `NETBOX_ADMIN_TOKEN` | `placeholder` (was empty/whitespace — filled by lab-init after NetBox token creation) |
| `GRAFANA_ADMIN_PASSWORD` | `labpassword` (missing entirely) |
| `STEP_CA_PROVISIONER_PASSWORD` | `labpassword` (missing entirely) |

Also created a `.env` symlink pointing to `.env.lab` so services with `env_file: - .env` in `docker-compose.yml` can resolve their variables.

### Variables already present
The following required variables were already set (values not shown):
- `DB_PASSWORD`
- `REDIS_PASSWORD`
- `PROXY_SECRET_KEY`
- `VAULT_TOKEN`
- `BROKER_MASTER_SECRET_PATH`
- `LAB_GRAFANA_ADMIN_PASSWORD`
- `LAB_NETBOX_DB_PASSWORD`
- `LAB_NETBOX_REDIS_PASSWORD`
- `LAB_NETBOX_ADMIN_PASSWORD`
- `OAUTH_STATE_SECRET`
- `MINIO_ROOT_USER`
- `MINIO_ROOT_PASSWORD`

### Missing variable not in task spec (noted)
- `STEP_CA_PROVISIONER_NAME` — referenced in docker-compose.yml but not in .env.lab. Compose warns "defaulting to blank string" on every run. Not breaking for the lab services started.

---

## Prerequisite Fixes Applied

### 1. Missing external Podman networks
`podman-compose.lab.yml` declares two external networks that must be pre-created:
```
podman network create --internal mcp-security-platform_vault-net
podman network create --internal mcp-security-platform_internal-net
```
Both created successfully before first bring-up attempt.

### 2. Proxy build context — local `mcp-audit-logger` dependency
`proxy/pyproject.toml` depends on `mcp-audit-logger` which lives at
`observability/mcp-audit-logger/` (not on PyPI). Original Dockerfile only copied
`proxy/pyproject.toml` with context `./proxy` — the local package was unreachable.

**Fixes applied:**
- `docker-compose.dev.yml`: changed proxy build context to project root (`.`) with
  explicit `dockerfile: proxy/Dockerfile`
- `proxy/Dockerfile`: added `COPY observability/mcp-audit-logger /tmp/mcp-audit-logger`
  and `RUN uv pip install --system --no-cache /tmp/mcp-audit-logger` before proxy deps
- `proxy/pyproject.toml`: added `[tool.hatch.build.targets.wheel] packages = ["app"]`
  so hatchling can locate the `app/` package from WORKDIR `/app`
- Updated `COPY` paths in Dockerfile to use `proxy/app` and `proxy/pyproject.toml`
  (project-root-relative)

### 3. OPA `--bundle` flag syntax error
Original compose command used `"--bundle=/policies"`. OPA 0.63's `--bundle` flag is
boolean — the value must be a separate list entry:
```yaml
- "--bundle"
- "/policies"
```
Fixed in both `docker-compose.yml` and `docker-compose.dev.yml`.

### 4. OPA Rego v1 compatibility errors
Three policy errors prevented OPA from loading:

**anomaly.rego** (2 fixes):
- `default structural_deny_reasons := set()` conflicts with `structural_deny_reasons contains ...` incremental rules in Rego v1. Removed the explicit default (sets are implicitly empty).
- `any([...])` is deprecated in Rego v1. Replaced with partial helper rules `_is_cred_tool(name)` and `_is_exec_tool(name)`.

**tool_risk.rego** (2 fixes):
- `risk_flags := flags if { ... }` (complete rule) combined with `default risk_flags := set()` — conflicting rules. Replaced with `risk_flags := _risk_flag` (one complete rule, no default needed since `_risk_flag` is always defined as a set).
- `any([...])` deprecated calls replaced with partial helper rules: `_is_network_param`, `_is_shell_param`, `_is_cred_param`, `_is_exec_tag`.

### 5. OPA health check — static binary has no shell/curl
OPA `0.63.0-static` is a distroless image with only `/opa`. The compose healthcheck
`["CMD-SHELL", "curl -sf http://localhost:8181/health || exit 1"]` fails because
there is no shell or curl. Changed to `test: ["NONE"]` in `docker-compose.yml`.

Because `proxy` depends on `opa: condition: service_healthy` (which requires a
health check), overrode this in `docker-compose.dev.yml`:
```yaml
proxy:
  depends_on:
    opa:
      condition: service_started
```
OPA health is verified externally via `curl http://localhost:8181/health`.

---

## Service Bring-Up

### Pull results (Task 3)
Images pulled successfully:
- `ghcr.io/dexidp/dex:v2.38.0`
- `docker.io/grafana/grafana-oss:11.0.0`
- `docker.io/grafana/loki:3.0.0`
- `docker.io/grafana/promtail:3.0.0`
- `docker.io/prom/alertmanager:v0.27.0`
- `docker.io/netboxcommunity/netbox:v4.2`
- `docker.io/hashicorp/vault:1.17`
- `docker.io/openpolicyagent/opa:0.63.0-static`
- `docker.io/library/postgres:16-alpine`
- `docker.io/library/redis:7-alpine`
- `docker.io/minio/minio:latest`
- `docker.io/minio/mc:latest`
- `docker.io/owasp/modsecurity-crs:nginx-alpine`
- `docker.io/smallstep/step-ca:latest`
- `docker.io/ollama/ollama:latest`

Images that required local build (expected — denied from registry):
- `mcp-security-proxy:latest` — built from `proxy/Dockerfile` (see fix #2)
- `mcp-compliance-checker:latest` — skipped (not started in this session)

Skipped (build-only, no registry image):
- `lab-seeder` — build context `./lab/seeder`, not started in this session

### Startup sequence

**Phase 1 — Infra services (Task 4)**

Command:
```
podman compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml \
  -f podman-compose.lab.yml up -d --build --remove-orphans \
  db redis vault opa lab-dex lab-grafana lab-netbox-db lab-netbox-redis
```

First attempt failed: `vault-net` and `internal-net` external networks not found.
Created networks manually, second attempt succeeded. All 8 containers started.

Status after 20s:
```
lab-dex            Up  (healthy)
lab-grafana        Up  (healthy)
lab-netbox-db      Up  (healthy)
lab-netbox-redis   Up  (healthy)
mcp-db             Up  (healthy)
mcp-redis          Up  (healthy)
mcp-vault          Up
mcp-opa            Up  (starting — Rego errors, fixed and recreated)
```

**Phase 2 — Remaining services (Task 5)**

Command:
```
podman compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml \
  -f podman-compose.lab.yml up -d proxy lab-netbox
```

Multiple iterations to fix build and OPA issues (see Prerequisite Fixes). Final
startup was clean. `lab-netbox` started immediately (pre-pulled image). Proxy was
built (~3 minutes) then started.

### Final service status (all running)
```
NAME               IMAGE                                         STATUS
lab-dex            ghcr.io/dexidp/dex:v2.38.0                   Up 11+ min
lab-grafana        docker.io/grafana/grafana-oss:11.0.0          Up 11+ min
lab-netbox         docker.io/netboxcommunity/netbox:v4.2         Up 7+ min
lab-netbox-db      docker.io/library/postgres:16-alpine          Up 11+ min
lab-netbox-redis   docker.io/library/redis:7-alpine              Up 11+ min
mcp-db             docker.io/library/postgres:16-alpine          Up 11+ min
mcp-opa            docker.io/openpolicyagent/opa:0.63.0-static   Up ~1 min
mcp-proxy          docker.io/library/mcp-security-proxy:latest   Up ~1 min
mcp-redis          docker.io/library/redis:7-alpine              Up 11+ min
mcp-vault          docker.io/hashicorp/vault:1.17                Up 11+ min
```

---

## Health Check Results

| Service | URL | HTTP Status | Result | Notes |
|---------|-----|-------------|--------|-------|
| proxy | `http://localhost:8000/health/ready` | 200 | `{"ready":true}` | Healthy |
| Dex | `http://localhost:5556/dex/healthz` | 200 | `Health check passed` | Healthy |
| lab-grafana | `http://localhost:3001/api/health` | 200 | `{"database":"ok","version":"11.0.0"}` | Healthy |
| lab-netbox | `http://localhost:8080/api/` | 403 | Auth required | Running — 403 is expected for unauthenticated requests |
| OPA | `http://localhost:8181/health` | 200 | `{}` | Healthy (tested via curl from host) |
| Vault | `http://localhost:8200/v1/sys/health` | N/A | Connection refused | Vault has no host port mapping — internal only. Healthy via `podman exec mcp-vault vault status` |

---

## Vault Init

`vault` CLI is NOT installed on the host. The vault-init.sh script exited with error code 1:
```
[vault-init] ERROR: 'vault' CLI not found on PATH.
Install the HashiCorp Vault CLI: brew install hashicorp/tap/vault
```

**Workaround applied:** Ran vault commands directly via `podman exec mcp-vault`:
```
vault secrets enable -path=secret kv-v2  (already enabled — idempotent, skipped)
vault kv put secret/mcp/broker-master key=<random-32-bytes>
vault kv put secret/mcp/lab-config grafana_url=http://lab-grafana:3000 \
  netbox_url=http://lab-netbox:8080
```

Both secrets written successfully:
- `secret/data/mcp/broker-master` (version 1)
- `secret/data/mcp/lab-config` (version 1)

---

## Issues Found

### P1 — OPA health check prevents proxy startup (FIXED)
OPA static binary has no shell/curl for in-container health checks. The `service_healthy`
dependency in proxy's `depends_on` blocked startup indefinitely.
**Fix applied:** `test: ["NONE"]` in docker-compose.yml + `condition: service_started`
override in docker-compose.dev.yml.

### P1 — Rego v1 policy errors in anomaly.rego and tool_risk.rego (FIXED)
Three incompatibility issues with OPA 0.63 + `import rego.v1`:
1. `default` on incremental set rules conflicts with `contains` rules
2. `any([...])` deprecated in Rego v1
3. Complete rule + default rule conflict in `risk_flags`
**Fix applied:** See Prerequisite Fixes section #4.

### P2 — Proxy build fails: mcp-audit-logger not on PyPI (FIXED)
Local package only. Build context needed to be project root.
**Fix applied:** See Prerequisite Fixes section #2.

### P2 — OPA --bundle flag syntax wrong in compose files (FIXED)
`"--bundle=/policies"` is invalid for a boolean flag.
**Fix applied:** See Prerequisite Fixes section #3.

### P3 — `vault` CLI not installed on host
`vault-init.sh` requires the vault CLI. Workaround via `podman exec` works for lab.
**Recommendation:** `brew install hashicorp/tap/vault` or add vault CLI to lab prereqs doc.

### P3 — `STEP_CA_PROVISIONER_NAME` not set
Compose warns on every invocation. The step-ca service was not brought up in this
session (not in scope). Add `STEP_CA_PROVISIONER_NAME=lab-provisioner` to `.env.lab`
if step-ca is needed.

### P3 — Vault has no host port mapping
`http://localhost:8200/v1/sys/health` returns connection refused. Vault is internal-only
by design. To access from host for debugging:
```
podman exec mcp-vault vault status -address=http://localhost:8200
```
Or add a port mapping in a local override compose file:
```yaml
services:
  vault:
    ports:
      - "8200:8200"
```

### P4 — lab-seeder and compliance-checker not started
`lab-seeder` (seeds Vault/Grafana/NetBox) and `mcp-compliance-checker` were not
brought up in this session. Seeder requires all health checks to pass; compliance
checker requires minio. These can be started after minio is available.

---

## What's Working

- `mcp-proxy` — FastAPI proxy at http://localhost:8000, responds `{"ready":true}`
- `lab-dex` — OIDC provider at http://localhost:5556/dex
- `lab-grafana` — Grafana at http://localhost:3001 (admin/labpassword)
- `lab-netbox` — NetBox IPAM at http://localhost:8080 (admin/labpassword)
- `mcp-db` — PostgreSQL on localhost:5432 (mcp_app/devpassword)
- `mcp-redis` — Redis on localhost:6379
- `mcp-vault` — Vault dev mode, initialized, KV secrets written
- `mcp-opa` — OPA server at http://localhost:8181, policies loaded, healthy

---

## Next Steps Required

1. **Install vault CLI on host:** `brew install hashicorp/tap/vault`
   Then run: `cd /Users/webr0ck/Code/mcp-security-platform && bash lab/scripts/vault-init.sh`

2. **Add STEP_CA_PROVISIONER_NAME to .env.lab** to silence compose warnings:
   ```
   STEP_CA_PROVISIONER_NAME=lab-provisioner
   ```

3. **Run lab-seeder** after all services are healthy:
   ```
   podman compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml \
     -f podman-compose.lab.yml up lab-seeder
   ```
   Seeder populates Vault with service credentials, creates Grafana SA token, and
   creates NetBox admin token — updates GRAFANA_ADMIN_TOKEN and NETBOX_ADMIN_TOKEN
   in .env.lab.

4. **Expose Vault to host** (optional, for CLI debugging):
   Create `podman-compose.local.yml` with:
   ```yaml
   services:
     vault:
       ports:
         - "8200:8200"
   ```

5. **Start minio and compliance-checker** when needed:
   ```
   podman compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml \
     -f podman-compose.lab.yml up -d minio mcp-minio-init compliance-checker
   ```

6. **Commit Rego and compose fixes to git** — the policy and compose changes are
   functional fixes that should be tracked:
   - `policies/rego/anomaly.rego` — Rego v1 compatibility
   - `policies/rego/tool_risk.rego` — Rego v1 compatibility
   - `docker-compose.yml` — OPA bundle flag + healthcheck fix
   - `docker-compose.dev.yml` — OPA bundle flag + proxy build context + service_started
   - `proxy/Dockerfile` — local package build support
   - `proxy/pyproject.toml` — hatchling packages config

---

## Commands Reference (for re-running)

```bash
# Pre-create external networks (only needed once, idempotent if already exist)
podman network create --internal mcp-security-platform_vault-net 2>/dev/null || true
podman network create --internal mcp-security-platform_internal-net 2>/dev/null || true

# Full lab bring-up
cd /Users/webr0ck/Code/mcp-security-platform
podman compose --env-file .env.lab \
  -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  up -d --build --remove-orphans \
  db redis vault opa lab-dex lab-grafana lab-netbox-db lab-netbox-redis

# Wait ~20s, then add remaining services
podman compose --env-file .env.lab \
  -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml \
  up -d proxy lab-netbox

# Check status
podman compose --env-file .env.lab \
  -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml ps

# Health checks
curl http://localhost:8000/health/ready
curl http://localhost:5556/dex/healthz
curl http://localhost:3001/api/health
curl http://localhost:8181/health
```
