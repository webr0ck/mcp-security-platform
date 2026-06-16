# INSTALL.md — Production-Shaped Deployment Guide

> **Honesty notice.** This is a reference implementation and learning project, not an audited
> production security gateway. The word "production" in this guide means "production-*shaped*
> topology": the full enforcement stack (gateway, proxy, OPA, PKI, Vault) running together under
> Docker Compose. It does **not** mean "cleared for production use without further hardening." Read
> the [Pre-production hardening checklist](#pre-production-hardening-checklist) and
> [docs/SECURITY_NONNEGATABLES.md](docs/SECURITY_NONNEGATABLES.md) before putting this in front of
> real traffic.

**Who this guide is for:** operators who bring their own infrastructure — their own IDP
(Keycloak/Entra/Okta/Auth0), their own SIEM/log collector, and their own MCP servers — and want to
run the engine tier as a security proxy in front of them.

> **Docker vs Podman:** Production tiers (`compose.engine.yml`, `compose.standard.yml`,
> `compose.poc.yml`) run on **Docker Compose v2.20+**. The testing lab runs on **Podman** and is
> documented separately in [LAB.md](LAB.md). Do not mix runtimes.

---

## Contents

1. [Prerequisites](#prerequisites)
2. [Quick install — engine tier](#quick-install--engine-tier)
3. [Bring your own infrastructure](#bring-your-own-infrastructure)
4. [Pre-production hardening checklist](#pre-production-hardening-checklist)
5. [Verifying the install](#verifying-the-install)
6. [Further reading](#further-reading)

---

## Prerequisites

| Tool | Minimum version | Notes |
|---|---|---|
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | **v2.20+** | Required for the `include:` directive used by all tier files. `docker compose version` |
| `openssl` | any modern | For generating secrets |
| `psql` (PostgreSQL client) | 14+ | Required by `infra/scripts/create-bootstrap-key.sh` |

The host running the stack must be able to reach any external IDP issuer URL (for OIDC token
validation) and, if using the Filebeat overlay, your SIEM ingest endpoint.

---

## Quick install — engine tier

The `engine` tier is the minimal core: nginx+ModSecurity gateway, FastAPI security proxy, OPA
policy engine, PostgreSQL, Redis, Vault, and step-ca (mTLS CA). No bundled IDP, no bundled
observability stack, no demo MCP servers.

```bash
# 1. Copy the environment template
cp deployments/engine/.env.example .env

# 2. Fill every REQUIRED value.
#    Generate secrets with openssl:
openssl rand -hex 32   # run once per variable below

# Required secrets to set in .env:
#   DB_PASSWORD
#   REDIS_PASSWORD
#   PROXY_SECRET_KEY
#   API_KEY_HMAC_KEY
#   SBOM_SIGNING_KEY
#   AUDIT_LOG_HMAC_KEY
#   OAUTH_STATE_SECRET
#   VAULT_TOKEN

# 3. Run the init script.
#    Safe to re-run — it never overwrites existing values.
#    Generates ADMIN_PASSWORD once and prints it. Save the output.
bash scripts/init-engine.sh

# 4. Start the stack
docker compose -f compose.engine.yml up -d

# 5. Confirm all containers are healthy
docker compose -f compose.engine.yml ps

# 6. Generate the bootstrap API key (requires psql)
#    Replace <your-db-password> with the value you set for DB_PASSWORD in .env
PGHOST=localhost PGPORT=5432 PGDATABASE=mcp_security \
PGUSER=mcp_app PGPASSWORD=<your-db-password> \
bash infra/scripts/create-bootstrap-key.sh
```

`create-bootstrap-key.sh` prints the raw key **once** and does not store it. Save it immediately.
Use it to create per-user API keys, then revoke the bootstrap key.

The admin panel is available at `https://localhost/admin` (LAN-only — RFC-1918 enforced by nginx).
Credentials: `admin` / the `ADMIN_PASSWORD` value printed in step 3.

---

## Bring your own infrastructure

The engine tier is designed to integrate with external infrastructure via environment variables and
overlay compose files. All integrations are optional unless noted.

### Your own IDP (OIDC)

Any OIDC-compliant provider works: Keycloak, Microsoft Entra ID, Okta, Auth0, Dex.

Set the following in `.env`, then restart the proxy:

```bash
docker compose -f compose.engine.yml restart proxy
```

| Variable | Required | Example | Notes |
|---|---|---|---|
| `OIDC_ENABLED` | yes | `true` | Enables the OIDC auth path |
| `OIDC_ISSUER_URL` | yes | `https://your-idp.example.com/realms/mcp` | Must be reachable from the proxy container |
| `OIDC_CLIENT_ID` | yes | `mcp-security-platform` | |
| `OIDC_CLIENT_SECRET` | yes | `<secret>` | |
| `OIDC_AUDIENCE` | yes | `mcp-security-platform` | **Required in production.** Startup is blocked if unset when `ENVIRONMENT=production` |
| `OIDC_ROLE_CLAIM_PATH` | no | `roles` | JWT claim path for role extraction |
| `OIDC_REDIRECT_URI` | yes | `https://<YOUR_LAN_IP>/api/v1/auth/oidc/callback` | Must be registered in your IDP |

> **Security note (F-001).** The proxy currently trusts the gateway-set `X-Client-Cert-CN` header
> for client identity. This is only safe when nginx is the **sole** network path to the proxy
> container. See [Pre-production hardening checklist](#pre-production-hardening-checklist) for
> details.

---

### Your own SIEM / log collector

Use the `compose.logging-agent.yml` Filebeat sidecar overlay. It ships `mcp-proxy` container logs
to your external Elastic, Logstash, Splunk, or OpenSearch endpoint.

```bash
# Attach to the engine tier
FILEBEAT_OUTPUT_HOSTS=logstash:5044 \
FILEBEAT_OUTPUT_TYPE=logstash \
  docker compose -f compose.engine.yml -f compose.logging-agent.yml up -d

# Or for Elasticsearch output
FILEBEAT_OUTPUT_HOSTS=es01:9200 \
FILEBEAT_OUTPUT_TYPE=elasticsearch \
FILEBEAT_USERNAME=filebeat_writer \
FILEBEAT_PASSWORD=<password> \
  docker compose -f compose.engine.yml -f compose.logging-agent.yml up -d
```

| Variable | Default | Notes |
|---|---|---|
| `FILEBEAT_OUTPUT_HOSTS` | `logstash:5044` | Target host:port |
| `FILEBEAT_OUTPUT_TYPE` | `logstash` | `logstash` or `elasticsearch` |
| `FILEBEAT_USERNAME` | _(empty)_ | Elasticsearch only |
| `FILEBEAT_PASSWORD` | _(empty)_ | Elasticsearch only |

The Filebeat sidecar filters to `mcp-proxy` container logs only. Other containers (gateway, OPA,
Vault) are dropped client-side.

---

### Your own MCP servers

`mcps.yaml` is **deprecated**. The database `server_registry` table is the authoritative source of
truth (30-second auto-refresh). Register servers via the onboarding script:

```bash
# Minimal onboarding — no credential injection
make onboard-server URL=https://your-mcp-server.example.com MODE=none NAME=my-service

# With service-account credential injection
make onboard-server URL=https://your-mcp-server.example.com MODE=service NAME=my-service

# Available MODE values:
#   none                    — no credential injection
#   service                 — injects a service credential from the credential store
#   user                    — per-user credential injection
#   service_account         — Keycloak client credentials
#   oauth_user_token        — RFC 8693 token exchange (direct-OIDC callers)
#   entra_client_credentials — Entra client credentials (Vault-backed)
#   entra_user_token        — delegated MS Graph (wired but not yet settable via API)
```

The script (`scripts/onboard_server.py`) drives a D3 dual-control workflow:
- Steps 1–2 (register + consent) and Step 6 (grant entitlements) use a **server owner** credential
  (`$OWNER_TOKEN` env var, `--owner-token` flag, or interactive prompt).
- Steps 3–5 (approve, discover tools, activate tools) use a **platform admin** credential
  (`$ADMIN_TOKEN` env var, `--admin-token` flag, or interactive prompt).

Single-person approval is intentionally blocked by the consent-token handoff. Tokens are never
echoed to stdout.

---

### Your own audit object store (S3-compatible WORM)

To replace the bundled MinIO with an external S3-compatible store, set these in `.env`:

| Variable | Notes |
|---|---|
| `AWS_ACCESS_KEY_ID` | |
| `AWS_SECRET_ACCESS_KEY` | |
| `AWS_REGION` | e.g. `ap-southeast-1` |
| `S3_AUDIT_BUCKET` | Target bucket name |

> **Note on WORM status.** The bundled MinIO uses GOVERNANCE retention mode, which is not
> tamper-proof WORM. For genuine immutability, use an external bucket with COMPLIANCE mode and
> object lock enabled. See the Enforced vs Roadmap table in `README.md`.

---

### Alerting

Set webhook URLs in `.env` before starting the stack:

| Variable | Purpose |
|---|---|
| `ALERT_WEBHOOK_URL` | General alert webhook (Slack, Teams, PagerDuty) |
| `ALERT_WEBHOOK_URL_CRITICAL` | High-severity alert webhook |
| `GF_ALERTING_WEBHOOK_URL` | Grafana alerting contact point (standard/poc tiers) |

> **The default values are placeholders that silently drop all alerts.** If these are not set to
> real endpoints before going live, you will receive no operational alerts.

---

### Assigning roles

Roles: `admin`, `agent`, `auditor`, `readonly`.

```bash
make assign-role CLIENT_ID=agent-001 ROLE=agent
make assign-role CLIENT_ID=alice ROLE=auditor
```

This performs an upsert into the `role_assignments` table and is idempotent.

---

## Deployment tiers

| Compose file | What it adds | When to use |
|---|---|---|
| `compose.engine.yml` | Core stack only: gateway, proxy, OPA, PostgreSQL, Redis, Vault, step-ca | Bring-your-own-IDP production path |
| `compose.standard.yml` | Engine + bundled Keycloak + Loki/Promtail/Grafana | Evaluation or dev where you want built-in OIDC and observability |
| `compose.poc.yml` | Standard + Wazuh SIEM + demo MCP servers + demo users (alice/bob/carol) | Full local POC or demo only — not suitable for production |

Each tier file uses the `include:` directive (requires Docker Compose v2.20+) to layer on the tier
below it.

---

## Pre-production hardening checklist

These are the known gaps between the current reference implementation and production-hardened
operation. The authoritative source of truth is the **Enforced today vs Roadmap** table in
`README.md` and `docs/SECURITY_NONNEGATABLES.md`.

| # | Item | Status | Action |
|---|---|---|---|
| H-01 | **F-001: X-Client-Cert-CN trust** | Known gap | The proxy trusts the `X-Client-Cert-CN` header set by the gateway. This is safe *only* when nginx is the sole network path to the proxy container. Set `GATEWAY_SECRET` and ensure no other container or host-port can reach `proxy:8000` directly. Validate with `python3 scripts/check_network_isolation.py`. |
| H-02 | **F-001 isolation gate scope** | Known gap | `make security-check` scans `docker-compose.yml` (the lab base file) for network isolation — it does **not** scan the tier compose files you actually deploy. Run `python3 scripts/check_network_isolation.py compose.engine.yml` (or your tier file) manually and confirm no violations. |
| H-03 | **OPA bundle signing** | Requires action | Set `ENVIRONMENT=production` and `POLICY_SIGNING_KEY` before deploying. The default lab stack auto-signs bundles; in production, ensure `make security-check` passes the `check_signed_default.sh` gate (INV-012). |
| H-04 | **Bundled Keycloak (`standard` tier) runs `start-dev`** | Not for production | The bundled Keycloak uses in-memory H2 storage — realm configuration and user accounts are **lost on restart**. For production, use an external Keycloak with a real Postgres backend and the `start` command (not `start-dev`). Use the engine tier with your external IDP instead. |
| H-05 | **Bundled Vault runs in dev mode** | Not for production | The Vault instance in the bundled stacks runs in dev mode (in-memory, no seal, auto-unseal). All secrets are lost on restart. For production, use an external production-configured Vault and point `VAULT_ADDR` / `VAULT_TOKEN` at it. |
| H-06 | **Alerting webhooks are placeholders** | Requires action | `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_URL_CRITICAL`, and `GF_ALERTING_WEBHOOK_URL` default to placeholder URLs that drop all alerts silently. Set real endpoints before operating. |
| H-07 | **MinIO GOVERNANCE retention is not WORM** | Known gap | GOVERNANCE retention can be overridden by privileged accounts. For genuine immutability of audit logs, use an external S3 bucket with COMPLIANCE mode and object lock. |
| H-08 | **Container image pinning** | Requires action | Some images in the compose files use `:latest` or floating version tags. Pin all images to immutable `@sha256:<digest>` references before production deployment. |
| H-09 | **`OIDC_AUDIENCE` must be set in production** | Enforced | Proxy startup is blocked if `OIDC_AUDIENCE` is unset when `ENVIRONMENT=production`. Do not set `ENVIRONMENT=production` before setting this value. |
| H-10 | **Bootstrap API key** | Requires action | Revoke the bootstrap key (`client_id = 'bootstrap'`) after creating per-user API keys. It has unrestricted access and exists only for initial setup. |
| H-11 | **`compose.poc.yml` has no TLS/mTLS/WAF** | By design | The POC tier ships without the gateway/WAF/TLS stack to simplify demo setup. Do not use it as a production baseline. |

---

## Verifying the install

### Health check

```bash
make health
```

This hits the proxy health endpoints and (if running the standard/poc tier) the Grafana API health
endpoint. All responses must return HTTP 200.

### Security gate

```bash
make security-check
```

Runs the machine-verifiable invariant suite: OPA deny-default check (INV-003), PII redaction
tests (INV-002), signed OPA bundle check (INV-012), secret-in-env scan, and the network isolation
check. All gates must pass before operating.

### Network isolation check

```bash
python3 scripts/check_network_isolation.py

# Or pass your actual tier file explicitly:
python3 scripts/check_network_isolation.py compose.engine.yml
```

Resolves the compose topology statically (no daemon required) and verifies that MCP server
containers cannot reach platform backend networks directly. Exit code 0 = all checks pass.

---

## Further reading

- [LAB.md](LAB.md) — full self-contained test lab on Podman (includes all three demo MCP servers,
  Wazuh, Keycloak, and the complete test suite)
- [docs/SECURITY_NONNEGATABLES.md](docs/SECURITY_NONNEGATABLES.md) — enforcement status of all
  security invariants (INV-001 through INV-012), the authoritative source on what is and is not
  machine-verified today
- [README.md](README.md) — architecture overview, the Enforced vs Roadmap table, and the honesty
  notice on what this project is and is not
- [deployments/engine/README.md](deployments/engine/README.md) — engine-tier quick reference
