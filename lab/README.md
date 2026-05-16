# MCP Security Platform — Lab Environment

Full Podman-based lab stack with a local OIDC provider (Dex), real upstream targets (Grafana, NetBox), and optional Entra test tenant integration via Graph API.

## Architecture

```
Podman (internal-net)          existing stack
Podman (observability-net)     existing stack
Podman (vault-net)             existing stack

Podman (lab-net)               real upstream targets + local IdP
├── lab-dex          local OIDC IdP (Dex, static users: alice/bob)
├── lab-grafana      real Grafana  (Approach B — SA token provisioning)
├── lab-netbox       real NetBox   (Approach B — API token provisioning)
├── lab-netbox-db    PostgreSQL for NetBox
├── lab-netbox-redis Redis for NetBox
└── lab-seeder       one-shot: Vault seed + DB tool records + service tokens

External (no tunnel needed)
└── Entra tenant     client_credentials via Graph API (PowerShell/Terraform)
                     managed with lab/terraform/entra/
```

The lab compose is a third overlay on top of the existing stack:

```bash
podman compose \
  -f docker-compose.yml \
  -f docker-compose.dev.yml \
  -f podman-compose.lab.yml \
  up -d
```

The `Makefile.lab` wraps this into simple targets.

## Prerequisites

- Podman 4.4+ with `podman compose`
- Python 3.12+
- `curl`, `jq`, `openssl`
- (Optional) Terraform 1.6+ for Entra app registration

## Quick Start

```bash
# 1. Copy and fill in lab environment variables
cp .env.lab.example .env.lab
# Edit .env.lab — defaults work for local services, Entra fields are optional

# 2. Start the full lab stack (~3 min on first run — image pulls)
make -f Makefile.lab lab-up

# 3. Verify everything is working
make -f Makefile.lab lab-smoke
```

## Environment Variables

Copy `.env.lab.example` to `.env.lab`. The file is self-documented. Key variables:

| Variable | Default | Notes |
|---|---|---|
| `LAB_GRAFANA_ADMIN_PASSWORD` | `labpassword` | Grafana admin password |
| `LAB_NETBOX_DB_PASSWORD` | `labpassword` | NetBox PostgreSQL password |
| `LAB_NETBOX_SECRET_KEY` | (placeholder) | Must be 50+ chars |
| `LAB_NETBOX_ADMIN_PASSWORD` | `labpassword` | NetBox superuser password |
| `GRAFANA_ADMIN_TOKEN` | (empty) | Filled by `lab-init` after Grafana SA creation |
| `NETBOX_ADMIN_TOKEN` | (empty) | Filled by `lab-init` after NetBox token creation |
| `VAULT_TOKEN` | `lab-root-token` | Vault dev mode root token |
| `ENTRA_TENANT_ID` | (empty) | Optional — for Graph API tests |
| `ENTRA_CLIENT_ID` | (empty) | Optional — from Terraform output |
| `ENTRA_CLIENT_SECRET` | (empty) | Optional — from Terraform output |

## Makefile Targets

Run with `make -f Makefile.lab <target>`.

| Target | Description |
|---|---|
| `lab-up` | Start full lab stack, build images, run init |
| `lab-down` | Stop lab containers (volumes preserved) |
| `lab-reset` | Full reset: stop + destroy volumes + restart |
| `lab-rebuild` | Rebuild only proxy + lab images, re-seed, no infra restart |
| `lab-init` | Idempotent: seed Vault KV + insert DB test data |
| `lab-test` | Run integration test suite against live stack |
| `lab-smoke` | E2E smoke: health + tool call + OPA deny + Dex redirect |
| `lab-logs` | Tail proxy + Dex + Grafana + NetBox logs |
| `lab-dex-logs` | Tail Dex logs only |
| `lab-ps` | Show running container status |
| `lab-entra-check` | Validate Entra env vars and test client_credentials flow |
| `lab-vault-init` | Re-run Vault KV initialization only |
| `lab-proxy-shell` | Shell into the proxy container |
| `lab-netbox-shell` | Shell into the NetBox container |

## Services

### Dex — Local OIDC Provider

Exposes a full OAuth2/OIDC authorization_code flow entirely on localhost — no tunnel needed.

- URL: `http://localhost:5556/dex`
- Client ID: `mcp-proxy` / Secret: `mcp-proxy-secret`
- Redirect URI: `http://localhost:8000/auth/callback/dex`
- Test users (password: `labpassword`):
  - `alice@corp` — role: operator
  - `bob@corp` — role: auditor

To enroll a user via the proxy:

```
GET http://localhost:8000/auth/enroll/dex
Headers: X-Session-Id: sess-1, X-Client-Cert-CN: alice@corp
→ 302 redirect to Dex login page
→ login with alice@corp / labpassword
→ Dex redirects to /auth/callback/dex
→ proxy exchanges code, encrypts refresh token, stores in DB
```

If login fails with "Invalid credentials", regenerate the bcrypt hash in `lab/dex/config.yaml`:

```bash
htpasswd -nbBC 10 "" labpassword | tr -d ':\n'
```

Replace both `hash:` values in `config.yaml` and restart: `podman compose ... restart lab-dex`.

### Grafana — Approach B Target

- URL: `http://localhost:3001` (host) / `http://lab-grafana:3000` (internal)
- Admin: `admin` / `labpassword`
- The seeder creates a service account and prints `GRAFANA_ADMIN_TOKEN=<key>` — copy this to `.env.lab`
- Credential flow: proxy calls `GrafanaAdapter.provision()` → creates per-user named SA token → injects as `Authorization: Bearer <token>`

### NetBox — Approach B Target

- URL: `http://localhost:8080` (host) / `http://lab-netbox:8080` (internal)
- Admin: `admin@lab.local` / `labpassword`
- Takes ~60s to start (Django migrations run on first boot)
- Set `LAB_NETBOX_ADMIN_TOKEN` in `.env.lab` after first start, then re-run `lab-init`

### Vault

Runs in dev mode (auto-unsealed). The `vault-init.sh` script enables KV v2 and writes the broker master secret. Data is lost on container restart — re-run `make -f Makefile.lab lab-init` after any restart.

## Test Scenarios

### Approach B — Grafana token injection

```bash
curl -s -X POST http://localhost:8000/api/v1/tools/invoke \
  -H "X-Client-Cert-CN: alice@corp" \
  -H "Content-Type: application/json" \
  -d '{"tool_name":"grafana-query","jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}'
# Response includes meta.audit_id
```

The proxy resolves credentials via `GrafanaAdapter.provision()`, injects `Authorization: Bearer <token>`, forwards to `lab-grafana:3000/mcp`, and zeroes the token after the call.

### Approach A — Dex OAuth enrollment + tool call

1. Open browser: `http://localhost:8000/auth/enroll/dex` (with mTLS headers via dev proxy)
2. Log in as `alice@corp` / `labpassword`
3. Callback completes — encrypted refresh token stored in DB
4. Invoke tool — proxy decrypts, calls `DexAdapter.refresh()`, injects bearer token

### Quarantine block

```bash
# Quarantine a tool
curl -X PUT http://localhost:8000/api/v1/tools/<tool_id>/status \
  -d '{"status":"quarantined"}'

# Invoke it — blocked before OPA runs
curl -X POST http://localhost:8000/api/v1/tools/invoke ...
# → 403 ToolQuarantinedError, audit event with outcome=deny
```

### Run all smoke tests

```bash
make -f Makefile.lab lab-smoke
```

## Entra Integration (Optional)

For Microsoft Graph API testing using a service principal (client_credentials flow — no browser redirect needed).

### 1. Provision with Terraform

```bash
cd lab/terraform/entra
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars: fill in tenant_id

terraform init
terraform apply

# Copy outputs to .env.lab
terraform output env_lab_snippet
terraform output -raw client_secret   # sensitive
```

### 2. Verify connectivity

```bash
make -f Makefile.lab lab-entra-check
```

This validates env vars, acquires a client_credentials token, and hits `https://graph.microsoft.com/v1.0/organization`.

### Terraform resources created

- App registration (`mcp-security-lab`, single-tenant)
- Service principal
- Client secret (1-year expiry by default)
- Graph API role assignments: `User.Read.All`, `Mail.Read`, `Calendars.Read` with admin consent

No redirect URI is registered — this app uses `client_credentials` only.

## Database Migration

`V007__tool_credential_columns.sql` adds four columns to `tool_registry`:

| Column | Type | Purpose |
|---|---|---|
| `service_name` | `VARCHAR(64)` | Maps tool to broker adapter key |
| `credential_approach` | `CHAR(1)` | `'A'` or `'B'` |
| `inject_header` | `VARCHAR(128)` | e.g. `Authorization` |
| `inject_prefix` | `VARCHAR(64)` | e.g. `Bearer ` or `Token ` |

Run migrations before seeding: `make db-migrate` (from main Makefile).

## Iterate Workflow

For any code change:

```bash
make -f Makefile.lab lab-rebuild   # rebuilds changed images, re-seeds
make -f Makefile.lab lab-test      # integration tests against live stack
make -f Makefile.lab lab-smoke     # E2E credential flow
```

OPA policy changes take effect immediately (bind-mounted with `--watch`). No restart needed.

## File Structure

```
lab/
├── dex/
│   ├── config.yaml          Dex OIDC config (static users, mcp-proxy client)
│   └── .gitignore
├── scripts/
│   ├── vault-init.sh        Idempotent Vault KV setup
│   ├── lab-smoke.sh         E2E smoke test (4 scenarios)
│   └── entra-check.sh       Validate Entra connectivity
├── seeder/
│   ├── Dockerfile
│   ├── seed.py              Vault + DB + Grafana SA + NetBox token seeding
│   └── sql/
│       ├── tools.sql        Test tool_registry rows
│       └── roles.sql        Test RBAC assignments
└── terraform/
    └── entra/
        ├── main.tf          App registration + SP + role assignments
        ├── variables.tf
        ├── outputs.tf       client_id, client_secret, env_lab_snippet
        ├── terraform.tfvars.example
        └── .gitignore

podman-compose.lab.yml       Lab service overlay
Makefile.lab                 Lab-specific make targets
.env.lab.example             Environment variable template
infra/db/migrations/
└── V007__tool_credential_columns.sql
proxy/app/credential_broker/adapters/
└── dex.py                   DexAdapter (authorization_code flow)
```
