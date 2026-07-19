#!/usr/bin/env bash
# lab/scripts/lab-setup.sh
# Zero-to-usable lab setup. Run once; idempotent on re-runs.
# Usage: bash lab/scripts/lab-setup.sh [--reset] [--skip-smoke]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${PROJECT_ROOT}"

LOG_FILE="${PROJECT_ROOT}/lab/logs/setup-$(date +%Y%m%d-%H%M%S).md"
mkdir -p "${PROJECT_ROOT}/lab/logs"

# ── Argument parsing ─────────────────────────────────────────────────────────
DO_RESET=false
SKIP_SMOKE=false
for arg in "$@"; do
    case "$arg" in
        --reset)      DO_RESET=true ;;
        --skip-smoke) SKIP_SMOKE=true ;;
    esac
done

# ── Logging helpers ──────────────────────────────────────────────────────────
log() { echo "[lab-setup] $*" | tee -a "${LOG_FILE}"; }
log_ok()   { echo "[lab-setup] ✓ $*" | tee -a "${LOG_FILE}"; }
log_warn() { echo "[lab-setup] ⚠ $*" | tee -a "${LOG_FILE}"; }
log_fail() { echo "[lab-setup] ✗ $*" | tee -a "${LOG_FILE}"; }
die()      { log_fail "$*"; exit 1; }

{
echo "# Lab Setup Log — $(date)"
echo ""
} > "${LOG_FILE}"

log "Starting MCP Security Platform lab setup"
log "Project root: ${PROJECT_ROOT}"

# ── Step 1: Prerequisites ────────────────────────────────────────────────────
log "Step 1: Checking prerequisites"

command -v podman >/dev/null 2>&1 || die "podman not found — install Podman Desktop"
command -v curl   >/dev/null 2>&1 || die "curl not found"
command -v jq     >/dev/null 2>&1 || die "jq not found — brew install jq"

# Ensure Podman machine is running (macOS)
if [[ "$(uname)" == "Darwin" ]]; then
    if ! podman machine list --format '{{.Running}}' 2>/dev/null | grep -q "true"; then
        log "Starting Podman machine..."
        podman machine start 2>&1 | tee -a "${LOG_FILE}" || true
        sleep 5
    fi
fi

log_ok "Prerequisites satisfied"

# ── Step 1b: mkcert root CA for end-user distribution ────────────────────────
# lab-certs/server.crt (the leaf cert nginx serves) is generated manually per
# lab/nginx/lab-certs/README.md — this step just also copies the mkcert ROOT
# CA alongside it so the gateway can serve it at /ca.crt for end users on a
# different machine (e.g. Windows/Codex) to trust, without them needing
# mkcert installed themselves. Skips cleanly if mkcert isn't installed or no
# leaf cert has been generated yet.
if command -v mkcert >/dev/null 2>&1 && [[ -f "${PROJECT_ROOT}/lab/nginx/lab-certs/server.crt" ]]; then
    MKCERT_CAROOT="$(mkcert -CAROOT)"
    if [[ -f "${MKCERT_CAROOT}/rootCA.pem" ]]; then
        cp "${MKCERT_CAROOT}/rootCA.pem" "${PROJECT_ROOT}/lab/nginx/lab-certs/mkcert-rootCA.pem"
        log_ok "mkcert root CA copied for /ca.crt distribution"
    fi
fi

# ── Step 2: Environment file ─────────────────────────────────────────────────
log "Step 2: Validating .env.lab"

ENV_LAB="${PROJECT_ROOT}/.env.lab"
ENV_LAB_EXAMPLE="${PROJECT_ROOT}/.env.lab.example"

if [[ ! -f "${ENV_LAB}" ]]; then
    if [[ -f "${ENV_LAB_EXAMPLE}" ]]; then
        cp "${ENV_LAB_EXAMPLE}" "${ENV_LAB}"
        log_warn ".env.lab not found — copied from .env.lab.example. Review before production use."
    else
        die ".env.lab not found and no .env.lab.example to copy from"
    fi
fi

# Auto-fill missing variables with safe defaults
env_set() {
    local key="$1" val="$2"
    if grep -q "^${key}=" "${ENV_LAB}" 2>/dev/null; then
        local current
        current="$(grep "^${key}=" "${ENV_LAB}" | cut -d= -f2-)"
        if [[ -z "${current}" ]]; then
            # Replace empty value
            sed -i.bak "s|^${key}=.*|${key}=${val}|" "${ENV_LAB}" && rm -f "${ENV_LAB}.bak"
            log "  Auto-set ${key}"
        fi
    else
        echo "${key}=${val}" >> "${ENV_LAB}"
        log "  Appended ${key}"
    fi
}

# Ensure critical defaults exist
env_set "LAB_GRAFANA_ADMIN_PASSWORD"  "labpassword"
env_set "LAB_NETBOX_DB_PASSWORD"      "labpassword"
env_set "LAB_NETBOX_REDIS_PASSWORD"   "labpassword"
env_set "LAB_NETBOX_ADMIN_PASSWORD"   "labpassword"
env_set "VAULT_TOKEN"                 "lab-root-token"

# Generate NetBox secret key if missing or placeholder
NB_KEY="$(grep '^LAB_NETBOX_SECRET_KEY=' "${ENV_LAB}" | cut -d= -f2- || true)"
if [[ -z "${NB_KEY}" || "${NB_KEY}" == *change-me* || "${NB_KEY}" == *placeholder* ]]; then
    NEW_KEY="$(openssl rand -hex 40)"
    env_set "LAB_NETBOX_SECRET_KEY" "${NEW_KEY}"
fi

# Generate ops-agent shared secret if missing or placeholder (WS-A). The compose
# files reference it as ${OPS_AGENT_TOKEN:?...} (hard-required, fail-closed), so a
# fresh clone must have a real value here or `lab-up`/`lab-reset` fail at parse.
OPS_TOKEN="$(grep '^OPS_AGENT_TOKEN=' "${ENV_LAB}" | cut -d= -f2- || true)"
if [[ -z "${OPS_TOKEN}" || "${OPS_TOKEN}" == *change-me* || "${OPS_TOKEN}" == *placeholder* ]]; then
    env_set "OPS_AGENT_TOKEN" "$(openssl rand -hex 32)"
fi

# Load env vars into current shell
set -a
# shellcheck disable=SC1090
source "${ENV_LAB}"
set +a

log_ok ".env.lab validated"

# ── Step 3: Optional reset ───────────────────────────────────────────────────
# `podman-compose` (the standalone Python tool), NOT `podman compose` (the
# built-in subcommand) — on this environment `podman compose` shells out to an
# external `/usr/local/bin/docker-compose` v2 binary as a "compose provider",
# which has repeatedly mishandled this repo's compose files during a real
# from-scratch boot: seccomp security_opt paths get corrupted into
# "file name too long" errors, external-network declarations get treated
# inconsistently across -f file merges, and same-named x-* extension fields
# get merged in ways that produce self-conflicting pids_limit/deploy.resources
# values. `podman-compose` does not exhibit any of these — Makefile.lab's
# LAB_COMPOSE already correctly uses it; this was the one place still using
# the buggy alternative.
LAB_COMPOSE="podman-compose --env-file .env.lab -f docker-compose.yml -f docker-compose.dev.yml -f podman-compose.lab.yml"

if [[ "${DO_RESET}" == "true" ]]; then
    log "Step 3: Resetting lab (destroying volumes)"
    ${LAB_COMPOSE} down -v 2>&1 | tee -a "${LOG_FILE}" || true
    log_ok "Volumes destroyed"
else
    log "Step 3: Reset skipped (pass --reset to destroy volumes)"
fi

# ── Step 4: Start infrastructure services ────────────────────────────────────
log "Step 4: Starting infrastructure services"

${LAB_COMPOSE} up -d --build 2>&1 | tee -a "${LOG_FILE}"

# Wait for core services
wait_for_health() {
    local name="$1" url="$2" max="${3:-120}" accept="${4:-200}"
    local elapsed=0
    log "  Waiting for ${name} at ${url} ..."
    until curl -sf -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null | grep -qE "^(${accept})$"; do
        if [[ ${elapsed} -ge ${max} ]]; then
            die "${name} did not become ready within ${max}s"
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log_ok "${name} is ready (${elapsed}s)"
}

# Vault (allow sealed/standby codes too — 200, 429, 472, 473, 501, 503 all mean "running")
log "  Waiting for Vault..."
VAULT_ELAPSED=0
until curl -sf "http://localhost:8200/v1/sys/health" >/dev/null 2>&1; do
    [[ ${VAULT_ELAPSED} -ge 60 ]] && die "Vault did not start within 60s"
    sleep 3; VAULT_ELAPSED=$((VAULT_ELAPSED + 3))
done
log_ok "Vault ready"

wait_for_health "Grafana" "http://localhost:3001/api/health" 120 "200"
# NetBox returns 403 on unauthenticated /api/ — that means it's up
log "  Waiting for NetBox..."
NB_ELAPSED=0
until curl -s "http://localhost:8090/api/" 2>&1 | grep -qiE "Authentication|netbox|detail"; do
    [[ ${NB_ELAPSED} -ge 180 ]] && die "NetBox did not start within 180s"
    sleep 10; NB_ELAPSED=$((NB_ELAPSED + 10))
done
log_ok "NetBox ready (${NB_ELAPSED}s)"

log_ok "All infrastructure services running"

# ── Step 4.5: Set application-role passwords ─────────────────────────────────
# V003/V063/V072 create proxy_app/compliance_checker_app/scanner_worker_app/
# build_worker_app with a literal 'PLACEHOLDER_REPLACED_AT_RUNTIME' password
# (passwords never live in migrations, INV-008) — this step is what actually
# replaces it, via infra/scripts/init-db-roles.sh. WITHOUT this step, every
# fresh boot leaves scanner-worker/build-worker unable to authenticate as
# their narrow DB roles (found by the 2026-07 WP-D3 full-wipe closeout gate —
# an accreted, never-wiped lab masks this because the role's password was set
# once, historically, and persists in the DB volume).
log "Step 4.5: Setting application DB role passwords (init-db-roles.sh)"
podman cp "${SCRIPT_DIR}/../../infra/scripts/init-db-roles.sh" mcp-db:/tmp/init-db-roles.sh
if podman exec \
    -e "PROXY_DB_PASSWORD=${PROXY_DB_PASSWORD:-}" \
    -e "COMPLIANCE_DB_PASSWORD=${COMPLIANCE_DB_PASSWORD:-}" \
    -e "SCANNER_WORKER_DB_PASSWORD=${SCANNER_WORKER_DB_PASSWORD:-}" \
    -e "BUILD_WORKER_DB_PASSWORD=${BUILD_WORKER_DB_PASSWORD:-}" \
    -e "PGPASSWORD=${DB_PASSWORD:-}" \
    mcp-db bash /tmp/init-db-roles.sh 2>&1 | tee -a "${LOG_FILE}"; then
    log_ok "Application DB role passwords set"
else
    die "init-db-roles.sh failed — scanner-worker/build-worker cannot authenticate to Postgres"
fi
# Recreate the workers so their already-correct env-var password now matches
# the DB role's actual password (a plain restart is not enough if the
# container was created before this step ran in the same lab-setup pass).
${LAB_COMPOSE} up -d --force-recreate scanner-worker 2>&1 | tee -a "${LOG_FILE}" || \
    log_warn "scanner-worker recreate failed — check manually"

# ── Step 5: Apply V007 DB migration ─────────────────────────────────────────
log "Step 5: Applying V007 DB migration (credential broker columns)"

# DB connection via docker/podman exec into mcp-db container
DB_CONTAINER="mcp-db"
DB_NAME="${DB_NAME:-mcp_security}"
DB_USER="${DB_USER:-mcp_app}"

V007_SQL="
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='tool_registry' AND column_name='service_name') THEN
        ALTER TABLE tool_registry ADD COLUMN service_name VARCHAR(64);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='tool_registry' AND column_name='credential_approach') THEN
        ALTER TABLE tool_registry ADD COLUMN credential_approach CHAR(1);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='tool_registry' AND column_name='inject_header') THEN
        ALTER TABLE tool_registry ADD COLUMN inject_header VARCHAR(128);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='tool_registry' AND column_name='inject_prefix') THEN
        ALTER TABLE tool_registry ADD COLUMN inject_prefix VARCHAR(64);
    END IF;
END
\$\$;
"

if podman exec "${DB_CONTAINER}" psql -U "${DB_USER}" -d "${DB_NAME}" -c "${V007_SQL}" 2>&1 | tee -a "${LOG_FILE}"; then
    log_ok "V007 migration applied (idempotent)"
else
    log_warn "V007 migration failed — container may not be running yet, continuing"
fi

# ── Step 5.5: Fix self-service upstream_allowlist_entry CIDR placeholder ─────
# PRD-0011 WS-3 (#2) / RCA: V052__self_service_default_seed.sql seeds
# server_registry.self-service.upstream_allowlist_entry as the literal string
# __SELF_SERVICE_UPSTREAM_CIDR_PLACEHOLDER__ (same convention as V002's
# __OIDC_ISSUER_PLACEHOLDER__ — see V052's own header comment). Unlike the OIDC
# issuer, nothing was ever wired to substitute this one: lab/seeder/seed.py only
# has fix_oidc_issuer_placeholder(), no CIDR equivalent, and no other script
# references __SELF_SERVICE_UPSTREAM_CIDR_PLACEHOLDER__ (confirmed by grep).
# Left as-is, every self-service tool call 403s with upstream_revalidation_failed
# on a fresh install (the invoke-time DNS-rebind/TOCTOU guard in
# proxy/app/services/invocation.py treats an unmatched upstream as "public").
#
# The value is the mcp-self-service-net bridge subnet, which podman assigns
# dynamically per-install and must NOT be hardcoded into a shared migration
# (docker's own bridge subnet differs — see V052's header, which documents the
# equivalent manual `docker network inspect` + UPDATE for non-lab installs).
# The network is already created by `compose up` in Step 4 above (podman/
# podman-compose create all declared networks up front, independent of which
# containers manage to start — self-service itself may still be down
# at this point since its SELF_SERVICE_API_KEY isn't seeded until Step 10), so
# the subnet is knowable here.
log "Step 5.5: Fixing self-service upstream_allowlist_entry CIDR placeholder"

# The self-service container's per-network /24 always falls inside podman's
# default 10.89.0.0/16 pool, so the /16 is the stable, proven allowlist value
# (matches the live acceptance-test fix). Override via SELF_SERVICE_UPSTREAM_CIDR
# for a non-default install. The WHERE-guard keeps this idempotent and won't
# clobber a value someone set deliberately.
# ponytail: fixed /16 default; per-net auto-detect only if a deployment ever
# moves off podman's default pool (then set SELF_SERVICE_UPSTREAM_CIDR).
SELF_SERVICE_CIDR="${SELF_SERVICE_UPSTREAM_CIDR:-10.89.0.0/16}"
SELF_SERVICE_CIDR_SQL="UPDATE server_registry SET upstream_allowlist_entry = '${SELF_SERVICE_CIDR}' WHERE name = 'self-service' AND upstream_allowlist_entry = '__SELF_SERVICE_UPSTREAM_CIDR_PLACEHOLDER__';"
if podman exec "${DB_CONTAINER}" psql -U "${DB_USER}" -d "${DB_NAME}" -c "${SELF_SERVICE_CIDR_SQL}" 2>&1 | tee -a "${LOG_FILE}"; then
    log_ok "self-service upstream_allowlist_entry resolved to ${SELF_SERVICE_CIDR} (idempotent — no-op if already set)"
else
    log_warn "Failed to update self-service upstream_allowlist_entry — server_registry row may not exist yet (re-run once V052 has applied); self-service tool calls will 403 upstream_revalidation_failed until this is set"
fi

# ── Step 6: Vault initialization ─────────────────────────────────────────────
log "Step 6: Initializing Vault KV"

bash "${SCRIPT_DIR}/vault-init.sh" 2>&1 | tee -a "${LOG_FILE}"

log_ok "Vault initialized"

# ── Step 7: Provision Grafana service account token ──────────────────────────
log "Step 7: Provisioning Grafana service account token"

GRAFANA_URL="http://localhost:3001"
GRAFANA_ADMIN_USER="${GF_SECURITY_ADMIN_USER:-admin}"
GRAFANA_ADMIN_PASS="${LAB_GRAFANA_ADMIN_PASSWORD:-labpassword}"

# Check if token already exists and is valid
CURRENT_TOKEN="${GRAFANA_ADMIN_TOKEN:-}"
if [[ -n "${CURRENT_TOKEN}" ]]; then
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${CURRENT_TOKEN}" \
        "${GRAFANA_URL}/api/org" 2>/dev/null || echo "000")
    if [[ "${STATUS}" == "200" ]]; then
        log_ok "Grafana token already valid — skipping"
    else
        CURRENT_TOKEN=""
    fi
fi

if [[ -z "${CURRENT_TOKEN}" ]]; then
    # Create service account
    SA_PAYLOAD='{"name":"mcp-lab-sa","role":"Admin","isDisabled":false}'
    SA_RESP=$(curl -sf -X POST "${GRAFANA_URL}/api/serviceaccounts" \
        -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASS}" \
        -H "Content-Type: application/json" \
        -d "${SA_PAYLOAD}" 2>/dev/null || echo '{}')
    SA_ID=$(echo "${SA_RESP}" | jq -r '.id // empty')

    if [[ -z "${SA_ID}" ]]; then
        # SA may already exist — find it
        SA_ID=$(curl -sf "${GRAFANA_URL}/api/serviceaccounts/search?query=mcp-lab-sa" \
            -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASS}" 2>/dev/null \
            | jq -r '.serviceAccounts[0].id // empty')
    fi

    if [[ -z "${SA_ID}" ]]; then
        log_warn "Could not create or find Grafana service account — skipping token"
    else
        # Create token for the SA
        TOKEN_PAYLOAD="{\"name\":\"mcp-lab-token-$(date +%s)\",\"role\":\"Admin\"}"
        TOKEN_RESP=$(curl -sf -X POST "${GRAFANA_URL}/api/serviceaccounts/${SA_ID}/tokens" \
            -u "${GRAFANA_ADMIN_USER}:${GRAFANA_ADMIN_PASS}" \
            -H "Content-Type: application/json" \
            -d "${TOKEN_PAYLOAD}" 2>/dev/null || echo '{}')
        NEW_TOKEN=$(echo "${TOKEN_RESP}" | jq -r '.key // empty')

        if [[ -n "${NEW_TOKEN}" ]]; then
            # Remove old line and append fresh value
            grep -v '^GRAFANA_ADMIN_TOKEN=' "${ENV_LAB}" > "${ENV_LAB}.tmp" && mv "${ENV_LAB}.tmp" "${ENV_LAB}"
            echo "GRAFANA_ADMIN_TOKEN=${NEW_TOKEN}" >> "${ENV_LAB}"
            GRAFANA_ADMIN_TOKEN="${NEW_TOKEN}"
            export GRAFANA_ADMIN_TOKEN
            log_ok "Grafana token provisioned (SA id=${SA_ID})"
        else
            log_warn "Grafana token creation returned empty key: ${TOKEN_RESP}"
        fi
    fi
fi

# ── Step 8: Provision NetBox API token ───────────────────────────────────────
log "Step 8: Provisioning NetBox admin API token"

NETBOX_URL="http://localhost:8090"
NETBOX_ADMIN_USER="admin"
NETBOX_ADMIN_PASS="${LAB_NETBOX_ADMIN_PASSWORD:-labpassword}"

# Check existing token
CURRENT_NB_TOKEN="${NETBOX_ADMIN_TOKEN:-}"
if [[ -n "${CURRENT_NB_TOKEN}" ]]; then
    STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
        -H "Authorization: Token ${CURRENT_NB_TOKEN}" \
        "${NETBOX_URL}/api/dcim/sites/?limit=1" 2>/dev/null || echo "000")
    if [[ "${STATUS}" == "200" ]]; then
        log_ok "NetBox token already valid — skipping"
    else
        CURRENT_NB_TOKEN=""
    fi
fi

if [[ -z "${CURRENT_NB_TOKEN}" ]]; then
    NB_TOKEN_RESP=$(curl -sf -X POST "${NETBOX_URL}/api/users/tokens/provision/" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${NETBOX_ADMIN_USER}\",\"password\":\"${NETBOX_ADMIN_PASS}\"}" \
        2>/dev/null || echo '{}')
    NB_TOKEN=$(echo "${NB_TOKEN_RESP}" | jq -r '.key // empty')

    if [[ -n "${NB_TOKEN}" ]]; then
        grep -v '^NETBOX_ADMIN_TOKEN=' "${ENV_LAB}" > "${ENV_LAB}.tmp" && mv "${ENV_LAB}.tmp" "${ENV_LAB}"
        echo "NETBOX_ADMIN_TOKEN=${NB_TOKEN}" >> "${ENV_LAB}"
        NETBOX_ADMIN_TOKEN="${NB_TOKEN}"
        export NETBOX_ADMIN_TOKEN
        log_ok "NetBox token provisioned"
    else
        log_warn "NetBox token provision failed: ${NB_TOKEN_RESP}"
        log_warn "NetBox may not be fully initialized yet — re-run lab-setup.sh after NetBox starts"
    fi
fi

# ── Step 9: Restart proxy to pick up new tokens ──────────────────────────────
log "Step 9: Restarting proxy with updated credentials"

${LAB_COMPOSE} restart proxy 2>&1 | tee -a "${LOG_FILE}"
sleep 5

# Wait for proxy. SEC-05 ingress allowlist rejects anything that isn't the
# gateway container or true loopback — curling the published host port lands
# as the rootless-podman NAT gateway address, not 127.0.0.1, so probe via
# podman exec instead (that's genuine container-loopback, same as its own
# healthcheck).
log "  Waiting for Proxy..."
PROXY_ELAPSED=0
until podman exec mcp-proxy curl -sf -o /dev/null -w "%{http_code}" "http://localhost:8000/health" 2>/dev/null | grep -qE "^200$"; do
    [[ ${PROXY_ELAPSED} -ge 60 ]] && die "Proxy did not become ready within 60s"
    sleep 5; PROXY_ELAPSED=$((PROXY_ELAPSED + 5))
done
log_ok "Proxy restarted and healthy (${PROXY_ELAPSED}s)"

# Wait for Gitea's admin user (lab/gitea/entrypoint.sh creates it after its own
# health probe passes — first boot does SSH keygen + SQLite init and can take
# a couple minutes, easily longer than everything above this point combined).
# The seeder's create_gitea_token() needs this user to exist or it 401s.
log "  Waiting for Gitea admin user..."
GITEA_ELAPSED=0
until curl -s -u "${GITEA_ADMIN_USER:-gitadmin}:${GITEA_ADMIN_PASSWORD:-labpassword}" \
    "http://localhost:3002/api/v1/user" 2>/dev/null | grep -q '"login"'; do
    if [[ ${GITEA_ELAPSED} -ge 300 ]]; then
        log_warn "Gitea admin user not ready within 300s — gitea token seeding may fail"
        break
    fi
    sleep 10; GITEA_ELAPSED=$((GITEA_ELAPSED + 10))
done
[[ ${GITEA_ELAPSED} -lt 300 ]] && log_ok "Gitea admin user ready (${GITEA_ELAPSED}s)"

# ── Step 10: Run lab seeder ───────────────────────────────────────────────────
log "Step 10: Running lab seeder (tool records + RBAC rows)"

${LAB_COMPOSE} run --rm lab-seeder 2>&1 | tee -a "${LOG_FILE}" || {
    log_warn "Seeder exited non-zero — check logs above for details"
}

log_ok "Seeder complete"

# The seeder writes fresh tokens (GRAFANA_SERVICE_ACCOUNT_TOKEN, GITEA_ADMIN_TOKEN,
# SELF_SERVICE_API_KEY) to .env.lab, but lab-mcp-grafana/lab-mcp-gitea/self-service
# each read a STATIC credential from their own container env at process start — a
# per-request broker-injected header isn't enough for these three (unlike netbox-query,
# which has no static token and needs no recreate). `restart` reuses the existing
# container's already-baked env; only recreating picks up the new .env.lab value.
# self-service missing from this list was the root cause of the
# 2026-07-07 remote-check findings (get_server_scaffold -> scaffold_unavailable,
# submit_mcp_server -> create_failed/unauthenticated): its baked SELF_SERVICE_API_KEY
# no longer matched the DB row the seeder had just (re)written, so every callback
# to /api/v1/design-assist/scaffold and /api/v1/submissions 401'd.
# Re-source .env.lab: compose variable substitution (${GRAFANA_SERVICE_ACCOUNT_TOKEN}
# in podman-compose.lab.yml) prefers THIS PROCESS's already-exported env var over
# --env-file's current file content. Step 2 exported the pre-seeder value; without
# refreshing it here, the recreate below would still resolve to that stale value
# even though .env.lab on disk now has the seeder's fresh one.
set -a
# shellcheck disable=SC1090
source "${ENV_LAB}"
set +a

log "  Recreating lab-mcp-grafana, lab-mcp-gitea, self-service with refreshed tokens..."
${LAB_COMPOSE} up -d --force-recreate --no-deps lab-mcp-grafana lab-mcp-gitea self-service 2>&1 | tee -a "${LOG_FILE}"
log_ok "MCP servers recreated with refreshed credentials"

# ── Step 11: Smoke tests ──────────────────────────────────────────────────────
if [[ "${SKIP_SMOKE}" == "true" ]]; then
    log "Step 11: Smoke tests skipped (--skip-smoke)"
else
    log "Step 11: Running smoke tests"
    bash "${SCRIPT_DIR}/lab-smoke.sh" 2>&1 | tee -a "${LOG_FILE}" && \
        log_ok "All smoke tests passed" || \
        log_warn "Some smoke tests failed — check ${LOG_FILE}"
fi

# ── Final summary ─────────────────────────────────────────────────────────────
{
echo ""
echo "---"
echo "## Lab Ready — $(date)"
echo ""
echo "| Service     | URL                         | Credentials |"
echo "|-------------|-----------------------------|-------------|"
echo "| Proxy / MCP | http://localhost:8000        | mTLS header X-Client-Cert-CN |"
echo "| Grafana     | http://localhost:3001        | admin / ${LAB_GRAFANA_ADMIN_PASSWORD:-labpassword} |"
echo "| NetBox      | http://localhost:8090        | admin@lab.local / ${LAB_NETBOX_ADMIN_PASSWORD:-labpassword} |"
echo "| Vault       | http://localhost:8200        | token: ${VAULT_TOKEN:-lab-root-token} |"
echo "| Dex OIDC    | http://localhost:5556/dex    | alice@corp or bob@corp / labpassword |"
echo ""
echo "Tokens written to .env.lab:"
echo "  GRAFANA_ADMIN_TOKEN=$(grep '^GRAFANA_ADMIN_TOKEN=' "${ENV_LAB}" | cut -d= -f2- | head -c 20)..."
echo "  NETBOX_ADMIN_TOKEN=$(grep '^NETBOX_ADMIN_TOKEN=' "${ENV_LAB}" | cut -d= -f2- | head -c 20)..."
echo ""
echo "Setup log: ${LOG_FILE}"
} | tee -a "${LOG_FILE}"

log_ok "Lab setup complete"
