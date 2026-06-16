#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# lab/scripts/vault-init.sh
# Idempotent Vault KV initialization for the MCP Security Platform lab.
#
# Usage:
#   bash lab/scripts/vault-init.sh
#
# Prerequisites:
#   - vault CLI installed and on PATH
#   - Vault reachable at VAULT_ADDR (default: http://localhost:8200)
#   - VAULT_TOKEN set (or loaded from .env.lab)
#
# What this script does:
#   1. Loads .env.lab if present
#   2. Waits for Vault to be healthy (max 60s)
#   3. Enables KV v2 at secret/ (idempotent)
#   4. Writes a fresh broker master secret to secret/mcp/broker-master
#   5. Writes lab service config to secret/mcp/lab-config
# =============================================================================

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-lab-root-token}"
export VAULT_ADDR VAULT_TOKEN

# ---------------------------------------------------------------------------
# Resolve vault executor — host CLI preferred, podman exec fallback
# ---------------------------------------------------------------------------
VAULT_CONTAINER="mcp-vault"

if command -v vault &>/dev/null; then
    VAULT_EXEC="vault"
    echo "[vault-init] Using host vault CLI"
elif podman exec "${VAULT_CONTAINER}" vault version &>/dev/null 2>&1; then
    # Run vault commands inside the container
    VAULT_EXEC="podman exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN=${VAULT_TOKEN:-lab-root-token} ${VAULT_CONTAINER} vault"
    # Health check against container-internal address when using exec
    HEALTH_URL="http://127.0.0.1:8200/v1/sys/health"
    echo "[vault-init] vault CLI not on host — using 'podman exec ${VAULT_CONTAINER} vault'"
else
    echo "[vault-init] ERROR: vault CLI not found on host and container '${VAULT_CONTAINER}' is not running." >&2
    echo "[vault-init] Install vault CLI:  brew install hashicorp/tap/vault" >&2
    echo "[vault-init] Or start the stack: make -f Makefile.lab lab-up" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Load .env.lab if present (project root or script directory)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ -f "${PROJECT_ROOT}/.env.lab" ]]; then
    echo "[vault-init] Loading environment from ${PROJECT_ROOT}/.env.lab"
    # Source so values containing spaces (e.g. multi-scope OIDC vars) and quotes
    # are preserved. `export $(... | xargs)` word-splits such values and fails.
    set -a
    # shellcheck disable=SC1091
    . "${PROJECT_ROOT}/.env.lab"
    set +a
fi

# Re-export after potential .env.lab override
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-lab-root-token}"
export VAULT_ADDR VAULT_TOKEN

# ---------------------------------------------------------------------------
# Wait for Vault health
# ---------------------------------------------------------------------------
HEALTH_URL="${VAULT_ADDR:-http://localhost:8200}/v1/sys/health"
MAX_WAIT=60
ELAPSED=0

echo "[vault-init] Waiting for Vault at ${VAULT_ADDR} ..."
until curl -sf "${HEALTH_URL}" > /dev/null 2>&1; do
    if [[ ${ELAPSED} -ge ${MAX_WAIT} ]]; then
        echo "[vault-init] ERROR: Vault did not become ready within ${MAX_WAIT}s." >&2
        exit 1
    fi
    echo "[vault-init] Vault not ready — retrying in 2s (${ELAPSED}s elapsed)"
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done
echo "[vault-init] Vault is ready."

# ---------------------------------------------------------------------------
# Enable KV v2 at secret/ (idempotent — ignore error if already enabled)
# ---------------------------------------------------------------------------
echo "[vault-init] Enabling KV v2 at 'secret/' ..."
${VAULT_EXEC} secrets enable -path=secret kv-v2 2>/dev/null || {
    echo "[vault-init] KV v2 at 'secret/' already enabled — skipping."
}

# ---------------------------------------------------------------------------
# Write broker master secret
# ---------------------------------------------------------------------------
MASTER_VALUE="$(openssl rand -hex 32)"
echo "[vault-init] Writing broker master secret to secret/mcp/broker-master ..."
${VAULT_EXEC} kv put secret/mcp/broker-master value="${MASTER_VALUE}"
echo "[vault-init] Broker master secret written."

# ---------------------------------------------------------------------------
# Write lab service config (informational — actual credentials set by seeder)
# ---------------------------------------------------------------------------
LAB_GRAFANA_URL="${LAB_GRAFANA_URL:-http://lab-grafana:3000}"
LAB_NETBOX_URL="${LAB_NETBOX_URL:-http://lab-netbox:8080}"
LAB_DEX_ISSUER="${LAB_DEX_ISSUER:-http://localhost:5556/dex}"

echo "[vault-init] Writing lab service config to secret/mcp/lab-config ..."
${VAULT_EXEC} kv put secret/mcp/lab-config \
    grafana_url="${LAB_GRAFANA_URL}" \
    netbox_url="${LAB_NETBOX_URL}" \
    dex_issuer="${LAB_DEX_ISSUER}"

echo ""
echo "[vault-init] Done."
echo "[vault-init] Broker master secret path: secret/mcp/broker-master"
echo "[vault-init] Lab service config path:   secret/mcp/lab-config"
echo ""
echo "[vault-init] To verify:"
echo "  vault kv get secret/mcp/broker-master"
echo "  vault kv get secret/mcp/lab-config"
