#!/bin/sh
# init-ca.sh — Bootstrap the MCP Security Platform internal CA
#
# This script initialises step-ca and configures it per the platform's
# security requirements:
#   - INV-010: Maximum certificate TTL of 24 hours
#   - ARCHITECTURE.md §9: Smallstep step-ca as internal CA
#
# Idempotent: safe to re-run. If the CA is already initialised, steps
# that would fail are skipped with a warning.
#
# Usage:
#   docker compose exec step-ca /scripts/init-ca.sh
#   OR run via: make step-ca-init
#
# The CA fingerprint is written to stdout at the end. Copy it into
# .env as STEP_CA_FINGERPRINT so Nginx and the proxy can bootstrap trust.
#
# Secrets: STEP_CA_PROVISIONER_PASSWORD is read from the Docker secret
# mounted at /run/secrets/step_ca_password (see docker-compose.yml secrets block).
# This script never echoes secret values.

set -eu

CA_NAME="${DOCKER_STEPCA_INIT_NAME:-MCP Security CA}"
CA_DNS="${DOCKER_STEPCA_INIT_DNS_NAMES:-step-ca,localhost}"
CA_PROVISIONER="${DOCKER_STEPCA_INIT_PROVISIONER_NAME:-mcp-security-platform}"
CA_ADDRESS="${STEP_CA_BIND_ADDRESS:-:9000}"
MAX_TLS_DURATION="${STEP_CA_MAX_TLS_DURATION:-24h}"

# The password file is injected via Docker secrets (never a plain env var)
PASSWORD_FILE="/run/secrets/step_ca_password"

if [ ! -f "${PASSWORD_FILE}" ]; then
    echo "[init-ca] ERROR: Password file not found at ${PASSWORD_FILE}" >&2
    echo "[init-ca] Ensure the step_ca_password Docker secret is configured." >&2
    exit 1
fi

CA_CONFIG_DIR="/home/step"
CA_CONFIG_FILE="${CA_CONFIG_DIR}/config/ca.json"

# ─── Step 1: Initialise CA (idempotent — skip if already done) ────────────────
if [ -f "${CA_CONFIG_FILE}" ]; then
    echo "[init-ca] CA already initialised at ${CA_CONFIG_FILE}. Skipping init."
else
    echo "[init-ca] Initialising step-ca..."
    step ca init \
        --name "${CA_NAME}" \
        --dns "${CA_DNS}" \
        --address "${CA_ADDRESS}" \
        --provisioner "${CA_PROVISIONER}" \
        --password-file "${PASSWORD_FILE}" \
        --deployment-type standalone
    echo "[init-ca] CA initialised successfully."
fi

# ─── Step 2: Configure ACME provisioner with 24h max TTL (INV-010) ────────────
# The DOCKER_STEPCA_INIT flow creates a JWK provisioner. We patch the config
# to enforce maxTLSDuration on all issued certificates.
#
# step-ca reads config/ca.json; we use Python for reliable JSON manipulation
# rather than sed/awk which are fragile on embedded JSON.
echo "[init-ca] Enforcing maxTLSDuration=${MAX_TLS_DURATION} on all provisioners..."

python3 - <<PYEOF
import json, sys, os

config_path = "${CA_CONFIG_FILE}"
max_duration = "${MAX_TLS_DURATION}"

with open(config_path) as f:
    cfg = json.load(f)

modified = False
for prov in cfg.get("authority", {}).get("provisioners", []):
    claims = prov.setdefault("claims", {})
    if claims.get("maxTLSDuration") != max_duration:
        claims["maxTLSDuration"] = max_duration
        claims["defaultTLSDuration"] = max_duration
        modified = True
        print(f"[init-ca]   Updated provisioner '{prov.get('name', prov.get('type'))}': maxTLSDuration={max_duration}")

if modified:
    with open(config_path, "w") as f:
        json.dump(cfg, f, indent=2)
    print("[init-ca] Config written.")
else:
    print("[init-ca] maxTLSDuration already set correctly. No changes needed.")
PYEOF

# ─── Step 3: Add ACME provisioner (for automated cert renewal) ────────────────
# Check if ACME provisioner already exists before adding.
# This provisioner allows the gateway to use ACME protocol to auto-renew its
# server certificate (though in Docker Compose, manual renewal is also acceptable).
echo "[init-ca] Checking for ACME provisioner..."

ACME_PROVISIONER_EXISTS=$(python3 -c "
import json
with open('${CA_CONFIG_FILE}') as f:
    cfg = json.load(f)
provisioners = cfg.get('authority', {}).get('provisioners', [])
acme_exists = any(p.get('type', '').upper() == 'ACME' for p in provisioners)
print('yes' if acme_exists else 'no')
")

if [ "${ACME_PROVISIONER_EXISTS}" = "yes" ]; then
    echo "[init-ca] ACME provisioner already configured. Skipping."
else
    echo "[init-ca] Adding ACME provisioner..."
    step ca provisioner add acme --type ACME \
        --ca-config "${CA_CONFIG_FILE}" \
        || echo "[init-ca] WARN: Could not add ACME provisioner (may require CA restart)"
fi

# ─── Step 4: Output CA fingerprint ────────────────────────────────────────────
# The fingerprint is used by Nginx, the proxy, and any step CLI client to
# bootstrap trust without needing out-of-band CA cert distribution.
# Copy this value into .env as STEP_CA_FINGERPRINT.
echo ""
echo "================================================================"
echo "[init-ca] CA ROOT FINGERPRINT (copy to .env STEP_CA_FINGERPRINT)"
echo "================================================================"
step certificate fingerprint "${CA_CONFIG_DIR}/certs/root_ca.crt" 2>/dev/null \
    || echo "[init-ca] WARN: Could not read root cert fingerprint yet (CA may still be starting)"
echo "================================================================"
echo ""
echo "[init-ca] Bootstrap complete."
echo "[init-ca] Restart the gateway service after copying the fingerprint."
