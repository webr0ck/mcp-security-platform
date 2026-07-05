#!/usr/bin/env sh
# lab/vault/auto-unseal.sh — LAB-ONLY Vault auto-unseal entrypoint wrapper.
#
# Replaces dev-mode (`vault server -dev`, in-memory) with a PERSISTENT file-storage
# Vault that survives restarts. Runs as the vault container's entrypoint so it
# re-runs on every (re)start and self-heals: it starts the server, initialises on
# first boot, and unseals using a key persisted in the vault-data volume.
#
# SECURITY MODEL (lab):
#   - The broker master secret (KEK) lives ONLY inside Vault's AES-GCM-encrypted
#     barrier storage on the vault-data volume — never as plaintext on disk. A
#     credential_store DB dump alone therefore stays useless (the KMS boundary the
#     appsec critic asked us to preserve).
#   - The unseal key + root token are persisted to /vault/data/.vault-init (mode
#     600) in that same volume so the container can auto-unseal across restarts.
#     This is the lab's accepted secret-zero tradeoff: opaque Vault-owned storage,
#     not a committable dotenv. PRODUCTION must instead use a real auto-unseal seal
#     (cloud KMS / transit / HSM) — see lab/vault/local.hcl.
#   - A FIXED bootstrap token (VAULT_BOOTSTRAP_TOKEN) is minted so the proxy/seeder
#     can authenticate with a static literal. It only works against a LIVE, unsealed
#     Vault over the network (revocable, non-exfiltratable as offline key material).
set -eu

CONFIG="${VAULT_CONFIG_FILE:-/vault/config/local.hcl}"
INIT_FILE="/vault/data/.vault-init"
export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
FIXED_TOKEN="${VAULT_BOOTSTRAP_TOKEN:?VAULT_BOOTSTRAP_TOKEN must be set}"

log() { echo "[vault-auto-unseal] $*"; }

# 1. Start the Vault server in the background; keep its PID for foreground handoff.
vault server -config="$CONFIG" &
VPID=$!

# 2. Wait until the API answers (status exit 0=unsealed or 2=sealed both mean "up").
log "waiting for Vault API on $VAULT_ADDR ..."
i=0
while true; do
  set +e; vault status >/dev/null 2>&1; code=$?; set -e
  [ "$code" = "0" ] || [ "$code" = "2" ] && break
  i=$((i + 1)); [ "$i" -gt 60 ] && { log "Vault did not come up"; kill "$VPID" 2>/dev/null || true; exit 1; }
  sleep 1
done

# 3. Initialise on first boot only (file storage persists across restarts).
if ! vault status 2>/dev/null | grep -q 'Initialized.*true'; then
  log "uninitialised — running operator init (1 share / 1 threshold) ..."
  vault operator init -key-shares=1 -key-threshold=1 > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  log "initialised; keys persisted to $INIT_FILE (mode 600)"
fi

UNSEAL_KEY="$(awk '/Unseal Key 1:/{print $NF}' "$INIT_FILE")"
ROOT_TOKEN="$(awk '/Initial Root Token:/{print $NF}' "$INIT_FILE")"
[ -n "$UNSEAL_KEY" ] && [ -n "$ROOT_TOKEN" ] || { log "FATAL: could not read keys from $INIT_FILE"; kill "$VPID" 2>/dev/null || true; exit 1; }

# 4. Unseal if sealed (covers both first boot and every subsequent restart).
if vault status 2>/dev/null | grep -q 'Sealed.*true'; then
  vault operator unseal "$UNSEAL_KEY" >/dev/null
  log "unsealed"
fi

# 5. Ensure the fixed bootstrap token exists (idempotent across restarts).
export VAULT_TOKEN="$ROOT_TOKEN"
if ! VAULT_TOKEN="$FIXED_TOKEN" vault token lookup >/dev/null 2>&1; then
  vault token create -id="$FIXED_TOKEN" -policy=root -orphan -period=8760h >/dev/null 2>&1 \
    || vault token create -id="$FIXED_TOKEN" -policy=root -orphan >/dev/null 2>&1
  log "bootstrap token ensured"
fi

# 6. Ensure KV v2 is mounted at secret/ (idempotent; the seeder also tolerates this).
VAULT_TOKEN="$FIXED_TOKEN" vault secrets enable -path=secret kv-v2 >/dev/null 2>&1 || true

# 6.5. Ensure the broker master secret (KEK) exists. Seeding it here — not only in
# lab/scripts/vault-init.sh — makes a clean start / restart self-healing: the proxy
# 500s every OIDC callback if this path 404s. NEVER rotate an existing value
# (would orphan already-encrypted credential_store rows).
if ! VAULT_TOKEN="$FIXED_TOKEN" vault kv get secret/mcp/broker-master >/dev/null 2>&1; then
  KEK="$(head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n')"
  VAULT_TOKEN="$FIXED_TOKEN" vault kv put secret/mcp/broker-master value="$KEK" >/dev/null
  unset KEK
  log "broker master secret seeded at secret/mcp/broker-master"
fi

log "ready — Vault unsealed and bootstrap token active; handing off to server (pid $VPID)"
# 7. Hand off: become a thin supervisor of the server process.
wait "$VPID"
