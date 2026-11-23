#!/usr/bin/env sh
# Vault entrypoint for the Dark Factory tier: start, init on first boot,
# unseal on every boot, then make sure the proxy's scoped token exists.
#
# Secret-zero trade-off, stated: the unseal key and root token live in
# /vault/data/.vault-init (0600) inside the Vault volume on vm-mcp, so a
# restart needs no operator. Whoever owns the host owns Vault - on a
# single-VM platform that was already true. What this still buys: the broker
# KEK is never plaintext on disk, a database dump alone decrypts nothing, and
# the proxy holds a token limited to its own paths, not root.
set -eu

INIT_FILE=/vault/data/.vault-init
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_CACERT=/vault/tls/ca.crt
PROXY_TOKEN="${VAULT_PROXY_TOKEN:?VAULT_PROXY_TOKEN must be set}"

log() { echo "[vault-df] $*"; }

vault server -config=/vault/config/df.hcl &
VPID=$!

i=0
while :; do
  set +e; vault status >/dev/null 2>&1; code=$?; set -e
  [ "$code" = 0 ] || [ "$code" = 2 ] && break
  i=$((i + 1)); [ "$i" -gt 60 ] && { log "Vault did not come up"; kill "$VPID"; exit 1; }
  sleep 1
done

if ! vault status 2>/dev/null | grep -q 'Initialized.*true'; then
  (umask 077; vault operator init -key-shares=1 -key-threshold=1 > "$INIT_FILE")
  log "initialised"
fi
UNSEAL_KEY=$(awk '/Unseal Key 1:/{print $NF}' "$INIT_FILE")
ROOT_TOKEN=$(awk '/Initial Root Token:/{print $NF}' "$INIT_FILE")
[ -n "$UNSEAL_KEY" ] && [ -n "$ROOT_TOKEN" ] || { log "cannot read $INIT_FILE"; kill "$VPID"; exit 1; }

if vault status 2>/dev/null | grep -q 'Sealed.*true'; then
  vault operator unseal "$UNSEAL_KEY" >/dev/null
  log "unsealed"
fi

export VAULT_TOKEN="$ROOT_TOKEN"
vault secrets list | grep -q '^secret/' || vault secrets enable -path=secret kv-v2 >/dev/null
vault policy write mcp-proxy /vault/config/proxy-policy.hcl >/dev/null
if ! VAULT_TOKEN="$PROXY_TOKEN" vault token lookup >/dev/null 2>&1; then
  vault token create -id="$PROXY_TOKEN" -policy=mcp-proxy -orphan -period=768h >/dev/null
  log "proxy token created"
fi
# The KEK is created once and never rotated here: rotating it would orphan
# every credential_store row already encrypted under it.
if ! vault kv get secret/mcp/broker-master >/dev/null 2>&1; then
  KEK=$(head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n')
  vault kv put secret/mcp/broker-master value="$KEK" >/dev/null
  unset KEK
  log "broker master secret seeded"
fi
unset VAULT_TOKEN ROOT_TOKEN UNSEAL_KEY
# A periodic token lives as long as someone renews it; this loop is that someone.
( while sleep 86400; do VAULT_TOKEN="$PROXY_TOKEN" vault token renew >/dev/null || log "renew failed"; done ) &
log "ready"
wait "$VPID"
