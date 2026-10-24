#!/usr/bin/env bash
# podman secret "shell" driver — lookup script.
#
# D2 fix: podman's default `file` driver writes secret VALUES base64-encoded
# (NOT encrypted) to secretsdata.json on the deploy host — proven against
# podman 5.8.3. For the credential-broker KEK and the audit HMAC key
# (rotating the latter invalidates verification of every prior audit row —
# see the mcphubd role README "audit HMAC key rotation" section), that
# means a stolen disk image / VM snapshot / backup yields either secret
# outright. This driver closes that: podman never gets a plaintext value to
# persist at all. `store.sh` (called at `podman secret create` time)
# discards the value it's given on stdin — the only thing written to disk
# is a non-secret pointer (index.json). This script resolves that pointer
# to a LIVE value, called by podman at the moment a container is started
# and needs the secret materialized (env or mount) — so the value exists on
# this host only transiently, in this script's memory and then in
# mcphubd's process memory, never at rest.
#
# Two pointer types, keyed by index.json's "type" field:
#   "kv"            -- read a field from a Vault KV-v2 path (the audit HMAC
#                      key; also how this driver could deliver any other
#                      Vault-KV-sourced secret in the future).
#   "approle_token" -- do a FRESH AppRole login and return the resulting
#                      client_token. Used for MCPHUB_VAULT_TOKEN: mcphubd's
#                      own VaultKekSource (rs/crates/mcphub-creds) uses this
#                      token to fetch the credential-broker KEK ITSELF, live,
#                      on its own schedule -- so the KEK never passes through
#                      Ansible OR this driver at all; only a bounded,
#                      revocable Vault token does, minted fresh at every
#                      container start (not a long-lived token sitting on
#                      disk). See the mcphubd role README "Vault token TTL"
#                      note for the one real caveat this introduces.
#
# Contract (see `man podman-secret-create` SECRET DRIVERS / shell): podman
# sets $SECRET_ID to the secret's name and expects the value on stdout.
set -euo pipefail

INDEX_FILE="${MCPHUB_VAULT_SECRET_INDEX:-/etc/mcphub/vault-secret-driver/index.json}"
APPROLE_ENV="${MCPHUB_VAULT_APPROLE_ENV:-/etc/mcphub/vault-approle.env}"

if [[ -z "${SECRET_ID:-}" ]]; then
  echo "lookup.sh: SECRET_ID not set" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$APPROLE_ENV"   # sets VAULT_ADDR, VAULT_ROLE_ID, VAULT_SECRET_ID — root-only 0600, see role README

entry_type=$(python3 -c "
import json, sys
with open('$INDEX_FILE') as f:
    idx = json.load(f)
e = idx.get('$SECRET_ID')
if e is None:
    sys.exit(1)
print(e.get('type', 'kv'))
")

login_token=$(curl -sf --cacert "${VAULT_CACERT:-/etc/mcphub/vault-tls/vault.crt}" \
  -X POST -d "{\"role_id\":\"${VAULT_ROLE_ID}\",\"secret_id\":\"${VAULT_SECRET_ID}\"}" \
  "${VAULT_ADDR}/v1/auth/approle/login" | python3 -c 'import json,sys; print(json.load(sys.stdin)["auth"]["client_token"])')

if [[ "$entry_type" == "approle_token" ]]; then
  # mcphubd wants a Vault token it can use itself, not a value we've already
  # resolved -- the fresh login above IS the answer.
  printf '%s' "$login_token"
  exit 0
fi

entry=$(python3 -c "
import json
with open('$INDEX_FILE') as f:
    idx = json.load(f)
e = idx['$SECRET_ID']
print(e['vault_path'])
print(e['vault_field'])
")
vault_path=$(echo "$entry" | sed -n 1p)
vault_field=$(echo "$entry" | sed -n 2p)

mount="${vault_path%%/*}"
kv_path="${vault_path#*/}"
curl -sf --cacert "${VAULT_CACERT:-/etc/mcphub/vault-tls/vault.crt}" \
  -H "X-Vault-Token: ${login_token}" \
  "${VAULT_ADDR}/v1/${mount}/data/${kv_path}" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['data']['$vault_field'], end='')"
