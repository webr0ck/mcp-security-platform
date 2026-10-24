#!/usr/bin/env bash
# podman secret "shell" driver — store script.
#
# DELIBERATELY DISCARDS the value podman gives it on stdin at `podman secret
# create` time — that value never touches disk. The Ansible mcphubd role
# writes the (non-secret) name -> {vault_path, vault_field} pointer into
# index.json BEFORE calling podman_secret, so all this script needs to do is
# confirm that pointer already exists (fail loudly if not — a secret with no
# registered pointer would otherwise "succeed" here and then fail opaquely
# at lookup time, on some future container start, far from the actual
# mistake).
set -euo pipefail

INDEX_FILE="${MCPHUB_VAULT_SECRET_INDEX:-/etc/mcphub/vault-secret-driver/index.json}"

if [[ -z "${SECRET_ID:-}" ]]; then
  echo "store.sh: SECRET_ID not set" >&2
  exit 1
fi

# Discard stdin (the plaintext value podman would otherwise persist).
cat >/dev/null

python3 -c "
import json, sys
with open('$INDEX_FILE') as f:
    idx = json.load(f)
if '$SECRET_ID' not in idx:
    print('store.sh: no vault pointer registered for $SECRET_ID in $INDEX_FILE — the mcphubd role must write index.json BEFORE creating this secret', file=sys.stderr)
    sys.exit(1)
"
