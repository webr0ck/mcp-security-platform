#!/usr/bin/env bash
# podman secret "shell" driver — delete script. Removes the pointer entry
# only; there was never a plaintext value on disk to remove.
set -euo pipefail

INDEX_FILE="${MCPHUB_VAULT_SECRET_INDEX:-/etc/mcphub/vault-secret-driver/index.json}"

if [[ -z "${SECRET_ID:-}" ]]; then
  echo "delete.sh: SECRET_ID not set" >&2
  exit 1
fi

python3 -c "
import json
with open('$INDEX_FILE') as f:
    idx = json.load(f)
idx.pop('$SECRET_ID', None)
with open('$INDEX_FILE', 'w') as f:
    json.dump(idx, f)
"
