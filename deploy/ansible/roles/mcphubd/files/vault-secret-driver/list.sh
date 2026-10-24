#!/usr/bin/env bash
# podman secret "shell" driver — list script. Prints registered secret
# NAMES only (one per line), never values.
set -euo pipefail

INDEX_FILE="${MCPHUB_VAULT_SECRET_INDEX:-/etc/mcphub/vault-secret-driver/index.json}"

python3 -c "
import json
with open('$INDEX_FILE') as f:
    idx = json.load(f)
for name in idx:
    print(name)
"
