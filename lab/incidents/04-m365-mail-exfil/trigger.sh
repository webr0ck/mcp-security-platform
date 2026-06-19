#!/usr/bin/env bash
# lab/incidents/04-m365-mail-exfil/trigger.sh
# Scenario: M365 client makes burst of mail-reading calls.
# Detection target: rule 100603.
# Usage: bash lab/incidents/04-m365-mail-exfil/trigger.sh

set -euo pipefail
PROXY="${PROXY_BASE:-http://localhost:8000}"
API_KEY="${MCP_API_KEY:-lab-dev-key}"

echo "[04-m365-mail-exfil] Generating 12 m365-graph mail-read calls..."
for i in $(seq 1 12); do
    curl -sf -X POST "${PROXY}/api/v1/tools/m365-graph/invoke" \
      -H "Authorization: Bearer ${API_KEY}" \
      -H "Content-Type: application/json" \
      -d '{"name":"list_messages","arguments":{"folder":"inbox","limit":50}}' \
      -o /dev/null || true
    sleep 2
done
echo "[04-m365-mail-exfil] Done — 12 calls. Check Wazuh for rule 100603 alert."
echo "Grafana: http://localhost:3000 → Four-Auth Trace → Case 1 panel"
