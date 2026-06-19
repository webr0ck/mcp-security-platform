#!/usr/bin/env bash
# lab/incidents/02-overprivileged-user/trigger.sh
# Scenario: a low-privilege user (carol, viewer role) repeatedly attempts to
# call a tool above their risk band. OPA denies each call.
#
# Detection target: rule 100601.
# Grafana panel: Case 3 panel on the Four-Auth Trace dashboard.
#
# Usage: bash lab/incidents/02-overprivileged-user/trigger.sh

set -euo pipefail
PROXY="${PROXY_BASE:-http://localhost:8000}"

CAROL_TOKEN=$(curl -sf -X POST \
  "http://localhost:8080/realms/mcp/protocol/openid-connect/token" \
  -d "client_id=mcp-proxy&client_secret=mcp-proxy-secret&grant_type=password&username=carol&password=carol123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "[02-overprivileged-user] Carol (viewer) calling netbox-query 5 times..."
for i in $(seq 1 5); do
    curl -sf -X POST "${PROXY}/api/v1/tools/netbox-query/invoke" \
      -H "Authorization: Bearer ${CAROL_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"name":"list_devices","arguments":{"limit":10}}' \
      -o /dev/null || true
    sleep 1
done
echo "[02-overprivileged-user] Done. Check Wazuh for rule 100601 alert."
echo "Grafana: http://localhost:3000 → Four-Auth Trace → Case 3 panel"
