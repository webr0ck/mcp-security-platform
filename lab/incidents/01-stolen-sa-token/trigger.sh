#!/usr/bin/env bash
# lab/incidents/01-stolen-sa-token/trigger.sh
# Scenario: adversary probes the proxy with a forged/expired token,
# generating a burst of CREDENTIAL_INJECTION_FAILED events for the
# grafana-query tool (simulating a stolen token that no longer matches
# the credential_store entry).
#
# Detection target: rule 100600 (below).
# Grafana panel: Case 2 panel on the Four-Auth Trace dashboard.
#
# Usage: bash lab/incidents/01-stolen-sa-token/trigger.sh

set -euo pipefail
PROXY="${PROXY_BASE:-http://localhost:8000}"

echo "[01-stolen-sa-token] Generating grafana-query injection failure burst..."
for i in $(seq 1 6); do
    curl -sf -X POST "${PROXY}/api/v1/tools/grafana-query/invoke" \
      -H "Authorization: Bearer INVALID_TOKEN_SIMULATING_STOLEN_CRED" \
      -H "Content-Type: application/json" \
      -d '{"name":"query_dashboards","arguments":{"search":"prod"}}' \
      -o /dev/null || true
    sleep 1
done
echo "[01-stolen-sa-token] Done — 6 requests sent. Check Wazuh for rule 100600 alert."
echo "Grafana: http://localhost:3000 → Four-Auth Trace → Case 2 panel"
