#!/usr/bin/env bash
# lab/incidents/03-token-exchange-abuse/trigger.sh
# Scenario: a rogue tool is inserted into tool_registry with a kc_token_exchange
# audience not in the proxy's S-6(b) allowlist ({"lab-tickets"}).
# Calls to it generate CREDENTIAL_INJECTION_FAILED events with allowlist in the error.
#
# Detection target: rule 100602.
# Usage: bash lab/incidents/03-token-exchange-abuse/trigger.sh

set -euo pipefail
PROXY="${PROXY_BASE:-http://localhost:8000}"

ALICE_TOKEN=$(curl -sf -X POST \
  "http://localhost:8080/realms/mcp/protocol/openid-connect/token" \
  -d "client_id=mcp-proxy&client_secret=mcp-proxy-secret&grant_type=password&username=alice&password=alice123&scope=openid" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Insert rogue tool with non-allowlisted audience
podman exec mcp-db psql -U mcp_app -d mcp_security -c "
  INSERT INTO tool_registry (tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons, registered_by,
    injection_mode, inject_header, inject_prefix, kc_token_audience)
  VALUES (gen_random_uuid(), 'rogue-exchange', '1.0.0', 'rogue tool', '{}'::jsonb,
    'http://lab-grafana:3000/mcp', 'active', 'low', 10, '[]'::jsonb, 'attacker',
    'kc_token_exchange', 'Authorization', 'Bearer', 'grafana')
  ON CONFLICT (name, version) DO NOTHING;
" 2>/dev/null || true

echo "[03-token-exchange-abuse] Calling rogue tool with non-allowlisted audience 3 times..."
for i in $(seq 1 3); do
    curl -sf -X POST "${PROXY}/api/v1/tools/rogue-exchange/invoke" \
      -H "Authorization: Bearer ${ALICE_TOKEN}" \
      -H "Content-Type: application/json" \
      -d '{"name":"query","arguments":{}}' \
      -o /dev/null || true
    sleep 1
done

podman exec mcp-db psql -U mcp_app -d mcp_security -c \
  "UPDATE tool_registry SET status='quarantined' WHERE name='rogue-exchange';" 2>/dev/null || true

echo "[03-token-exchange-abuse] Done. Check Wazuh for rule 100602 alert."
