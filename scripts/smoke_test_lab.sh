#!/usr/bin/env bash
# Smoke test: verifies all lab services respond from a clean start.
# Run after: podman compose -f podman-compose.lab.yml down -v && podman compose -f podman-compose.lab.yml up -d
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; FAILURES=$((FAILURES+1)); }

PROXY="${PROXY_URL:-http://localhost:8000}"
KEYCLOAK="${KC_URL:-http://localhost:8080}"
FAILURES=0

wait_for() {
  local url=$1 label=$2 timeout=${3:-60}
  local elapsed=0
  while ! curl -sf "$url" -o /dev/null 2>/dev/null; do
    sleep 2; elapsed=$((elapsed+2))
    [[ $elapsed -ge $timeout ]] && fail "$label did not respond within ${timeout}s" && return
  done
  ok "$label"
}

echo "Waiting for services to be healthy…"
wait_for "${PROXY}/health"                "Proxy health"         90
wait_for "${KEYCLOAK}/health/ready"       "Keycloak ready"       120
wait_for "http://localhost:3000/api/health" "Grafana"            60
wait_for "http://localhost:5432"           "PostgreSQL"           30 || true  # TCP check
wait_for "http://localhost:6379"           "Redis"                30 || true

# Proxy endpoints
curl -sf "${PROXY}/openapi.json" -o /dev/null && ok "Proxy OpenAPI" || fail "Proxy OpenAPI"
curl -sf "${PROXY}/.well-known/oauth-authorization-server" -o /dev/null && ok "OAuth metadata" || fail "OAuth metadata"

# MCP servers (via proxy registration, not direct)
for srv in poc-echo-server poc-notes-server poc-search-server; do
  REGISTERED=$(curl -sf "${PROXY}/api/v1/servers" \
    -H "X-Api-Key: ${LAB_API_KEY:-lab-admin-key}" 2>/dev/null \
    | python3 -c "import sys,json; d=json.load(sys.stdin); names=[s.get('name','') for s in d]; print('${srv}' in names)" 2>/dev/null || echo "False")
  [[ "$REGISTERED" == "True" ]] && ok "MCP server registered: ${srv}" || fail "MCP server not registered: ${srv}"
done

echo ""
if [[ $FAILURES -eq 0 ]]; then
  echo -e "${GREEN}All checks passed.${NC}"
else
  echo -e "${RED}${FAILURES} check(s) failed.${NC}"
  exit 1
fi
