#!/usr/bin/env bash
# Smoke test: verifies all lab services respond from a clean start.
# Run after: podman compose -f podman-compose.lab.yml down -v && podman compose -f podman-compose.lab.yml up -d
set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; FAILURES=$((FAILURES+1)); }

PROXY="${PROXY_URL:-http://localhost:8000}"
KEYCLOAK="${KC_URL:-http://localhost:8082}"
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
wait_for "${KEYCLOAK}/realms/mcp/.well-known/openid-configuration" "Keycloak realm" 120
wait_for "http://localhost:3000/api/health" "Grafana"            60

# Proxy services (DB and Redis via proxy health — they don't expose direct TCP)
PROXY_HEALTH=$(curl -sf "${PROXY}/health" 2>/dev/null || echo "{}")
DB_OK=$(echo "$PROXY_HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('services',{}).get('database','?'))" 2>/dev/null || echo "?")
REDIS_OK=$(echo "$PROXY_HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('services',{}).get('redis','?'))" 2>/dev/null || echo "?")
[[ "$DB_OK" == "ok" ]] && ok "PostgreSQL (via proxy)" || fail "PostgreSQL (via proxy) — got: $DB_OK"
[[ "$REDIS_OK" == "ok" ]] && ok "Redis (via proxy)" || fail "Redis (via proxy) — got: $REDIS_OK"

# Proxy endpoints
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
