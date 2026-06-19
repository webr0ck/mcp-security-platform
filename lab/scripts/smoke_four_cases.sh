#!/usr/bin/env bash
# smoke_four_cases.sh — PRD-0002 P0 acceptance test (cases 1–3 OK, case 4 SKIP)
#
# Usage:
#   bash lab/scripts/smoke_four_cases.sh
#
# What it checks:
#   Case 1: m365-graph        injection_mode=entra_client_credentials
#   Case 2: grafana-query     injection_mode=service
#   Case 3: netbox-query      injection_mode=user
#   Case 4: lab-tickets-query injection_mode=kc_token_exchange
#
# Strategy: try the proxy API first (GET /api/v1/tools); if it's unreachable
# or returns unexpected JSON, fall back to a direct psql query against mcp-db.
# Exits 0 when cases 1–3 are all registered with the correct injection_mode.
# Exits 1 if any of 1–3 fail.

set -euo pipefail

PROXY_BASE="${PROXY_BASE:-http://localhost:8000}"
FAILURES=0

# ---------------------------------------------------------------------------
# Helper: ANSI colours (no-op on non-TTY)
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; NC=''
fi

pass() { echo -e "${GREEN}case $1: OK${NC}  (tool=$2 injection_mode=$3)"; }
fail() { echo -e "${RED}case $1: FAIL${NC}  (tool=$2 expected=$3 got=$4)"; FAILURES=$((FAILURES + 1)); }
skip() { echo -e "${YELLOW}case $1: SKIP${NC}  ($2)"; }

echo ""
echo "PRD-0002 P0 — four-auth-case smoke test"
echo "Proxy: ${PROXY_BASE}"
echo "========================================"
echo ""

# ---------------------------------------------------------------------------
# Determine data source: API or psql fallback
# ---------------------------------------------------------------------------
USE_API=false
API_JSON=""

if curl -sf "${PROXY_BASE}/health/ready" >/dev/null 2>&1; then
    # Proxy is up — try to fetch the tools list (no auth header required for
    # list; if auth IS required the fallback handles it gracefully)
    API_RESPONSE=$(curl -sf "${PROXY_BASE}/api/v1/tools" 2>/dev/null || true)
    if echo "${API_RESPONSE}" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'data' in d" 2>/dev/null; then
        USE_API=true
        API_JSON="${API_RESPONSE}"
    fi
fi

get_injection_mode() {
    local tool_name="$1"
    local mode=""

    if [[ "${USE_API}" == "true" ]]; then
        mode=$(echo "${API_JSON}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for t in d.get('data', []):
    if t.get('name') == '${tool_name}':
        print(t.get('injection_mode', ''))
        break
" 2>/dev/null || true)
    fi

    # Fallback to psql if API gave us nothing
    # DB credentials: mcp_app / mcp_security (see podman-compose.lab.yml)
    if [[ -z "${mode}" ]]; then
        mode=$(podman exec mcp-db psql -U mcp_app -d mcp_security -tAc \
            "SELECT injection_mode FROM tool_registry WHERE name='${tool_name}' AND deleted_at IS NULL LIMIT 1;" \
            2>/dev/null | tr -d '[:space:]' || true)
    fi

    echo "${mode}"
}

# ---------------------------------------------------------------------------
# Case 1: m365-graph → entra_client_credentials
# ---------------------------------------------------------------------------
TOOL1="m365-graph"
EXPECTED1="entra_client_credentials"
MODE1=$(get_injection_mode "${TOOL1}")
if [[ "${MODE1}" == "${EXPECTED1}" ]]; then
    pass 1 "${TOOL1}" "${MODE1}"
else
    fail 1 "${TOOL1}" "${EXPECTED1}" "${MODE1:-<not found>}"
fi

# ---------------------------------------------------------------------------
# Case 2: grafana-query → service
# ---------------------------------------------------------------------------
TOOL2="grafana-query"
EXPECTED2="service"
MODE2=$(get_injection_mode "${TOOL2}")
if [[ "${MODE2}" == "${EXPECTED2}" ]]; then
    pass 2 "${TOOL2}" "${MODE2}"
else
    fail 2 "${TOOL2}" "${EXPECTED2}" "${MODE2:-<not found>}"
fi

# ---------------------------------------------------------------------------
# Case 3: netbox-query → user
# ---------------------------------------------------------------------------
TOOL3="netbox-query"
EXPECTED3="user"
MODE3=$(get_injection_mode "${TOOL3}")
if [[ "${MODE3}" == "${EXPECTED3}" ]]; then
    pass 3 "${TOOL3}" "${MODE3}"
else
    fail 3 "${TOOL3}" "${EXPECTED3}" "${MODE3:-<not found>}"
fi

# ---------------------------------------------------------------------------
# Case 4: lab-tickets-query → kc_token_exchange
# ---------------------------------------------------------------------------
TOOL4="lab-tickets-query"
EXPECTED4="kc_token_exchange"
MODE4=$(get_injection_mode "${TOOL4}")
if [[ "${MODE4}" == "${EXPECTED4}" ]]; then
    pass 4 "${TOOL4}" "${MODE4}"
else
    fail 4 "${TOOL4}" "${EXPECTED4}" "${MODE4:-<not found>}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
if [[ ${FAILURES} -eq 0 ]]; then
    echo -e "${GREEN}PASS: P1 bar met — all 4 cases active${NC}"
    exit 0
else
    echo -e "${RED}FAIL: ${FAILURES} case(s) did not pass — P0 bar NOT met${NC}"
    exit 1
fi
