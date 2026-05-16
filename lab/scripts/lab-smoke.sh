#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# lab/scripts/lab-smoke.sh
# End-to-end smoke test for the MCP Security Platform lab stack.
#
# Usage:
#   bash lab/scripts/lab-smoke.sh
#
# Prerequisites:
#   - curl and jq installed
#   - Lab stack running (proxy on localhost:8000, Dex on localhost:5556)
#
# Tests:
#   1. Health check           — GET  /health/ready              → 200
#   2. Grafana tool call      — POST /api/v1/tools/invoke        → audit_id in response
#   3. OPA deny (unknown)     — POST /api/v1/tools/invoke        → 403 / deny
#   4. Dex enrollment redirect— GET  /auth/enroll/dex            → 302 to localhost:5556
# =============================================================================

PROXY_BASE="${PROXY_BASE:-http://localhost:8000}"
PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helper: run a test, print PASS or FAIL
# ---------------------------------------------------------------------------
run_test() {
    local name="$1"
    local result="$2"   # "pass" or "fail"
    local detail="$3"

    if [[ "${result}" == "pass" ]]; then
        echo "  [PASS] ${name}"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] ${name} — ${detail}"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "MCP Security Platform — Lab Smoke Tests"
echo "Proxy: ${PROXY_BASE}"
echo "========================================"

# ---------------------------------------------------------------------------
# Test 1: Health check
# ---------------------------------------------------------------------------
echo ""
echo "Test 1: Health check (GET /health/ready)"
HTTP_STATUS=$(
    curl -s -o /dev/null -w "%{http_code}" \
        "${PROXY_BASE}/health/ready"
)
if [[ "${HTTP_STATUS}" == "200" ]]; then
    run_test "Health check" "pass" ""
else
    run_test "Health check" "fail" "Expected 200, got ${HTTP_STATUS}"
fi

# ---------------------------------------------------------------------------
# Test 2: Grafana tool call (alice@corp — should be allowed)
# ---------------------------------------------------------------------------
echo ""
echo "Test 2: Grafana tool call (X-Client-Cert-CN: alice@corp)"
INVOKE_PAYLOAD='{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}'

# Resolve grafana-query tool_id from registry (alice has read access)
GRAFANA_TOOL_ID=$(
    curl -sf "${PROXY_BASE}/api/v1/tools" \
        -H "X-Client-Cert-CN: alice@corp" 2>/dev/null \
    | jq -r '.data[] | select(.name=="grafana-query") | .tool_id' 2>/dev/null | head -1 || echo ""
)

_TMPBODY=$(mktemp)
INVOKE_STATUS=$(
    curl -s -o "${_TMPBODY}" -w "%{http_code}" \
        -X POST "${PROXY_BASE}/api/v1/tools/${GRAFANA_TOOL_ID}/invoke" \
        -H "Content-Type: application/json" \
        -H "X-Client-Cert-CN: alice@corp" \
        -d "${INVOKE_PAYLOAD}"
)
INVOKE_BODY=$(cat "${_TMPBODY}"); rm -f "${_TMPBODY}"

# Check for audit_id in meta or error.data (proxy always stamps audit_id)
AUDIT_ID=$(echo "${INVOKE_BODY}" | jq -r '
    .meta.audit_id // .error.data.audit_id // empty
' 2>/dev/null || true)

if [[ -n "${AUDIT_ID}" && "${AUDIT_ID}" != "null" ]]; then
    run_test "Grafana tool call (audit_id present)" "pass" ""
else
    run_test "Grafana tool call (audit_id present)" "fail" \
        "audit_id not found in response. Status=${INVOKE_STATUS} Body=${INVOKE_BODY}"
fi

# ---------------------------------------------------------------------------
# Test 3: OPA deny — unknown external client
# ---------------------------------------------------------------------------
echo ""
echo "Test 3: OPA deny (X-Client-Cert-CN: unknown@external)"
_TMPBODY=$(mktemp)
DENY_STATUS=$(
    curl -s -o "${_TMPBODY}" -w "%{http_code}" \
        -X POST "${PROXY_BASE}/api/v1/tools/${GRAFANA_TOOL_ID}/invoke" \
        -H "Content-Type: application/json" \
        -H "X-Client-Cert-CN: unknown@external" \
        -d "${INVOKE_PAYLOAD}"
)
DENY_BODY=$(cat "${_TMPBODY}"); rm -f "${_TMPBODY}"

# Accept 403 HTTP status, or a JSON body with outcome=deny / error code 403
if [[ "${DENY_STATUS}" == "403" ]]; then
    run_test "OPA deny (unknown@external)" "pass" ""
else
    # Check body for a deny/forbidden indicator
    DENY_OUTCOME=$(echo "${DENY_BODY}" | jq -r '
        .outcome // .error.code // empty
    ' 2>/dev/null || true)
    if [[ "${DENY_OUTCOME}" == "deny" || "${DENY_OUTCOME}" == "403" ]]; then
        run_test "OPA deny (unknown@external)" "pass" ""
    else
        run_test "OPA deny (unknown@external)" "fail" \
            "Expected 403 or deny outcome. Status=${DENY_STATUS} Body=${DENY_BODY}"
    fi
fi

# ---------------------------------------------------------------------------
# Test 4: Dex enrollment redirect
# ---------------------------------------------------------------------------
echo ""
echo "Test 4: Dex enrollment redirect (GET /auth/enroll/dex)"
ENROLL_STATUS=$(
    curl -s -o /dev/null -w "%{http_code}" \
        -H "X-Session-Id: smoke-1" \
        -H "X-Client-Cert-CN: alice@corp" \
        "${PROXY_BASE}/auth/enroll/dex"
)
REDIRECT_URL=$(
    curl -s -o /dev/null -w "%{redirect_url}" \
        -H "X-Session-Id: smoke-1" \
        -H "X-Client-Cert-CN: alice@corp" \
        "${PROXY_BASE}/auth/enroll/dex"
)

if [[ "${ENROLL_STATUS}" == "302" ]] && echo "${REDIRECT_URL}" | grep -q "5556"; then
    run_test "Dex enrollment redirect (302 → :5556)" "pass" ""
elif [[ "${ENROLL_STATUS}" == "302" ]]; then
    run_test "Dex enrollment redirect (302 → :5556)" "fail" \
        "Got 302 but redirect URL '${REDIRECT_URL}' does not contain :5556"
else
    run_test "Dex enrollment redirect (302 → :5556)" "fail" \
        "Expected 302, got ${ENROLL_STATUS}. Redirect: ${REDIRECT_URL}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
TOTAL=$((PASS + FAIL))
echo "Results: ${PASS}/${TOTAL} passed"
if [[ ${FAIL} -gt 0 ]]; then
    echo "SMOKE TEST FAILED — ${FAIL} test(s) did not pass."
    exit 1
else
    echo "SMOKE TEST PASSED"
    exit 0
fi
