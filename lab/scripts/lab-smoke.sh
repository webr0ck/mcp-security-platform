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
#   - Lab stack running, mcp-proxy container healthy
#
# All requests run via `podman exec mcp-proxy curl ...` (true container
# loopback), NOT the host-published :8000 port. The proxy's SEC-05 ingress
# allowlist (proxy/app/middleware/ingress.py) only trusts the gateway
# container and real loopback — a host curl to the published port arrives
# NAT'd through rootless podman's slirp4netns/pasta gateway, which is
# neither, and gets a correct 403. Running curl inside the container is
# the same "own healthcheck" caller the middleware already trusts.
#
# Tests:
#   1. Health check           — GET  /health/ready              → 200
#   2. Grafana tool call      — POST /api/v1/tools/invoke        → audit_id in response
#   3. OPA deny (unknown)     — POST /api/v1/tools/invoke        → 403 / deny
#   4. Dex enrollment redirect— GET  /auth/enroll/dex            → 302 to localhost:5556
# =============================================================================

PROXY_CONTAINER="${PROXY_CONTAINER:-mcp-proxy}"
PROXY_BASE="${PROXY_BASE:-http://localhost:8000}"
# RT-NEW-005: the proxy only honours X-Client-Cert-CN when it also carries
# X-Gateway-Secret matching GATEWAY_SHARED_SECRET — proof the header was set
# by Nginx, not forged by whoever's calling. Nginx sets both on every proxied
# request; since these tests stand in for Nginx, they must set both too.
GATEWAY_SHARED_SECRET="${GATEWAY_SHARED_SECRET:-}"
PASS=0
FAIL=0

pcurl() {
    podman exec "${PROXY_CONTAINER}" curl "$@"
}

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
echo "Proxy: ${PROXY_BASE} (via podman exec ${PROXY_CONTAINER})"
echo "========================================"

# ---------------------------------------------------------------------------
# Test 1: Health check
# ---------------------------------------------------------------------------
echo ""
echo "Test 1: Health check (GET /health/ready)"
HTTP_STATUS=$(
    pcurl -s -o /dev/null -w "%{http_code}" \
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
    pcurl -sf "${PROXY_BASE}/api/v1/tools" \
        -H "X-Client-Cert-CN: alice@corp" \
        -H "X-Gateway-Secret: ${GATEWAY_SHARED_SECRET}" 2>/dev/null \
    | jq -r '.data[] | select(.name=="grafana-query") | .tool_id' 2>/dev/null | head -1 || echo ""
)

INVOKE_RESP=$(
    pcurl -s -w $'\n%{http_code}' \
        -X POST "${PROXY_BASE}/api/v1/tools/${GRAFANA_TOOL_ID}/invoke" \
        -H "Content-Type: application/json" \
        -H "X-Client-Cert-CN: alice@corp" \
        -H "X-Gateway-Secret: ${GATEWAY_SHARED_SECRET}" \
        -d "${INVOKE_PAYLOAD}"
)
INVOKE_STATUS=$(tail -n1 <<<"${INVOKE_RESP}")
INVOKE_BODY=$(sed '$d' <<<"${INVOKE_RESP}")

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
DENY_RESP=$(
    pcurl -s -w $'\n%{http_code}' \
        -X POST "${PROXY_BASE}/api/v1/tools/${GRAFANA_TOOL_ID}/invoke" \
        -H "Content-Type: application/json" \
        -H "X-Client-Cert-CN: unknown@external" \
        -H "X-Gateway-Secret: ${GATEWAY_SHARED_SECRET}" \
        -d "${INVOKE_PAYLOAD}"
)
DENY_STATUS=$(tail -n1 <<<"${DENY_RESP}")
DENY_BODY=$(sed '$d' <<<"${DENY_RESP}")

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
# Test 4: Dex enrollment consent page
# R-5/D1: GET /auth/enroll/{service} renders a consent page (HTTP 200) with a
# POST form to /auth/enroll/{service}/consent — it deliberately does NOT redirect
# straight to the IdP (the older 302→:5556 behavior). See oauth.py::enroll.
# ---------------------------------------------------------------------------
echo ""
echo "Test 4: Dex enrollment consent page (GET /auth/enroll/dex)"
ENROLL_BODY=$(
    pcurl -s \
        -H "X-Session-Id: smoke-1" \
        -H "X-Client-Cert-CN: alice@corp" \
        -H "X-Gateway-Secret: ${GATEWAY_SHARED_SECRET}" \
        "${PROXY_BASE}/auth/enroll/dex"
)
ENROLL_STATUS=$(
    pcurl -s -o /dev/null -w "%{http_code}" \
        -H "X-Session-Id: smoke-1" \
        -H "X-Client-Cert-CN: alice@corp" \
        -H "X-Gateway-Secret: ${GATEWAY_SHARED_SECRET}" \
        "${PROXY_BASE}/auth/enroll/dex"
)

if [[ "${ENROLL_STATUS}" == "200" ]] && echo "${ENROLL_BODY}" | grep -q "/auth/enroll/dex/consent"; then
    run_test "Dex enrollment consent page (200 + consent form)" "pass" ""
else
    run_test "Dex enrollment consent page (200 + consent form)" "fail" \
        "Expected 200 with a POST form to /auth/enroll/dex/consent, got status ${ENROLL_STATUS}"
fi

# ---------------------------------------------------------------------------
# Test 5: no server stuck in auto-quarantine (R4.3)
#
# invocation.py auto-flips a server to debug_mode=true (debug_enabled_by=
# 'system:auto-health-check') after 3 consecutive connection-class failures,
# and NEVER auto-clears it (deliberate, fail-closed). While debug_mode=true,
# ONLY the owner/maintainers may invoke that server's tools — everyone else
# gets SERVER_IN_MAINTENANCE (services/invocation.py). This already happened
# live to the platform's own 'self-service' server and silently denied every
# non-owner caller platform-wide; it was only found by wiping the lab.
#
# Scope: debug_enabled_by = 'system:auto-health-check' specifically, NOT
# "any server with debug_mode=true" — that would false-positive constantly,
# since a freshly-approved self-hosted submission legitimately lands in
# debug_mode=true (owner-only, pending an explicit "go live") as part of the
# normal PRD-0012 C2 approval flow (debug_enabled_by is the approving
# reviewer's client_id in that case, e.g. 'carol@corp' — confirmed live in
# this lab: 18 servers were debug_mode=true from normal AT3 approvals when
# this check was written, only ONE (lab-m365) was the system auto-flag).
# Also NOT scoped to just 'self-service' — lab-m365 is live proof the same
# auto-quarantine already hits an arbitrary onboarded server, not only the
# platform's bundled one, so any such row is worth failing loudly on.
#
# debug_enabled_by isn't exposed by GET /api/v1/admin/servers today, so this
# queries server_registry directly (same pattern lab/tests/acceptance's
# conftest.py::db_query uses) rather than adding an endpoint.
# ---------------------------------------------------------------------------
echo ""
echo "Test 5: no server auto-quarantined (debug_enabled_by='system:auto-health-check')"
DB_CONTAINER="${DB_CONTAINER:-mcp-db}"
AUTO_QUARANTINED=$(
    podman exec "${DB_CONTAINER}" psql -q -U mcp_app -d mcp_security -tAc \
        "SELECT name FROM server_registry WHERE debug_mode = true \
         AND debug_enabled_by = 'system:auto-health-check' AND deleted_at IS NULL \
         ORDER BY name" 2>/dev/null || true
)
if [[ -z "${AUTO_QUARANTINED}" ]]; then
    run_test "No server auto-quarantined" "pass" ""
else
    NAMES="$(echo "${AUTO_QUARANTINED}" | tr '\n' ',' | sed 's/,$//')"
    run_test "No server auto-quarantined" "fail" \
        "Auto-quarantined (debug_mode=true, never auto-clears): ${NAMES} — EVERY non-owner caller is denied SERVER_IN_MAINTENANCE for these servers platform-wide. Clear via POST /api/v1/servers/{server_id}/debug-mode {\"enabled\": false} (platform_admin may disable even though only the owner/maintainers may enable) or the portal's admin 'Go live' action."
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
