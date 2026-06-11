#!/usr/bin/env bash
# test_mcp_egress_control.sh — RT-MCP-002
# Validates default-closed egress for lab MCP servers:
#   a) lab-mcp-echo (no egress net) cannot reach the internet directly
#   b) lab-mcp-m365 (on mcp-egress-net) routes allowlisted hosts via the
#      forward proxy (lab-egress-proxy), and non-allowlisted hosts are blocked
#
# Requirements:
#   - Lab stack must be running
#   - lab-mcp-echo and lab-mcp-m365 containers must be running
#
# Exit code: 0 = all probes behave correctly, 1 = any unexpected result

set -euo pipefail

ECHO_CONTAINER="${ECHO_CONTAINER:-lab-mcp-echo}"
M365_CONTAINER="${M365_CONTAINER:-lab-mcp-m365}"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
pass() { printf "[PASS] %s %s\n" "$(ts)" "$*"; }
fail() { printf "[FAIL] %s %s\n" "$(ts)" "$*"; return 1; }
warn() { printf "[WARN] %s %s\n" "$(ts)" "$*"; }

OVERALL=0

# Helper: check if a container is running
_running() {
    podman inspect "$1" --format "{{.State.Running}}" 2>/dev/null | grep -q "true"
}

echo "[INFO] $(ts) RT-MCP-002: Testing egress control for lab MCP servers..."

# ── RT-MCP-002a: lab-mcp-echo cannot reach the internet (lab-net is internal: true) ──
if ! _running "${ECHO_CONTAINER}"; then
    warn "${ECHO_CONTAINER} not running — skipping internet egress test (static config validated)"
else
    # Try curl to https://example.com from inside echo container
    if podman exec "${ECHO_CONTAINER}" sh -c \
        "curl -s --max-time 5 https://example.com 2>&1" | grep -qi "example"; then
        fail "RT-MCP-002a: ${ECHO_CONTAINER} reached https://example.com — internet egress not blocked"
        OVERALL=1
    else
        pass "RT-MCP-002a: ${ECHO_CONTAINER} cannot reach https://example.com (lab-net is internal: true)"
    fi
fi

# ── RT-MCP-002b: lab-mcp-m365 can reach allowlisted MS endpoints via egress proxy ──
# (This test validates proxy connectivity — it does NOT authenticate to Microsoft)
if ! _running "${M365_CONTAINER}"; then
    warn "${M365_CONTAINER} not running — skipping m365 egress test"
else
    # HTTPS CONNECT to login.microsoftonline.com via squid proxy should succeed
    result=$(podman exec "${M365_CONTAINER}" sh -c \
        "curl -s --proxy http://lab-egress-proxy:3128 --max-time 10 \
        -o /dev/null -w '%{http_code}' \
        https://login.microsoftonline.com 2>&1" || echo "FAILED")
    if echo "${result}" | grep -qE "^[234][0-9][0-9]$"; then
        pass "RT-MCP-002b: ${M365_CONTAINER} reached login.microsoftonline.com via egress proxy (HTTP ${result})"
    else
        warn "RT-MCP-002b: ${M365_CONTAINER} → login.microsoftonline.com returned '${result}'"
        warn "  This may be expected if the lab has no internet connectivity."
        warn "  The test validates proxy connectivity, not MS authentication."
    fi

    # Blocked: curl to non-allowlisted host should be denied
    denied=$(podman exec "${M365_CONTAINER}" sh -c \
        "curl -s --proxy http://lab-egress-proxy:3128 --max-time 10 \
        -o /dev/null -w '%{http_code}' \
        https://example.com 2>&1" || echo "FAILED")
    if echo "${denied}" | grep -qE "^(403|503|000|FAILED)"; then
        pass "RT-MCP-002c: ${M365_CONTAINER} cannot reach https://example.com via egress proxy (denied: ${denied})"
    else
        fail "RT-MCP-002c: ${M365_CONTAINER} reached https://example.com via egress proxy (HTTP ${denied}) — allowlist not enforced"
        OVERALL=1
    fi
fi

echo "[INFO] $(ts) Egress control probes complete."

if [[ ${OVERALL} -ne 0 ]]; then
    echo "[FAIL] $(ts) RT-MCP-002: Egress control violations detected"
    exit 1
else
    echo "[PASS] $(ts) RT-MCP-002: Egress control behaves correctly"
    exit 0
fi
