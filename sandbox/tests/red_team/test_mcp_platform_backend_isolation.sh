#!/usr/bin/env bash
# test_mcp_platform_backend_isolation.sh — RT-MCP-001
# Proves that lab MCP containers cannot reach platform backends (db, redis, opa).
#
# Plan requirement: from inside lab-mcp-echo, nc to mcp-db:5432, mcp-redis:6379,
# and mcp-opa:8181 must all fail (Task 2.2a red-team probe).
#
# Requirements:
#   - Lab stack must be running: podman-compose -f docker-compose.yml -f podman-compose.lab.yml up -d
#   - lab-mcp-echo container must be running
#
# Exit code: 0 = all probes blocked (PASS), 1 = any probe succeeded (FAIL)

set -euo pipefail

MCP_ECHO_CONTAINER="${MCP_ECHO_CONTAINER:-lab-mcp-echo}"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
pass() { printf "[PASS] %s %s\n" "$(ts)" "$*"; }
fail() { printf "[FAIL] %s %s\n" "$(ts)" "$*"; return 1; }
warn() { printf "[WARN] %s %s\n" "$(ts)" "$*"; }

OVERALL=0

echo "[INFO] $(ts) RT-MCP-001: Testing platform backend isolation from ${MCP_ECHO_CONTAINER}..."

# Preflight: check container is running
if ! podman inspect "${MCP_ECHO_CONTAINER}" --format "{{.State.Running}}" 2>/dev/null | grep -q "true"; then
    warn "Container ${MCP_ECHO_CONTAINER} is not running — is the lab stack up?"
    warn "Run: podman-compose -f docker-compose.yml -f podman-compose.lab.yml up -d lab-mcp-echo"
    echo "[SKIP] RT-MCP-001: lab-mcp-echo not running — skipping runtime probes (static config validated)"
    exit 0
fi

# Helper: attempt TCP connect from inside the MCP echo container
_probe() {
    local host="$1"
    local port="$2"
    local label="$3"
    # RELIABILITY FIX (validation HIGH-2): the old probe used `nc -z`, but nc is
    # NOT installed in these MCP containers, so it exited non-zero (command not
    # found) and the test reported "blocked" — a FALSE PASS that hid real
    # reachability (MCP-to-MCP lateral movement went undetected). Use a Python
    # socket connect, which is reliably present and actually establishes the TCP
    # connection. rc 0 = reachable (ISOLATION BROKEN), rc != 0 = blocked.
    if podman exec "${MCP_ECHO_CONTAINER}" python3 -c "
import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect(('${host}', ${port})); s.close(); sys.exit(0)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        fail "${label}: TCP connect to ${host}:${port} SUCCEEDED — reachable from MCP server (ISOLATION BROKEN)"
        OVERALL=1
    else
        pass "${label}: TCP connect to ${host}:${port} blocked — ${host} not reachable from MCP container"
    fi
}

# RT-MCP-001a: DB not reachable from echo MCP
_probe "mcp-db" "5432" "RT-MCP-001a (db:5432)"

# RT-MCP-001b: Redis not reachable from echo MCP
_probe "mcp-redis" "6379" "RT-MCP-001b (redis:6379)"

# RT-MCP-001c: OPA not reachable from echo MCP
_probe "mcp-opa" "8181" "RT-MCP-001c (opa:8181)"

# RT-MCP-001d: Vault not reachable from echo MCP
_probe "mcp-vault" "8200" "RT-MCP-001d (vault:8200)"

# RT-MCP-002: MCP-to-MCP lateral movement (validation HIGH-2). A compromised MCP
# server must NOT be able to reach ANOTHER MCP server's port directly — that
# bypasses the proxy/OPA/auth/credential-injection. Probes from lab-mcp-echo to
# peer MCP servers; each must be blocked (no shared network).
_probe "mcp-netbox"          "8000" "RT-MCP-002a (peer MCP mcp-netbox:8000)"
_probe "lab-mcp-gitea"       "8000" "RT-MCP-002b (peer MCP lab-mcp-gitea:8000)"
_probe "lab-mcp-grafana"     "8000" "RT-MCP-002c (peer MCP lab-mcp-grafana:8000)"
_probe "lab-mcp-lab-tickets" "8000" "RT-MCP-002d (peer MCP lab-mcp-lab-tickets:8000)"

echo "[INFO] $(ts) Platform backend + MCP-to-MCP isolation probes complete."

if [[ ${OVERALL} -ne 0 ]]; then
    echo "[FAIL] $(ts) RT-MCP-001: One or more platform backends are reachable from lab-mcp-echo — ISOLATION BROKEN"
    exit 1
else
    echo "[PASS] $(ts) RT-MCP-001: All platform backends are unreachable from lab-mcp-echo"
    exit 0
fi
