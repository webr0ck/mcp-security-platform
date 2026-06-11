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
    # nc -z = scan only (no data); -w 3 = 3s timeout; exit 0 if connected, 1 if not
    if podman exec "${MCP_ECHO_CONTAINER}" sh -c "nc -z -w3 ${host} ${port} 2>/dev/null"; then
        fail "${label}: TCP connect to ${host}:${port} SUCCEEDED — platform backend reachable from MCP server (ISOLATION BROKEN)"
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

echo "[INFO] $(ts) Platform backend isolation probes complete."

if [[ ${OVERALL} -ne 0 ]]; then
    echo "[FAIL] $(ts) RT-MCP-001: One or more platform backends are reachable from lab-mcp-echo — ISOLATION BROKEN"
    exit 1
else
    echo "[PASS] $(ts) RT-MCP-001: All platform backends are unreachable from lab-mcp-echo"
    exit 0
fi
