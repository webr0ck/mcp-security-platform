#!/usr/bin/env bash
# test_network_isolation.sh — RT-001 + RT-002
# Proves internet egress and host network are unreachable from sandbox containers.

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/busybox:1.36}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"
NO_CLEANUP="${NO_CLEANUP:-false}"
RUN_ID="netiso-$(date +%s)"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
pass() { printf "[PASS] %s %s\n" "$(ts)" "$*"; }
fail() { printf "[FAIL] %s %s\n" "$(ts)" "$*"; return 1; }

HARDENED=(
    --rm
    --network "${SANDBOX_NETWORK}"
    --cap-drop=ALL
    --security-opt no-new-privileges
    ${SECCOMP_FLAGS}
    --read-only
    --tmpfs /tmp:rw,noexec,nosuid,size=16m
    --memory=64m
    --pids-limit=16
)

cleanup() {
    if [[ "${NO_CLEANUP}" != "true" ]]; then
        podman rm -f "netiso-egress-${RUN_ID}" "netiso-dns-${RUN_ID}" "netiso-host-${RUN_ID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[INFO] $(ts) RT-001: Testing internet egress from ${SANDBOX_NETWORK}..."

# RT-001a: TCP connect to 8.8.8.8:53
output=$(podman run --name "netiso-egress-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c "nc -z -w5 8.8.8.8 53 2>&1; echo EXIT:$?" 2>&1) || true

if echo "${output}" | grep -q "EXIT:0"; then
    fail "RT-001a: TCP connect to 8.8.8.8:53 SUCCEEDED. Internet is reachable."
else
    pass "RT-001a: TCP connect to 8.8.8.8:53 blocked."
fi

# RT-001b: DNS lookup
output=$(podman run --name "netiso-dns-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c "nslookup google.com 2>&1; echo EXIT:$?" 2>&1) || true

if echo "${output}" | grep -q "EXIT:0" && echo "${output}" | grep -qi "address\|answer"; then
    fail "RT-001b: DNS lookup for google.com succeeded. DNS server is reachable."
else
    pass "RT-001b: DNS lookup for google.com failed or returned no address."
fi

# RT-002: Host network reachability
echo "[INFO] $(ts) RT-002: Testing host network reachability from ${SANDBOX_NETWORK}..."

# Get host IP (first non-loopback)
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | head -1)

if [[ -z "${HOST_IP}" ]]; then
    echo "[WARN] $(ts) Could not determine host IP. Skipping RT-002."
else
    # Try to reach host SSH port
    output=$(podman run --name "netiso-host-${RUN_ID}" "${HARDENED[@]}" \
        "${TEST_IMAGE}" \
        sh -c "nc -z -w5 ${HOST_IP} 22 2>&1; echo EXIT:$?" 2>&1) || true

    if echo "${output}" | grep -q "EXIT:0"; then
        fail "RT-002: Reached host (${HOST_IP}) port 22 from sandbox. Host network is reachable."
    else
        pass "RT-002: Host (${HOST_IP}) port 22 not reachable from sandbox."
    fi
fi

echo "[INFO] $(ts) Network isolation tests complete."
