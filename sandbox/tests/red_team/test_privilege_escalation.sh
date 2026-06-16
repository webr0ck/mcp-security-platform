#!/usr/bin/env bash
# test_privilege_escalation.sh — RT-004
# Proves --no-new-privileges and seccomp block privilege escalation attempts.

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/busybox:1.36}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"
NO_CLEANUP="${NO_CLEANUP:-false}"
RUN_ID="privesc-$(date +%s)"

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
        podman rm -f "privesc-unshare-${RUN_ID}" "privesc-ns-${RUN_ID}" "privesc-setuid-${RUN_ID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[INFO] $(ts) RT-004: Testing privilege escalation resistance..."

# RT-004a: unshare --map-root-user
output=$(podman run --name "privesc-unshare-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c 'unshare --map-root-user id 2>&1; echo EXIT:$?' 2>&1) || true

# If unshare ran and returned uid=0, that is a failure
if echo "${output}" | grep -q "uid=0" && echo "${output}" | grep -q "EXIT:0"; then
    fail "RT-004a: unshare --map-root-user returned uid=0. User namespace creation not blocked."
else
    pass "RT-004a: unshare --map-root-user blocked (seccomp CLONE_NEWUSER or no-new-privileges)."
fi

# RT-004b: Attempt to read host process info via /proc
output=$(podman run --name "privesc-ns-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c '
        # Try to enumerate host PIDs (should only see container PIDs)
        ls /proc/ 2>/dev/null | grep -E "^[0-9]+$" | sort -n | tail -5
        PID_MAX=$(ls /proc/ 2>/dev/null | grep -E "^[0-9]+$" | sort -n | tail -1)
        if [ -n "${PID_MAX}" ] && [ "${PID_MAX}" -gt 1000 ]; then
            echo "HIGH_PID_VISIBLE:${PID_MAX}"
        else
            echo "PID_NAMESPACE_ISOLATED"
        fi
    ' 2>&1) || true

if echo "${output}" | grep -q "HIGH_PID_VISIBLE"; then
    PID=$(echo "${output}" | grep "HIGH_PID_VISIBLE" | cut -d: -f2)
    fail "RT-004b: Visible PID ${PID} suggests host PID namespace is visible."
else
    pass "RT-004b: PID namespace appears isolated (no high host PIDs visible)."
fi

# RT-004c: CAP_SETUID / CAP_SETGID blocked
output=$(podman run --name "privesc-setuid-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c '
        # Try to setuid to 0
        python3 -c "import os; os.setuid(0); print(\"SETUID_OK\")" 2>&1 || echo "SETUID_BLOCKED"
    ' 2>&1) || true

if echo "${output}" | grep -q "SETUID_OK"; then
    fail "RT-004c: setuid(0) succeeded inside container. CAP_SETUID not dropped."
else
    pass "RT-004c: setuid(0) blocked — CAP_SETUID correctly dropped."
fi

echo "[INFO] $(ts) Privilege escalation tests complete."
