#!/usr/bin/env bash
# test_filesystem_isolation.sh — RT-003
# Proves --read-only rootfs prevents writes to sensitive paths.

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/busybox:1.36}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"
NO_CLEANUP="${NO_CLEANUP:-false}"
RUN_ID="fsiso-$(date +%s)"

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
        podman rm -f "fsiso-etc-${RUN_ID}" "fsiso-root-${RUN_ID}" "fsiso-tmp-${RUN_ID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[INFO] $(ts) RT-003: Testing filesystem isolation (read-only rootfs)..."

# RT-003a: Write to /etc/passwd
output=$(podman run --name "fsiso-etc-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c 'echo "evil:x:0:0:root:/root:/bin/bash" >> /etc/passwd 2>&1; echo EXIT:$?' 2>&1) || true

if echo "${output}" | grep -q "EXIT:0"; then
    fail "RT-003a: Write to /etc/passwd succeeded. rootfs is NOT read-only."
else
    pass "RT-003a: Write to /etc/passwd blocked by read-only rootfs."
fi

# RT-003b: Create file at root
output=$(podman run --name "fsiso-root-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c 'touch /host-escape-test 2>&1; echo EXIT:$?' 2>&1) || true

if echo "${output}" | grep -q "EXIT:0"; then
    fail "RT-003b: touch /host-escape-test succeeded. rootfs is NOT read-only."
else
    pass "RT-003b: touch /host-escape-test blocked."
fi

# RT-003c: /tmp is writable (tmpfs) but /etc is not
output=$(podman run --name "fsiso-tmp-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c '
        # /tmp should be writable (it is a tmpfs)
        touch /tmp/test-write 2>&1 && echo TMP_WRITE_OK || echo TMP_WRITE_FAIL
        # /etc should NOT be writable
        touch /etc/test-write 2>&1 && echo ETC_WRITE_OK || echo ETC_WRITE_FAIL
    ' 2>&1) || true

if echo "${output}" | grep -q "TMP_WRITE_OK"; then
    pass "RT-003c: /tmp is writable (tmpfs correctly mounted)."
else
    echo "[WARN] $(ts) RT-003c: /tmp is not writable — this may break some MCP servers."
fi

if echo "${output}" | grep -q "ETC_WRITE_FAIL"; then
    pass "RT-003c: /etc is NOT writable (read-only rootfs enforced)."
else
    fail "RT-003c: /etc is writable. read-only rootfs not enforced."
fi

echo "[INFO] $(ts) Filesystem isolation tests complete."
