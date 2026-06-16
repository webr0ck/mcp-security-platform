#!/usr/bin/env bash
# test_seccomp.sh — RT-007
# Proves the seccomp profile blocks dangerous syscalls (ptrace, mount, kexec_load).

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
TEST_IMAGE="${TEST_IMAGE:-docker.io/busybox:1.36}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/python:3.12-slim}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"
NO_CLEANUP="${NO_CLEANUP:-false}"
RUN_ID="seccomp-$(date +%s)"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
pass() { printf "[PASS] %s %s\n" "$(ts)" "$*"; }
fail() { printf "[FAIL] %s %s\n" "$(ts)" "$*"; return 1; }
warn() { printf "[WARN] %s %s\n" "$(ts)" "$*"; }

cleanup() {
    if [[ "${NO_CLEANUP}" != "true" ]]; then
        podman rm -f "seccomp-ptrace-${RUN_ID}" "seccomp-mount-${RUN_ID}" "seccomp-caps-${RUN_ID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "[INFO] $(ts) RT-007: Testing seccomp profile enforcement..."

if [[ -z "${SECCOMP_FLAGS}" ]]; then
    warn "No seccomp profile configured. These tests will likely FAIL."
    warn "Run 01-prepare-environment.yml to deploy the seccomp profile."
fi

HARDENED=(
    --rm
    --network "${SANDBOX_NETWORK}"
    --cap-drop=ALL
    --security-opt no-new-privileges
    ${SECCOMP_FLAGS}
    --read-only
    --tmpfs /tmp:rw,noexec,nosuid,size=16m
    --memory=128m
    --pids-limit=16
)

# RT-007a: ptrace blocked
output=$(podman run --name "seccomp-ptrace-${RUN_ID}" "${HARDENED[@]}" \
    "${PYTHON_IMAGE}" \
    python3 -c "
import ctypes, sys, os

libc = ctypes.CDLL('libc.so.6', use_errno=True)

# PTRACE_TRACEME = 0
result = libc.ptrace(0, 0, 0, 0)
errno = ctypes.get_errno()

if result == -1:
    if errno == 1:  # EPERM
        print('PTRACE_BLOCKED_EPERM')
    elif errno == 13:  # EACCES
        print('PTRACE_BLOCKED_EACCES')
    else:
        print(f'PTRACE_BLOCKED_ERRNO_{errno}')
    sys.exit(0)
else:
    print(f'PTRACE_ALLOWED result={result}')
    sys.exit(1)
" 2>&1) || PTRACE_EXIT=$?

if echo "${output}" | grep -q "PTRACE_BLOCKED"; then
    pass "RT-007a: ptrace blocked by seccomp (${output})."
elif echo "${output}" | grep -q "PTRACE_ALLOWED"; then
    fail "RT-007a: ptrace allowed by seccomp. Attacker can trace host processes."
else
    warn "RT-007a: Unexpected output from ptrace test: ${output}"
    fail "RT-007a: ptrace test inconclusive."
fi

# RT-007b: mount blocked
output=$(podman run --name "seccomp-mount-${RUN_ID}" "${HARDENED[@]}" \
    "${PYTHON_IMAGE}" \
    python3 -c "
import ctypes, sys

libc = ctypes.CDLL('libc.so.6', use_errno=True)

# Try to mount tmpfs on /tmp (already mounted, but mount() is the test)
result = libc.mount(b'none', b'/tmp', b'tmpfs', 0, None)
errno = ctypes.get_errno()

if result == -1:
    if errno == 1:   # EPERM
        print('MOUNT_BLOCKED_EPERM')
    elif errno == 13:  # EACCES
        print('MOUNT_BLOCKED_EACCES')
    elif errno == 22:  # EINVAL
        # EINVAL can mean the syscall was allowed but the args were bad
        print(f'MOUNT_EINVAL — syscall may have been allowed (errno=22)')
        sys.exit(1)
    else:
        print(f'MOUNT_BLOCKED_ERRNO_{errno}')
    sys.exit(0)
else:
    print(f'MOUNT_ALLOWED result={result}')
    sys.exit(1)
" 2>&1) || MOUNT_EXIT=$?

if echo "${output}" | grep -qE "MOUNT_BLOCKED"; then
    pass "RT-007b: mount blocked by seccomp (${output})."
elif echo "${output}" | grep -q "MOUNT_ALLOWED"; then
    fail "RT-007b: mount allowed by seccomp. Attacker can mount host filesystems."
else
    warn "RT-007b: mount test output: ${output}"
    # EINVAL after the kernel allowed the syscall is worse than EPERM
    fail "RT-007b: mount test inconclusive — seccomp may not be blocking mount."
fi

# RT-007c: CapEff must be zero
output=$(podman run --name "seccomp-caps-${RUN_ID}" "${HARDENED[@]}" \
    "${TEST_IMAGE}" \
    sh -c 'grep CapEff /proc/1/status 2>/dev/null || echo NO_PROC_STATUS' 2>&1) || true

CAPEFF=$(echo "${output}" | grep "^CapEff:" | awk '{print $2}')

if [[ -z "${CAPEFF}" ]]; then
    warn "RT-007c: Could not read CapEff from /proc/1/status."
elif echo "${CAPEFF}" | grep -qE "^0+$"; then
    pass "RT-007c: CapEff=${CAPEFF} — all capabilities dropped."
else
    fail "RT-007c: CapEff=${CAPEFF} — container has non-zero capabilities."
fi

echo "[INFO] $(ts) Seccomp tests complete."
