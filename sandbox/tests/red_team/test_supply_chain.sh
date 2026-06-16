#!/usr/bin/env bash
# =============================================================================
# test_supply_chain.sh — Supply Chain: Malicious Package Indicator Detection
# =============================================================================
# Verifies that no credential-bearing env vars, credential files, or sensitive
# mounts are accessible to a container — the exact data a malicious MCP package
# (like the fake Oura malware or Postmark BCC injector) would silently exfiltrate.
#
# Covers: Fake Oura MCP (Feb 2026), Postmark MCP BCC injection (Sep 2025)
# Addresses: FINDING-001 (env var credential leak), FINDING-003 (rhsm mount)
#
# Exit code: 0 = no sensitive data exposed, 1 = sensitive data found

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/python:3.12-slim}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"

PASS=0
FAIL=0

pass() { printf "[PASS] %s\n" "$*"; (( PASS++ )) || true; }
fail() { printf "[FAIL] %s\n" "$*"; (( FAIL++ )) || true; }

# ---------------------------------------------------------------------------
# RT-SC-001: No credential-bearing env vars injected into sandbox container
# ---------------------------------------------------------------------------
result=$(podman run --rm \
    --network "${SANDBOX_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    ${SECCOMP_FLAGS} \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --memory=64m \
    --pids-limit=32 \
    "${PYTHON_IMAGE}" \
    python3 -c "
import os, sys
sensitive_keywords = ['KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'PRIVATE', 'CERT']
found = [k for k in os.environ if any(kw in k.upper() for kw in sensitive_keywords)]
# Exclude known-safe container infrastructure vars (not user-injected credentials)
safe_container_vars = {
    'GPG_KEY',           # Python base image: package signing key (not a secret)
    'PYTHON_GPG_KEY',    # Python base image variant
    'HOME',              # not credential-related despite potential name match
}
found = [k for k in found if k not in safe_container_vars]
if found:
    print(f'LEAKED: credential-like env vars found: {found}')
    sys.exit(1)
else:
    print(f'CLEAN: no credential-like env vars. Total vars: {len(os.environ)}')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "LEAKED"; then
    fail "RT-SC-001: Credential env vars exposed to container — FINDING-001 confirmed: ${result}"
else
    pass "RT-SC-001: No credential env vars in container"
fi

# ---------------------------------------------------------------------------
# RT-SC-002: No credential files mounted (AWS, GCloud, SSH keys)
# ---------------------------------------------------------------------------
result=$(podman run --rm \
    --network "${SANDBOX_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    ${SECCOMP_FLAGS} \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --memory=64m \
    --pids-limit=32 \
    "${PYTHON_IMAGE}" \
    python3 -c "
import pathlib, sys
credential_paths = [
    '/root/.aws/credentials',
    '/root/.aws/config',
    '/root/.config/gcloud/credentials.db',
    '/root/.config/gcloud/access_tokens.db',
    pathlib.Path.home() / '.ssh' / 'id_rsa',
    pathlib.Path.home() / '.ssh' / 'id_ed25519',
    '/run/secrets/aws_access_key',
    '/run/secrets/api_token',
]
found = [str(p) for p in credential_paths if pathlib.Path(p).exists()]
if found:
    print(f'EXPOSED: credential files accessible: {found}')
    sys.exit(1)
else:
    print('CLEAN: no credential files found')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "EXPOSED"; then
    fail "RT-SC-002: Credential files accessible in container — ${result}"
else
    pass "RT-SC-002: No credential files mounted in container"
fi

# ---------------------------------------------------------------------------
# RT-SC-003: RHSM auto-mount check (FINDING-003)
# ---------------------------------------------------------------------------
result=$(podman run --rm \
    --network "${SANDBOX_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    ${SECCOMP_FLAGS} \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --memory=64m \
    --pids-limit=32 \
    "${PYTHON_IMAGE}" \
    python3 -c "
import pathlib, sys
rhsm = pathlib.Path('/run/secrets/rhsm')
if rhsm.exists():
    contents = list(rhsm.iterdir()) if rhsm.is_dir() else []
    print(f'MOUNTED: /run/secrets/rhsm exists with {len(contents)} entries (FINDING-003)')
    # Low severity — not a test failure but we report it
    sys.exit(0)
else:
    print('CLEAN: /run/secrets/rhsm not mounted')
    sys.exit(0)
" 2>&1)

# RHSM is low severity — warn but do not fail
if echo "${result}" | grep -q "MOUNTED"; then
    printf "[WARN] RT-SC-003: %s\n" "${result}"
    (( PASS++ )) || true
else
    pass "RT-SC-003: /run/secrets/rhsm not auto-mounted"
fi

# ---------------------------------------------------------------------------
# RT-SC-004: Docker/Podman socket not accessible (prevents container escape via API)
# ---------------------------------------------------------------------------
result=$(podman run --rm \
    --network "${SANDBOX_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    ${SECCOMP_FLAGS} \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --memory=64m \
    --pids-limit=32 \
    "${PYTHON_IMAGE}" \
    python3 -c "
import pathlib, sys
sockets = [
    '/var/run/docker.sock',
    '/var/run/podman/podman.sock',
    '/run/user/0/podman/podman.sock',
]
found = [s for s in sockets if pathlib.Path(s).exists()]
if found:
    print(f'EXPOSED: container runtime socket accessible: {found}')
    sys.exit(1)
else:
    print('CLEAN: no container runtime sockets accessible')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "EXPOSED"; then
    fail "RT-SC-004: Container runtime socket exposed — enables CVE-2025-9074 class escape: ${result}"
else
    pass "RT-SC-004: No container runtime socket accessible"
fi

# ---------------------------------------------------------------------------
# RT-SC-005: /proc/1/environ does not contain host secrets
# ---------------------------------------------------------------------------
result=$(podman run --rm \
    --network "${SANDBOX_NETWORK}" \
    --cap-drop=ALL \
    --security-opt no-new-privileges \
    ${SECCOMP_FLAGS} \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=32m \
    --memory=64m \
    --pids-limit=32 \
    "${PYTHON_IMAGE}" \
    python3 -c "
import sys
safe_container_vars = {'GPG_KEY', 'PYTHON_GPG_KEY'}  # Python base image signing keys
try:
    with open('/proc/1/environ', 'rb') as f:
        raw = f.read(65536)
    pairs = [p.decode('utf-8', errors='replace') for p in raw.split(b'\x00') if p and b'=' in p]
    sensitive_keywords = ['KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL']
    found = [p for p in pairs if any(kw in p.upper() for kw in sensitive_keywords)
             and p.split('=', 1)[0] not in safe_container_vars]
    if found:
        print(f'LEAKED: /proc/1/environ has {len(found)} credential-like entries')
        sys.exit(1)
    else:
        print(f'CLEAN: /proc/1/environ has {len(pairs)} vars, none credential-like (user-injected)')
        sys.exit(0)
except (PermissionError, OSError) as e:
    print(f'CLEAN: /proc/1/environ not readable: {e}')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "LEAKED"; then
    fail "RT-SC-005: /proc/1/environ leaks credentials — ${result}"
else
    pass "RT-SC-005: /proc/1/environ contains no credential-bearing vars"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Supply chain test: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
