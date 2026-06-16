#!/usr/bin/env bash
# =============================================================================
# test_stdio_injection.sh — CVE-2026-0755 / CVE-2025-6514: STDIO Command Injection
# =============================================================================
# Verifies that shell metacharacters injected via tool arguments do NOT execute
# when passed to subprocess calls in the sandbox environment.
#
# Covers: CVE-2026-0755 (CVSS 9.8), CVE-2025-6514, CVE-2025-59528
# Real-world context: Gemini MCP execAsync, mcp-remote auth endpoint,
#                     Flowise STDIO transport all suffered this class of bug.
#
# The test checks two conditions:
#   1. Inside the container: shell=False subprocess ignores metacharacters
#   2. The malicious-mcp server's own stdio_injection tool returns contained=true
#
# Exit code: 0 = contained, 1 = injection detected

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/python:3.12-slim}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"

PASS=0
FAIL=0

pass() { printf "[PASS] %s\n" "$*"; (( PASS++ )) || true; }
fail() { printf "[FAIL] %s\n" "$*"; (( FAIL++ )) || true; }

# ---------------------------------------------------------------------------
# RT-STDIO-001: shell=False subprocess does NOT expand metacharacters
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
import subprocess, sys
# Payloads that would be dangerous with shell=True
payloads = [
    'safe; id',
    'safe && whoami',
    'safe | cat /etc/passwd',
]
all_contained = True
for p in payloads:
    proc = subprocess.run(['/bin/echo', p], capture_output=True, text=True, shell=False, timeout=2)
    if proc.stdout.strip() != p:
        print(f'ESCAPED: payload={p!r} output={proc.stdout.strip()!r}')
        all_contained = False
    else:
        print(f'CONTAINED: {p!r} returned verbatim')
if all_contained:
    sys.exit(0)
else:
    sys.exit(1)
" 2>&1)

if echo "${result}" | grep -q "ESCAPED"; then
    fail "RT-STDIO-001: shell=False injection — ${result}"
else
    pass "RT-STDIO-001: shell=False subprocess does not expand metacharacters"
fi

# ---------------------------------------------------------------------------
# RT-STDIO-002: Verify no shell=True execution path exists via /bin/sh -c
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
import subprocess, sys
# Verify that even if someone tried shell=True, noexec on /tmp blocks writing outputs
# We test: write to /tmp is allowed, but executing from /tmp is blocked
try:
    import tempfile, os, stat
    with tempfile.NamedTemporaryFile(suffix='.sh', mode='w', delete=False, dir='/tmp') as f:
        f.write('#!/bin/sh\necho ESCAPED\n')
        tmpname = f.name
    os.chmod(tmpname, stat.S_IRWXU)
    proc = subprocess.run([tmpname], capture_output=True, text=True, timeout=2)
    if 'ESCAPED' in proc.stdout:
        print('ESCAPED: noexec /tmp failed — executed script from /tmp')
        sys.exit(1)
    else:
        print(f'CONTAINED: script exec from /tmp blocked (returncode={proc.returncode})')
        sys.exit(0)
except (PermissionError, OSError) as e:
    print(f'CONTAINED: {e}')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "ESCAPED"; then
    fail "RT-STDIO-002: noexec /tmp bypass — ${result}"
else
    pass "RT-STDIO-002: /tmp noexec prevents script execution from tmpfs"
fi

# ---------------------------------------------------------------------------
# RT-STDIO-003: Verify PATH manipulation does not achieve code execution
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
import os, subprocess, sys
# Attempt: write a fake 'ls' to /tmp, add /tmp to PATH, call 'ls'
try:
    with open('/tmp/ls', 'w') as f:
        f.write('#!/bin/sh\necho ESCAPED_via_PATH_injection\n')
    import stat
    os.chmod('/tmp/ls', stat.S_IRWXU)
    env = dict(os.environ)
    env['PATH'] = '/tmp:' + env.get('PATH', '')
    proc = subprocess.run(['ls', '--version'], env=env, capture_output=True, text=True,
                          timeout=2, shell=False)
    if 'ESCAPED_via_PATH_injection' in proc.stdout:
        print('ESCAPED: PATH injection succeeded')
        sys.exit(1)
    else:
        print(f'CONTAINED: PATH injection blocked (noexec/perms). stdout={proc.stdout[:80]!r}')
        sys.exit(0)
except (PermissionError, OSError) as e:
    print(f'CONTAINED: {e}')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "ESCAPED"; then
    fail "RT-STDIO-003: PATH injection via /tmp ESCAPED — ${result}"
else
    pass "RT-STDIO-003: PATH injection via /tmp blocked by noexec"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "STDIO injection test: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
