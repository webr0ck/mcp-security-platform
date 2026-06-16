#!/usr/bin/env bash
# =============================================================================
# test_symlink_escape.sh — CVE-2025-53109/53110: Symlink Path Traversal
# =============================================================================
# Verifies that symlinks inside the container CANNOT reach host-only filesystem
# paths. The container has its own /etc/passwd etc. — those are not escapes.
# A real escape would be reading paths that only exist on the macOS host or the
# Podman VM, not inside the container image.
#
# Also tests application-level path canonicalization (the actual CVE vector):
# CVE-2025-53109/53110 was a bug in the Anthropic Filesystem MCP Server where
# it checked path allowlists BEFORE resolving symlinks, allowing traversal
# WITHIN the MCP server's allowed directory scope.
#
# Covers: CVE-2025-53109, CVE-2025-53110 (Anthropic Filesystem MCP Server)
# FINDING: FINDING-002 (/proc/1/root is container-only, not host)
#
# Exit code: 0 = contained, 1 = host escape detected

set -euo pipefail

SANDBOX_NETWORK="${SANDBOX_NETWORK:-mcp-sandbox-net}"
PYTHON_IMAGE="${PYTHON_IMAGE:-docker.io/python:3.12-slim}"
SECCOMP_FLAGS="${SECCOMP_FLAGS:-}"

PASS=0
FAIL=0

pass() { printf "[PASS] %s\n" "$*"; (( PASS++ )) || true; }
fail() { printf "[FAIL] %s\n" "$*"; (( FAIL++ )) || true; }

# ---------------------------------------------------------------------------
# RT-SYM-001: Symlink cannot reach HOST-only paths (macOS or Podman VM paths)
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

# These paths exist ONLY on a macOS host, NOT inside a Linux container image.
# If a symlink inside /tmp can read them, the container overlay has leaked to host.
host_only_paths = [
    '/Users',              # macOS user home base — does not exist in Linux containers
    '/Library',            # macOS system library
    '/private/etc/sudoers', # macOS-specific path
    '/System/Library',     # macOS System directory
]

results = []
for target in host_only_paths:
    sym = pathlib.Path(f'/tmp/sym_test_{pathlib.Path(target).name}')
    try:
        if sym.is_symlink():
            sym.unlink()
        sym.symlink_to(target)
        # If the symlink target EXISTS, we have leaked to host
        if pathlib.Path(target).exists() or sym.exists():
            results.append({'target': target, 'escaped': True})
            print(f'ESCAPED: {target} reachable via symlink — host filesystem visible')
        else:
            results.append({'target': target, 'escaped': False})
    except (PermissionError, OSError) as e:
        results.append({'target': target, 'escaped': False, 'error': str(e)})
    finally:
        try:
            sym.unlink(missing_ok=True)
        except OSError:
            pass

escaped = [r for r in results if r.get('escaped')]
if escaped:
    print(f'ESCAPED: {len(escaped)} host paths reachable via symlink')
    sys.exit(1)
else:
    print(f'CONTAINED: none of {len(host_only_paths)} host-only paths reachable via symlink')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "^ESCAPED"; then
    fail "RT-SYM-001: Symlink reaches host filesystem — ${result}"
else
    pass "RT-SYM-001: Symlinks cannot reach host-only paths (container overlay isolated)"
fi
echo "  Detail: ${result}"

# ---------------------------------------------------------------------------
# RT-SYM-002: /proc/1/root shows container overlay, NOT host filesystem
# Validates FINDING-002: confirmed contained in prior red team session
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
try:
    root = pathlib.Path('/proc/1/root')
    contents = [p.name for p in root.iterdir()]
    # macOS host indicators — these must NOT appear in a Linux container
    host_indicators = [n for n in contents if n in ('Users', 'Library', 'System', 'Applications')]
    if host_indicators:
        print(f'ESCAPED: /proc/1/root shows macOS host dirs: {host_indicators}')
        sys.exit(1)
    else:
        print(f'CONTAINED: /proc/1/root shows Linux container dirs: {sorted(contents)[:10]}')
        sys.exit(0)
except (PermissionError, OSError) as e:
    print(f'CONTAINED: /proc/1/root not accessible: {e}')
    sys.exit(0)
" 2>&1)

if echo "${result}" | grep -q "ESCAPED"; then
    fail "RT-SYM-002: /proc/1/root shows host filesystem — ${result}"
else
    pass "RT-SYM-002: /proc/1/root scoped to container overlay (FINDING-002 confirmed contained)"
fi
echo "  Detail: ${result}"

# ---------------------------------------------------------------------------
# RT-SYM-003: Application-level path canonicalization (CVE-2025-53109 logic)
# Simulates the filesystem MCP server allowlist bypass:
#   allowed_dir = /tmp/allowed
#   symlink: /tmp/allowed/lnk -> /tmp/outside/secret
#   pre-canonicalization check: /tmp/allowed/lnk is IN allowed — PASSES (vulnerable)
#   post-canonicalization check: realpath = /tmp/outside/secret — NOT in allowed — BLOCKS (safe)
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
import pathlib, sys, os

# Simulate CVE-2025-53109: MCP server checks allowlist before resolving symlink
allowed_dir = pathlib.Path('/tmp/allowed')
outside_dir = pathlib.Path('/tmp/outside')
allowed_dir.mkdir(exist_ok=True)
outside_dir.mkdir(exist_ok=True)

secret_file = outside_dir / 'secret.txt'
secret_file.write_text('SECRET_CONTENT')

symlink = allowed_dir / 'link_to_secret'
symlink.symlink_to(secret_file)

# Vulnerable check: checks symlink path against allowlist (CVE pattern)
def vulnerable_check(path: str, allowed: str) -> bool:
    return path.startswith(allowed)  # does NOT resolve symlinks first

# Secure check: resolves realpath first
def secure_check(path: str, allowed: str) -> bool:
    real = os.path.realpath(path)
    return real.startswith(os.path.realpath(allowed))

symlink_path = str(symlink)
allowed_path = str(allowed_dir)

vuln_result = vulnerable_check(symlink_path, allowed_path)
secure_result = secure_check(symlink_path, allowed_path)

print(f'Vulnerable check allows traversal: {vuln_result}   (would allow reading {secret_file})')
print(f'Secure check (realpath first) allows: {secure_result}  (blocks traversal)')

if vuln_result and not secure_result:
    print('CORRECT: secure_check blocks what vulnerable_check allows — CVE-2025-53109 pattern demonstrated')
    sys.exit(0)
else:
    print(f'UNEXPECTED: vuln={vuln_result} secure={secure_result}')
    sys.exit(1)
" 2>&1)

if echo "${result}" | grep -q "CORRECT"; then
    pass "RT-SYM-003: Path canonicalization (realpath) blocks symlink traversal — CVE-2025-53109 pattern"
else
    fail "RT-SYM-003: Canonicalization test unexpected result — ${result}"
fi
echo "  Detail: ${result}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Symlink escape test: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
