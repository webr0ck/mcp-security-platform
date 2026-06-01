"""
Validates the Vault deny-set policy for platform_admin (security invariant #3).

Checks:
- All required secret paths are present with 'deny' capability
- No wildcard paths (must be mount-precise)
- Transit KEK operations are denied
"""
import re
from pathlib import Path

POLICY_FILE = Path(__file__).parent.parent.parent.parent / "policies/vault/deny_platform_admin.hcl"

REQUIRED_DENIED_PATHS = [
    "secret/data/servers/*",
    "secret/metadata/servers/*",
    "secret/data/users/*",
    "secret/metadata/users/*",
    "transit/export/*",
    "transit/datakey/*",
    "transit/rewrap/*",
    "transit/rotate/*",
]


def _parse_policy_paths(content: str) -> dict[str, list[str]]:
    """Parse HCL policy into {path: [capabilities]}."""
    paths = {}
    for match in re.finditer(r'path\s+"([^"]+)"\s*\{[^}]*capabilities\s*=\s*\[([^\]]+)\]', content, re.DOTALL):
        path = match.group(1)
        caps = [c.strip().strip('"') for c in match.group(2).split(",")]
        paths[path] = caps
    return paths


def test_policy_file_exists():
    assert POLICY_FILE.exists(), f"Policy file not found: {POLICY_FILE}"


def test_all_required_paths_are_denied():
    content = POLICY_FILE.read_text()
    paths = _parse_policy_paths(content)

    for required_path in REQUIRED_DENIED_PATHS:
        assert required_path in paths, f"Missing deny for path: {required_path}"
        caps = paths[required_path]
        assert "deny" in caps, f"Path {required_path} has caps {caps}, expected 'deny'"


def test_no_wildcard_root_paths():
    """No single-segment wildcard (secret/* or transit/*) — must be mount-precise."""
    content = POLICY_FILE.read_text()
    # Disallow bare wildcard mounts like "secret/*"
    assert not re.search(r'path\s+"secret/\*"', content), "Wildcard 'secret/*' is forbidden — use mount-precise paths"
    assert not re.search(r'path\s+"transit/\*"', content), "Wildcard 'transit/*' is forbidden"


def test_delete_undelete_destroy_also_denied():
    """Deny set must include delete/undelete/destroy to prevent soft-delete bypass."""
    content = POLICY_FILE.read_text()
    paths = _parse_policy_paths(content)
    for op in ("delete", "undelete", "destroy"):
        server_path = f"secret/{op}/servers/*"
        assert server_path in paths, f"Missing deny for {server_path}"
        assert "deny" in paths[server_path]
