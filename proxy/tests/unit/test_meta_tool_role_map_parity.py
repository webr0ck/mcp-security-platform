"""
Parity between _TOOLS[i]["_roles"] (list-time) and authz.rego's
platform_meta_tool_roles (invoke-time).

authz.rego's own comment has always said this map "MUST mirror the _roles set
declared on each entry in _TOOLS" — but nothing enforced it, and it drifted: four
meta-tools were missing entirely, so `is_platform_meta_tool` was false for them and
they fell through to the generic allow. That path's `client_has_invoke_permission`
recognises agent/user/admin/platform_admin/analyst/platform_internal/server_owner/
manager and never viewer or editor, while _TOOLS grants exactly those roles.

Net effect: a viewer or editor SAW get_my_profile / enable_mcp_server in tools/list
and was denied on tools/call — the listed-but-denied class again, and specifically on
the recovery path out of a profile lockout.

A comment is not an enforcement mechanism. This test is.
"""
import re
from pathlib import Path

import pytest

from app.routers.mcp_server import _TOOLS

_REGO = Path(__file__).resolve().parents[2].parent / "policies" / "rego" / "authz.rego"

# invoke_tool is deliberately absent from the rego map: it runs the full OPA pipeline
# against its TARGET registry tool via services/invocation.py, so gating the wrapper
# itself as a meta-tool would double-gate it against the wrong subject.
_INTENTIONALLY_ABSENT = {"invoke_tool"}


def _parse_rego_meta_tool_roles() -> dict[str, set[str]]:
    src = _REGO.read_text()
    block = re.search(
        r"platform_meta_tool_roles\s*:=\s*\{(.*?)\n\}", src, re.DOTALL
    )
    assert block, "platform_meta_tool_roles map not found in authz.rego"
    body = block.group(1)
    out: dict[str, set[str]] = {}
    for name, roles in re.findall(r'"([\w-]+)"\s*:\s*\{([^}]*)\}', body):
        out[name] = set(re.findall(r'"([\w-]+)"', roles))
    return out


def _python_meta_tool_roles() -> dict[str, set[str]]:
    return {t["name"]: set(t["_roles"]) for t in _TOOLS}


class TestMetaToolRoleParity:
    def test_rego_map_parses(self):
        assert _parse_rego_meta_tool_roles(), "failed to parse the rego map"

    def test_every_meta_tool_is_mapped(self):
        py = _python_meta_tool_roles()
        rego = _parse_rego_meta_tool_roles()
        missing = set(py) - set(rego) - _INTENTIONALLY_ABSENT
        assert not missing, (
            f"meta-tools visible at list time but absent from platform_meta_tool_roles: "
            f"{sorted(missing)}. They fall through to the generic allow, which does not "
            f"recognise viewer/editor — so those roles see them and cannot call them."
        )

    def test_no_phantom_entries_in_rego(self):
        py = _python_meta_tool_roles()
        rego = _parse_rego_meta_tool_roles()
        phantom = set(rego) - set(py)
        assert not phantom, (
            f"platform_meta_tool_roles grants roles on tools that no longer exist in "
            f"_TOOLS: {sorted(phantom)}. Stale grants are silent over-permission."
        )

    @pytest.mark.parametrize("tool_name", sorted(set(_python_meta_tool_roles()) - _INTENTIONALLY_ABSENT))
    def test_role_sets_match_exactly(self, tool_name):
        py = _python_meta_tool_roles()[tool_name]
        rego = _parse_rego_meta_tool_roles().get(tool_name, set())
        assert py == rego, (
            f"{tool_name}: _TOOLS grants {sorted(py)} but authz.rego grants {sorted(rego)}. "
            f"Extra in rego = callable but not listed; extra in _TOOLS = listed but denied."
        )

    def test_recovery_tools_reachable_by_every_role_that_can_see_them(self):
        # get_my_profile / enable_mcp_server are how a user escapes a profile lockout
        # (see _RECOVERY_MCPS in routers/profiles.py). Recovery that works for only
        # some roles is not recovery.
        rego = _parse_rego_meta_tool_roles()
        py = _python_meta_tool_roles()
        for tool in ("get_my_profile", "enable_mcp_server"):
            assert tool in rego, f"{tool} is a recovery tool and MUST be OPA-reachable"
            assert py[tool] == rego[tool], (
                f"{tool}: a role can see it but not call it — recovery is broken for "
                f"{sorted(py[tool] ^ rego[tool])}"
            )
