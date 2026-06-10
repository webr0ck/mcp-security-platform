"""
AppSec review (2026-06-08) findings — drift guards.

HIGH-1 / MEDIUM-3: server_role_grant has no revoked_at column by design.
  Revocation is enforced by DELETE, not soft-delete. The Step-3 query in
  check_entitlement() and the UNION leg in list_entitled_servers() must document
  this invariant so a future migration can't silently break it.

MEDIUM-1: dispatcher.py stale comment claiming invoke_tool passes user_kc_token=None
  was fixed in 6.3 and the comment must be removed.

MEDIUM-2: _TOOLS map and platform_meta_tool_roles Rego map must stay in sync.
  An unknown meta-tool name with is_platform_meta=True must be denied, not granted.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest


# ─── HIGH-1 / MEDIUM-3 ──────────────────────────────────────────────────────

@pytest.mark.unit
def test_server_role_grant_no_revoked_at_column_in_schema():
    """V015 must NOT define a revoked_at column on server_role_grant.
    The column exists only on the entitlement table; server_role_grant
    revocation is by DELETE. This guards against a future migration that
    adds the column without updating the Step-3 and list_entitled_servers queries."""
    _REPO_ROOT = Path(__file__).parent.parent.parent.parent
    sql = (_REPO_ROOT / "infra/db/migrations/V015__server_role_grant_entitlement.sql").read_text()
    # Isolate the server_role_grant CREATE TABLE block (ends before 'CREATE TABLE entitlement')
    srg_block = sql.split("CREATE TABLE IF NOT EXISTS entitlement")[0]
    assert "server_role_grant" in srg_block, "V015 must define server_role_grant"
    assert "revoked_at" not in srg_block, (
        "server_role_grant gained a revoked_at column. "
        "Update the Step-3 query in check_entitlement() AND the UNION leg in "
        "list_entitled_servers() to add 'AND revoked_at IS NULL'."
    )


@pytest.mark.unit
def test_check_entitlement_step3_comment_documents_no_revocation():
    """Step-3 server_role_grant query must have an explicit comment saying
    revocation is by DELETE so a future column addition doesn't silently create a gap."""
    from app.services import entitlement as ent_mod
    src = inspect.getsource(ent_mod.check_entitlement)
    assert "revocation is by delete" in src.lower() or "no revoked_at" in src.lower(), (
        "check_entitlement() Step-3 (server_role_grant query) must contain an explicit "
        "comment: 'no revoked_at' or 'revocation is by DELETE'. "
        "If someone adds that column, they must also add the WHERE clause guard here."
    )


@pytest.mark.unit
def test_list_entitled_servers_union_comment_documents_no_revocation():
    """The UNION leg reading server_role_grant in list_entitled_servers()
    must document the DELETE-based revocation contract."""
    from app.services import entitlement as ent_mod
    src = inspect.getsource(ent_mod.list_entitled_servers)
    assert "revocation is by delete" in src.lower() or "no revoked_at" in src.lower(), (
        "list_entitled_servers() server_role_grant UNION leg must document "
        "why there is no 'revoked_at IS NULL' guard: revocation is by DELETE."
    )


# ─── MEDIUM-1 ───────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_dispatcher_stale_kc_token_comment_removed():
    """The stale comment in dispatcher.py claiming 'invoke_tool currently passes
    user_kc_token=None' was invalidated by commit 6.3 and must be removed."""
    from app.credential_broker import dispatcher as disp_mod
    src = inspect.getsource(disp_mod)
    assert "invoke_tool currently passes user_kc_token=None" not in src, (
        "Stale comment in dispatcher.py must be removed: 6.3 wired user_kc_token. "
        "The comment misrepresents the current implementation to security reviewers."
    )


# ─── MEDIUM-2 ───────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_mcp_server_tools_has_sync_comment():
    """_TOOLS in mcp_server.py must have a comment pointing to the Rego
    platform_meta_tool_roles map so developers know to update both."""
    src = Path(__file__).parent.parent.parent / "app/routers/mcp_server.py"
    src = src.read_text()
    assert "platform_meta_tool_roles" in src or "authz.rego" in src, (
        "_TOOLS definition in mcp_server.py must reference platform_meta_tool_roles "
        "in authz.rego so developers updating one remember to update the other."
    )
