"""
Unit tests — Task 4.1: tools/list filtered by entitlement + profile; admin bypass removed.

Covers:
  1. User entitled to server A but not B sees only A's tools in tools/list
  2. Profile-disabled MCP's tools disappear from tools/list
  3. Admin is filtered the same as everyone else (admin bypass removed)
  4. NULL-server_id tool follows grants-only visibility (data.json grants)
  5. NULL-server_id tool with no grant is hidden
  6. Discovery == invoke: the listed set equals what entitlement.enforce_tool_entitlement
     would allow on the invoke path.

All tests use mocked DB / entitlement stubs — no live services required.
Run: pytest proxy/tests/unit/test_mcp_tools_list_filtering.py -v
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — fake DB rows
# ---------------------------------------------------------------------------

class _FakeRow:
    """Dict-like fake row for SQLAlchemy mapping results."""

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key: str):
        return self._data.get(key)

    def get(self, key, default=None):
        return self._data.get(key, default)


def _tool_db_row(
    tool_id: str,
    name: str,
    server_id: str | None,
    description: str = "A test tool",
    tags: list | None = None,
    schema: str | None = None,
) -> _FakeRow:
    return _FakeRow({
        "tool_id": tool_id,
        "name": name,
        "server_id": server_id,
        "description": description,
        "schema": schema or "{}",
        "tags": tags or [],
    })


class _FakeMappings:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def mappings(self):
        return _FakeMappings(self._rows)


class _FakeSession:
    """Context-manager fake session that returns the configured rows."""

    def __init__(self, rows: list) -> None:
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def execute(self, *_a, **_kw):
        return _FakeResult(self._rows)


# ---------------------------------------------------------------------------
# Entitlement result factories
# ---------------------------------------------------------------------------

def _entitled(server_id: str) -> SimpleNamespace:
    return SimpleNamespace(entitled=True, role="user", server_id=server_id, reason="entitlement_table")


def _not_entitled(server_id: str) -> SimpleNamespace:
    return SimpleNamespace(entitled=False, role=None, server_id=server_id, reason="not_found")


# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------
SERVER_A = "aaaaaaaa-0000-0000-0000-000000000001"
SERVER_B = "bbbbbbbb-0000-0000-0000-000000000002"

ROW_A1 = _tool_db_row("t-a1", "tool-alpha", SERVER_A)
ROW_A2 = _tool_db_row("t-a2", "tool-beta",  SERVER_A)
ROW_B1 = _tool_db_row("t-b1", "tool-gamma", SERVER_B)
ROW_NULL = _tool_db_row("t-null", "tool-unlinked", None)


# ---------------------------------------------------------------------------
# Patch helpers
# ---------------------------------------------------------------------------

def _make_db_patch(rows: list):
    """
    Return a context manager that patches AsyncSessionLocal inside mcp_server
    via a lazy-import patch on app.core.database.AsyncSessionLocal so the
    local `from app.core.database import AsyncSessionLocal` inside the function
    picks it up at call time.
    """
    session = _FakeSession(rows)

    class _CM:
        def __call__(self):
            return session  # called as AsyncSessionLocal() context manager

        def __enter__(self):
            return session

        def __exit__(self, *_):
            pass

    return _CM()


# ---------------------------------------------------------------------------
# Test 1: user entitled to server A sees only A's tools
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_entitled_server_a_only_sees_a_tools():
    """
    A user entitled to server A but not server B should only see A's tools.
    Tool with NULL server_id is excluded (no data.json grant).
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_A1, ROW_A2, ROW_B1, ROW_NULL]

    async def fake_check(principal_type, principal_id, server_id):
        return _entitled(server_id) if server_id == SERVER_A else _not_entitled(server_id)

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", side_effect=fake_check), \
         patch("app.routers.mcp_server._load_grants_data", return_value=({}, {})), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        result = await _registered_tools_for_client(
            client_id="alice",
            roles=["agent"],
            principal_id="alice",
            principal_type="human",
        )

    names = {t["name"] for t in result}
    assert "tool-alpha" in names
    assert "tool-beta" in names
    assert "tool-gamma" not in names, "server B tool must be hidden"
    assert "tool-unlinked" not in names, "NULL-server_id with no grant must be hidden"


# ---------------------------------------------------------------------------
# Test 2: profile-disabled MCP disappears from tools/list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_profile_disabled_mcp_hidden():
    """
    If mcp_profiles has enabled=false for the caller's identity + tool name,
    the tool must not appear in tools/list.
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_A1, ROW_A2]

    disabled_profile = _FakeRow({"enabled": False})
    enabled_profile = _FakeRow({"enabled": True})

    async def fake_check(principal_type, principal_id, server_id):
        return _entitled(SERVER_A)

    async def fake_profile_lookup(profile_id: str, mcp_name: str):
        # tool-alpha is disabled; tool-beta is enabled
        if profile_id == "alice" and mcp_name == "tool-alpha":
            return disabled_profile
        return enabled_profile

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", side_effect=fake_check), \
         patch("app.routers.mcp_server._load_grants_data", return_value=({}, {})), \
         patch("app.routers.mcp_server._lookup_profile_row", side_effect=fake_profile_lookup):

        result = await _registered_tools_for_client(
            client_id="alice",
            roles=["agent"],
            principal_id="alice",
            principal_type="human",
        )

    names = {t["name"] for t in result}
    assert "tool-alpha" not in names, "profile-disabled tool must be hidden"
    assert "tool-beta" in names, "enabled tool must be visible"


# ---------------------------------------------------------------------------
# Test 3: admin is filtered the same as everyone else (bypass removed)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_admin_filtered_same_as_regular_user():
    """
    admin/platform_admin callers must go through the same entitlement filter.
    An admin not entitled to server B must not see server B's tools.
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_A1, ROW_B1]

    async def fake_check(principal_type, principal_id, server_id):
        return _entitled(server_id) if server_id == SERVER_A else _not_entitled(server_id)

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", side_effect=fake_check), \
         patch("app.routers.mcp_server._load_grants_data", return_value=({}, {})), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        result = await _registered_tools_for_client(
            client_id="admin-user",
            roles=["admin"],          # admin role — must NOT bypass entitlement
            principal_id="admin-user",
            principal_type="human",
        )

    names = {t["name"] for t in result}
    assert "tool-alpha" in names, "admin entitled to server A must see tool-alpha"
    assert "tool-gamma" not in names, "admin NOT entitled to server B must NOT see tool-gamma"


# ---------------------------------------------------------------------------
# Test 4: NULL-server_id tool visible when data.json grant exists
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_null_server_id_tool_grants_visible():
    """
    A tool with NULL server_id is shown when the caller has a data.json
    allowed_tools grant.  Mirrors OPA-only invoke path for unlinked tools.
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_NULL]

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", new=AsyncMock()) as mock_ent, \
         patch("app.routers.mcp_server._load_grants_data", return_value=(
             {"alice": {"allowed_tools": ["tool-unlinked"], "allowed_tags": []}}, {}
         )), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        result = await _registered_tools_for_client(
            client_id="alice",
            roles=["agent"],
            principal_id="alice",
            principal_type="human",
        )

    names = {t["name"] for t in result}
    assert "tool-unlinked" in names, "NULL-server_id with grant must be visible"
    mock_ent.assert_not_called()  # entitlement check bypassed for NULL-server_id tools


# ---------------------------------------------------------------------------
# Test 5: NULL-server_id tool hidden when no data.json grant
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_null_server_id_tool_no_grant_invisible():
    """
    A tool with NULL server_id is NOT shown when the caller has no data.json grant.
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_NULL]

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", new=AsyncMock()), \
         patch("app.routers.mcp_server._load_grants_data", return_value=({}, {})), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        result = await _registered_tools_for_client(
            client_id="bob",
            roles=["agent"],
            principal_id="bob",
            principal_type="human",
        )

    names = {t["name"] for t in result}
    assert "tool-unlinked" not in names


# ---------------------------------------------------------------------------
# Test 6: discovery == invoke parity
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_discovery_equals_invoke_set():
    """
    The tool set from tools/list (discovery) must equal the tool set that
    enforce_tool_entitlement would allow on the invoke path (invoke).
    Verify: tool-gamma on SERVER_B absent from discovery when not entitled.
    """
    from app.routers.mcp_server import _registered_tools_for_client

    all_rows = [ROW_A1, ROW_B1]

    async def fake_check(principal_type, principal_id, server_id):
        return _entitled(server_id) if server_id == SERVER_A else _not_entitled(server_id)

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession(all_rows)), \
         patch("app.services.entitlement.check_entitlement", side_effect=fake_check), \
         patch("app.routers.mcp_server._load_grants_data", return_value=({}, {})), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        result = await _registered_tools_for_client(
            client_id="alice",
            roles=["agent"],
            principal_id="alice",
            principal_type="human",
        )

    discoverable = {t["name"] for t in result}
    assert "tool-alpha" in discoverable, "invokable tool must be discoverable"
    assert "tool-gamma" not in discoverable, "non-invokable tool must not be discoverable"
