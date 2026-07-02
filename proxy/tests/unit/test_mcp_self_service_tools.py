"""Unit tests for self-service MCP profile management meta-tools.

Tests cover the four new handlers added to mcp_server.py:
  _handle_list_available_mcps
  _handle_get_my_profile
  _handle_enable_mcp_server
  _handle_disable_mcp_server

And the new _TOOLS list entries + _visible_tools() role filtering.

All DB calls are mocked — no live database required.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(client_id: str = "test-client", roles: list | None = None) -> MagicMock:
    req = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = roles or ["editor"]
    return req


def _make_db_rows(data: list[dict]):
    """Create a mock that returns mapping-style rows."""
    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = [MagicMock(**d) for d in data]
    return mock_result


def _make_db_row_first(data: dict | None):
    mock_result = MagicMock()
    mock_result.mappings.return_value.first.return_value = MagicMock(**data) if data else None
    return mock_result


# ---------------------------------------------------------------------------
# _TOOLS list: role visibility
# ---------------------------------------------------------------------------

def test_list_available_mcps_visible_to_viewer():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["viewer"])
    names = [t["name"] for t in tools]
    assert "list_available_mcps" in names


def test_get_my_profile_visible_to_viewer():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["viewer"])
    names = [t["name"] for t in tools]
    assert "get_my_profile" in names


def test_enable_mcp_server_not_visible_to_viewer():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["viewer"])
    names = [t["name"] for t in tools]
    assert "enable_mcp_server" not in names


def test_disable_mcp_server_not_visible_to_viewer():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["viewer"])
    names = [t["name"] for t in tools]
    assert "disable_mcp_server" not in names


def test_enable_mcp_server_visible_to_editor():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["editor"])
    names = [t["name"] for t in tools]
    assert "enable_mcp_server" in names


def test_disable_mcp_server_visible_to_admin():
    from app.routers.mcp_server import _visible_tools
    tools = _visible_tools(["admin"])
    names = [t["name"] for t in tools]
    assert "disable_mcp_server" in names


def test_self_service_tools_strip_roles_key():
    """_visible_tools must not expose the internal _roles field to callers."""
    from app.routers.mcp_server import _visible_tools
    for tool in _visible_tools(["admin"]):
        assert "_roles" not in tool, f"Tool {tool['name']} leaks _roles to caller"


# ---------------------------------------------------------------------------
# _handle_list_available_mcps
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_available_mcps_returns_catalog():
    from app.routers.mcp_server import _handle_list_available_mcps

    # Rows match tool_registry columns: name, description, status, risk_level
    tool_rows = [
        {"name": "poc-echo-server", "description": "Test echo", "status": "active", "risk_level": "low"},
        {"name": "web-search", "description": "Internet search", "status": "active", "risk_level": "high"},
    ]
    profile_rows = [
        {"mcp_name": "poc-echo-server", "enabled": True},
    ]

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)

    call_count = 0

    async def execute_side_effect(query, params=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # tool_registry query
            result = MagicMock()
            result.mappings.return_value.all.return_value = [
                {"name": r["name"], "description": r["description"],
                 "status": r["status"], "risk_level": r["risk_level"]}
                for r in tool_rows
            ]
            return result
        else:
            # mcp_profiles query
            result = MagicMock()
            result.mappings.return_value.all.return_value = [
                {"mcp_name": r["mcp_name"], "enabled": r["enabled"]}
                for r in profile_rows
            ]
            return result

    mock_session.execute = AsyncMock(side_effect=execute_side_effect)

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        result = await _handle_list_available_mcps({}, _make_request("u1"))

    data = json.loads(result["text"])
    assert data["total"] == 2
    tools_by_name = {t["tool_name"]: t for t in data["tools"]}
    assert tools_by_name["poc-echo-server"]["enabled_for_your_profile"] is True
    assert tools_by_name["web-search"]["enabled_for_your_profile"] is False


@pytest.mark.asyncio
async def test_list_available_mcps_db_error_returns_error_text():
    from app.routers.mcp_server import _handle_list_available_mcps

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(side_effect=Exception("DB offline"))

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        result = await _handle_list_available_mcps({}, _make_request())

    assert result["type"] == "text"
    assert "Error" in result["text"]


# ---------------------------------------------------------------------------
# _handle_get_my_profile
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_my_profile_returns_profile():
    from app.routers.mcp_server import _handle_get_my_profile

    profile_rows = [
        {"mcp_name": "poc-echo-server", "enabled": True, "allowed_functions": None},
        {"mcp_name": "web-search", "enabled": False, "allowed_functions": '["search"]'},
    ]
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = [
        {"mcp_name": r["mcp_name"], "enabled": r["enabled"], "allowed_functions": r["allowed_functions"]}
        for r in profile_rows
    ]
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        result = await _handle_get_my_profile({}, _make_request("alice"))

    data = json.loads(result["text"])
    assert data["principal"] == "alice"
    mcps_by_name = {m["server_name"]: m for m in data["mcps"]}
    assert mcps_by_name["poc-echo-server"]["enabled"] is True
    assert mcps_by_name["poc-echo-server"]["allowed_functions"] is None
    assert mcps_by_name["web-search"]["enabled"] is False
    assert mcps_by_name["web-search"]["allowed_functions"] == ["search"]


@pytest.mark.asyncio
async def test_get_my_profile_empty_profile():
    from app.routers.mcp_server import _handle_get_my_profile

    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_result = MagicMock()
    mock_result.mappings.return_value.all.return_value = []
    mock_session.execute = AsyncMock(return_value=mock_result)

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session):
        result = await _handle_get_my_profile({}, _make_request("newuser"))

    data = json.loads(result["text"])
    assert data["mcps"] == []


# ---------------------------------------------------------------------------
# _handle_enable_mcp_server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enable_mcp_server_success():
    from app.routers.mcp_server import _handle_enable_mcp_server
    from fastapi import HTTPException

    async def fake_assert_exists(name): pass
    async def fake_get_row(principal, name): return None
    async def fake_upsert(principal, name, enabled, fns, changed_by): pass
    async def fake_invalidate(principal, name, val): pass

    with (
        patch("app.routers.profiles._assert_mcp_exists", new=fake_assert_exists),
        patch("app.routers.profiles._get_profile_row", new=fake_get_row),
        patch("app.routers.profiles._upsert_profile_row", new=fake_upsert),
        patch("app.routers.profiles._invalidate_profile_cache", new=fake_invalidate),
    ):
        result = await _handle_enable_mcp_server(
            {"server_name": "poc-echo-server"}, _make_request("u1", ["editor"])
        )

    data = json.loads(result["text"])
    assert data["ok"] is True
    assert data["enabled"] is True
    assert "poc-echo-server" in data["message"]


@pytest.mark.asyncio
async def test_enable_mcp_server_missing_name():
    from app.routers.mcp_server import _handle_enable_mcp_server
    result = await _handle_enable_mcp_server({}, _make_request())
    assert "Error" in result["text"]
    assert "server_name" in result["text"]


@pytest.mark.asyncio
async def test_enable_mcp_server_not_found_returns_error():
    from app.routers.mcp_server import _handle_enable_mcp_server
    from fastapi import HTTPException

    async def fake_assert_raises(name):
        raise HTTPException(status_code=404, detail=f"MCP '{name}' not found in registry")

    with patch("app.routers.profiles._assert_mcp_exists", new=fake_assert_raises):
        result = await _handle_enable_mcp_server(
            {"server_name": "nonexistent"}, _make_request()
        )

    assert "Error" in result["text"]
    assert "not found" in result["text"]


# ---------------------------------------------------------------------------
# _handle_disable_mcp_server
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_disable_mcp_server_success():
    from app.routers.mcp_server import _handle_disable_mcp_server

    async def fake_assert_exists(name): pass
    async def fake_get_row(principal, name): return {"enabled": True, "allowed_functions": None}
    async def fake_upsert(principal, name, enabled, fns, changed_by):
        assert enabled is False
    async def fake_invalidate(principal, name, val):
        assert val["enabled"] is False

    with (
        patch("app.routers.profiles._assert_mcp_exists", new=fake_assert_exists),
        patch("app.routers.profiles._get_profile_row", new=fake_get_row),
        patch("app.routers.profiles._upsert_profile_row", new=fake_upsert),
        patch("app.routers.profiles._invalidate_profile_cache", new=fake_invalidate),
    ):
        result = await _handle_disable_mcp_server(
            {"server_name": "web-search"}, _make_request("u2", ["editor"])
        )

    data = json.loads(result["text"])
    assert data["ok"] is True
    assert data["enabled"] is False


@pytest.mark.asyncio
async def test_disable_mcp_server_missing_name():
    from app.routers.mcp_server import _handle_disable_mcp_server
    result = await _handle_disable_mcp_server({}, _make_request())
    assert "Error" in result["text"]


# ---------------------------------------------------------------------------
# TOOL_HANDLERS registration
# ---------------------------------------------------------------------------

def test_all_self_service_tools_have_handlers():
    from app.routers.mcp_server import _TOOL_HANDLERS
    for name in ("list_available_mcps", "get_my_profile", "enable_mcp_server", "disable_mcp_server"):
        assert name in _TOOL_HANDLERS, f"No handler registered for {name}"
