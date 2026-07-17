"""
Unit tests — Task 5: tool_registry.metadata.required_roles discovery gate.

Covers:
  1. A row with metadata.required_roles set is excluded when the caller's
     roles don't intersect required_roles.
  2. The same row is included when the caller has a matching role.
  3. A row with no required_roles key at all (or an empty one) is
     unrestricted — included regardless of caller roles.

Follows the mocking pattern established in test_mcp_tools_list_filtering.py:
a dict-like _FakeRow / _FakeSession stand in for the SQLAlchemy mapping
result, and _load_grants_data / check_entitlement / _lookup_profile_row are
patched so only the required_roles gate is under test.

Run: pytest proxy/tests/unit/test_registered_tools_required_roles.py -v
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers — fake DB rows (mirrors test_mcp_tools_list_filtering.py)
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
    name: str,
    server_id: str | None,
    required_roles: list | None = None,
    metadata_present: bool = True,
) -> _FakeRow:
    metadata = {}
    if metadata_present and required_roles is not None:
        metadata = {"required_roles": required_roles}
    return _FakeRow({
        "name": name,
        "server_id": server_id,
        "description": f"desc for {name}",
        "schema": "{}",
        "tags": [],
        "metadata": metadata,
    })


class _FakeMappings:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def fetchall(self):
        return self._rows


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


SERVER_A = "aaaaaaaa-0000-0000-0000-000000000001"


# ---------------------------------------------------------------------------
# Test 1: required_roles excludes a caller without a matching role
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_required_roles_excludes_non_matching_caller():
    from app.routers.mcp_server import _registered_tools_for_client

    row = _tool_db_row("approve_submission", SERVER_A, required_roles=["admin", "security_reviewer"])

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession([row])), \
         patch("app.services.entitlement.check_entitlement", new=AsyncMock(
             return_value=type("Ent", (), {"entitled": True})()
         )), \
         patch("app.routers.mcp_server._load_grants_data", new=AsyncMock(return_value=({}, {}))), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        tools = await _registered_tools_for_client(
            client_id="bob@corp",
            roles=["user"],
            principal_id="human:keycloak:bob@corp",
            principal_type="human",
        )

    assert tools == []


# ---------------------------------------------------------------------------
# Test 2: required_roles includes a caller with a matching role
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_required_roles_includes_matching_caller():
    from app.routers.mcp_server import _registered_tools_for_client

    row = _tool_db_row("approve_submission", SERVER_A, required_roles=["admin", "security_reviewer"])

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession([row])), \
         patch("app.services.entitlement.check_entitlement", new=AsyncMock(
             return_value=type("Ent", (), {"entitled": True})()
         )), \
         patch("app.routers.mcp_server._load_grants_data", new=AsyncMock(return_value=({}, {}))), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        tools = await _registered_tools_for_client(
            client_id="alice@corp",
            roles=["admin"],
            principal_id="human:keycloak:alice@corp",
            principal_type="human",
        )

    assert len(tools) == 1
    assert tools[0]["name"] == "approve_submission"


# ---------------------------------------------------------------------------
# Test 3: absent required_roles key is unrestricted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_absent_required_roles_is_unrestricted():
    from app.routers.mcp_server import _registered_tools_for_client

    row = _tool_db_row("ping", SERVER_A, required_roles=None)  # no required_roles key at all

    with patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession([row])), \
         patch("app.services.entitlement.check_entitlement", new=AsyncMock(
             return_value=type("Ent", (), {"entitled": True})()
         )), \
         patch("app.routers.mcp_server._load_grants_data", new=AsyncMock(return_value=({}, {}))), \
         patch("app.routers.mcp_server._lookup_profile_row", new=AsyncMock(return_value=None)):

        tools = await _registered_tools_for_client(
            client_id="bob@corp",
            roles=["user"],
            principal_id="human:keycloak:bob@corp",
            principal_type="human",
        )

    assert len(tools) == 1
    assert tools[0]["name"] == "ping"
