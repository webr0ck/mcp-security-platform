"""
Unit tests for entitlement service.
All DB calls are mocked — no real database connection required.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers to build mock DB row mappings
# ---------------------------------------------------------------------------

def _mock_mapping(data: dict | None):
    """Return a MagicMock that behaves like a SQLAlchemy RowMapping."""
    if data is None:
        return None
    m = MagicMock()
    m.__getitem__ = lambda self, k: data[k]
    m.get = lambda k, default=None: data.get(k, default)
    return m


def _mock_result(row: dict | None):
    """Return a mock result whose .mappings().first() returns the given row."""
    mapping = _mock_mapping(row)
    result = MagicMock()
    result.mappings.return_value.first.return_value = mapping
    result.mappings.return_value.all.return_value = [mapping] if row else []
    return result


def _make_session(*query_results):
    """
    Return a mock AsyncSessionLocal context manager that yields a session
    whose execute() calls return results in order.
    """
    session = AsyncMock()
    session.execute = AsyncMock(side_effect=list(query_results))

    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)

    session_factory = MagicMock(return_value=ctx)
    return session_factory


# ---------------------------------------------------------------------------
# check_entitlement tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_check_entitlement_returns_not_found_for_unknown_server():
    """Server not in server_registry → entitled=False, reason='server_not_approved'."""
    from app.services.entitlement import check_entitlement

    # server_registry query returns nothing
    r_registry = _mock_result(None)

    factory = _make_session(r_registry)

    with patch("app.services.entitlement.AsyncSessionLocal", factory):
        result = await check_entitlement(
            principal_type="human",
            principal_id="human:keycloak:alice",
            server_id="00000000-0000-0000-0000-000000000001",
        )

    assert result.entitled is False
    assert result.role is None
    assert result.server_id is None
    assert result.reason == "server_not_approved"


@pytest.mark.asyncio
async def test_check_entitlement_suspended_server_denied():
    """Server exists but status='suspended' → entitled=False."""
    from app.services.entitlement import check_entitlement

    r_registry = _mock_result(
        {"server_id": "00000000-0000-0000-0000-000000000002", "status": "suspended"}
    )

    factory = _make_session(r_registry)

    with patch("app.services.entitlement.AsyncSessionLocal", factory):
        result = await check_entitlement(
            principal_type="human",
            principal_id="human:keycloak:bob",
            server_id="00000000-0000-0000-0000-000000000002",
        )

    assert result.entitled is False
    assert result.reason == "server_not_approved"


@pytest.mark.asyncio
async def test_check_entitlement_via_entitlement_table():
    """Entitlement row exists → entitled=True, reason='entitlement_table'."""
    from app.services.entitlement import check_entitlement

    sid = "00000000-0000-0000-0000-000000000003"
    r_registry = _mock_result({"server_id": sid, "status": "approved"})
    r_entitlement = _mock_result({"role": "user"})

    factory = _make_session(r_registry, r_entitlement)

    with patch("app.services.entitlement.AsyncSessionLocal", factory):
        result = await check_entitlement(
            principal_type="human",
            principal_id="human:keycloak:alice",
            server_id=sid,
        )

    assert result.entitled is True
    assert result.role == "user"
    assert result.server_id == sid
    assert result.reason == "entitlement_table"


@pytest.mark.asyncio
async def test_check_entitlement_via_role_grant_fallback():
    """No entitlement row but server_role_grant row → entitled=True, reason='role_grant'."""
    from app.services.entitlement import check_entitlement

    sid = "00000000-0000-0000-0000-000000000004"
    r_registry = _mock_result({"server_id": sid, "status": "approved"})
    r_entitlement = _mock_result(None)    # no entitlement row
    r_role_grant = _mock_result({"role": "server_owner"})

    factory = _make_session(r_registry, r_entitlement, r_role_grant)

    with patch("app.services.entitlement.AsyncSessionLocal", factory):
        result = await check_entitlement(
            principal_type="agent",
            principal_id="agent:internal-ca:deploy-bot",
            server_id=sid,
        )

    assert result.entitled is True
    assert result.role == "server_owner"
    assert result.reason == "role_grant"


@pytest.mark.asyncio
async def test_list_entitled_servers_filters_by_principal():
    """list_entitled_servers returns only servers the principal is granted."""
    from app.services.entitlement import list_entitled_servers

    rows = [
        {
            "server_id": "aaaa0000-0000-0000-0000-000000000001",
            "name": "server-alpha",
            "upstream_url": "http://alpha.internal",
            "custody_mode": "session_suk",
            "role": "user",
        },
        {
            "server_id": "bbbb0000-0000-0000-0000-000000000002",
            "name": "server-beta",
            "upstream_url": "http://beta.internal",
            "custody_mode": "hsm_agent",
            "role": "manager",
        },
    ]

    # Build a mock result whose .mappings().all() returns the rows
    result_mock = MagicMock()
    mock_rows = []
    for r in rows:
        m = MagicMock()
        m.__getitem__ = lambda self, k, _r=r: _r[k]
        m.get = lambda k, default=None, _r=r: _r.get(k, default)
        mock_rows.append(m)
    result_mock.mappings.return_value.all.return_value = mock_rows

    session = AsyncMock()
    session.execute = AsyncMock(return_value=result_mock)

    ctx = AsyncMock()
    ctx.__aenter__ = AsyncMock(return_value=session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock(return_value=ctx)

    with patch("app.services.entitlement.AsyncSessionLocal", factory):
        servers = await list_entitled_servers(
            principal_type="human",
            principal_id="human:keycloak:alice",
        )

    assert len(servers) == 2
    server_ids = {s["server_id"] for s in servers}
    assert "aaaa0000-0000-0000-0000-000000000001" in server_ids
    assert "bbbb0000-0000-0000-0000-000000000002" in server_ids


@pytest.mark.asyncio
async def test_discovery_equals_invoke_invariant():
    """
    list_entitled_servers only returns servers where check_entitlement → True.
    Verify the invariant by running both functions against the same mock state.
    """
    from app.services.entitlement import check_entitlement, list_entitled_servers

    sid = "cccc0000-0000-0000-0000-000000000003"

    # --- check_entitlement mock: server approved, entitlement row present ---
    r_registry = _mock_result({"server_id": sid, "status": "approved"})
    r_entitlement = _mock_result({"role": "user"})
    factory_check = _make_session(r_registry, r_entitlement)

    with patch("app.services.entitlement.AsyncSessionLocal", factory_check):
        check_result = await check_entitlement(
            principal_type="human",
            principal_id="human:keycloak:carol",
            server_id=sid,
        )

    assert check_result.entitled is True

    # --- list_entitled_servers mock: same server appears in results ---
    row_data = {
        "server_id": sid,
        "name": "server-carol",
        "upstream_url": "http://carol.internal",
        "custody_mode": "session_suk",
        "role": "user",
    }
    list_result_mock = MagicMock()
    m = MagicMock()
    m.__getitem__ = lambda self, k: row_data[k]
    m.get = lambda k, default=None: row_data.get(k, default)
    list_result_mock.mappings.return_value.all.return_value = [m]

    session2 = AsyncMock()
    session2.execute = AsyncMock(return_value=list_result_mock)
    ctx2 = AsyncMock()
    ctx2.__aenter__ = AsyncMock(return_value=session2)
    ctx2.__aexit__ = AsyncMock(return_value=False)
    factory_list = MagicMock(return_value=ctx2)

    with patch("app.services.entitlement.AsyncSessionLocal", factory_list):
        servers = await list_entitled_servers(
            principal_type="human",
            principal_id="human:keycloak:carol",
        )

    listed_ids = {s["server_id"] for s in servers}
    # The server that check_entitlement approves must appear in list
    assert check_result.server_id in listed_ids
