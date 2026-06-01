"""
Unit tests for the catalog router.
Mocks the entitlement service — no real DB or auth required.
"""
from __future__ import annotations

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(principal_id="human:keycloak:alice", principal_type="human"):
    req = MagicMock()
    req.state = SimpleNamespace(
        principal_id=principal_id,
        principal_type=principal_type,
        client_roles=["user"],
        client_id=principal_id,
    )
    return req


def _make_request_no_principal():
    req = MagicMock()
    req.state = SimpleNamespace(
        principal_id=None,
        principal_type=None,
        client_roles=[],
        client_id=None,
    )
    return req


_MOCK_SERVERS = [
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


# ---------------------------------------------------------------------------
# list_my_servers tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_my_servers_returns_entitled_only():
    """list_my_servers returns the servers from list_entitled_servers."""
    from app.routers.catalog import list_my_servers

    request = _make_request()

    with patch(
        "app.routers.catalog.list_entitled_servers",
        new=AsyncMock(return_value=_MOCK_SERVERS),
    ):
        response = await list_my_servers(request)

    assert response["count"] == 2
    assert len(response["servers"]) == 2
    ids = {s["server_id"] for s in response["servers"]}
    assert "aaaa0000-0000-0000-0000-000000000001" in ids
    assert "bbbb0000-0000-0000-0000-000000000002" in ids


@pytest.mark.asyncio
async def test_list_my_servers_missing_principal_returns_401():
    """No principal on request → 401."""
    from app.routers.catalog import list_my_servers

    request = _make_request_no_principal()

    with pytest.raises(HTTPException) as exc_info:
        await list_my_servers(request)

    assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_server_detail tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_server_detail_entitled_returns_200():
    """Entitled principal → 200 with server detail."""
    from app.routers.catalog import get_server_detail
    from app.services.entitlement import EntitlementResult

    sid = "aaaa0000-0000-0000-0000-000000000001"
    request = _make_request()

    ent_result = EntitlementResult(
        entitled=True,
        role="user",
        server_id=sid,
        reason="entitlement_table",
    )

    with patch(
        "app.routers.catalog.check_entitlement",
        new=AsyncMock(return_value=ent_result),
    ), patch(
        "app.routers.catalog.list_entitled_servers",
        new=AsyncMock(return_value=_MOCK_SERVERS),
    ):
        response = await get_server_detail(sid, request)

    assert response["server_id"] == sid
    assert response["role"] == "user"
    assert response["entitlement_reason"] == "entitlement_table"
    assert "name" in response
    assert "upstream_url" in response


@pytest.mark.asyncio
async def test_get_server_detail_not_entitled_returns_404():
    """Not-entitled principal → 404, never 403."""
    from app.routers.catalog import get_server_detail
    from app.services.entitlement import EntitlementResult

    sid = "bbbb0000-0000-0000-0000-000000000002"
    request = _make_request()

    ent_result = EntitlementResult(
        entitled=False,
        role=None,
        server_id=sid,
        reason="not_found",
    )

    with patch(
        "app.routers.catalog.check_entitlement",
        new=AsyncMock(return_value=ent_result),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await get_server_detail(sid, request)

    assert exc_info.value.status_code == 404
    # Verify it's NOT 403 (no information leakage)
    assert exc_info.value.status_code != 403


@pytest.mark.asyncio
async def test_get_server_detail_no_information_leak():
    """
    Both 'server not found' and 'not entitled' must return 404 with the
    same detail message — no information leak about server existence.
    """
    from app.routers.catalog import get_server_detail
    from app.services.entitlement import EntitlementResult

    request = _make_request()

    # Case 1: server_not_approved (server doesn't exist in registry)
    ent_not_approved = EntitlementResult(
        entitled=False,
        role=None,
        server_id=None,
        reason="server_not_approved",
    )

    # Case 2: not_found (server exists but principal has no grant)
    ent_not_found = EntitlementResult(
        entitled=False,
        role=None,
        server_id="dddd0000-0000-0000-0000-000000000004",
        reason="not_found",
    )

    responses = []
    for ent_result in (ent_not_approved, ent_not_found):
        with patch(
            "app.routers.catalog.check_entitlement",
            new=AsyncMock(return_value=ent_result),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await get_server_detail("dddd0000-0000-0000-0000-000000000004", request)
            responses.append(exc_info.value)

    # Both must return 404
    assert all(r.status_code == 404 for r in responses)
    # Both must return the same detail (indistinguishable)
    assert responses[0].detail == responses[1].detail
