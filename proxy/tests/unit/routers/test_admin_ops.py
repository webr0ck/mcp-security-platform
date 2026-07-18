"""
Unit tests for the admin_ops router (WS-A) — authz, debug_mode gate, fail-closed
ops-agent configuration, and container-name derivation. DB and ops-agent HTTP
calls are mocked; no real Postgres or ops-agent required.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException


def _make_request(roles=("platform_admin",), client_id="admin1"):
    req = MagicMock()
    req.state = SimpleNamespace(client_roles=list(roles), client_id=client_id)
    return req


def _mock_db_session(row: dict | None):
    """Return a context-manager mock matching `async with AsyncSessionLocal() as db`."""
    mock_db = AsyncMock()
    mock_result = MagicMock()
    mock_result.fetchone.return_value = SimpleNamespace(_mapping=row) if row is not None else None
    mock_db.execute = AsyncMock(return_value=mock_result)
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    return factory


# ---------------------------------------------------------------------------
# Pure helper functions
# ---------------------------------------------------------------------------

def test_derive_container_name_from_upstream_url():
    from app.routers.admin_ops import _derive_container_name
    assert _derive_container_name("http://lab-mcp-echo:8000/mcp") == "lab-mcp-echo"


def test_derive_container_name_https():
    from app.routers.admin_ops import _derive_container_name
    assert _derive_container_name("https://mcp-netbox:8000/mcp") == "mcp-netbox"


def test_derive_container_name_no_hostname_raises_422():
    from app.routers.admin_ops import _derive_container_name
    with pytest.raises(HTTPException) as exc_info:
        _derive_container_name("not-a-url")
    assert exc_info.value.status_code == 422


def test_require_debug_mode_passes_when_enabled():
    from app.routers.admin_ops import _require_debug_mode
    _require_debug_mode({"debug_mode": True})


def test_require_debug_mode_rejects_when_disabled():
    from app.routers.admin_ops import _require_debug_mode
    with pytest.raises(HTTPException) as exc_info:
        _require_debug_mode({"debug_mode": False})
    assert exc_info.value.status_code == 409


def test_require_debug_mode_rejects_when_missing():
    from app.routers.admin_ops import _require_debug_mode
    with pytest.raises(HTTPException) as exc_info:
        _require_debug_mode({})
    assert exc_info.value.status_code == 409


# ---------------------------------------------------------------------------
# ops-agent config fail-closed
# ---------------------------------------------------------------------------

def test_ops_agent_configured_raises_503_when_url_unset():
    from app.routers import admin_ops
    with patch.object(admin_ops.settings, "OPS_AGENT_URL", ""), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "sometoken"):
        with pytest.raises(HTTPException) as exc_info:
            admin_ops._require_ops_agent_configured()
        assert exc_info.value.status_code == 503


def test_ops_agent_configured_raises_503_when_token_unset():
    from app.routers import admin_ops
    with patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", ""):
        with pytest.raises(HTTPException) as exc_info:
            admin_ops._require_ops_agent_configured()
        assert exc_info.value.status_code == 503


def test_ops_agent_configured_ok_when_both_set():
    from app.routers import admin_ops
    with patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "sometoken"):
        url, token = admin_ops._require_ops_agent_configured()
    assert url == "http://lab-ops-agent:9000"
    assert token == "sometoken"


# ---------------------------------------------------------------------------
# Authz — owner/maintainer/platform_admin
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_require_authz_404_for_missing_server():
    from app.routers.admin_ops import _require_authz
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(None)):
        with pytest.raises(HTTPException) as exc_info:
            await _require_authz("nonexistent-id", _make_request())
        assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_require_authz_allows_owner():
    from app.routers.admin_ops import _require_authz
    row = {
        "server_id": "s1",
        "owner_sub": "alice",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://mcp-x:8000",
    }
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)):
        result = await _require_authz(
            "s1", _make_request(roles=["server_owner"], client_id="alice")
        )
    assert result["owner_sub"] == "alice"


@pytest.mark.asyncio
async def test_require_authz_allows_platform_admin_even_if_not_owner():
    from app.routers.admin_ops import _require_authz
    row = {
        "server_id": "s1",
        "owner_sub": "alice",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://mcp-x:8000",
    }
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)):
        result = await _require_authz(
            "s1", _make_request(roles=["platform_admin"], client_id="admin1")
        )
    assert result["owner_sub"] == "alice"


@pytest.mark.asyncio
async def test_require_authz_rejects_unrelated_user():
    from app.routers.admin_ops import _require_authz
    row = {
        "server_id": "s1",
        "owner_sub": "alice",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://mcp-x:8000",
    }
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)):
        with pytest.raises(HTTPException) as exc_info:
            await _require_authz("s1", _make_request(roles=["user"], client_id="mallory"))
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Full endpoint behavior — debug_mode gate, fail-closed 503, audit emission
# ---------------------------------------------------------------------------

def _mock_httpx_response(status_code: int, json_body: dict):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = str(json_body)
    return resp


@pytest.mark.asyncio
async def test_get_server_logs_rejects_when_debug_mode_off():
    from app.routers.admin_ops import get_server_logs
    row = {
        "server_id": "s1",
        "owner_sub": "alice",
        "maintainers": [],
        "debug_mode": False,
        "upstream_url": "http://mcp-x:8000",
    }
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)):
        with pytest.raises(HTTPException) as exc_info:
            await get_server_logs("s1", _make_request(roles=["platform_admin"]), tail=100)
        assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_get_server_logs_fails_closed_when_ops_agent_unconfigured():
    from app.routers import admin_ops
    row = {
        "server_id": "s1",
        "owner_sub": "admin1",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://mcp-x:8000",
    }
    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)), \
         patch.object(admin_ops.settings, "OPS_AGENT_URL", ""), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", ""):
        with pytest.raises(HTTPException) as exc_info:
            await admin_ops.get_server_logs("s1", _make_request(roles=["platform_admin"]), tail=100)
        assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_get_server_logs_forwards_to_ops_agent_and_returns_body():
    from app.routers import admin_ops
    row = {
        "server_id": "s1",
        "owner_sub": "admin1",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://lab-mcp-echo:8000/mcp",
    }
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(
        return_value=_mock_httpx_response(200, {"container": "lab-mcp-echo", "logs": "hello\n"})
    )
    fake_client_cm = MagicMock()
    fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)), \
         patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "secret-token"), \
         patch("app.routers.admin_ops.httpx.AsyncClient", return_value=fake_client_cm):
        resp = await admin_ops.get_server_logs(
            "s1", _make_request(roles=["platform_admin"]), tail=100
        )

    assert resp.status_code == 200
    fake_client.request.assert_called_once()
    call_args, call_kwargs = fake_client.request.call_args
    assert call_args[0] == "GET"
    assert call_args[1] == "http://lab-ops-agent:9000/ops/logs"
    assert call_kwargs["headers"]["X-Ops-Token"] == "secret-token"
    assert call_kwargs["params"]["container"] == "lab-mcp-echo"


@pytest.mark.asyncio
async def test_restart_server_emits_admin_audit_event():
    from app.routers import admin_ops
    row = {
        "server_id": "s1",
        "owner_sub": "admin1",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://lab-mcp-echo:8000/mcp",
    }
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(
        return_value=_mock_httpx_response(200, {"container": "lab-mcp-echo", "restarted": True})
    )
    fake_client_cm = MagicMock()
    fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)), \
         patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "secret-token"), \
         patch("app.routers.admin_ops.httpx.AsyncClient", return_value=fake_client_cm), \
         patch(
             "app.services.admin_audit.emit_admin_config_event", new_callable=AsyncMock
         ) as mock_emit:
        resp = await admin_ops.restart_server("s1", _make_request(roles=["platform_admin"]))

    assert resp.status_code == 200
    mock_emit.assert_awaited_once()
    _, kwargs = mock_emit.call_args
    assert kwargs["action"] == "server_restart"
    assert kwargs["client_id"] == "s1"


@pytest.mark.asyncio
async def test_rebuild_server_forwards_error_from_ops_agent():
    from app.routers import admin_ops
    row = {
        "server_id": "s1",
        "owner_sub": "admin1",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://lab-mcp-echo:8000/mcp",
    }
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(
        return_value=_mock_httpx_response(
            502, {"detail": "podman-compose rebuild failed: boom"}
        )
    )
    fake_client_cm = MagicMock()
    fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)), \
         patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "secret-token"), \
         patch("app.routers.admin_ops.httpx.AsyncClient", return_value=fake_client_cm):
        with pytest.raises(HTTPException) as exc_info:
            await admin_ops.rebuild_server("s1", _make_request(roles=["platform_admin"]))
        assert exc_info.value.status_code == 502
        assert "boom" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_restart_server_unreachable_ops_agent_returns_503():
    import httpx

    from app.routers import admin_ops
    row = {
        "server_id": "s1",
        "owner_sub": "admin1",
        "maintainers": [],
        "debug_mode": True,
        "upstream_url": "http://lab-mcp-echo:8000/mcp",
    }
    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    fake_client_cm = MagicMock()
    fake_client_cm.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client_cm.__aexit__ = AsyncMock(return_value=False)

    with patch("app.routers.admin_ops.AsyncSessionLocal", _mock_db_session(row)), \
         patch.object(admin_ops.settings, "OPS_AGENT_URL", "http://lab-ops-agent:9000"), \
         patch.object(admin_ops.settings, "OPS_AGENT_TOKEN", "secret-token"), \
         patch("app.routers.admin_ops.httpx.AsyncClient", return_value=fake_client_cm):
        with pytest.raises(HTTPException) as exc_info:
            await admin_ops.restart_server("s1", _make_request(roles=["platform_admin"]))
        assert exc_info.value.status_code == 503
