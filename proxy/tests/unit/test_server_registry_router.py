"""Unit tests for server registry router — mocks DB, no real connection needed."""
import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock


def _make_request(roles=("platform_admin",), client_id="admin1"):
    req = MagicMock()
    req.state = SimpleNamespace(client_roles=list(roles), client_id=client_id)
    return req


def test_require_platform_admin_passes_for_platform_admin():
    from app.routers.server_registry import _require_platform_admin
    _require_platform_admin(_make_request(roles=["platform_admin"]))


def test_require_platform_admin_passes_for_legacy_admin():
    from app.routers.server_registry import _require_platform_admin
    _require_platform_admin(_make_request(roles=["admin"]))


def test_require_platform_admin_rejects_user():
    from fastapi import HTTPException
    from app.routers.server_registry import _require_platform_admin
    with pytest.raises(HTTPException) as exc_info:
        _require_platform_admin(_make_request(roles=["user"]))
    assert exc_info.value.status_code == 403


def test_require_platform_admin_rejects_agent():
    from fastapi import HTTPException
    from app.routers.server_registry import _require_platform_admin
    with pytest.raises(HTTPException) as exc_info:
        _require_platform_admin(_make_request(roles=["agent"]))
    assert exc_info.value.status_code == 403


def test_require_platform_admin_rejects_empty_roles():
    from fastapi import HTTPException
    from app.routers.server_registry import _require_platform_admin
    with pytest.raises(HTTPException) as exc_info:
        _require_platform_admin(_make_request(roles=[]))
    assert exc_info.value.status_code == 403


def test_server_create_rejects_invalid_injection_mode():
    from pydantic import ValidationError
    from app.routers.server_registry import ServerCreate
    with pytest.raises(ValidationError):
        ServerCreate(name="x", upstream_url="http://x", injection_mode="invalid_mode")


def test_server_create_accepts_all_valid_modes():
    from app.routers.server_registry import ServerCreate
    for mode in ("none", "service", "user", "service_account", "oauth_user_token"):
        s = ServerCreate(name="x", upstream_url="http://x", injection_mode=mode)
        assert s.injection_mode == mode


def test_server_update_excludes_injection_mode():
    from app.routers.server_registry import ServerUpdate
    # ServerUpdate should not have injection_mode (mode changes require consent)
    assert not hasattr(ServerUpdate.model_fields, "injection_mode") or \
           "injection_mode" not in ServerUpdate.model_fields


def test_serialize_converts_datetime():
    from app.routers.server_registry import _serialize
    import datetime
    d = {"created_at": datetime.datetime(2026, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc), "name": "srv"}
    out = _serialize(d)
    assert isinstance(out["created_at"], str)
    assert "2026" in out["created_at"]
    assert out["name"] == "srv"


@pytest.mark.asyncio
async def test_approve_server_rejects_when_under_submission_review():
    """The D3 direct-registration approve endpoint must never approve a server
    that's mid-flow in the self-service submission pipeline (submission_status
    != 'draft') — that flips status='approved' (what the servers-list UI
    reads) while submission_status stays e.g. 'awaiting_review' (what the
    submissions admin page reads), silently skipping that pipeline's
    high-risk-scope reviewer gate. Found 2026-07-19 on a live server."""
    from unittest.mock import AsyncMock, patch
    from fastapi import HTTPException
    from app.routers.server_registry import approve_server, ApproveBody

    row = ("http://upstream", "owner-sub", None, None, "none", None, "awaiting_review")
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(return_value=MagicMock(
        fetchone=MagicMock(return_value=row)
    ))

    with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_session):
        with pytest.raises(HTTPException) as exc_info:
            await approve_server(
                "srv-1", ApproveBody(consent_token="tok"), _make_request()
            )
    assert exc_info.value.status_code == 409
    assert "submission" in exc_info.value.detail.lower()
    # Must fail before ever touching the consent token / SSRF / healthcheck.
    assert mock_session.execute.await_count == 1
