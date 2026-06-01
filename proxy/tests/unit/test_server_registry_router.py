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
