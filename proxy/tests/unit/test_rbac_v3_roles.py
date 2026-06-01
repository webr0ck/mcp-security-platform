"""Tests for v3 three-tier RBAC role model."""
import pytest
from app.middleware.rbac import PUBLIC_PATHS, _resolve_allowed_roles


def test_platform_admin_allowed_on_admin_paths():
    allowed = _resolve_allowed_roles("POST", "/api/v1/tools")
    assert allowed is not None
    assert "platform_admin" in allowed


def test_legacy_admin_still_allowed_on_admin_paths():
    allowed = _resolve_allowed_roles("POST", "/api/v1/tools")
    assert allowed is not None
    assert "admin" in allowed


def test_user_role_allowed_on_invoke():
    allowed = _resolve_allowed_roles("POST", "/api/v1/tools/abc/invoke")
    assert allowed is not None
    assert "user" in allowed


def test_user_role_not_allowed_on_admin_tools_create():
    allowed = _resolve_allowed_roles("POST", "/api/v1/tools")
    assert allowed is not None
    assert "user" not in allowed
    assert "agent" not in allowed


def test_mcp_path_not_in_rbac_public_paths():
    assert "/mcp" not in PUBLIC_PATHS


def test_mcp_path_has_role_constraint():
    allowed = _resolve_allowed_roles("POST", "/mcp")
    assert allowed is not None
    assert len(allowed) > 0


def test_user_role_can_access_mcp():
    allowed = _resolve_allowed_roles("POST", "/mcp")
    assert "user" in allowed


def test_agent_role_can_access_mcp():
    allowed = _resolve_allowed_roles("POST", "/mcp")
    assert "agent" in allowed


def test_server_registry_requires_platform_admin_not_user():
    allowed = _resolve_allowed_roles("POST", "/api/v1/admin/servers")
    assert allowed is not None
    assert "platform_admin" in allowed
    assert "user" not in allowed
    assert "agent" not in allowed


def test_server_registry_list_requires_platform_admin():
    allowed = _resolve_allowed_roles("GET", "/api/v1/admin/servers")
    assert allowed is not None
    assert "platform_admin" in allowed


def test_approved_servers_list_accessible_to_any_authenticated():
    allowed = _resolve_allowed_roles("GET", "/api/v1/servers")
    assert allowed is not None
    assert "user" in allowed
    assert "agent" in allowed
    assert "readonly" in allowed
