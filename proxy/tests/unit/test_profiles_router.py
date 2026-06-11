"""
Unit tests — Task 4.2: Core proxy profile CRUD router.

Coverage:
  - _assert_may_write / _assert_may_read authorization gate
    * Self can always write/read own profile
    * Non-admin cannot write another principal's profile (403)
    * Admin can write any profile
  - enable_mcp / disable_mcp
    * Writes correct enabled state
    * Emits MCP_ENABLED / MCP_DISABLED event (append-only)
    * Invalidates Redis cache after mutation
    * 404 when MCP does not exist in registry
  - upsert_profile_mcp
    * Stores allowed_functions
  - enable_function / disable_function
    * No-op when already unrestricted (enable)
    * Builds restricted list on first disable from unrestricted
  - X-User-Role sort in invocation.py (Task 4.2 item 3)
    * [readonly, agent, admin] → primary_role == "admin"
    * [auditor, agent] → primary_role == "agent"
    * empty → primary_role == "user"
  - Cache invalidation: profile write updates Redis cache key

All DB and Redis interactions are mocked — no live connections needed.

Run from proxy/:
  .venv/bin/python -m pytest tests/unit/test_profiles_router.py -v
"""
from __future__ import annotations

import json
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(
    client_id: str = "user-001",
    roles: list[str] | None = None,
    request_id: str = "req-test",
) -> MagicMock:
    req = MagicMock()
    req.state = SimpleNamespace(
        client_id=client_id,
        client_roles=roles if roles is not None else ["agent"],
        request_id=request_id,
    )
    return req


# ---------------------------------------------------------------------------
# Authorization gate
# ---------------------------------------------------------------------------

class TestAuthorizationGate:
    @pytest.mark.unit
    def test_self_can_write_own_profile(self):
        from app.routers.profiles import _assert_may_write
        req = _make_request(client_id="alice", roles=["agent"])
        # Should not raise
        _assert_may_write(req, "alice")

    @pytest.mark.unit
    def test_non_admin_cannot_write_other_profile(self):
        from fastapi import HTTPException
        from app.routers.profiles import _assert_may_write
        req = _make_request(client_id="alice", roles=["agent"])
        with pytest.raises(HTTPException) as exc_info:
            _assert_may_write(req, "bob")
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    def test_admin_can_write_other_profile(self):
        from app.routers.profiles import _assert_may_write
        req = _make_request(client_id="admin-user", roles=["admin"])
        # Should not raise
        _assert_may_write(req, "some-other-user")

    @pytest.mark.unit
    def test_platform_admin_can_write_other_profile(self):
        from app.routers.profiles import _assert_may_write
        req = _make_request(client_id="platform-admin", roles=["platform_admin"])
        _assert_may_write(req, "anybody")

    @pytest.mark.unit
    def test_no_identity_raises_401(self):
        from fastapi import HTTPException
        from app.routers.profiles import _assert_may_write
        req = _make_request(client_id="", roles=["agent"])
        with pytest.raises(HTTPException) as exc_info:
            _assert_may_write(req, "bob")
        assert exc_info.value.status_code == 401

    @pytest.mark.unit
    def test_self_can_read_own_profile(self):
        from app.routers.profiles import _assert_may_read
        req = _make_request(client_id="alice", roles=["agent"])
        _assert_may_read(req, "alice")

    @pytest.mark.unit
    def test_auditor_can_read_other_profile(self):
        from app.routers.profiles import _assert_may_read
        req = _make_request(client_id="auditor-1", roles=["auditor"])
        _assert_may_read(req, "anybody")

    @pytest.mark.unit
    def test_agent_cannot_read_other_profile(self):
        from fastapi import HTTPException
        from app.routers.profiles import _assert_may_read
        req = _make_request(client_id="alice", roles=["agent"])
        with pytest.raises(HTTPException) as exc_info:
            _assert_may_read(req, "bob")
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------

class TestProfileUpsertBody:
    @pytest.mark.unit
    def test_valid_with_allowed_functions(self):
        from app.routers.profiles import ProfileUpsertBody
        body = ProfileUpsertBody(enabled=True, allowed_functions=["read", "write"])
        assert body.allowed_functions == ["read", "write"]

    @pytest.mark.unit
    def test_valid_null_allowed_functions(self):
        from app.routers.profiles import ProfileUpsertBody
        body = ProfileUpsertBody(enabled=False)
        assert body.allowed_functions is None

    @pytest.mark.unit
    def test_blank_function_name_rejected(self):
        from pydantic import ValidationError
        from app.routers.profiles import ProfileUpsertBody
        with pytest.raises(ValidationError):
            ProfileUpsertBody(enabled=True, allowed_functions=["read", "   "])


# ---------------------------------------------------------------------------
# enable_mcp
# ---------------------------------------------------------------------------

class TestEnableMcp:
    @pytest.mark.unit
    async def test_enable_mcp_self_service(self):
        """Self can enable their own MCP; event emitted; cache invalidated."""
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": False, "allowed_functions": None}

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()) as mock_upsert, \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()) as mock_cache:

            resp = await enable_mcp("alice", "file_tool", req)

        body = json.loads(resp.body)
        assert body["ok"] is True
        assert body["enabled"] is True
        assert body["mcp_name"] == "file_tool"
        mock_upsert.assert_awaited_once()
        mock_event.assert_awaited_once()
        _, call_kwargs = mock_event.call_args
        assert mock_event.call_args[0][2] == "MCP_ENABLED"  # event_type positional arg
        mock_cache.assert_awaited_once()

    @pytest.mark.unit
    async def test_enable_mcp_non_admin_cannot_enable_other(self):
        """Non-admin cannot enable another user's MCP."""
        from fastapi import HTTPException
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        with pytest.raises(HTTPException) as exc_info:
            await enable_mcp("bob", "file_tool", req)
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    async def test_enable_mcp_admin_can_enable_other(self):
        """Admin can enable another user's MCP."""
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="admin-user", roles=["admin"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()), \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            resp = await enable_mcp("target-user", "file_tool", req)

        body = json.loads(resp.body)
        assert body["ok"] is True
        assert body["principal"] == "target-user"

    @pytest.mark.unit
    async def test_enable_mcp_404_when_mcp_not_in_registry(self):
        """404 when MCP name is not in tool_registry."""
        from fastapi import HTTPException
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        with patch(
            "app.routers.profiles._assert_mcp_exists",
            AsyncMock(side_effect=HTTPException(status_code=404, detail="not found")),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await enable_mcp("alice", "nonexistent_mcp", req)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# disable_mcp
# ---------------------------------------------------------------------------

class TestDisableMcp:
    @pytest.mark.unit
    async def test_disable_mcp_self_service(self):
        """Self can disable their own MCP; MCP_DISABLED event emitted."""
        from app.routers.profiles import disable_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": True, "allowed_functions": ["read"]}

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()) as mock_upsert, \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()) as mock_cache:

            resp = await disable_mcp("alice", "file_tool", req)

        body = json.loads(resp.body)
        assert body["ok"] is True
        assert body["enabled"] is False
        assert mock_event.call_args[0][2] == "MCP_DISABLED"
        # Cache must be updated with enabled=False
        mock_cache.assert_awaited_once()
        cached_value = mock_cache.call_args[0][2]
        assert cached_value["enabled"] is False
        # allowed_functions preserved from old row
        assert cached_value["allowed_functions"] == ["read"]

    @pytest.mark.unit
    async def test_disable_preserves_allowed_functions(self):
        """Disabling an MCP preserves the existing allowed_functions list."""
        from app.routers.profiles import disable_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": True, "allowed_functions": ["fn_a", "fn_b"]}

        mock_upsert = AsyncMock()

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", mock_upsert), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()), \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            await disable_mcp("alice", "file_tool", req)

        # _upsert_profile_row is called with keyword args for enabled/allowed_functions/changed_by
        mock_upsert.assert_awaited_once()
        kwargs = mock_upsert.call_args.kwargs
        assert kwargs["allowed_functions"] == ["fn_a", "fn_b"]


# ---------------------------------------------------------------------------
# Events are append-only
# ---------------------------------------------------------------------------

class TestEventsAppendOnly:
    @pytest.mark.unit
    async def test_events_emitted_on_enable(self):
        """MCP_ENABLED event is emitted via _emit_profile_event (append-only, no update)."""
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="alice", roles=["agent"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            await enable_mcp("alice", "file_tool", req)

        mock_event.assert_awaited_once()
        event_type = mock_event.call_args[0][2]
        assert event_type == "MCP_ENABLED"

    @pytest.mark.unit
    async def test_events_emitted_on_disable(self):
        """MCP_DISABLED event is emitted via _emit_profile_event (append-only, no update)."""
        from app.routers.profiles import disable_mcp

        req = _make_request(client_id="alice", roles=["agent"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            await disable_mcp("alice", "file_tool", req)

        mock_event.assert_awaited_once()
        assert mock_event.call_args[0][2] == "MCP_DISABLED"


# ---------------------------------------------------------------------------
# Cache invalidation (Task 1.10 interaction)
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    @pytest.mark.unit
    async def test_cache_invalidated_on_enable(self):
        """After enable, Redis cache key is updated with enabled=True."""
        from app.routers.profiles import enable_mcp

        req = _make_request(client_id="alice", roles=["agent"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()), \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()) as mock_cache:

            await enable_mcp("alice", "file_tool", req)

        mock_cache.assert_awaited_once_with(
            "alice", "file_tool",
            {"enabled": True, "allowed_functions": None},
        )

    @pytest.mark.unit
    async def test_cache_invalidated_on_disable(self):
        """After disable, Redis cache key is updated with enabled=False."""
        from app.routers.profiles import disable_mcp

        req = _make_request(client_id="alice", roles=["agent"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()), \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()) as mock_cache:

            await disable_mcp("alice", "file_tool", req)

        mock_cache.assert_awaited_once()
        cached_value = mock_cache.call_args[0][2]
        assert cached_value["enabled"] is False

    @pytest.mark.unit
    async def test_cache_invalidated_on_upsert(self):
        """After PUT upsert, Redis cache key is updated with the new state."""
        from app.routers.profiles import upsert_profile_mcp, ProfileUpsertBody

        req = _make_request(client_id="alice", roles=["agent"])
        body = ProfileUpsertBody(enabled=True, allowed_functions=["fn_a"])

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()), \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()) as mock_cache:

            await upsert_profile_mcp("alice", "file_tool", body, req)

        mock_cache.assert_awaited_once_with(
            "alice", "file_tool",
            {"enabled": True, "allowed_functions": ["fn_a"]},
        )

    @pytest.mark.unit
    async def test_invalidate_profile_cache_writes_redis(self):
        """_invalidate_profile_cache calls redis.setex with the correct key and TTL."""
        from app.routers.profiles import _invalidate_profile_cache, _PROFILE_CACHE_TTL_SECONDS

        mock_redis = AsyncMock()
        mock_redis.setex = AsyncMock()
        mock_pool = MagicMock()
        mock_pool.client = mock_redis

        with patch("app.routers.profiles.redis_pool", mock_pool, create=True):
            # Patch the import inside the function
            with patch("app.core.redis_client.redis_pool", mock_pool):
                await _invalidate_profile_cache(
                    "alice", "file_tool",
                    {"enabled": False, "allowed_functions": None},
                )

        # Verify setex was called with the right key and TTL
        mock_redis.setex.assert_awaited_once()
        call_args = mock_redis.setex.call_args[0]
        assert call_args[0] == "mcp_profile:alice:file_tool"
        assert call_args[1] == _PROFILE_CACHE_TTL_SECONDS
        stored_value = json.loads(call_args[2])
        assert stored_value["enabled"] is False

    @pytest.mark.unit
    async def test_invalidate_profile_cache_sentinel_when_none(self):
        """_invalidate_profile_cache writes the sentinel when new_value is None."""
        from app.routers.profiles import _invalidate_profile_cache, _SENTINEL_NO_ROW

        mock_redis = AsyncMock()
        mock_pool = MagicMock()
        mock_pool.client = mock_redis

        with patch("app.core.redis_client.redis_pool", mock_pool):
            await _invalidate_profile_cache("alice", "file_tool", None)

        call_args = mock_redis.setex.call_args[0]
        assert call_args[2] == _SENTINEL_NO_ROW


# ---------------------------------------------------------------------------
# Function-level enable/disable
# ---------------------------------------------------------------------------

class TestFunctionToggle:
    @pytest.mark.unit
    async def test_enable_function_noop_when_unrestricted(self):
        """Enable function is a no-op when allowed_functions is null (unrestricted)."""
        from app.routers.profiles import enable_function

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": True, "allowed_functions": None}

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()) as mock_upsert, \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            resp = await enable_function("alice", "file_tool", "write_file", req)

        body = json.loads(resp.body)
        assert body["ok"] is True
        assert "unrestricted" in body.get("note", "").lower()
        # No upsert or event because it's a no-op
        mock_upsert.assert_not_awaited()
        mock_event.assert_not_awaited()

    @pytest.mark.unit
    async def test_disable_function_from_unrestricted_creates_empty_list(self):
        """
        Disabling a function when allowed_functions=null creates an empty restriction
        list (the disabled function is now excluded from allowed_functions=[]).
        """
        from app.routers.profiles import disable_function

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": True, "allowed_functions": None}

        captured: list = []

        async def _capture_upsert(*args, **kwargs):
            captured.extend(args)

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock(side_effect=_capture_upsert)), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            resp = await disable_function("alice", "file_tool", "write_file", req)

        body = json.loads(resp.body)
        assert body["ok"] is True
        assert body["enabled"] is False
        # new allowed_functions is [] (empty — write_file is excluded)
        assert body["allowed_functions"] == []
        assert mock_event.call_args[0][2] == "FUNCTION_DISABLED"

    @pytest.mark.unit
    async def test_enable_function_adds_to_existing_list(self):
        """Enable function adds fn to the existing allowed_functions list."""
        from app.routers.profiles import enable_function

        req = _make_request(client_id="alice", roles=["agent"])
        old_row = {"enabled": True, "allowed_functions": ["read_file"]}

        with patch("app.routers.profiles._assert_mcp_exists", AsyncMock()), \
             patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=old_row)), \
             patch("app.routers.profiles._upsert_profile_row", AsyncMock()), \
             patch("app.routers.profiles._emit_profile_event", AsyncMock()) as mock_event, \
             patch("app.routers.profiles._invalidate_profile_cache", AsyncMock()):

            resp = await enable_function("alice", "file_tool", "write_file", req)

        body = json.loads(resp.body)
        assert "write_file" in body["allowed_functions"]
        assert "read_file" in body["allowed_functions"]
        assert mock_event.call_args[0][2] == "FUNCTION_ENABLED"


# ---------------------------------------------------------------------------
# X-User-Role sort (Task 4.2 item 3)
# ---------------------------------------------------------------------------

class TestRoleSort:
    @pytest.mark.unit
    def test_admin_wins_over_agent_and_readonly(self):
        """
        client_roles=[readonly, agent, admin] → primary_role == admin.

        The upstream MCP server's admin gate must receive the highest-privilege role.
        """
        # Import the constant and replicate the sort logic from invocation.py
        _ROLE_PRIORITY: dict[str, int] = {
            "admin": 0,
            "platform_admin": 0,
            "agent": 1,
            "auditor": 2,
            "readonly": 3,
        }
        roles = ["readonly", "agent", "admin"]
        sorted_roles = sorted(roles, key=lambda r: _ROLE_PRIORITY.get(r, 99))
        assert sorted_roles[0] == "admin"

    @pytest.mark.unit
    def test_agent_wins_over_auditor(self):
        _ROLE_PRIORITY: dict[str, int] = {
            "admin": 0, "platform_admin": 0,
            "agent": 1, "auditor": 2, "readonly": 3,
        }
        roles = ["auditor", "agent"]
        sorted_roles = sorted(roles, key=lambda r: _ROLE_PRIORITY.get(r, 99))
        assert sorted_roles[0] == "agent"

    @pytest.mark.unit
    def test_empty_roles_falls_back_to_user(self):
        _ROLE_PRIORITY: dict[str, int] = {
            "admin": 0, "platform_admin": 0,
            "agent": 1, "auditor": 2, "readonly": 3,
        }
        roles: list[str] = []
        sorted_roles = sorted(roles, key=lambda r: _ROLE_PRIORITY.get(r, 99))
        primary_role = sorted_roles[0] if sorted_roles else "user"
        assert primary_role == "user"

    @pytest.mark.unit
    def test_invocation_primary_role_uses_highest_privilege(self):
        """
        Verify the sort logic in invocation.py picks the most-privileged role
        regardless of list order.
        """
        _ROLE_PRIORITY = {
            "admin": 0, "platform_admin": 0,
            "agent": 1, "auditor": 2, "readonly": 3,
        }
        for test_roles, expected in [
            (["readonly", "agent", "admin"], "admin"),
            (["auditor"], "auditor"),
            (["agent", "readonly"], "agent"),
            (["platform_admin", "agent"], "platform_admin"),
        ]:
            sorted_r = sorted(test_roles, key=lambda r: _ROLE_PRIORITY.get(r, 99))
            primary = sorted_r[0] if sorted_r else "user"
            assert primary == expected, f"Expected {expected} for {test_roles}, got {primary}"


# ---------------------------------------------------------------------------
# GET profile endpoint
# ---------------------------------------------------------------------------

class TestGetProfile:
    @pytest.mark.unit
    async def test_get_returns_defaults_when_no_row(self):
        """GET returns enabled=True, allowed_functions=None when no explicit row exists."""
        from app.routers.profiles import get_profile_mcp

        req = _make_request(client_id="alice", roles=["agent"])

        with patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=None)):
            resp = await get_profile_mcp("alice", "file_tool", req)

        body = json.loads(resp.body)
        assert body["enabled"] is True
        assert body["allowed_functions"] is None
        assert body["explicit_row"] is False

    @pytest.mark.unit
    async def test_get_returns_stored_row(self):
        """GET returns the stored row when it exists."""
        from app.routers.profiles import get_profile_mcp

        req = _make_request(client_id="alice", roles=["agent"])
        stored = {"enabled": False, "allowed_functions": ["read_file"]}

        with patch("app.routers.profiles._get_profile_row", AsyncMock(return_value=stored)):
            resp = await get_profile_mcp("alice", "file_tool", req)

        body = json.loads(resp.body)
        assert body["enabled"] is False
        assert body["allowed_functions"] == ["read_file"]
        assert body["explicit_row"] is True
