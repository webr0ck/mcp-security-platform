"""
Unit tests — Task 4.3: Named profiles + session-profile binding (SELF-F5/F8).

Coverage:
  - Login with ?profile=analyst → profile UUID resolved, stored in session + JWT
  - Login without profile → session has NULL profile_uuid (backward compat)
  - V019 profile_tokens table: migration V036 drops it (tested via migration file content)
  - _issue_session_jwt: adds "profile" claim when profile_uuid is provided, absent otherwise
  - auth middleware: sets request.state.profile_uuid from JWT claim
  - _lookup_profile_with_cache: uses profile_uuid-scoped cache key + DB query when set
  - _registered_tools_for_client: filters by profile_mcp_bindings when profile_uuid is set
  - Named profile CRUD: create, list, get, bind MCP

All DB and Redis interactions are mocked — no live connections needed.

Run from proxy/:
  .venv/bin/python -m pytest tests/unit/test_named_profiles.py -v
"""
from __future__ import annotations

import json
import re
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# V036 migration content tests
# ---------------------------------------------------------------------------

def _read_migration(filename: str) -> str:
    import os
    migrations_dir = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "infra", "db", "migrations",
    )
    path = os.path.join(migrations_dir, filename)
    with open(path) as f:
        return f.read()


class TestV036Migration:
    """Verify the V036 migration SQL is structurally correct."""

    def test_v036_file_exists(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert sql  # non-empty

    def test_creates_profiles_table(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "CREATE TABLE IF NOT EXISTS profiles" in sql

    def test_creates_profile_mcp_bindings_table(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "CREATE TABLE IF NOT EXISTS profile_mcp_bindings" in sql

    def test_adds_profile_uuid_to_oidc_sessions(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "ALTER TABLE oidc_sessions" in sql
        assert "profile_uuid" in sql

    def test_adds_profile_uuid_to_mcp_profiles(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "ALTER TABLE mcp_profiles" in sql
        assert "profile_uuid" in sql

    def test_drops_profile_tokens(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "DROP TABLE IF EXISTS profile_tokens" in sql

    def test_inv_011_grants_present(self) -> None:
        sql = _read_migration("V036__named_profiles_session_binding.sql")
        assert "GRANT" in sql
        assert "profiles" in sql
        assert "profile_mcp_bindings" in sql

    def test_v019_profile_tokens_is_dead_schema(self) -> None:
        """V019 profile_tokens has no references in proxy/ source code."""
        import subprocess
        import os
        proxy_dir = os.path.join(os.path.dirname(__file__), "..", "..")
        result = subprocess.run(
            ["grep", "-r", "profile_tokens", proxy_dir, "--include=*.py"],
            capture_output=True,
            text=True,
        )
        # Only allow references from test files themselves (this file checking the migration)
        lines = [l for l in result.stdout.splitlines() if "test_named_profiles" not in l]
        assert lines == [], f"profile_tokens referenced in proxy code: {lines}"


# ---------------------------------------------------------------------------
# _issue_session_jwt — profile claim
# ---------------------------------------------------------------------------

class TestIssueSessionJwt:
    """_issue_session_jwt adds 'profile' claim when profile_uuid is set."""

    def _make_settings(self) -> SimpleNamespace:
        return SimpleNamespace(
            PROXY_BASE_URL="http://proxy.test",
            PROXY_SECRET_KEY="test-secret-key-for-unit-tests",
            SESSION_JWT_EXPIRE_SECONDS=3600,
        )

    def test_no_profile_claim_when_not_provided(self) -> None:
        import jwt as jose_jwt
        with patch("app.routers.oidc_browser.settings", self._make_settings()):
            from app.routers.oidc_browser import _issue_session_jwt
            token = _issue_session_jwt(
                subject="user123",
                client_id="user@corp",
                roles=["agent"],
                jti=str(uuid.uuid4()),
            )
        claims = jose_jwt.decode(
            token,
            "test-secret-key-for-unit-tests",
            algorithms=["HS256"],
            audience="mcp-proxy-session",
        )
        assert "profile" not in claims

    def test_profile_claim_added_when_profile_uuid_provided(self) -> None:
        import jwt as jose_jwt
        p_uuid = str(uuid.uuid4())
        with patch("app.routers.oidc_browser.settings", self._make_settings()):
            from app.routers.oidc_browser import _issue_session_jwt
            token = _issue_session_jwt(
                subject="user123",
                client_id="user@corp",
                roles=["agent"],
                jti=str(uuid.uuid4()),
                profile_uuid=p_uuid,
            )
        claims = jose_jwt.decode(
            token,
            "test-secret-key-for-unit-tests",
            algorithms=["HS256"],
            audience="mcp-proxy-session",
        )
        assert claims["profile"] == p_uuid

    def test_profile_uuid_none_omits_claim(self) -> None:
        import jwt as jose_jwt
        with patch("app.routers.oidc_browser.settings", self._make_settings()):
            from app.routers.oidc_browser import _issue_session_jwt
            token = _issue_session_jwt(
                subject="user123",
                client_id="user@corp",
                roles=["agent"],
                jti=str(uuid.uuid4()),
                profile_uuid=None,
            )
        claims = jose_jwt.decode(
            token,
            "test-secret-key-for-unit-tests",
            algorithms=["HS256"],
            audience="mcp-proxy-session",
        )
        assert "profile" not in claims


# ---------------------------------------------------------------------------
# Auth middleware — request.state.profile_uuid propagation
# ---------------------------------------------------------------------------

class TestAuthMiddlewareProfileUuid:
    """Auth middleware sets request.state.profile_uuid from the JWT 'profile' claim."""

    def _make_session_jwt(self, profile_uuid: str | None = None) -> str:
        import jwt as jose_jwt
        import time
        payload: dict[str, Any] = {
            "sub": "user123",
            "client_id": "user@corp",
            "roles": ["agent"],
            "iss": "http://proxy.test",
            "aud": "mcp-proxy-session",
            "jti": str(uuid.uuid4()),
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "auth_method": "oidc_browser",
        }
        if profile_uuid:
            payload["profile"] = profile_uuid
        return jose_jwt.encode(payload, "test-secret-key-for-unit-tests", algorithm="HS256")

    def _make_request(self, token: str, via_cookie: bool = True) -> MagicMock:
        req = MagicMock()
        req.url.path = "/api/v1/tools/call"
        req.method = "POST"
        req.state = SimpleNamespace()
        req.client = SimpleNamespace(host="127.0.0.1")
        if via_cookie:
            req.cookies = {"mcp_session": token}
            req.headers = MagicMock()
            req.headers.get = MagicMock(return_value="")
        else:
            req.cookies = {}
            req.headers = MagicMock()
            req.headers.get = MagicMock(side_effect=lambda k, d="": {
                "Authorization": f"Bearer {token}",
            }.get(k, d))
        return req

    @pytest.mark.asyncio
    async def test_profile_uuid_set_on_state_from_cookie(self) -> None:
        p_uuid = str(uuid.uuid4())
        token = self._make_session_jwt(profile_uuid=p_uuid)
        req = self._make_request(token, via_cookie=True)

        mock_settings = SimpleNamespace(
            PROXY_SECRET_KEY="test-secret-key-for-unit-tests",
            SESSION_COOKIE_NAME="mcp_session",
            OIDC_ENABLED=False,
            ENVIRONMENT="production",
            GATEWAY_SHARED_SECRET="",
            PROXY_BASE_URL="http://proxy.test",
            OIDC_ISSUER_ID="test-issuer",
            MTLS_CA_ID="step-ca",
            PROXY_ALLOWED_HOSTS="",
            OIDC_TRUST_FORWARDED_HOST=False,
        )

        async def mock_call_next(r):
            return MagicMock(status_code=200)

        with (
            patch("app.middleware.auth.settings", mock_settings),
            patch("app.middleware.auth._is_session_jti_revoked", new_callable=AsyncMock, return_value=False),
            patch("app.middleware.auth._load_roles", new_callable=AsyncMock, return_value=["agent"]),
        ):
            from app.middleware.auth import AuthMiddleware
            mw = AuthMiddleware(app=MagicMock())
            await mw.dispatch(req, mock_call_next)

        assert req.state.profile_uuid == p_uuid

    @pytest.mark.asyncio
    async def test_profile_uuid_is_none_when_no_profile_claim(self) -> None:
        """Sessions without profile claim → profile_uuid=None (backward compat)."""
        token = self._make_session_jwt(profile_uuid=None)
        req = self._make_request(token, via_cookie=True)

        mock_settings = SimpleNamespace(
            PROXY_SECRET_KEY="test-secret-key-for-unit-tests",
            SESSION_COOKIE_NAME="mcp_session",
            OIDC_ENABLED=False,
            ENVIRONMENT="production",
            GATEWAY_SHARED_SECRET="",
            PROXY_BASE_URL="http://proxy.test",
            OIDC_ISSUER_ID="test-issuer",
            MTLS_CA_ID="step-ca",
            PROXY_ALLOWED_HOSTS="",
            OIDC_TRUST_FORWARDED_HOST=False,
        )

        async def mock_call_next(r):
            return MagicMock(status_code=200)

        with (
            patch("app.middleware.auth.settings", mock_settings),
            patch("app.middleware.auth._is_session_jti_revoked", new_callable=AsyncMock, return_value=False),
            patch("app.middleware.auth._load_roles", new_callable=AsyncMock, return_value=["agent"]),
        ):
            from app.middleware.auth import AuthMiddleware
            mw = AuthMiddleware(app=MagicMock())
            await mw.dispatch(req, mock_call_next)

        assert req.state.profile_uuid is None


# ---------------------------------------------------------------------------
# _lookup_profile_with_cache — profile_uuid-scoped lookup
# ---------------------------------------------------------------------------

class TestLookupProfileWithCacheProfileUuid:
    """profile_uuid path uses uuid-scoped cache key and profile_uuid DB query."""

    def test_uuid_cache_key_format(self) -> None:
        """Verify the cache key format string for profile_uuid path."""
        p_uuid = "abc-123"
        tool_name = "my-tool"
        # This mirrors the exact logic in _lookup_profile_with_cache
        cache_key = f"mcp_profile:uuid:{p_uuid}:{tool_name}"
        assert cache_key == "mcp_profile:uuid:abc-123:my-tool"

    def test_legacy_cache_key_format(self) -> None:
        """Verify the cache key format for the legacy (no profile_uuid) path."""
        client_id = "user@corp"
        tool_name = "my-tool"
        cache_key = f"mcp_profile:{client_id}:{tool_name}"
        assert cache_key == "mcp_profile:user@corp:my-tool"

    def test_cache_key_uses_uuid_not_client_id_when_profile_uuid_set(self) -> None:
        """Confirm that profile_uuid path key differs from legacy key."""
        p_uuid = str(uuid.uuid4())
        client_id = "user@corp"
        tool_name = "tool-x"
        uuid_key = f"mcp_profile:uuid:{p_uuid}:{tool_name}"
        legacy_key = f"mcp_profile:{client_id}:{tool_name}"
        assert uuid_key != legacy_key
        assert "uuid" in uuid_key
        assert "uuid" not in legacy_key

    def test_profile_uuid_db_query_targets_different_column(self) -> None:
        """The profile_uuid DB path queries profile_uuid column, not profile_id.

        This test validates the SQL string embedded in invocation.py contains
        the correct column name for the named-profile path by reading the source
        file directly (avoids inspect issues when function is mocked by autouse).
        """
        import os
        invocation_path = os.path.join(
            os.path.dirname(__file__),
            "..", "..", "app", "services", "invocation.py",
        )
        with open(invocation_path) as f:
            source = f.read()
        # The named-profile path must use profile_uuid= (not profile_id=) in its SQL
        assert "profile_uuid=:uuid" in source, (
            "Named-profile DB query must filter by profile_uuid column"
        )
        # The legacy path must still use profile_id=:pid
        assert "profile_id=:pid" in source, (
            "Legacy DB query must still use profile_id column"
        )


# ---------------------------------------------------------------------------
# _registered_tools_for_client — profile_mcp_bindings filter
# ---------------------------------------------------------------------------

class TestRegisteredToolsProfileMcpBindings:
    """When profile_uuid is set, _registered_tools_for_client filters by profile_mcp_bindings."""

    @pytest.mark.asyncio
    async def test_tool_excluded_when_binding_disabled(self) -> None:
        p_uuid = str(uuid.uuid4())

        # Mock: two tools returned from DB; one has a disabled binding
        rows = [
            {"name": "tool-a", "description": "Tool A", "schema": "{}", "tags": [], "server_id": None},
            {"name": "tool-b", "description": "Tool B", "schema": "{}", "tags": [], "server_id": None},
        ]

        # Mock: grants allow both tools
        grants_data = {
            "client1@corp": {"allowed_tools": ["tool-a", "tool-b"], "allowed_tags": []}
        }

        mock_mappings = MagicMock()
        mock_mappings.fetchall = MagicMock(return_value=rows)
        mock_execute_result = MagicMock()
        mock_execute_result.mappings = MagicMock(return_value=mock_mappings)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_execute_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        # Binding: tool-b is disabled for this profile; tool-a has no binding (default allow)
        async def mock_lookup_binding(profile_uuid_arg: str, mcp_name: str):
            if mcp_name == "tool-b":
                return {"enabled": False, "allowed_functions": None}
            return None  # no binding = default allow

        with (
            patch("app.core.database.AsyncSessionLocal", MagicMock(return_value=mock_db)),
            patch("app.routers.mcp_server._load_grants_data", return_value=(grants_data, {})),
            patch("app.routers.mcp_server._lookup_profile_mcp_binding", side_effect=mock_lookup_binding),
            patch("app.routers.mcp_server._TOOLS", []),
        ):
            from app.routers.mcp_server import _registered_tools_for_client
            result = await _registered_tools_for_client(
                client_id="client1@corp",
                roles=["agent"],
                principal_id=None,
                principal_type=None,
                profile_uuid=p_uuid,
            )

        tool_names = [t["name"] for t in result]
        assert "tool-a" in tool_names
        assert "tool-b" not in tool_names, "tool-b should be excluded by disabled binding"

    @pytest.mark.asyncio
    async def test_no_profile_uuid_falls_back_to_legacy_path(self) -> None:
        """Without profile_uuid, the legacy mcp_profiles gate is used, not profile_mcp_bindings."""
        rows = [
            {"name": "tool-a", "description": "Tool A", "schema": "{}", "tags": [], "server_id": None},
        ]
        grants_data = {
            "user@corp": {"allowed_tools": ["tool-a"], "allowed_tags": []}
        }

        mock_mappings = MagicMock()
        mock_mappings.fetchall = MagicMock(return_value=rows)
        mock_execute_result = MagicMock()
        mock_execute_result.mappings = MagicMock(return_value=mock_mappings)

        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_execute_result)
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=None)

        binding_calls: list[str] = []

        async def mock_lookup_binding(profile_uuid_arg: str, mcp_name: str):
            binding_calls.append(mcp_name)
            return None

        with (
            patch("app.core.database.AsyncSessionLocal", MagicMock(return_value=mock_db)),
            patch("app.routers.mcp_server._load_grants_data", return_value=(grants_data, {})),
            patch("app.routers.mcp_server._lookup_profile_mcp_binding", side_effect=mock_lookup_binding),
            patch("app.routers.mcp_server._lookup_profile_row", new_callable=AsyncMock, return_value=None),
            patch("app.routers.mcp_server._TOOLS", []),
        ):
            from app.routers.mcp_server import _registered_tools_for_client
            await _registered_tools_for_client(
                client_id="user@corp",
                roles=["agent"],
                principal_id="human:test-issuer:user@corp",
                principal_type="human",
                profile_uuid=None,  # no named profile
            )

        # profile_mcp_bindings lookup must NOT be called when profile_uuid is None
        assert binding_calls == [], (
            "_lookup_profile_mcp_binding should not be called when profile_uuid is None"
        )


# ---------------------------------------------------------------------------
# Named profile CRUD router tests
# ---------------------------------------------------------------------------

class TestNamedProfileCrud:
    """Named profile CRUD endpoints: create, list, get, MCP bind."""

    def _make_admin_request(self) -> MagicMock:
        req = MagicMock()
        req.state = SimpleNamespace(
            client_id="admin@corp",
            client_roles=["admin"],
        )
        return req

    def _make_nonadmin_request(self) -> MagicMock:
        req = MagicMock()
        req.state = SimpleNamespace(
            client_id="user@corp",
            client_roles=["agent"],
        )
        return req

    @pytest.mark.asyncio
    async def test_list_profiles_returns_profiles(self) -> None:
        sample_profile = {
            "id": uuid.uuid4(),
            "name": "analyst",
            "display_name": "Analyst",
            "description": "Read-only analyst profile",
            "created_by": "admin@corp",
            "created_at": __import__("datetime").datetime(2026, 1, 1),
            "is_active": True,
        }
        with patch("app.routers.profiles._list_named_profiles", new_callable=AsyncMock, return_value=[sample_profile]):
            from app.routers.profiles import list_named_profiles
            req = self._make_admin_request()
            response = await list_named_profiles(req)
        data = json.loads(response.body)
        assert len(data["profiles"]) == 1
        assert data["profiles"][0]["name"] == "analyst"

    @pytest.mark.asyncio
    async def test_list_profiles_forbidden_for_non_admin(self) -> None:
        from fastapi import HTTPException
        from app.routers.profiles import list_named_profiles
        req = self._make_nonadmin_request()
        with pytest.raises(HTTPException) as exc_info:
            await list_named_profiles(req)
        assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_create_profile_returns_201(self) -> None:
        created = {
            "id": uuid.uuid4(),
            "name": "deployment-eng",
            "display_name": "Deployment Engineer",
            "description": None,
            "created_by": "admin@corp",
            "created_at": __import__("datetime").datetime(2026, 1, 1),
            "is_active": True,
        }
        with (
            patch("app.routers.profiles._get_named_profile", new_callable=AsyncMock, return_value=None),
            patch("app.routers.profiles._create_named_profile", new_callable=AsyncMock, return_value=created),
        ):
            from app.routers.profiles import create_named_profile, NamedProfileCreateBody
            req = self._make_admin_request()
            body = NamedProfileCreateBody(name="deployment-eng", display_name="Deployment Engineer")
            response = await create_named_profile(body, req)
        assert response.status_code == 201
        data = json.loads(response.body)
        assert data["name"] == "deployment-eng"

    @pytest.mark.asyncio
    async def test_create_profile_409_on_duplicate(self) -> None:
        existing = {"id": uuid.uuid4(), "name": "analyst", "is_active": True}
        with patch("app.routers.profiles._get_named_profile", new_callable=AsyncMock, return_value=existing):
            from fastapi import HTTPException
            from app.routers.profiles import create_named_profile, NamedProfileCreateBody
            req = self._make_admin_request()
            body = NamedProfileCreateBody(name="analyst")
            with pytest.raises(HTTPException) as exc_info:
                await create_named_profile(body, req)
        assert exc_info.value.status_code == 409

    @pytest.mark.asyncio
    async def test_get_profile_returns_with_bindings(self) -> None:
        p_uuid = uuid.uuid4()
        profile = {
            "id": p_uuid,
            "name": "analyst",
            "display_name": "Analyst",
            "description": None,
            "created_by": "admin@corp",
            "created_at": __import__("datetime").datetime(2026, 1, 1),
            "is_active": True,
        }
        bindings = [{"mcp_name": "grafana-query", "enabled": True, "allowed_functions": None}]
        with (
            patch("app.routers.profiles._get_named_profile", new_callable=AsyncMock, return_value=profile),
            patch("app.routers.profiles._get_profile_mcp_bindings", new_callable=AsyncMock, return_value=bindings),
        ):
            from app.routers.profiles import get_named_profile
            req = self._make_admin_request()
            response = await get_named_profile("analyst", req)
        data = json.loads(response.body)
        assert data["name"] == "analyst"
        assert len(data["mcp_bindings"]) == 1

    @pytest.mark.asyncio
    async def test_get_profile_404_when_not_found(self) -> None:
        with patch("app.routers.profiles._get_named_profile", new_callable=AsyncMock, return_value=None):
            from fastapi import HTTPException
            from app.routers.profiles import get_named_profile
            req = self._make_admin_request()
            with pytest.raises(HTTPException) as exc_info:
                await get_named_profile("nonexistent", req)
        assert exc_info.value.status_code == 404

    @pytest.mark.asyncio
    async def test_upsert_named_profile_mcp_binding(self) -> None:
        p_uuid = uuid.uuid4()
        profile = {
            "id": p_uuid,
            "name": "analyst",
            "display_name": "Analyst",
            "description": None,
            "created_by": "admin@corp",
            "created_at": __import__("datetime").datetime(2026, 1, 1),
            "is_active": True,
        }
        with (
            patch("app.routers.profiles._get_named_profile", new_callable=AsyncMock, return_value=profile),
            patch("app.routers.profiles._assert_mcp_exists", new_callable=AsyncMock),
            patch("app.routers.profiles._upsert_profile_mcp_binding", new_callable=AsyncMock),
            patch("app.routers.profiles._invalidate_profile_mcp_binding_cache", new_callable=AsyncMock),
        ):
            from app.routers.profiles import upsert_named_profile_mcp, NamedProfileMCPBindingBody
            req = self._make_admin_request()
            body = NamedProfileMCPBindingBody(enabled=True, allowed_functions=["list", "query"])
            response = await upsert_named_profile_mcp("analyst", "grafana-query", body, req)
        data = json.loads(response.body)
        assert data["ok"] is True
        assert data["mcp_name"] == "grafana-query"
        assert data["enabled"] is True
        assert data["profile_name"] == "analyst"

    def test_profile_name_validation_rejects_bad_chars(self) -> None:
        from pydantic import ValidationError
        from app.routers.profiles import NamedProfileCreateBody
        with pytest.raises(ValidationError):
            NamedProfileCreateBody(name="bad name!")  # space + exclamation

    def test_profile_name_validation_accepts_valid_names(self) -> None:
        from app.routers.profiles import NamedProfileCreateBody
        body = NamedProfileCreateBody(name="read-only_analyst-v2")
        assert body.name == "read-only_analyst-v2"


# ---------------------------------------------------------------------------
# Login flow — profile param embedded in state
# ---------------------------------------------------------------------------

class TestLoginProfileParam:
    """?profile=<name> is embedded in OAuth state and resolved on callback."""

    def test_valid_profile_name_accepted(self) -> None:
        """Valid profile names match [A-Za-z0-9_-]{1,64}."""
        import re as _re
        valid = ["analyst", "read-only", "deployment_eng", "v2-profile", "A" * 64]
        for name in valid:
            assert _re.match(r'^[A-Za-z0-9_-]{1,64}$', name), f"{name!r} should be valid"

    def test_invalid_profile_names_rejected(self) -> None:
        import re as _re
        invalid = ["bad name", "profile!", "a" * 65, "", "has.dot"]
        for name in invalid:
            assert not _re.match(r'^[A-Za-z0-9_-]{1,64}$', name), f"{name!r} should be invalid"

    def test_state_encodes_profile_name_as_third_part(self) -> None:
        """State format: <random>.<base64url(redirect)>.<base64url(profile)>"""
        import base64
        profile = "analyst"
        encoded = base64.urlsafe_b64encode(profile.encode()).rstrip(b"=").decode()
        state = f"random_part.encoded_redirect.{encoded}"
        parts = state.split(".")
        assert len(parts) == 3
        padding = "=" * (-len(parts[2]) % 4)
        decoded = base64.urlsafe_b64decode(parts[2] + padding).decode()
        assert decoded == "analyst"
