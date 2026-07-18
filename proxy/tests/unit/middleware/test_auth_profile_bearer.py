"""
Unit tests — WS-1 (PRD-0011 Task 1.1): external OIDC BEARER path profile
scoping via ?profile=<uuid> / X-MCP-Profile.

Two layers of coverage:
  1. `_resolve_active_profile_uuid` in isolation (DB seam mocked directly).
  2. The bearer-path wiring in `AuthMiddleware.dispatch` (auth.py:356 area):
     supplied+valid -> resolver awaited, request proceeds; supplied+unknown
     -> 403; DB error during resolution -> 503; no `?profile` -> resolver
     never called (legacy no-profile path, backward compatible).

Fixture/client pattern copied from proxy/tests/unit/test_auth_middleware.py.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient, ASGITransport


# ---------------------------------------------------------------------------
# Shared helpers (mirrors test_auth_middleware.py)
# ---------------------------------------------------------------------------

def _make_app():
    from app.main import app
    return app


def _patch_load_roles(roles: list[str]):
    return patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=roles))


def _patch_validate_oidc_jwt(sub: str | None, jwt_roles: list[str] | None = None,
                              is_service_account: bool = False):
    return patch(
        "app.middleware.auth._validate_oidc_jwt",
        new=AsyncMock(return_value=(sub, jwt_roles or [], is_service_account)),
    )


def _override_db(app):
    from app.core.database import get_db

    class _FakeScalar:
        def scalar(self):
            return 0

        def fetchall(self):
            return []

    class _FakeDB:
        async def execute(self, *a, **k):
            return _FakeScalar()

        async def commit(self):
            pass

    async def _gen():
        yield _FakeDB()

    app.dependency_overrides[get_db] = _gen
    return app


ACTIVE_PROFILE = "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# _resolve_active_profile_uuid — resolver unit tests (DB seam mocked)
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_resolver_returns_uuid_for_active_profile():
    from app.middleware import auth
    with patch("app.core.database.AsyncSessionLocal") as sess:
        row = (ACTIVE_PROFILE,)
        ctx = sess.return_value.__aenter__.return_value
        ctx.execute = AsyncMock(return_value=AsyncMock(fetchone=lambda: row))
        assert await auth._resolve_active_profile_uuid(ACTIVE_PROFILE) == ACTIVE_PROFILE


@pytest.mark.unit
async def test_resolver_returns_none_for_unknown_profile():
    from app.middleware import auth
    with patch("app.core.database.AsyncSessionLocal") as sess:
        ctx = sess.return_value.__aenter__.return_value
        ctx.execute = AsyncMock(return_value=AsyncMock(fetchone=lambda: None))
        assert await auth._resolve_active_profile_uuid("deadbeef") is None


@pytest.mark.unit
async def test_resolver_raises_on_db_error():
    from app.middleware import auth
    with patch("app.core.database.AsyncSessionLocal") as sess:
        ctx = sess.return_value.__aenter__.return_value
        ctx.execute = AsyncMock(side_effect=RuntimeError("db unreachable"))
        with pytest.raises(RuntimeError):
            await auth._resolve_active_profile_uuid(ACTIVE_PROFILE)


# ---------------------------------------------------------------------------
# Bearer-path wiring — request.state.profile_uuid promotion
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_bearer_no_profile_param_leaves_profile_uuid_none():
    """
    No ?profile / X-MCP-Profile supplied on an OIDC bearer request -> the
    resolver must never be called, and the request proceeds (legacy
    full-visibility path, backward compatible).
    """
    app = _override_db(_make_app())
    resolver_mock = AsyncMock(return_value=ACTIVE_PROFILE)

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    app.dependency_overrides.clear()
    resolver_mock.assert_not_awaited()
    assert resp.status_code == 200


@pytest.mark.unit
async def test_bearer_valid_profile_query_param_resolves_and_proceeds():
    """
    ?profile=<uuid> on an OIDC bearer request with an active profile ->
    resolver awaited with the supplied GUID, request proceeds (200).
    """
    app = _override_db(_make_app())
    resolver_mock = AsyncMock(return_value=ACTIVE_PROFILE)

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                f"/api/v1/tools?profile={ACTIVE_PROFILE}",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    app.dependency_overrides.clear()
    resolver_mock.assert_awaited_once_with(ACTIVE_PROFILE)
    assert resp.status_code == 200


@pytest.mark.unit
async def test_bearer_valid_profile_header_resolves_and_proceeds():
    """X-MCP-Profile header fallback behaves the same as the query param."""
    app = _override_db(_make_app())
    resolver_mock = AsyncMock(return_value=ACTIVE_PROFILE)

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={
                    "Authorization": "Bearer eyJsome.jwt.token",
                    "X-MCP-Profile": ACTIVE_PROFILE,
                },
            )

    app.dependency_overrides.clear()
    resolver_mock.assert_awaited_once_with(ACTIVE_PROFILE)
    assert resp.status_code == 200


@pytest.mark.unit
async def test_bearer_unknown_profile_returns_403_never_falls_back():
    """
    Supplied-but-unresolvable GUID (unknown or inactive) -> 403, fail-closed.
    Must NOT fall back to the no-profile (full-visibility) path.
    """
    app = _make_app()
    resolver_mock = AsyncMock(return_value=None)

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools?profile=deadbeef-dead-beef-dead-beefdeadbeef",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    assert resp.status_code == 403
    body = resp.json()
    assert body["error"] == "profile_not_found"


@pytest.mark.unit
async def test_bearer_profile_resolution_db_error_returns_503():
    """
    DB error during profile resolution -> 503 (INV-015 fail-closed). Must
    NOT silently continue with no-profile visibility.
    """
    app = _make_app()
    resolver_mock = AsyncMock(side_effect=RuntimeError("db unreachable"))

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                f"/api/v1/tools?profile={ACTIVE_PROFILE}",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    assert resp.status_code == 503
    body = resp.json()
    assert body["error"] == "profile_lookup_failed"


@pytest.mark.unit
async def test_mtls_caller_never_triggers_profile_resolution():
    """
    mTLS callers are not auth_method=='oidc' -> the profile-GUID branch must
    never engage, even if a ?profile= param is present (defence in depth /
    scope check for the WS-1 condition).
    """
    app = _override_db(_make_app())
    resolver_mock = AsyncMock(return_value=ACTIVE_PROFILE)

    with (
        patch("app.middleware.auth._resolve_active_profile_uuid", resolver_mock),
        _patch_load_roles(["agent"]),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                f"/api/v1/tools?profile={ACTIVE_PROFILE}",
                headers={"X-Client-Cert-CN": "mtls-client"},
            )

    app.dependency_overrides.clear()
    resolver_mock.assert_not_awaited()
    assert resp.status_code == 200
