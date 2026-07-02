"""
Unit Tests — AuthMiddleware edge cases
(proxy/app/middleware/auth.py)

Every test exercises a distinct auth resolution path or rejection case.
No external services are required — DB and Redis are replaced with
AsyncMock / side_effect stubs via sys.modules patching at the seam
established by _load_roles and _resolve_api_key.

Security coverage:
  - Missing / empty / whitespace-only X-Client-Cert-CN → 401
  - Injection chars in CN → accepted (proxy sanitises downstream; CN must
    not cause a 500, and must never be treated as a role grant)
  - API key happy path: token resolves to a client_id
  - API key wrong/unknown: returns 401
  - mTLS CN present AND Bearer token present: CN wins (priority rule)
  - JWT Bearer when OIDC_ENABLED=false: falls through to API key check
  - JWT Bearer when OIDC_ENABLED=true: validates sub claim
  - No identity at all on public path: passes through (no 401)
"""
from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_app():
    """Import the real ASGI app (lazy to avoid Settings validation errors)."""
    from app.main import app
    return app


def _patch_load_roles(roles: list[str]):
    """Patch the roles loader so no DB round-trip is needed."""
    return patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=roles))


def _override_db(app):
    """
    Override the get_db dependency with an empty-result stub so route handlers
    that execute DB queries (e.g. list_tools) return 200 with an empty list
    rather than 500 when real DB is unavailable.
    """
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


def _patch_resolve_api_key(client_id: str | None):
    """Patch the API key resolver."""
    return patch("app.middleware.auth._resolve_api_key", new=AsyncMock(return_value=client_id))


def _patch_validate_oidc_jwt(sub: str | None, jwt_roles: list[str] | None = None,
                             is_service_account: bool = False):
    """Patch the OIDC JWT validator (returns the P1-2 3-tuple)."""
    return patch(
        "app.middleware.auth._validate_oidc_jwt",
        new=AsyncMock(return_value=(sub, jwt_roles or [], is_service_account)),
    )


# ---------------------------------------------------------------------------
# Tests: missing / malformed CN
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_missing_cn_no_auth_returns_401():
    """
    No X-Client-Cert-CN and no Authorization header on a protected endpoint
    must return 401 UNAUTHENTICATED per ARCHITECTURE.md §5.4 and INV-009.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/tools")
    assert resp.status_code == 401
    body = resp.json()
    assert body["error"] == "unauthenticated"
    assert "WWW-Authenticate" in resp.headers


@pytest.mark.unit
async def test_empty_cn_header_returns_401():
    """
    An X-Client-Cert-CN header present but empty (after strip()) must be
    treated as missing — .strip() is applied in auth.py line 85.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/tools", headers={"X-Client-Cert-CN": "   "})
    assert resp.status_code == 401


@pytest.mark.unit
async def test_whitespace_only_cn_returns_401():
    """Tabs and newlines in CN should also resolve to empty after strip."""
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/tools", headers={"X-Client-Cert-CN": "\t\n"})
    assert resp.status_code == 401


@pytest.mark.unit
async def test_cn_with_sql_injection_chars_does_not_crash():
    """
    A CN value containing SQL injection metacharacters must not cause a 500.
    The middleware must accept or reject gracefully — never crash.
    The injected value becomes client_id but RBAC denies based on roles.
    """
    app = _make_app()
    with _patch_load_roles([]):  # no roles → RBAC will deny or pass through to 403
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"X-Client-Cert-CN": "' OR 1=1; DROP TABLE role_assignments; --"},
            )
    # Must not be 500; either 403 (role denied) or 200 (if GET /tools allows empty roles)
    assert resp.status_code in (200, 403, 404)


@pytest.mark.unit
async def test_cn_with_null_byte_handled_gracefully():
    """
    Null bytes in CN must not cause a 500 crash. Defence-in-depth against
    header injection attacks.
    """
    app = _make_app()
    with _patch_load_roles([]):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            # httpx will encode the header; we verify the app doesn't 500
            resp = await c.get(
                "/api/v1/tools",
                headers={"X-Client-Cert-CN": "valid-cn\x00injected"},
            )
    # Null byte in CN must not crash the proxy. With an empty role list the
    # middleware either treats the CN as valid (subject to RBAC → 403) or
    # sanitises/rejects the header (401). 500 is never acceptable.
    assert resp.status_code in (200, 400, 401, 403, 404)


# ---------------------------------------------------------------------------
# Tests: API key auth
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_valid_api_key_bearer_resolves_client():
    """
    A recognised Bearer token (API key) must resolve to client_id and
    allow auth to succeed (subject to RBAC).
    auth_method is set to 'api_key'.
    """
    app = _override_db(_make_app())
    with (
        _patch_resolve_api_key("api-client-001"),
        _patch_load_roles(["readonly"]),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer mcp_validtokenvalue"},
            )
    app.dependency_overrides.clear()
    # readonly role can GET /tools per RBAC matrix — DB is mocked via _patch_load_roles
    # so 500 is not a valid outcome here; the exact expected code is 200.
    assert resp.status_code == 200


@pytest.mark.unit
async def test_unknown_api_key_returns_401():
    """
    A Bearer token that doesn't match any api_keys row (or is revoked)
    must return 401, not 403 or 200.
    """
    app = _make_app()
    with _patch_resolve_api_key(None):  # no client found
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer mcp_unknowntoken"},
            )
    assert resp.status_code == 401
    assert resp.json()["error"] == "unauthenticated"


@pytest.mark.unit
async def test_bearer_prefix_missing_returns_401():
    """
    'Authorization: Token <key>' (wrong scheme) must return 401 — only
    'Bearer' scheme is accepted.
    """
    app = _make_app()
    with _patch_resolve_api_key("api-client-001"):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Token mcp_validkey"},
            )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: mTLS priority over Bearer token
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_cn_wins_when_both_cn_and_bearer_present():
    """
    When X-Client-Cert-CN and Authorization: Bearer are both present,
    mTLS CN must win (auth.py priority order: mTLS → OIDC → API key).
    The API key resolver must NOT be called.
    """
    app = _override_db(_make_app())
    api_key_mock = AsyncMock(return_value="api-client-001")
    roles_mock = AsyncMock(return_value=["agent"])

    with (
        patch("app.middleware.auth._resolve_api_key", api_key_mock),
        patch("app.middleware.auth._load_roles", roles_mock),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={
                    "X-Client-Cert-CN": "test-cert-client",
                    "Authorization": "Bearer mcp_some_api_key",
                },
            )

    app.dependency_overrides.clear()
    # API key resolver must not have been called (mTLS wins at line 86-88)
    api_key_mock.assert_not_awaited()
    # Auth must succeed (client_id set from CN). The "agent" role allows GET /tools
    # → 200. 403 would mean RBAC denied despite the role patch; 500 is not valid
    # when DB and roles are fully mocked. Exact expected code is 200.
    assert resp.status_code == 200


@pytest.mark.unit
async def test_auth_method_set_to_mtls_when_cn_present():
    """
    When CN resolves identity, request.state.auth_method must be 'mtls'.
    We verify indirectly: no API key lookup was made.
    """
    app = _make_app()
    api_key_mock = AsyncMock(return_value=None)

    with (
        patch("app.middleware.auth._resolve_api_key", api_key_mock),
        _patch_load_roles(["admin"]),
    ):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            await c.get("/api/v1/tools", headers={"X-Client-Cert-CN": "mtls-client"})

    api_key_mock.assert_not_awaited()


# ---------------------------------------------------------------------------
# Tests: OIDC JWT handling
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_oidc_disabled_skips_jwt_validation_falls_to_api_key():
    """
    When OIDC_ENABLED=false, a Bearer token must NOT be treated as JWT —
    it falls through to the API key lookup.
    """
    app = _make_app()
    jwt_mock = AsyncMock(return_value=("oidc-subject", ["admin"]))
    api_key_mock = AsyncMock(return_value="api-key-client")

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        patch("app.middleware.auth._validate_oidc_jwt", jwt_mock),
        patch("app.middleware.auth._resolve_api_key", api_key_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = False
        mock_settings.OIDC_ISSUER_URL = ""
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    jwt_mock.assert_not_awaited()
    api_key_mock.assert_awaited_once()


@pytest.mark.unit
async def test_oidc_enabled_valid_jwt_resolves_client():
    """
    When OIDC_ENABLED=true and JWT validates, sub becomes client_id
    and auth_method is 'oidc'. API key lookup must NOT be called.
    """
    app = _make_app()
    api_key_mock = AsyncMock(return_value="should-not-be-called")

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt("oidc-sub-001", ["agent"]),
        patch("app.middleware.auth._resolve_api_key", api_key_mock),
        _patch_load_roles(["agent"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer eyJsome.jwt.token"},
            )

    api_key_mock.assert_not_awaited()


@pytest.mark.unit
async def test_oidc_jwt_invalid_falls_through_to_api_key():
    """
    If OIDC_ENABLED=true but JWT validation fails (returns None), the
    middleware must fall through to the API key check — not immediately 401.
    """
    app = _override_db(_make_app())
    api_key_mock = AsyncMock(return_value="api-fallback-client")

    with (
        patch("app.middleware.auth.settings") as mock_settings,
        _patch_validate_oidc_jwt(None),  # JWT validation fails
        patch("app.middleware.auth._resolve_api_key", api_key_mock),
        _patch_load_roles(["readonly"]),
    ):
        mock_settings.OIDC_ENABLED = True
        mock_settings.OIDC_ISSUER_URL = "http://dex:5556"
        mock_settings.OIDC_AUDIENCE = ""
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
            resp = await c.get(
                "/api/v1/tools",
                headers={"Authorization": "Bearer bad.jwt.token"},
            )

    app.dependency_overrides.clear()
    api_key_mock.assert_awaited_once()
    # JWT failed → fell through to API key → api_key_mock returned a valid client_id
    # → "readonly" role allows GET /tools → 200. With DB and roles fully mocked,
    # 403 or 500 are not valid outcomes here; exact expected code is 200.
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Tests: public paths bypass auth
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_health_endpoint_is_public_no_auth_required():
    """
    GET /health is listed in PUBLIC_PATHS and must respond 200 without any
    auth header. Auth middleware must not return 401.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/health")
    # /health is public — auth middleware must not return 401.
    # With mocked services the expected code is 200; 503 only if a real
    # health dependency check fails. Use in (200, 503) rather than != 401
    # so any future addition of auth to /health causes a test failure.
    assert resp.status_code in (200, 503)


@pytest.mark.unit
async def test_oidc_callback_is_public():
    """
    /api/v1/auth/oidc/callback is a public path; no cert/key needed.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/auth/oidc/callback")
    # /api/v1/auth/oidc/callback is public — must not return 401.
    # Expected codes: 200 (if route exists and stub returns ok), 400/422 (missing
    # OIDC params), 404 (route not wired yet). None of these should be 401.
    assert resp.status_code not in (401,)


@pytest.mark.unit
async def test_well_known_prefix_is_public():
    """
    /.well-known/* paths are public per _PUBLIC_PATH_PREFIXES.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/.well-known/oauth-protected-resource")
    # /.well-known/* is public — must not return 401.
    # Expected: 200 (metadata endpoint) or 404 (if not yet implemented).
    assert resp.status_code in (200, 404)


@pytest.mark.unit
async def test_options_preflight_bypasses_auth():
    """
    OPTIONS requests must bypass auth middleware for CORS preflight.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.options("/api/v1/tools")
    # OPTIONS preflight bypasses auth — must not return 401.
    # Expected: 200 (CORS preflight) or 405 (if OPTIONS not explicitly handled).
    assert resp.status_code in (200, 204, 405)


# ---------------------------------------------------------------------------
# Tests: WWW-Authenticate header on 401
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_401_includes_www_authenticate_header():
    """
    Per RFC 6750 §3.1, 401 responses must include a WWW-Authenticate header
    with realm and resource_metadata pointing to /.well-known/oauth-protected-resource.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/tools")
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers
    assert "Bearer" in resp.headers["WWW-Authenticate"]
    assert "resource_metadata" in resp.headers["WWW-Authenticate"]


@pytest.mark.unit
async def test_401_error_body_is_rfc6750_compliant():
    """
    The error body must have 'error' as a string (OAuth clients check this).
    'error_description' is optional but must be present for debugging.
    """
    app = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as c:
        resp = await c.get("/api/v1/tools")
    body = resp.json()
    assert isinstance(body["error"], str), "RFC 6750 §3.1: error must be a string"
    assert "error_description" in body
    assert "request_id" in body
