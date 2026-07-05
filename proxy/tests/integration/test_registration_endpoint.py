"""
Integration Tests for POST /api/v1/servers — Self-Service Registration (Task 7)

Tests the server_owner role's ability to register new MCP servers.
Servers land in 'pending' status awaiting admin approval.

INV-001: Every registration emits a synchronous audit event BEFORE response.
"""
from __future__ import annotations

import json
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.services.server_onboarding import InvalidOnboardingConfig


def _make_request(roles=None, client_id="test-owner"):
    """Create a mock request with roles and client_id."""
    req = MagicMock()
    req.state = SimpleNamespace(
        client_roles=list(roles) if roles else [],
        client_id=client_id
    )
    return req


@pytest.fixture(autouse=True)
def _restore_direct_registration_flag():
    """ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN lives on the lru_cache'd
    Settings singleton — restore it after every test so one test flipping it
    doesn't leak into the next."""
    from app.core.config import get_settings
    settings = get_settings()
    original = settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN
    yield
    settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = original


@pytest.mark.asyncio
async def test_server_owner_direct_registration_forbidden_by_default():
    """CR-08: bare server_owner (no admin role) must NOT reach the unscanned
    direct-registration path by default — ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN
    defaults to false, so this is now a 403, not the 201 it used to be."""
    from app.main import app

    with patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["server_owner"])):
        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "new-gitea",
                    "upstream_url": "https://gitea.internal",
                    "injection_mode": "user",
                    "upstream_idp_type": None,
                    "upstream_idp_config": None,
                    "adapter_name": None
                },
                headers={"X-Client-Cert-CN": "owner-123"}
            )

        assert response.status_code == 403


@pytest.mark.asyncio
async def test_server_owner_can_register_server_when_flag_enabled():
    """With ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN=true (e.g. a trusted
    lab), server_owner registration still works: 201, status='pending'."""
    from app.main import app
    from app.core.config import get_settings

    # Setup request context
    request = _make_request(roles=["server_owner"], client_id="owner-123")

    # Mock database for registration
    mock_db = AsyncMock()
    async_session_mock = AsyncMock()

    # Mock the INSERT response
    insert_result = MagicMock()
    insert_result.fetchone.return_value = MagicMock(
        server_id="550e8400-e29b-41d4-a716-446655440000",
        service_name="new-gitea",
        status="pending",
        created_at="2026-06-10T12:00:00Z"
    )

    async_session_mock.execute.return_value = insert_result
    async_session_mock.commit = AsyncMock()

    settings = get_settings()
    original_flag = settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN
    settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = True
    try:
        # Patch AsyncSessionLocal and validation functions
        with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_local, \
             patch("app.routers.server_registry.validate_mode_and_idp") as mock_validate_mode, \
             patch("app.routers.server_registry.validate_upstream_url_ssrf") as mock_validate_url, \
             patch("app.routers.server_registry.validate_upstream_idp_config") as mock_validate_idp_config, \
             patch("app.routers.server_registry._emit_registration_audit") as mock_audit, \
             patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["server_owner"])):

            # Setup mocks
            mock_session_local.return_value.__aenter__.return_value = async_session_mock
            mock_session_local.return_value.__aexit__.return_value = None
            mock_validate_mode.return_value = None
            mock_validate_url.return_value = None
            mock_validate_idp_config.return_value = None
            mock_audit.return_value = None

            # Make the request
            from httpx import ASGITransport, AsyncClient
            async with AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://testserver"
            ) as client:
                response = await client.post(
                    "/api/v1/servers",
                    json={
                        "service_name": "new-gitea",
                        "upstream_url": "https://gitea.internal",
                        "injection_mode": "user",
                        "upstream_idp_type": None,
                        "upstream_idp_config": None,
                        "adapter_name": None
                    },
                    headers={"X-Client-Cert-CN": "owner-123"}
                )

            assert response.status_code == 201
            body = response.json()
            assert body["server_id"]
            assert body["service_name"] == "new-gitea"
            assert body["status"] == "pending"
    finally:
        settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = original_flag


@pytest.mark.asyncio
async def test_register_requires_server_owner_role():
    """Without server_owner role, register → 403."""
    from app.main import app
    from httpx import ASGITransport, AsyncClient

    with patch("app.routers.server_registry.AsyncSessionLocal"), \
         patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["user"])):

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "new-gitea",
                    "upstream_url": "https://gitea.internal",
                    "injection_mode": "user"
                },
                headers={"X-Client-Cert-CN": "user-456"}
            )

        # Should be 403 Forbidden (RBAC rejection)
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_register_validates_mode_idp():
    """Invalid mode↔IdP combo → 400. Needs the direct-registration flag on so
    server_owner reaches this validation instead of the CR-08 403 gate."""
    from app.routers.server_registry import router
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.config import get_settings
    from app.services.server_onboarding import InvalidOnboardingConfig

    request = _make_request(roles=["server_owner"], client_id="owner-123")
    settings = get_settings()
    settings.ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = True

    with patch("app.routers.server_registry.AsyncSessionLocal"), \
         patch("app.routers.server_registry.validate_mode_and_idp") as mock_validate_mode, \
         patch("app.routers.server_registry.validate_upstream_url_ssrf"), \
         patch("app.routers.server_registry.validate_upstream_idp_config"), \
         patch("app.routers.server_registry._emit_registration_audit"), \
         patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["server_owner"])):

        # Make validation fail
        mock_validate_mode.side_effect = InvalidOnboardingConfig(
            "injection_mode='oauth_user_token' requires upstream_idp_type='gateway_idp'"
        )

        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "bad-config",
                    "upstream_url": "https://gitea.internal",
                    "injection_mode": "oauth_user_token",
                    "upstream_idp_type": "entra",  # Wrong!
                    "upstream_idp_config": None
                },
                headers={"X-Client-Cert-CN": "owner-123"}
            )

        assert response.status_code == 400
        body = response.json()
        assert "detail" in body


@pytest.mark.asyncio
async def test_register_validates_ssrf():
    """SSRF URL → 400. Needs the direct-registration flag on so server_owner
    reaches this validation instead of the CR-08 403 gate."""
    from app.routers.server_registry import router
    from fastapi.testclient import TestClient
    from app.main import app
    from app.core.config import get_settings
    from app.services.server_onboarding import InvalidOnboardingConfig

    request = _make_request(roles=["server_owner"], client_id="owner-123")
    get_settings().ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = True

    with patch("app.routers.server_registry.AsyncSessionLocal"), \
         patch("app.routers.server_registry.validate_mode_and_idp"), \
         patch("app.routers.server_registry.validate_upstream_url_ssrf") as mock_validate_url, \
         patch("app.routers.server_registry.validate_upstream_idp_config"), \
         patch("app.routers.server_registry._emit_registration_audit"), \
         patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["server_owner"])):

        # Make SSRF validation fail
        mock_validate_url.side_effect = InvalidOnboardingConfig(
            "Hostname '127.0.0.1' is a blocked private/reserved IP address"
        )

        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "localhost-server",
                    "upstream_url": "https://127.0.0.1:9000",
                    "injection_mode": "user"
                },
                headers={"X-Client-Cert-CN": "owner-123"}
            )

        assert response.status_code == 400
        body = response.json()
        assert "detail" in body


@pytest.mark.asyncio
async def test_register_audited_before_response():
    """Audit event exists before 201 returned (INV-001). Needs the
    direct-registration flag on so server_owner reaches this code path
    instead of the CR-08 403 gate."""
    from app.routers.server_registry import router
    from app.main import app
    from app.core.config import get_settings

    request = _make_request(roles=["server_owner"], client_id="owner-123")
    get_settings().ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN = True

    # Track call order
    call_order = []

    async def mock_emit_audit(*args, **kwargs):
        call_order.append("audit")

    async def mock_execute(*args, **kwargs):
        # Verify audit was called before DB INSERT
        assert "audit" in call_order, "Audit must be called before DB operations"
        call_order.append("insert")
        result = MagicMock()
        result.fetchone.return_value = MagicMock(
            server_id="550e8400-e29b-41d4-a716-446655440000",
            service_name="new-gitea",
            status="pending"
        )
        return result

    mock_db = AsyncMock()
    mock_db.execute = mock_execute
    mock_db.commit = AsyncMock()

    with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_local, \
         patch("app.routers.server_registry.validate_mode_and_idp"), \
         patch("app.routers.server_registry.validate_upstream_url_ssrf"), \
         patch("app.routers.server_registry.validate_upstream_idp_config"), \
         patch("app.routers.server_registry._emit_registration_audit", side_effect=mock_emit_audit), \
         patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["server_owner"])):

        mock_session_local.return_value.__aenter__.return_value = mock_db
        mock_session_local.return_value.__aexit__.return_value = None

        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "new-gitea",
                    "upstream_url": "https://gitea.internal",
                    "injection_mode": "user"
                },
                headers={"X-Client-Cert-CN": "owner-123"}
            )

        assert response.status_code == 201
        assert call_order == ["audit", "insert"]


@pytest.mark.asyncio
async def test_platform_admin_can_also_register():
    """As platform_admin, register server → 201."""
    from app.routers.server_registry import router
    from app.main import app

    mock_db = AsyncMock()
    insert_result = MagicMock()
    insert_result.fetchone.return_value = MagicMock(
        server_id="550e8400-e29b-41d4-a716-446655440000",
        service_name="admin-created",
        status="pending"
    )

    mock_db.execute.return_value = insert_result
    mock_db.commit = AsyncMock()

    with patch("app.routers.server_registry.AsyncSessionLocal") as mock_session_local, \
         patch("app.routers.server_registry.validate_mode_and_idp"), \
         patch("app.routers.server_registry.validate_upstream_url_ssrf"), \
         patch("app.routers.server_registry.validate_upstream_idp_config"), \
         patch("app.routers.server_registry._emit_registration_audit"), \
         patch("app.middleware.auth._load_roles", new=AsyncMock(return_value=["platform_admin"])):

        mock_session_local.return_value.__aenter__.return_value = mock_db
        mock_session_local.return_value.__aexit__.return_value = None

        from httpx import ASGITransport, AsyncClient
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver"
        ) as client:
            response = await client.post(
                "/api/v1/servers",
                json={
                    "service_name": "admin-created",
                    "upstream_url": "https://admin-server.internal",
                    "injection_mode": "service"
                },
                headers={"X-Client-Cert-CN": "admin-001"}
            )

        assert response.status_code == 201
