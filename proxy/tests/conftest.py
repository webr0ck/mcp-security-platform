"""
MCP Security Platform — Test Configuration and Fixtures

Provides shared fixtures for unit and integration tests.
Unit tests do not require running services.
Integration tests (marked @pytest.mark.integration) require docker compose up.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from httpx import AsyncClient, ASGITransport

# Ensure Settings validation succeeds in the test process even when
# docker-compose env vars (DB_PASSWORD etc.) are not injected into the shell.
# Tests that run against a real server send HTTP requests to localhost:8000
# and never use these credentials directly; they are only needed to satisfy
# pydantic-settings validation when importing the app.
_SETTINGS_DEFAULTS = {
    "DB_PASSWORD": "test",
    "REDIS_PASSWORD": "test",
    "PROXY_SECRET_KEY": "test",
    "API_KEY_HMAC_KEY": "test",
    "SBOM_SIGNING_KEY": "test",
    "AUDIT_LOG_HMAC_KEY": "test",
    "WEBHOOK_SIGNING_KEY": "test",
    "MINIO_ROOT_USER": "test",
    "MINIO_ROOT_PASSWORD": "test",
}
for _k, _v in _SETTINGS_DEFAULTS.items():
    os.environ.setdefault(_k, _v)


def _load_gw_secret() -> str:
    """Read GATEWAY_SHARED_SECRET from app settings (loaded from proxy/.env)."""
    try:
        from app.core.config import settings
        return settings.GATEWAY_SHARED_SECRET
    except Exception:
        return ""


_GW_SECRET = _load_gw_secret()


@pytest.fixture(autouse=True)
def _trust_proxy_for_tests(request):
    """
    Auto-patch _is_trusted_proxy to return True for all in-process ASGI tests.

    RT-NEW-005: production requires X-Gateway-Secret from Nginx. Tests that use
    ASGITransport bypass Nginx entirely and cannot provide a real gateway header.
    This fixture restores the pre-RT-NEW-005 behaviour for the test suite without
    weakening the production check.

    Tests that connect to a real server (localhost:8000) are unaffected — the patch
    only applies to the in-process Python interpreter, not external containers.
    """
    with patch("app.middleware.auth._is_trusted_proxy", return_value=True):
        yield


@pytest.fixture
async def async_client():
    """Async test client for async route tests."""
    from app.main import app  # lazy: avoids Settings validation in unit tests
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


@pytest.fixture
def admin_headers() -> dict:
    """
    HTTP headers simulating an admin client via mTLS cert CN.
    The gateway injects X-Client-Cert-CN; we simulate it here.
    """
    return {"X-Client-Cert-CN": "test-admin-client", "X-Gateway-Secret": _GW_SECRET}


@pytest.fixture
def agent_headers() -> dict:
    """Headers simulating an agent client."""
    return {"X-Client-Cert-CN": "test-agent-client", "X-Gateway-Secret": _GW_SECRET}


@pytest.fixture
def auditor_headers() -> dict:
    """Headers simulating an auditor client."""
    return {"X-Client-Cert-CN": "test-auditor-client", "X-Gateway-Secret": _GW_SECRET}
