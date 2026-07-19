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
def _default_redis_host() -> str:
    """
    Resolve the right Mac-host-vs-in-container REDIS_HOST default.

    Inside the mcp-proxy container, REDIS_HOST is deliberately left UNSET in
    the container env — compose relies on the app's own Settings default
    ("redis", see app/core/config.py). Historically this function's caller
    used a blanket os.environ.setdefault("REDIS_HOST", "localhost") for Mac-
    host convenience, but setdefault() always wins when the var is unset,
    which silently pointed in-container test runs at the wrong host and
    broke Redis connectivity for in-container integration tests (see the
    now-redundant workaround this used to require in
    tests/integration/test_taint_floor_invoke.py::redis_ready).

    Fix: probe whether "redis" resolves via DNS. If it does, we're on the
    podman/docker network — leave REDIS_HOST unset so the app's own "redis"
    default (or an explicitly-set REDIS_HOST) wins. Only fall back to
    "localhost" when "redis" is unresolvable, i.e. we're really running on
    the Mac host outside the container network.
    """
    import socket

    try:
        socket.getaddrinfo("redis", 6379)
    except OSError:
        return "localhost"
    return "redis"


_SETTINGS_DEFAULTS = {
    # Skip production-startup validation so unit / oracle tests work without
    # a full container stack or real secrets loaded into the shell.
    "ENVIRONMENT": "development",
    "DB_PASSWORD": "test",
    "REDIS_PASSWORD": "test",
    "PROXY_SECRET_KEY": "test",
    "API_KEY_HMAC_KEY": "test",
    "SBOM_SIGNING_KEY": "test",
    "AUDIT_LOG_HMAC_KEY": "test",
    "WEBHOOK_SIGNING_KEY": "test",
    "MINIO_ROOT_USER": "test",
    "MINIO_ROOT_PASSWORD": "test",
    # When running integration tests from the Mac host (outside the podman
    # network), service names like "db", "redis", and "opa" don't resolve via
    # DNS.  The lab compose exposes:
    #   mcp-db    → localhost:5432
    #   mcp-redis → localhost:5678   (non-standard host port)
    #   mcp-opa   → 127.0.0.1:8181
    # These defaults are applied only when the env vars are not already set
    # (i.e. they are no-ops inside a container where DB_HOST=db is already set
    # by docker-compose).
    "DB_HOST": "localhost",
    # REDIS_HOST: see _default_redis_host() — must NOT unconditionally win
    # with "localhost" inside the proxy container.
    "REDIS_HOST": _default_redis_host(),
    "REDIS_PORT": "6379",
    "OPA_HOST": "localhost",
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
