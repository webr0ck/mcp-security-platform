"""
Tests for IPRateLimitMiddleware Redis-error behavior (S6 security fix).

Verifies the scoped fail-closed policy:
- Pre-auth paths (_IP_RL_FAIL_CLOSED_PATHS) → 429 when Redis is down
- Authenticated/other paths → fail-open (pass through) when Redis is down
- Exempt paths (_IP_RL_EXEMPT_PATHS) → always pass through, Redis is never called
- Normal flow (Redis available, under limit) → pass through
- Normal flow (Redis available, over limit) → 429
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware.audit import IPRateLimitMiddleware


def _ok(request: Request) -> PlainTextResponse:
    return PlainTextResponse("OK")


def _make_app(limit: int = 100) -> Starlette:
    app = Starlette(
        routes=[
            Route("/oauth/register", _ok),
            Route("/oauth/authorize", _ok),
            Route("/health", _ok),
            Route("/health/ready", _ok),
            Route("/api/v1/tools", _ok),
            Route("/mcp", _ok),
        ]
    )
    app.add_middleware(IPRateLimitMiddleware, limit=limit, window=60)
    return app


def _redis_error_mock() -> MagicMock:
    """Return a mock redis_pool whose pipeline always raises."""
    mock_pool = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline.incr = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(side_effect=Exception("Redis connection refused"))
    mock_pool.rate_limit_client.pipeline.return_value = mock_pipeline
    return mock_pool


def _redis_ok_mock(count: int) -> MagicMock:
    """Return a mock redis_pool that returns `count` as the pipeline result."""
    mock_pool = MagicMock()
    mock_pipeline = MagicMock()
    mock_pipeline.incr = MagicMock()
    mock_pipeline.expire = MagicMock()
    mock_pipeline.execute = AsyncMock(return_value=[count, True])
    mock_pool.rate_limit_client.pipeline.return_value = mock_pipeline
    return mock_pool


# ---------------------------------------------------------------------------
# Test 1: Redis error on pre-auth path → 429 (fail-closed)
# ---------------------------------------------------------------------------

def test_redis_error_preauth_path_returns_429():
    """When Redis is down, /oauth/register must return 429 (fail-closed)."""
    app = _make_app()
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/oauth/register")
    assert resp.status_code == 429
    body = resp.json()
    assert body["error"]["code"] == "RATE_LIMITED"


def test_redis_error_oauth_authorize_returns_429():
    """/oauth/authorize is also a pre-auth path; must be fail-closed."""
    app = _make_app()
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/oauth/authorize")
    assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Test 2: Redis error on authenticated path → pass through (fail-open)
# ---------------------------------------------------------------------------

def test_redis_error_authenticated_path_passes_through():
    """When Redis is down, /api/v1/tools must pass through (fail-open, not 429)."""
    app = _make_app()
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools")
    assert resp.status_code == 200
    assert resp.text == "OK"


def test_redis_error_mcp_path_passes_through():
    """/mcp is not a pre-auth path for global IP RL; must fail-open."""
    app = _make_app()
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/mcp")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test 3: /health is exempt — Redis is never reached, always 200
# ---------------------------------------------------------------------------

def test_health_exempt_when_redis_down():
    """/health must return 200 regardless of Redis state (exempt path)."""
    app = _make_app()
    # Even if redis_pool would raise, /health bypasses the Redis call entirely.
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health")
    assert resp.status_code == 200


def test_health_ready_exempt_when_redis_down():
    """/health/ready must return 200 regardless of Redis state."""
    app = _make_app()
    with patch("app.middleware.audit.redis_pool", _redis_error_mock()):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/health/ready")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test 4: Normal flow — Redis works, request under limit → passes through
# ---------------------------------------------------------------------------

def test_normal_flow_under_limit_passes():
    """When Redis works and count ≤ limit, request passes through."""
    app = _make_app(limit=100)
    with patch("app.middleware.audit.redis_pool", _redis_ok_mock(count=50)):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools")
    assert resp.status_code == 200

    # Also confirm pre-auth path passes when under limit
    with patch("app.middleware.audit.redis_pool", _redis_ok_mock(count=1)):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/oauth/register")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test 5: Normal flow — Redis works, count > limit → 429
# ---------------------------------------------------------------------------

def test_normal_flow_over_limit_returns_429():
    """When Redis works and count > limit, middleware returns 429."""
    app = _make_app(limit=100)
    with patch("app.middleware.audit.redis_pool", _redis_ok_mock(count=101)):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/api/v1/tools")
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "RATE_LIMITED"

    # Also confirm pre-auth path returns 429 over limit
    with patch("app.middleware.audit.redis_pool", _redis_ok_mock(count=200)):
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/oauth/register")
    assert resp.status_code == 429
