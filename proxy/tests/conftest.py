"""
MCP Security Platform — Test Configuration and Fixtures

Provides shared fixtures for unit and integration tests.
Unit tests do not require running services.
Integration tests (marked @pytest.mark.integration) require docker compose up.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.fixture
async def async_client():
    """Async test client for async route tests."""
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
    TODO (qa): Replace with proper test API key fixture once auth is implemented.
    """
    return {"X-Client-Cert-CN": "test-admin-client"}


@pytest.fixture
def agent_headers() -> dict:
    """Headers simulating an agent client."""
    return {"X-Client-Cert-CN": "test-agent-client"}


@pytest.fixture
def auditor_headers() -> dict:
    """Headers simulating an auditor client."""
    return {"X-Client-Cert-CN": "test-auditor-client"}
