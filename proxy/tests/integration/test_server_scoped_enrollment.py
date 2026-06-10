"""
Integration tests for server-scoped OAuth enrollment (Task 12).

Task 12 enhances GET /auth/enroll/{service} to resolve the service from
server_registry (if it exists) and use its upstream_idp_config (issuer,
client_id, scopes), falling back to hardcoded adapters (m365/bitbucket/dex)
for backward compatibility.

Invariants under test:
  * Unknown service → 404 (not in registry, not a hardcoded adapter)
  * Known hardcoded service (m365) still works with fallback adapters
  * Backward compatibility maintained
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, MagicMock, patch


def _make_client():
    """Create a test client (matching pattern from test_auth_flows.py)."""
    from app.main import app
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


@pytest.mark.integration
async def test_enroll_unknown_service_returns_404():
    """
    Task 12: GET /auth/enroll/unknown → 404 (server not found in registry
    and not a hardcoded adapter like m365/bitbucket/dex).
    """
    async with _make_client() as c:
        resp = await c.get(
            "/auth/enroll/unknown-nonexistent-service-xyz",
            headers={"X-Client-Cert-CN": "alice@corp"},
            follow_redirects=False,
        )

    assert resp.status_code == 404


@pytest.mark.integration
async def test_enroll_backward_compatible_with_hardcoded_m365_adapter():
    """
    Task 12: Backward compatibility test. Even with registry enhancements,
    hardcoded adapters like m365 should still work (when called with valid
    credentials and mocked adapter).
    """
    # Mock the adapter to avoid needing real Entra credentials
    class _FakeAdapter:
        @property
        def scopes(self):
            return ["Mail.Read", "Calendars.Read"]

        def build_auth_url(self, state: str, code_challenge: str | None = None) -> str:
            return f"https://idp.example/auth?state={state}&code_challenge={code_challenge}"

    fake_redis = MagicMock()
    fake_redis.client = MagicMock()
    fake_redis.client.setex = AsyncMock()

    with patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
         patch("app.core.redis_client.redis_pool", fake_redis):
        async with _make_client() as c:
            resp = await c.get(
                "/auth/enroll/m365",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )

    # Should return 200 HTML consent page
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    assert "text/html" in resp.headers.get("content-type", "")
