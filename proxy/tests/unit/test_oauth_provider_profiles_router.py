"""
Unit tests — oauth_provider_profiles.py router (WP-A6 Finding 6).

Covers GET /api/v1/oauth-provider-profiles — the self-service (non-admin)
listing of APPROVED profiles the onboarding wizard/POST /api/v1/servers
caller picks an oauth_provider_profile_id from. Previously only the
admin-gated /api/v1/admin/oauth-provider-profiles listing existed.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

pytestmark = pytest.mark.unit


def _client():
    from app.main import app
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


@pytest.mark.unit
async def test_self_service_listing_requires_authentication():
    async with _client() as c:
        resp = await c.get("/api/v1/oauth-provider-profiles")
    assert resp.status_code == 401


@pytest.mark.unit
async def test_self_service_listing_always_filters_to_approved():
    from app.services import oauth_provider_profile as profile_svc

    calls = {}

    async def _fake_list_profiles(db, *, status=None):
        calls["status"] = status
        return [
            profile_svc.ProfileRow(
                id="p-1", slug="acme", display_name="Acme", provider_type="generic_oauth2",
                injection_mode="external_oauth_user_token", issuer="https://idp.example",
                authorization_endpoint=None, token_endpoint=None, jwks_uri=None, metadata_url=None,
                default_scopes=[], allowed_scopes=[], blocked_scopes=[],
                allowed_redirect_patterns=[], allowed_client_auth_methods=[],
                token_audience_or_resource=None, supports_pkce=True, supports_refresh_token=True,
                supports_client_credentials=False, service_adapter=None, status="approved",
                high_risk_scopes_approved_by=None, created_by="admin@corp", approved_by="admin@corp",
            )
        ]

    with patch("app.routers.oauth_provider_profiles.profile_svc.list_profiles", new=_fake_list_profiles):
        async with _client() as c:
            resp = await c.get(
                "/api/v1/oauth-provider-profiles?status=draft",  # attempted override — must be ignored
                headers={"X-Client-Cert-CN": "alice@corp"},
            )
    assert resp.status_code == 200
    assert calls["status"] == "approved"
    assert resp.json()["profiles"][0]["slug"] == "acme"
