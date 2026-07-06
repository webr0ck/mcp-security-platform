"""
WP-A3 (CR-04 remainder) — GenericOAuthAdapter unit tests.

Covers app.credential_broker.adapters.generic_oauth.GenericOAuthAdapter:
build_auth_url (PKCE), exchange_code, refresh, and the client_auth_method
split (client_secret_post vs client_secret_basic).
"""
from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.adapters.generic_oauth import GenericOAuthAdapter


def _adapter(**overrides) -> GenericOAuthAdapter:
    base = dict(
        client_id="client-abc",
        client_secret="s3cr3t",
        redirect_uri="https://proxy.example.com/auth/callback/my-service",
        scopes=["read:issue", "write:issue"],
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
    )
    base.update(overrides)
    return GenericOAuthAdapter(**base)


def test_scopes_property_returns_configured_scopes():
    """Task-12 live-proof regression: routers/oauth.py's GET /auth/enroll/{service}
    reads adapter.scopes to render the consent page and persist credential_store's
    scopes column. Without a public accessor this silently fell into an
    `except AttributeError` fallback and showed the wrong (Entra) scope list for
    every dynamic external_oauth enrollment — only discoverable by actually
    rendering a real consent page, not a mocked test."""
    adapter = _adapter(scopes=["read:issue", "write:issue"])
    assert adapter.scopes == ["read:issue", "write:issue"]
    # Must be a copy — mutating the returned list must not affect the adapter.
    returned = adapter.scopes
    returned.append("mutated")
    assert adapter.scopes == ["read:issue", "write:issue"]


class TestBuildAuthUrl:
    def test_contains_client_id_and_scopes(self):
        adapter = _adapter()
        url = adapter.build_auth_url(state="state123")
        assert "client_id=client-abc" in url
        assert "state=state123" in url
        assert url.startswith("https://idp.example.com/authorize?")

    def test_pkce_challenge_included_when_provided(self):
        adapter = _adapter()
        url = adapter.build_auth_url(state="s", code_challenge="chal123")
        assert "code_challenge=chal123" in url
        assert "code_challenge_method=S256" in url

    def test_pkce_omitted_when_not_provided(self):
        adapter = _adapter()
        url = adapter.build_auth_url(state="s")
        assert "code_challenge" not in url


class TestClientAuthMethod:
    def test_invalid_client_auth_method_rejected(self):
        with pytest.raises(ValueError):
            _adapter(client_auth_method="totally_invalid")

    def test_client_secret_post_default(self):
        adapter = _adapter()
        kwargs = adapter._auth_kwargs({"grant_type": "authorization_code"})
        assert kwargs["data"]["client_id"] == "client-abc"
        assert kwargs["data"]["client_secret"] == "s3cr3t"
        assert "headers" not in kwargs

    def test_client_secret_basic_uses_header_not_body(self):
        adapter = _adapter(client_auth_method="client_secret_basic")
        kwargs = adapter._auth_kwargs({"grant_type": "authorization_code"})
        assert "client_id" not in kwargs["data"]
        assert "client_secret" not in kwargs["data"]
        expected = base64.b64encode(b"client-abc:s3cr3t").decode()
        assert kwargs["headers"]["Authorization"] == f"Basic {expected}"


@pytest.mark.asyncio
class TestExchangeAndRefresh:
    async def test_exchange_code_returns_tokens(self):
        adapter = _adapter()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600,
        })
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            access, refresh, expires_in = await adapter.exchange_code("auth-code-1")
        assert (access, refresh, expires_in) == ("at-1", "rt-1", 3600)

    async def test_refresh_missing_refresh_token_defaults_empty(self):
        """Some IdPs omit refresh_token on a refresh-grant response when the
        old one is still valid (dex.py's documented defensive pattern)."""
        adapter = _adapter()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={"access_token": "at-2", "expires_in": 1800})
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            access, refresh, expires_in = await adapter.refresh("old-refresh-token")
        assert access == "at-2"
        assert refresh == ""
        assert expires_in == 1800

    async def test_http_error_raises_token_exchange_error_without_body(self):
        import httpx
        from app.credential_broker.adapters.base import TokenExchangeError

        adapter = _adapter()
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("bad", request=MagicMock(), response=mock_resp)
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(TokenExchangeError) as exc_info:
                await adapter.exchange_code("bad-code")
        # CB-010: never surface raw IdP response body text.
        assert "bad-code" not in str(exc_info.value)
        assert exc_info.value.status_code == 400
