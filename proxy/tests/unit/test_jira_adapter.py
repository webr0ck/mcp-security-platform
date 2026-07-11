"""
WP-A3 (CR-04 fast-follow, D2 droppable) — Atlassian Jira Cloud OAuth 2.0 3LO
adapter unit tests.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.adapters.jira import JiraAdapter


def _adapter(**overrides) -> JiraAdapter:
    base = dict(
        client_id="jira-client-id",
        client_secret="jira-client-secret",
        redirect_uri="https://proxy.example.com/auth/callback/jira",
        scopes=["read:jira-work", "offline_access"],
    )
    base.update(overrides)
    return JiraAdapter(**base)


class TestBuildAuthUrl:
    def test_uses_atlassian_authorize_endpoint(self):
        adapter = _adapter()
        url = adapter.build_auth_url(state="s1")
        assert url.startswith("https://auth.atlassian.com/authorize?")
        assert "audience=api.atlassian.com" in url
        assert "prompt=consent" in url

    def test_pkce_challenge_included(self):
        adapter = _adapter()
        url = adapter.build_auth_url(state="s1", code_challenge="chal1")
        assert "code_challenge=chal1" in url
        assert "code_challenge_method=S256" in url


class TestRegistration:
    def test_jira_registered_in_adapter_registry(self):
        from app.credential_broker.adapters.registry import get_spec

        spec = get_spec("jira", approach="A")
        assert spec is not None
        assert spec.requires == ("JIRA_OAUTH_CLIENT_ID", "JIRA_OAUTH_CLIENT_SECRET")

    def test_not_configured_when_env_unset(self):
        """Matches every other adapter: absent required settings -> excluded
        from build_adapters(), not a crash."""
        from app.credential_broker.adapters.registry import get_spec

        spec = get_spec("jira", approach="A")
        settings = MagicMock(JIRA_OAUTH_CLIENT_ID="", JIRA_OAUTH_CLIENT_SECRET="")
        assert spec.is_configured(settings) is False


@pytest.mark.asyncio
class TestExchangeAndRefresh:
    async def test_exchange_code_returns_rotated_refresh_token(self):
        """Atlassian rotates refresh tokens on every use — always present,
        unlike Dex's optional field."""
        adapter = _adapter()
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json = MagicMock(return_value={
            "access_token": "at-1", "refresh_token": "rt-rotated", "expires_in": 3600,
        })
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            access, refresh, expires_in = await adapter.exchange_code("auth-code")
        assert (access, refresh, expires_in) == ("at-1", "rt-rotated", 3600)
        # JSON body (not form-encoded) per Atlassian's token endpoint contract.
        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["client_id"] == "jira-client-id"

    async def test_http_error_never_leaks_response_body(self):
        import httpx
        from app.credential_broker.adapters.base import TokenExchangeError

        adapter = _adapter()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("bad", request=MagicMock(), response=mock_resp)
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)
        with patch("httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(TokenExchangeError) as exc_info:
                await adapter.refresh("old-refresh")
        assert exc_info.value.status_code == 401
        assert "old-refresh" not in str(exc_info.value)
