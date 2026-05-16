from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

@pytest.mark.unit
def test_build_auth_url():
    from app.credential_broker.adapters.bitbucket import BitbucketAdapter
    adapter = BitbucketAdapter(
        client_id="bb-cid",
        client_secret="bb-secret",
        redirect_uri="https://gw/auth/callback/bitbucket",
        scopes=["repository:read"],
        auth_url="https://bitbucket.internal/site/oauth2/authorize",
        token_url="https://bitbucket.internal/site/oauth2/access_token",
    )
    url = adapter.build_auth_url(state="state-xyz")
    assert "client_id=bb-cid" in url
    assert "state=state-xyz" in url
    assert "repository%3Aread" in url or "repository:read" in url

@pytest.mark.unit
async def test_exchange_code():
    from app.credential_broker.adapters.bitbucket import BitbucketAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={
        "access_token": "bb-at",
        "refresh_token": "bb-rt",
        "expires_in": 7200,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.credential_broker.adapters.bitbucket.httpx.AsyncClient", return_value=mock_client):
        adapter = BitbucketAdapter(
            client_id="bb-cid", client_secret="bb-secret",
            redirect_uri="https://gw/auth/callback/bitbucket",
            scopes=["repository:read"],
            auth_url="https://bitbucket.internal/site/oauth2/authorize",
            token_url="https://bitbucket.internal/site/oauth2/access_token",
        )
        at, rt, expires = await adapter.exchange_code("code-xyz")

    assert at == "bb-at"
    assert rt == "bb-rt"
