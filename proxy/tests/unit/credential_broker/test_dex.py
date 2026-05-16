from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.unit
def test_dex_build_auth_url():
    from app.credential_broker.adapters.dex import DexAdapter

    adapter = DexAdapter(
        issuer_url="http://localhost:5556/dex",
        client_id="mcp-proxy",
        client_secret="mcp-proxy-secret",
        redirect_uri="http://localhost:8000/auth/callback/dex",
        scopes=["openid", "profile", "email", "offline_access"],
    )
    url = adapter.build_auth_url(state="test-state")

    assert "client_id=mcp-proxy" in url
    assert "response_type=code" in url
    assert "redirect_uri" in url
    assert "state=test-state" in url


@pytest.mark.unit
async def test_dex_exchange_code():
    from app.credential_broker.adapters.dex import DexAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={
        "access_token": "dex-at-123",
        "refresh_token": "dex-rt-456",
        "expires_in": 3600,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.credential_broker.adapters.dex.httpx.AsyncClient", return_value=mock_client):
        adapter = DexAdapter(
            issuer_url="http://localhost:5556/dex",
            client_id="mcp-proxy",
            client_secret="mcp-proxy-secret",
            redirect_uri="http://localhost:8000/auth/callback/dex",
            scopes=["openid", "profile"],
        )
        at, rt, expires_in = await adapter.exchange_code(code="auth-code-abc")

    assert at == "dex-at-123"
    assert rt == "dex-rt-456"
    assert expires_in == 3600

    # Verify the correct grant_type was sent
    call_kwargs = mock_client.post.call_args
    sent_data = call_kwargs.kwargs.get("data") or call_kwargs.args[1] if len(call_kwargs.args) > 1 else call_kwargs.kwargs.get("data", {})
    # post was called with data= keyword
    assert mock_client.post.called
    posted_data = mock_client.post.call_args[1].get("data") or mock_client.post.call_args[0][1]
    assert posted_data["grant_type"] == "authorization_code"
    assert posted_data["code"] == "auth-code-abc"


@pytest.mark.unit
async def test_dex_refresh():
    from app.credential_broker.adapters.dex import DexAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={
        "access_token": "dex-at-new",
        "refresh_token": "dex-rt-new",
        "expires_in": 3600,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.credential_broker.adapters.dex.httpx.AsyncClient", return_value=mock_client):
        adapter = DexAdapter(
            issuer_url="http://localhost:5556/dex",
            client_id="mcp-proxy",
            client_secret="mcp-proxy-secret",
            redirect_uri="http://localhost:8000/auth/callback/dex",
            scopes=["openid", "profile"],
        )
        at, rt, _ = await adapter.refresh(refresh_token="dex-rt-old")

    assert at == "dex-at-new"
    assert rt == "dex-rt-new"

    posted_data = mock_client.post.call_args[1].get("data") or mock_client.post.call_args[0][1]
    assert posted_data["grant_type"] == "refresh_token"
    assert posted_data["refresh_token"] == "dex-rt-old"
