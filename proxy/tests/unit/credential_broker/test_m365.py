from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

@pytest.mark.unit
def test_build_auth_url_contains_required_params():
    from app.credential_broker.adapters.m365 import M365Adapter
    adapter = M365Adapter(
        client_id="cid",
        client_secret="csecret",
        tenant_id="tid",
        redirect_uri="https://gw/auth/callback/m365",
        scopes=["Mail.Read"],
        token_url="https://login.microsoftonline.com/tid/oauth2/v2.0/token",
        auth_url="https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
    )
    url = adapter.build_auth_url(state="test-state")
    assert "client_id=cid" in url
    assert "state=test-state" in url
    assert "Mail.Read" in url
    assert "response_type=code" in url

@pytest.mark.unit
async def test_exchange_code_returns_tokens():
    from app.credential_broker.adapters.m365 import M365Adapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={
        "access_token": "at-123",
        "refresh_token": "rt-456",
        "expires_in": 3600,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.credential_broker.adapters.m365.httpx.AsyncClient", return_value=mock_client):
        adapter = M365Adapter(
            client_id="cid", client_secret="csecret", tenant_id="tid",
            redirect_uri="https://gw/auth/callback/m365",
            scopes=["Mail.Read"],
            token_url="https://login.microsoftonline.com/tid/oauth2/v2.0/token",
            auth_url="https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
        )
        at, rt, expires_in = await adapter.exchange_code(code="auth-code-123")

    assert at == "at-123"
    assert rt == "rt-456"
    assert expires_in == 3600

@pytest.mark.unit
async def test_refresh_access_token():
    from app.credential_broker.adapters.m365 import M365Adapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={
        "access_token": "at-new",
        "refresh_token": "rt-new",
        "expires_in": 3600,
    })
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.post = AsyncMock(return_value=mock_resp)

    with patch("app.credential_broker.adapters.m365.httpx.AsyncClient", return_value=mock_client):
        adapter = M365Adapter(
            client_id="cid", client_secret="csecret", tenant_id="tid",
            redirect_uri="https://gw/auth/callback/m365",
            scopes=["Mail.Read"],
            token_url="https://login.microsoftonline.com/tid/oauth2/v2.0/token",
            auth_url="https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
        )
        at, rt, _ = await adapter.refresh(refresh_token="rt-old")

    assert at == "at-new"
    assert rt == "rt-new"
