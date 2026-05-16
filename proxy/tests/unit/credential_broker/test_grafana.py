from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

def _mock_httpx_client(post_response=None, delete_response=None):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    if post_response:
        mock_client.post = AsyncMock(return_value=post_response)
    if delete_response:
        mock_client.delete = AsyncMock(return_value=delete_response)
    return mock_client

@pytest.mark.unit
async def test_grafana_provision_returns_token():
    from app.credential_broker.adapters.grafana import GrafanaAdapter

    mock_resp = AsyncMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = AsyncMock()
    mock_resp.json = MagicMock(return_value={"id": 42, "key": "glsa_abc123"})

    with patch("app.credential_broker.adapters.grafana.httpx.AsyncClient") as cls:
        cls.return_value = _mock_httpx_client(post_response=mock_resp)
        adapter = GrafanaAdapter(
            base_url="http://grafana:3000",
            service_account_id=1,
            admin_token="admin-token",
        )
        token = await adapter.provision(user_sub="alice@corp", session_id="sess-1")

    assert token.value == "glsa_abc123"
    assert token.token_id == "42"

@pytest.mark.unit
async def test_grafana_revoke_calls_delete():
    from app.credential_broker.adapters.grafana import GrafanaAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = AsyncMock()

    with patch("app.credential_broker.adapters.grafana.httpx.AsyncClient") as cls:
        mock_client = _mock_httpx_client(delete_response=mock_resp)
        cls.return_value = mock_client
        adapter = GrafanaAdapter(
            base_url="http://grafana:3000",
            service_account_id=1,
            admin_token="admin-token",
        )
        await adapter.revoke("42")
        mock_client.delete.assert_awaited_once()
