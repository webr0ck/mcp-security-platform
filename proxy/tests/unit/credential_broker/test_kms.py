from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.unit
async def test_get_master_secret_calls_vault():
    from app.credential_broker.kms import VaultKMSClient
    import base64

    # httpx.Response.json() and raise_for_status() are synchronous — use MagicMock
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"data": {"master_secret": base64.b64encode(b"test-secret").decode()}}
    }
    mock_response.raise_for_status = MagicMock()

    with patch("app.credential_broker.kms.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_client

        client = VaultKMSClient(addr="http://vault:8200", token="dev-root-token")
        secret = await client.get_master_secret("secret/data/credential-broker")

    assert secret == b"test-secret"


@pytest.mark.unit
async def test_get_master_secret_raises_on_vault_error():
    from app.credential_broker.kms import VaultKMSClient, KMSError
    import httpx

    with patch("app.credential_broker.kms.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("refused"))
        mock_client_cls.return_value = mock_client

        client = VaultKMSClient(addr="http://vault:8200", token="dev-root-token")
        with pytest.raises(KMSError, match="Vault unreachable"):
            await client.get_master_secret("secret/data/credential-broker")
