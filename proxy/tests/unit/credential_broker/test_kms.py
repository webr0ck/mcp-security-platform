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
    secret_bytes = b"x" * 32  # 256-bit secret (meets the length floor)
    mock_response.json.return_value = {
        "data": {"data": {"master_secret": base64.b64encode(secret_bytes).decode()}}
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

    assert secret == secret_bytes


@pytest.mark.unit
def test_decode_master_secret_rejects_short_hex():
    """A decoded master secret below the 256-bit (32-byte) floor must be
    rejected, not silently HKDF-stretched into a weak KEK (SR-4)."""
    from app.credential_broker.kms import _decode_master_secret, KMSError

    with pytest.raises(KMSError, match="at least 32 bytes"):
        _decode_master_secret("00" * 16)  # 16 bytes — below the floor


@pytest.mark.unit
def test_decode_master_secret_rejects_short_base64():
    """A short base64-encoded master secret must also be rejected."""
    import base64

    from app.credential_broker.kms import _decode_master_secret, KMSError

    short = base64.b64encode(b"too-short-secret").decode()  # 16 bytes
    with pytest.raises(KMSError, match="at least 32 bytes"):
        _decode_master_secret(short)


@pytest.mark.unit
def test_decode_master_secret_accepts_32_byte_hex():
    """A full 256-bit hex secret must decode to exactly 32 bytes."""
    from app.credential_broker.kms import _decode_master_secret

    out = _decode_master_secret("ab" * 32)  # 64 hex chars -> 32 bytes
    assert len(out) == 32


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
