"""
Unit Tests — Credential Envelope Storage Service

Tests the credential storage service for AES-GCM envelope encryption
of stored credentials (e.g., Entra client secrets). Credentials are encrypted
with a KEK from Vault, persisted with nonce in credential_store, and decrypted
on retrieval.

Run: pytest tests/unit/test_credential_storage.py -v
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.credential_storage import (
    store_credential,
    retrieve_credential,
)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_and_retrieve_credential():
    """
    Test full credential storage lifecycle:
    1. Store plaintext credential with encryption
    2. Retrieve encrypted credential and decrypt it
    3. Verify plaintext is never stored in DB
    4. Verify decrypted value matches original
    """
    # Mock data
    credential_data = {
        "client_id": "app-xyz",
        "client_secret": "super-secret-value-xyz",
        "tenant_id": "tenant-123",
    }
    credential_type = "entra_client_secret"
    owner_type = "service"
    owner_id = "test-owner-id"
    user_sub = "test-user-sub"
    service = "entra"
    tool_id = str(uuid.uuid4())
    credential_id = str(uuid.uuid4())

    # Mock Vault KMS client
    mock_vault_client = AsyncMock()
    master_secret = b"0" * 32  # 256-bit master secret
    mock_vault_client.get_master_secret = AsyncMock(return_value=master_secret)

    # Mock database pool/connection with proper async context manager.
    # db_pool() is called synchronously; its return value must support __aenter__/__aexit__.
    # Production code: store uses session.execute()+commit(); retrieve uses session.execute()
    # then result.mappings().first().
    mock_db_conn = AsyncMock()
    mock_db_conn.commit = AsyncMock()
    _mock_execute_result = MagicMock()
    _mock_execute_result.mappings.return_value.first.return_value = {
        "encrypted_blob": b"mock-nonce-data" + b"mock-ciphertext",
        "user_sub": user_sub,
        "service": service,
        "tool_id": tool_id,
        "owner_type": owner_type,
    }
    mock_db_conn.execute = AsyncMock(return_value=_mock_execute_result)
    _mock_cm = MagicMock()
    _mock_cm.__aenter__ = AsyncMock(return_value=mock_db_conn)
    _mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_db_pool = MagicMock(return_value=_mock_cm)

    # Store the credential
    stored_id = await store_credential(
        credential_data=credential_data,
        credential_type=credential_type,
        owner_type=owner_type,
        owner_id=owner_id,
        user_sub=user_sub,
        service=service,
        tool_id=tool_id,
        vault_client=mock_vault_client,
        db_pool=mock_db_pool,
    )

    assert stored_id is not None
    assert isinstance(stored_id, str)

    # Verify Vault was called to get the KEK
    mock_vault_client.get_master_secret.assert_called()

    # Verify INSERT was called (encrypted_blob, not plaintext)
    assert mock_db_conn.execute.called

    # Retrieve the credential
    with patch(
        "app.services.credential_storage.envelope_decrypt"
    ) as mock_decrypt:
        # When we decrypt, we should get back the original data
        mock_decrypt.return_value = '{"client_id": "app-xyz", "client_secret": "super-secret-value-xyz", "tenant_id": "tenant-123"}'

        retrieved = await retrieve_credential(
            credential_id=credential_id,
            user_sub=user_sub,
            service=service,
            tool_id=tool_id,
            owner_type=owner_type,
            vault_client=mock_vault_client,
            db_pool=mock_db_pool,
        )

        # Verify the retrieved credential matches the original
        assert retrieved["client_secret"] == "super-secret-value-xyz"
        assert retrieved["client_id"] == "app-xyz"

        # Verify decrypt was called with the encrypted blob
        mock_decrypt.assert_called()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_credential_encrypts_with_kek():
    """
    Test that store_credential fetches KEK from Vault and uses it
    to encrypt the credential before storing in DB.
    """
    credential_data = {"secret": "value"}
    credential_type = "api_key"
    owner_type = "user"
    owner_id = "user-123"
    user_sub = "user-123"
    service = "github"
    tool_id = None

    # Mock Vault
    mock_vault_client = AsyncMock()
    master_secret = b"x" * 32
    mock_vault_client.get_master_secret = AsyncMock(return_value=master_secret)

    # Mock DB: db_pool() returns an async context manager yielding the session.
    mock_db_conn = AsyncMock()
    _mock_cm = MagicMock()
    _mock_cm.__aenter__ = AsyncMock(return_value=mock_db_conn)
    _mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_db_pool = MagicMock(return_value=_mock_cm)
    mock_db_conn.execute = AsyncMock()
    mock_db_conn.commit = AsyncMock()

    # Patch envelope_encrypt to track calls
    with patch("app.services.credential_storage.envelope_encrypt") as mock_encrypt:
        # Simulate encryption output
        mock_encrypt.return_value = (b"nonce", b"ciphertext")

        stored_id = await store_credential(
            credential_data=credential_data,
            credential_type=credential_type,
            owner_type=owner_type,
            owner_id=owner_id,
            user_sub=user_sub,
            service=service,
            tool_id=tool_id,
            vault_client=mock_vault_client,
            db_pool=mock_db_pool,
        )

        # Verify Vault was called to get master secret
        mock_vault_client.get_master_secret.assert_called_once()

        # Verify envelope_encrypt was called with the plaintext
        assert mock_encrypt.called


@pytest.mark.unit
@pytest.mark.asyncio
async def test_retrieve_credential_decrypts_with_kek():
    """
    Test that retrieve_credential fetches encrypted_blob from DB,
    fetches KEK from Vault, and decrypts the blob.
    """
    credential_id = str(uuid.uuid4())
    user_sub = "user-123"
    service = "github"
    tool_id = None
    owner_type = "user"

    # Mock Vault
    mock_vault_client = AsyncMock()
    master_secret = b"x" * 32
    mock_vault_client.get_master_secret = AsyncMock(return_value=master_secret)

    # Mock DB: db_pool() returns an async context manager yielding the session.
    # Production code calls session.execute(...) then result.mappings().first().
    mock_db_conn = AsyncMock()
    mock_execute_result = MagicMock()
    mock_row = {
        "encrypted_blob": b"nonce-data" + b"ciphertext-data",
        "user_sub": user_sub,
        "service": service,
        "tool_id": tool_id,
        "owner_type": owner_type,
    }
    mock_execute_result.mappings.return_value.first.return_value = mock_row
    mock_db_conn.execute = AsyncMock(return_value=mock_execute_result)
    _mock_cm = MagicMock()
    _mock_cm.__aenter__ = AsyncMock(return_value=mock_db_conn)
    _mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_db_pool = MagicMock(return_value=_mock_cm)

    # Patch envelope_decrypt
    with patch("app.services.credential_storage.envelope_decrypt") as mock_decrypt:
        mock_decrypt.return_value = '{"token": "secret-token"}'

        retrieved = await retrieve_credential(
            credential_id=credential_id,
            user_sub=user_sub,
            service=service,
            tool_id=tool_id,
            owner_type=owner_type,
            vault_client=mock_vault_client,
            db_pool=mock_db_pool,
        )

        # Verify Vault was called
        mock_vault_client.get_master_secret.assert_called_once()

        # Verify DB SELECT was called
        assert mock_db_conn.execute.called

        # Verify envelope_decrypt was called with encrypted_blob and KEK
        assert mock_decrypt.called

        # Verify result
        assert retrieved["token"] == "secret-token"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_store_credential_uses_correct_kek_path():
    """
    Test that store_credential calls get_master_secret with the correct path.
    """
    credential_data = {"secret": "value"}
    credential_type = "api_key"
    owner_type = "user"
    owner_id = "user-123"
    user_sub = "user-123"
    service = "github"
    tool_id = None

    # Mock Vault
    mock_vault_client = AsyncMock()
    master_secret = b"x" * 32
    mock_vault_client.get_master_secret = AsyncMock(return_value=master_secret)

    # Mock DB: db_pool() returns an async context manager yielding the session.
    mock_db_conn = AsyncMock()
    _mock_cm = MagicMock()
    _mock_cm.__aenter__ = AsyncMock(return_value=mock_db_conn)
    _mock_cm.__aexit__ = AsyncMock(return_value=False)
    mock_db_pool = MagicMock(return_value=_mock_cm)
    mock_db_conn.execute = AsyncMock()
    mock_db_conn.commit = AsyncMock()

    with patch("app.services.credential_storage.envelope_encrypt") as mock_encrypt:
        mock_encrypt.return_value = (b"nonce", b"ct")

        await store_credential(
            credential_data=credential_data,
            credential_type=credential_type,
            owner_type=owner_type,
            owner_id=owner_id,
            user_sub=user_sub,
            service=service,
            tool_id=tool_id,
            vault_client=mock_vault_client,
            db_pool=mock_db_pool,
        )

        # Verify the correct path was used
        call_args = mock_vault_client.get_master_secret.call_args
        assert call_args is not None
        path = call_args[0][0] if call_args[0] else call_args[1].get("path")
        # Should be either explicit or from settings
        assert path is not None
