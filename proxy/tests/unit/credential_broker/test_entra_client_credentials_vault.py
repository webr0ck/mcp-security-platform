"""
Unit Tests — Entra Client Credentials from Vault-Backed Credential Store

Tests that the dispatcher's entra_client_credentials injection mode reads
Entra secrets from the vault-backed credential_store instead of environment
variables, via credential_storage.retrieve_credential().

Run: pytest tests/unit/credential_broker/test_entra_client_credentials_vault.py -v
"""
from __future__ import annotations

import json
import os
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.dispatcher import (
    dispatch_credential_injection,
    CredentialInjectionError,
)


@pytest.mark.unit
@pytest.mark.asyncio
async def test_entra_client_credentials_reads_from_vault():
    """
    Test that entra_client_credentials mode reads Entra secrets from
    credential_store instead of environment variables.

    Setup:
      1. Store entra secret in credential_store via credential_storage.store_credential()
      2. Tool registry has credential_id pointing to that stored secret
      3. Monkeypatch os.environ to NOT have entra secrets (verify we're not reading env)
      4. Call dispatch_credential_injection() with tool that has injection_mode='entra_client_credentials'

    Assert:
      5. Result contains Authorization header with valid Entra token
    """
    # Setup: Store Entra credentials in credential_store
    credential_id = str(uuid.uuid4())
    entra_data = {
        "tenant_id": "12345678-1234-1234-1234-123456789012",
        "client_id": "app-entra-xyz",
        "client_secret": "super-secret-entra-value",
    }
    user_sub = "service-owner"
    service = "entra"
    tool_id = str(uuid.uuid4())

    # Mock Vault KMS client
    mock_vault_client = AsyncMock()
    master_secret = b"0" * 32  # 256-bit master secret
    mock_vault_client.get_master_secret = AsyncMock(return_value=master_secret)

    # Mock database pool/connection
    mock_db_conn = AsyncMock()
    mock_db_pool = AsyncMock()
    mock_db_pool.acquire = MagicMock()
    mock_db_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_db_conn)
    mock_db_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

    # Mock the SELECT for retrieve_credential
    # The encrypted_blob is nonce(12B) + ciphertext
    nonce = b"x" * 12
    ciphertext = b"mock-ciphertext-data"
    encrypted_blob = nonce + ciphertext

    mock_db_conn.fetchrow = AsyncMock(
        return_value={
            "id": credential_id,
            "encrypted_blob": encrypted_blob,
            "user_sub": user_sub,
            "service": service,
            "tool_id": tool_id,
            "owner_type": "service",
        }
    )

    # Tool record with credential_id pointing to the stored secret
    tool_record = {
        "tool_id": tool_id,
        "name": "entra-graph-tool",
        "service_name": "entra",
        "injection_mode": "entra_client_credentials",
        "credential_id": credential_id,
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    # Mock Entra token response
    mock_entra_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock.token"
    mock_entra_response = {
        "access_token": mock_entra_token,
        "expires_in": 3600,
        "token_type": "Bearer",
    }

    # Mock broker_instance with vault_client and db_pool
    mock_broker = AsyncMock()
    mock_broker.vault_client = mock_vault_client
    mock_broker.db_pool = mock_db_pool

    # Monkeypatch os.environ to NOT have Entra secrets
    # (verify we're not reading from environment)
    with patch.dict(
        os.environ,
        {
            "AZURE_TENANT_ID": "",
            "AZURE_CLIENT_ID": "",
            "AZURE_CLIENT_SECRET": "",
            "ENTRA_TENANT_ID": "",
            "ENTRA_CLIENT_ID": "",
            "ENTRA_CLIENT_SECRET": "",
        },
        clear=False,
    ):
        # Mock broker_instance
        with patch("app.services.invocation.broker_instance", mock_broker):
            # Mock retrieve_credential to return the entra_data
            with patch(
                "app.services.credential_storage.retrieve_credential"
            ) as mock_retrieve:
                mock_retrieve.return_value = entra_data

                # Mock the HTTP call to Entra token endpoint
                with patch("httpx.AsyncClient") as mock_http_client_class:
                    mock_response = AsyncMock()
                    mock_response.raise_for_status = MagicMock()
                    mock_response.json = MagicMock(return_value=mock_entra_response)

                    mock_http_client = AsyncMagicMock()
                    mock_http_client.post = AsyncMock(return_value=mock_response)
                    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
                    mock_http_client.__aexit__ = AsyncMock(return_value=False)

                    mock_http_client_class.return_value = mock_http_client

                    # Call the dispatcher
                    result = await dispatch_credential_injection(
                        tool_record=tool_record,
                        client_id="test-client",
                        user_kc_token=None,
                    )

                    # Verify result contains Authorization header with the Entra token
                    assert "Authorization" in result
                    assert result["Authorization"] == f"Bearer {mock_entra_token}"

                    # Verify retrieve_credential was called with the correct credential_id
                    mock_retrieve.assert_called_once()
                    call_kwargs = mock_retrieve.call_args[1]
                    assert call_kwargs["credential_id"] == credential_id
                    assert call_kwargs["user_sub"] == "__service__"
                    assert call_kwargs["service"] == "entra"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_entra_client_credentials_missing_credential_id_fails():
    """
    Test that entra_client_credentials mode fails if credential_id is not
    provided in the tool_record.
    """
    tool_record = {
        "tool_id": str(uuid.uuid4()),
        "name": "entra-graph-tool",
        "injection_mode": "entra_client_credentials",
        # Missing credential_id — should fail
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    # Mock broker_instance to avoid initialization errors
    mock_broker = AsyncMock()
    with patch("app.services.invocation.broker_instance", mock_broker):
        with pytest.raises(CredentialInjectionError) as exc_info:
            await dispatch_credential_injection(
                tool_record=tool_record,
                client_id="test-client",
                user_kc_token=None,
            )

        assert "credential_id" in str(exc_info.value).lower() or "entra" in str(
            exc_info.value
        ).lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_entra_client_credentials_credential_store_not_found_fails():
    """
    Test that entra_client_credentials mode fails gracefully when the
    credential_id is not found in credential_store.
    """
    credential_id = str(uuid.uuid4())
    tool_record = {
        "tool_id": str(uuid.uuid4()),
        "name": "entra-graph-tool",
        "injection_mode": "entra_client_credentials",
        "credential_id": credential_id,
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    # Mock broker_instance
    mock_broker = AsyncMock()
    mock_broker.vault_client = AsyncMock()
    mock_broker.db_pool = AsyncMock()

    with patch("app.services.invocation.broker_instance", mock_broker):
        # Mock retrieve_credential to raise KeyError (credential not found)
        with patch(
            "app.services.credential_storage.retrieve_credential"
        ) as mock_retrieve:
            mock_retrieve.side_effect = KeyError(f"Credential {credential_id} not found")

            with pytest.raises(CredentialInjectionError) as exc_info:
                await dispatch_credential_injection(
                    tool_record=tool_record,
                    client_id="test-client",
                    user_kc_token=None,
                )

            assert "entra" in str(exc_info.value).lower()


class AsyncMagicMock(MagicMock):
    """Helper to mock async context managers."""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def __call__(self, *args, **kwargs):
        return super().__call__(*args, **kwargs)
