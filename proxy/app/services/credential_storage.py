"""
MCP Security Platform — Credential Envelope Storage Service

Implements AES-256-GCM envelope encryption of stored credentials.
Credentials (e.g., Entra client secrets) are encrypted with a KEK from Vault,
persisted with nonce in credential_store, and decrypted on retrieval.

Guarantees:
  - Plaintext never persists to disk
  - Each credential is encrypted with a fresh nonce
  - KEK is derived from Vault at runtime (never stored)
  - Decryption fails if any context metadata has changed (user_sub, service, tool_id, owner_type)

Key processes:
  1. store_credential: fetch KEK → encrypt plaintext → INSERT encrypted_blob + nonce
  2. retrieve_credential: SELECT encrypted_blob + nonce → fetch KEK → decrypt
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from app.credential_broker.kms import envelope_decrypt, envelope_encrypt

logger = logging.getLogger(__name__)


async def store_credential(
    credential_data: dict[str, Any],
    credential_type: str,
    owner_type: str,
    owner_id: str,
    user_sub: str,
    service: str,
    tool_id: str | None,
    vault_client,
    db_pool,
) -> str:
    """
    Store a credential with AES-GCM envelope encryption.

    Args:
        credential_data: plaintext dict (e.g., {"client_id": "...", "client_secret": "..."})
        credential_type: enum value (entra_client_secret, api_key, etc.)
        owner_type: 'service' or 'user'
        owner_id: identifier (user_sub for user mode, tool_id for service mode)
        user_sub: Keycloak subject (for filtering)
        service: service name (entra, github, etc.)
        tool_id: tool UUID if service-owned, None for user-owned
        vault_client: VaultKMSClient instance
        db_pool: asyncpg connection pool

    Returns:
        credential_id (UUID string)

    Raises:
        KMSError: if Vault is unreachable
        Exception: if database insertion fails
    """
    from app.core.config import get_settings

    settings = get_settings()

    # Step 1: Fetch KEK from Vault
    try:
        master_secret = await vault_client.get_master_secret(
            settings.BROKER_MASTER_SECRET_PATH
        )
    except Exception as exc:
        logger.error("Failed to fetch KEK from Vault", extra={"error": str(exc)})
        raise

    # Step 2: Convert credential_data to JSON and encrypt
    plaintext = json.dumps(credential_data)
    nonce, ciphertext = envelope_encrypt(plaintext, master_secret)

    # Step 3: Store in credential_store table
    credential_id = str(uuid.uuid4())
    try:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO credential_store
                    (id, user_sub, service, tool_id, credential_type, owner_type,
                     encrypted_blob, created_at, updated_at)
                VALUES
                    ($1, $2, $3, $4, $5, $6, $7, now(), now())
                """,
                credential_id,
                user_sub,
                service,
                tool_id,
                credential_type,
                owner_type,
                nonce + ciphertext,  # Store nonce || ciphertext
            )
    except Exception as exc:
        logger.error(
            "Failed to store credential in database",
            extra={"credential_id": credential_id, "error": str(exc)},
        )
        raise

    logger.info(
        "Credential stored",
        extra={
            "credential_id": credential_id,
            "credential_type": credential_type,
            "owner_type": owner_type,
            "service": service,
        },
    )

    return credential_id


async def retrieve_credential(
    credential_id: str,
    user_sub: str,
    service: str,
    tool_id: str | None,
    owner_type: str,
    vault_client,
    db_pool,
) -> dict[str, Any]:
    """
    Retrieve and decrypt a stored credential.

    Args:
        credential_id: credential UUID
        user_sub: Keycloak subject
        service: service name
        tool_id: tool UUID if service-owned
        owner_type: 'service' or 'user'
        vault_client: VaultKMSClient instance
        db_pool: asyncpg connection pool

    Returns:
        Decrypted credential dict.

    Raises:
        KeyError: if credential_id not found
        KMSError: if Vault is unreachable
        cryptography.exceptions.InvalidTag: if ciphertext is tampered
    """
    from app.core.config import get_settings

    settings = get_settings()

    # Step 1: Fetch KEK from Vault
    try:
        master_secret = await vault_client.get_master_secret(
            settings.BROKER_MASTER_SECRET_PATH
        )
    except Exception as exc:
        logger.error("Failed to fetch KEK from Vault", extra={"error": str(exc)})
        raise

    # Step 2: Fetch encrypted_blob from database
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT encrypted_blob, user_sub, service, tool_id, owner_type
                FROM credential_store
                WHERE id = $1
                """,
                credential_id,
            )
            if not row:
                raise KeyError(f"Credential {credential_id} not found")
    except KeyError:
        raise
    except Exception as exc:
        logger.error(
            "Failed to fetch credential from database",
            extra={"credential_id": credential_id, "error": str(exc)},
        )
        raise

    encrypted_blob = row["encrypted_blob"]
    retrieved_user_sub = row["user_sub"]
    retrieved_service = row["service"]
    retrieved_tool_id = row["tool_id"]
    retrieved_owner_type = row["owner_type"]

    # Verify context matches (fail-closed if metadata changed)
    if (
        retrieved_user_sub != user_sub
        or retrieved_service != service
        or retrieved_tool_id != tool_id
        or retrieved_owner_type != owner_type
    ):
        logger.warning(
            "Credential context mismatch",
            extra={
                "credential_id": credential_id,
                "expected": {
                    "user_sub": user_sub,
                    "service": service,
                    "tool_id": tool_id,
                    "owner_type": owner_type,
                },
                "retrieved": {
                    "user_sub": retrieved_user_sub,
                    "service": retrieved_service,
                    "tool_id": retrieved_tool_id,
                    "owner_type": retrieved_owner_type,
                },
            },
        )
        raise ValueError(
            "Credential context mismatch; decryption would be insecure"
        )

    # Step 3: Split nonce (first 12 bytes) and ciphertext
    _NONCE_SIZE = 12
    if len(encrypted_blob) < _NONCE_SIZE + 1:
        raise ValueError(
            f"Encrypted blob too short ({len(encrypted_blob)} bytes); "
            f"expected at least {_NONCE_SIZE + 1}"
        )

    nonce = encrypted_blob[:_NONCE_SIZE]
    ciphertext = encrypted_blob[_NONCE_SIZE:]

    # Step 4: Decrypt
    try:
        plaintext = envelope_decrypt(ciphertext, nonce, master_secret)
    except Exception as exc:
        logger.error(
            "Failed to decrypt credential",
            extra={"credential_id": credential_id, "error": str(exc)},
        )
        raise

    # Step 5: Parse JSON back to dict
    try:
        credential_dict = json.loads(plaintext)
    except json.JSONDecodeError as exc:
        logger.error(
            "Failed to parse decrypted credential",
            extra={"credential_id": credential_id, "error": str(exc)},
        )
        raise

    logger.info(
        "Credential retrieved and decrypted",
        extra={"credential_id": credential_id},
    )

    return credential_dict
