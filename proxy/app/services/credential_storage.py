"""
MCP Security Platform — Credential Envelope Storage Service

Implements AES-256-GCM encryption of stored credentials using the SAME codec
as every other credential_store writer/reader (approach_a: salt || nonce ||
ciphertext, HKDF-derived KEK, AAD bound to user_sub/service/tool_id/owner_type).

One-codec invariant (credential write/read interop fix): admin_credentials,
oauth, oidc_browser, portal and broker all use approach_a.encrypt/decrypt.
This module previously used a private nonce||ciphertext envelope, so anything
written by the admin path failed with InvalidTag when read here. Do NOT
reintroduce a second ciphertext format.

Guarantees:
  - Plaintext never persists to disk
  - Each credential is encrypted with a fresh salt + nonce
  - KEK is HKDF-derived from the Vault master secret at runtime (never stored)
  - Decryption fails if any context metadata has changed (user_sub, service, tool_id, owner_type)

Key processes:
  1. store_credential: fetch master secret → approach_a.encrypt → INSERT encrypted_blob
  2. retrieve_credential: SELECT encrypted_blob → fetch master secret → approach_a.decrypt
"""
from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from app.credential_broker.approaches.approach_a import (
    decrypt as approach_a_decrypt,
    encrypt as approach_a_encrypt,
)

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

    # Step 2: Convert credential_data to JSON and encrypt with the shared
    # approach_a codec so retrieve_credential AND the broker paths can read it.
    plaintext = json.dumps(credential_data)
    blob = approach_a_encrypt(
        plaintext,
        user_sub,
        master_secret,
        service=service,
        tool_id=str(tool_id) if tool_id is not None else None,
        owner_type=owner_type,
    )

    # Step 3: Store in credential_store table
    credential_id = str(uuid.uuid4())
    try:
        from sqlalchemy import text
        async with db_pool() as session:
            await session.execute(
                text("""
                    INSERT INTO credential_store
                        (id, user_sub, service, tool_id, credential_type, owner_type,
                         encrypted_blob, created_at, updated_at)
                    VALUES
                        (:id, :sub, :svc, :tid, :ctype, :otype, :blob, now(), now())
                """),
                {
                    "id": credential_id,
                    "sub": user_sub,
                    "svc": service,
                    "tid": tool_id,
                    "ctype": credential_type,
                    "otype": owner_type,
                    "blob": blob,  # approach_a format: salt || nonce || ciphertext+tag
                },
            )
            await session.commit()
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
        from sqlalchemy import text
        async with db_pool() as session:
            result = await session.execute(
                text("""
                    SELECT encrypted_blob, user_sub, service, tool_id, owner_type
                    FROM credential_store
                    WHERE id = :cid
                """),
                {"cid": credential_id},
            )
            row = result.mappings().first()
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
    retrieved_tool_id = str(row["tool_id"]) if row["tool_id"] is not None else None
    retrieved_owner_type = row["owner_type"]

    # Verify context matches (fail-closed if metadata changed)
    if (
        retrieved_user_sub != user_sub
        or retrieved_service != service
        or retrieved_tool_id != (str(tool_id) if tool_id is not None else None)
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

    # Step 3+4: Decrypt with the shared approach_a codec (salt || nonce || ct).
    # The AAD binds decryption to the same context tuple used at write time,
    # so a wrong user_sub/service/tool_id/owner_type raises InvalidTag.
    try:
        plaintext = approach_a_decrypt(
            bytes(encrypted_blob),
            user_sub,
            master_secret,
            service=service,
            tool_id=str(tool_id) if tool_id is not None else None,
            owner_type=owner_type,
        )
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
