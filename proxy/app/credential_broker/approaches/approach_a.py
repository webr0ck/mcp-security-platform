from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
_KEK_SIZE = 32  # 256-bit KEK for AES-256-GCM
# Domain-separation prefix; bump the version suffix if the KDF construction
# ever changes so old and new KEKs can never collide.
_HKDF_INFO_PREFIX = b"mcp-credential-broker-kek-v1:"
# AAD prefix; binds ciphertext to its row context so blobs cannot be moved
# between rows to cause credential confusion (FIND-010 fix).
_AAD_PREFIX = "mcp-cred-v1"


def _derive_kek(user_sub: str, master_secret: bytes) -> bytes:
    """
    CB-007: derive the per-user Key Encryption Key with HKDF-SHA256
    (RFC 5869) instead of a single-round HMAC. The user identity is bound
    into the HKDF `info` for domain separation, so a leaked master secret
    cannot be turned into a per-user KEK with one trivial HMAC call.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEK_SIZE,
        salt=None,
        info=_HKDF_INFO_PREFIX + user_sub.encode(),
    )
    return hkdf.derive(master_secret)


def _make_aad(user_sub: str, service: str, tool_id: str | None, owner_type: str) -> bytes:
    """
    Canonical AAD binding ciphertext to its credential_store row context.
    Prevents blob-swapping attacks: decryption succeeds only when all four
    context fields match the values used at encryption time (FIND-010).
    """
    return f"{_AAD_PREFIX}|{user_sub}|{service}|{tool_id or ''}|{owner_type}".encode()


def encrypt(
    plaintext: str,
    user_sub: str,
    master_secret: bytes,
    *,
    service: str = "",
    tool_id: str | None = None,
    owner_type: str = "user",
) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM with a user-derived KEK.
    AAD binds the ciphertext to its row context (user_sub, service, tool_id, owner_type).
    Returns: nonce(12B) || ciphertext+tag
    """
    kek = _derive_kek(user_sub, master_secret)
    nonce = os.urandom(_NONCE_SIZE)
    aad = _make_aad(user_sub, service, tool_id, owner_type)
    ct = AESGCM(kek).encrypt(nonce, plaintext.encode(), aad)
    return nonce + ct


def decrypt(
    blob: bytes,
    user_sub: str,
    master_secret: bytes,
    *,
    service: str = "",
    tool_id: str | None = None,
    owner_type: str = "user",
) -> str:
    """
    Decrypt blob produced by encrypt().
    Raises cryptography.exceptions.InvalidTag if user_sub, service, tool_id, owner_type,
    or the ciphertext itself is wrong or tampered.
    """
    kek = _derive_kek(user_sub, master_secret)
    nonce = blob[:_NONCE_SIZE]
    ct = blob[_NONCE_SIZE:]
    aad = _make_aad(user_sub, service, tool_id, owner_type)
    return AESGCM(kek).decrypt(nonce, ct, aad).decode()


async def decrypt_credential(
    user_sub: str,
    service: str,
    tool_id: str | None = None,
    owner_type: str = "user",
) -> str | None:
    """
    Fetch and decrypt a credential from credential_store.

    For owner_type='service': looks up by tool_id + service (ignores user_sub).
    For owner_type='user': looks up by user_sub + service (original behaviour).

    Returns plaintext string or None if not found/decryption fails.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.credential_broker.broker import _load_master_secret  # type: ignore[attr-defined]

    try:
        master = await _load_master_secret()
    except Exception:
        return None

    try:
        async with AsyncSessionLocal() as session:
            if owner_type == "service" and tool_id:
                result = await session.execute(
                    text(
                        "SELECT encrypted_blob, user_sub FROM credential_store "
                        "WHERE owner_type = 'service' AND tool_id = :tool_id AND service = :svc "
                        "LIMIT 1"
                    ),
                    {"tool_id": str(tool_id), "svc": service},
                )
            else:
                result = await session.execute(
                    text(
                        "SELECT encrypted_blob, user_sub FROM credential_store "
                        "WHERE user_sub = :sub AND service = :svc "
                        "AND (owner_type = 'user' OR owner_type IS NULL) "
                        "LIMIT 1"
                    ),
                    {"sub": user_sub, "svc": service},
                )
            row = result.fetchone()
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("DB error in decrypt_credential: %s", exc)
        return None

    if row is None:
        return None

    try:
        # For service-mode rows the encryption key is derived from the stored user_sub
        # (which is "__service__" or a domain-specific sentinel set at enrolment time)
        kek_sub = row.user_sub or user_sub
        return decrypt(
            bytes(row.encrypted_blob),
            kek_sub,
            master,
            service=service,
            tool_id=tool_id,
            owner_type=owner_type,
        )
    except Exception as exc:
        import logging
        logging.getLogger(__name__).error("Decryption failed for %s/%s: %s", user_sub, service, exc)
        return None
