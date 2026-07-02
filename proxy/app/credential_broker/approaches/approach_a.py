from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12   # 96-bit nonce for AES-GCM
_KEK_SIZE = 32    # 256-bit KEK for AES-256-GCM
_SALT_SIZE = 32   # 256-bit random salt prepended to every blob (CB-F002)
# Domain-separation prefix; bumped to v2 because the on-disk blob format changed
# (salt prepended) — v1 blobs lack the salt prefix and are now unreadable.
# CB-F002: old v1 blobs stored with salt=None are intentionally not migrated;
# the lab seeder re-encrypts on startup so this breakage is acceptable.
_HKDF_INFO_PREFIX = b"mcp-credential-broker-kek-v2:"
# AAD prefix; binds ciphertext to its row context so blobs cannot be moved
# between rows to cause credential confusion (FIND-010 fix).
_AAD_PREFIX = "mcp-cred-v2"


def _derive_kek(user_sub: str, master_secret: bytes, salt: bytes) -> bytearray:
    """
    CB-007 / CB-F002: derive the per-user Key Encryption Key with HKDF-SHA256
    (RFC 5869) with a per-derivation random salt. The user identity is bound
    into the HKDF `info` for domain separation. Salt is caller-supplied so that
    encrypt() generates it fresh each call and decrypt() reads it back from the blob.

    Returns a bytearray so callers can zero it in a finally block (CB-F004).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEK_SIZE,
        salt=salt,
        info=_HKDF_INFO_PREFIX + user_sub.encode(),
    )
    return bytearray(hkdf.derive(master_secret))


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

    CB-F002: a fresh random salt is generated per-call and prepended to the blob.
    Stored format: salt(32B) || nonce(12B) || ciphertext+tag
    """
    salt = os.urandom(_SALT_SIZE)
    kek = _derive_kek(user_sub, master_secret, salt)
    try:
        nonce = os.urandom(_NONCE_SIZE)
        aad = _make_aad(user_sub, service, tool_id, owner_type)
        ct = AESGCM(bytes(kek)).encrypt(nonce, plaintext.encode(), aad)
        return salt + nonce + ct
    finally:
        # CB-F004: best-effort zero of the derived KEK (bytearray is mutable)
        for i in range(len(kek)):
            kek[i] = 0


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

    CB-F002: reads the per-derivation salt from the first 32 bytes of the blob.
    Expected format: salt(32B) || nonce(12B) || ciphertext+tag

    Raises cryptography.exceptions.InvalidTag if user_sub, service, tool_id, owner_type,
    or the ciphertext itself is wrong or tampered. Raises ValueError for truncated blobs.
    """
    min_size = _SALT_SIZE + _NONCE_SIZE + 1
    if len(blob) < min_size:
        raise ValueError(
            f"Credential blob too short ({len(blob)} bytes); expected at least {min_size}. "
            "This may be a v1 blob (pre-CB-F002 salt format); re-enrolment required."
        )
    salt = blob[:_SALT_SIZE]
    nonce = blob[_SALT_SIZE : _SALT_SIZE + _NONCE_SIZE]
    ct = blob[_SALT_SIZE + _NONCE_SIZE :]
    kek = _derive_kek(user_sub, master_secret, salt)
    try:
        aad = _make_aad(user_sub, service, tool_id, owner_type)
        return AESGCM(bytes(kek)).decrypt(nonce, ct, aad).decode()
    finally:
        # CB-F004: best-effort zero of the derived KEK
        for i in range(len(kek)):
            kek[i] = 0


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
    from app.credential_broker.kms import load_master_secret_standalone

    try:
        master = await load_master_secret_standalone()
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
        # A row WAS found (row is not None here) but decryption failed. This is
        # almost always master-secret drift (the blob was encrypted under a master
        # the broker no longer loads) or tampering — NOT a missing credential.
        # Say so explicitly: the caller collapses None into "not provisioned",
        # which sent a prior acceptance-test run on a 30-min goose chase (USR-04).
        import logging
        logging.getLogger(__name__).error(
            "Credential row FOUND for %s/%s (owner=%s) but decryption FAILED (%s: %s) — "
            "likely broker master-secret drift or tampering; re-enroll this credential.",
            user_sub, service, owner_type, type(exc).__name__, exc,
        )
        return None
