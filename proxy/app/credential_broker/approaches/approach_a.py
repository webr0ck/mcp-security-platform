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


def encrypt(plaintext: str, user_sub: str, master_secret: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM with a user-derived KEK.
    Returns: nonce(12B) || ciphertext+tag
    """
    kek = _derive_kek(user_sub, master_secret)
    nonce = os.urandom(_NONCE_SIZE)
    ct = AESGCM(kek).encrypt(nonce, plaintext.encode(), None)
    return nonce + ct


def decrypt(blob: bytes, user_sub: str, master_secret: bytes) -> str:
    """
    Decrypt blob produced by encrypt().
    Raises cryptography.exceptions.InvalidTag if user_sub is wrong or blob is tampered.
    """
    kek = _derive_kek(user_sub, master_secret)
    nonce = blob[:_NONCE_SIZE]
    ct = blob[_NONCE_SIZE:]
    return AESGCM(kek).decrypt(nonce, ct, None).decode()
