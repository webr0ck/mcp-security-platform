from __future__ import annotations

import hmac
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM


def _derive_kek(user_sub: str, master_secret: bytes) -> bytes:
    """Derive per-user Key Encryption Key via HMAC-SHA256."""
    return hmac.new(master_secret, user_sub.encode(), hashlib.sha256).digest()


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
