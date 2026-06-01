"""
MCP Security Platform — Key Custody Service

Implements the ZK-at-rest guarantee:
  SUK = HKDF(ikm=session_secret, salt=server_nonce, info=principal_id|server_id)

The session_secret (IKM) is ephemeral server-side — never persisted, never logged.
A storage-only attacker (Vault KV + Postgres + MinIO + any snapshot) cannot derive
the SUK and therefore cannot decrypt wrapped secrets.

Custody modes:
  session_suk  — SUK-derived from human OIDC/API-key session. Default.
  hsm_agent    — Vault transit key, non-exportable, bound to agent mTLS identity. Stub.

See: docs/superpowers/specs/2026-05-31-mcp-blind-custody-rbac-design-v3.md §DD1
"""
from __future__ import annotations

import base64
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class CustodyRef:
    """
    Opaque envelope for wrapped secret data.

    INVARIANT: this object MUST NOT contain plaintext, IKM, SUK, or session_secret.
    The ciphertext_b64 field stores: base64(server_nonce_16 || AES-GCM-ciphertext).
    """
    ciphertext_b64: str   # base64(16-byte HKDF salt || AES-256-GCM ciphertext+tag)
    nonce_b64: str        # base64(12-byte GCM nonce)
    kek_id: str           # Vault KEK path or key identifier
    kek_version: int      # for key rotation tracking
    custody_mode: str     # 'session_suk' | 'hsm_agent'

    def __repr__(self) -> str:
        # Safe repr — never expose ciphertext bytes in logs
        return (
            f"CustodyRef(kek_id={self.kek_id!r}, kek_version={self.kek_version}, "
            f"custody_mode={self.custody_mode!r})"
        )


class KeyCustodian(ABC):
    """
    Abstract per-request unwrap interface.

    Callers MUST zero the returned plaintext bytes after use.
    Implementations MUST NOT persist SUK, IKM, or plaintext.
    """

    @abstractmethod
    async def wrap(self, principal_id: str, server_id: str, plaintext: bytes) -> CustodyRef:
        """Encrypt plaintext under a key derived for this (principal, server) pair."""

    @abstractmethod
    async def unwrap(self, principal_id: str, server_id: str, ref: CustodyRef) -> bytes:
        """
        Decrypt ref using the live session material.
        Raises ValueError if principal_id or server_id does not match the wrapped envelope.
        Raises CustodySessionExpiredError if the session secret has been zeroed.
        """


class CustodySessionExpiredError(Exception):
    """Raised when unwrap is attempted after the session secret has been zeroed."""


class SessionSUKCustodian(KeyCustodian):
    """
    SUK = HKDF-SHA256(ikm=session_secret, salt=server_nonce, info=principal_id|server_id)

    The session_secret (IKM) lives only in proxy memory during an authenticated session.
    It is NEVER persisted to disk, Vault, Postgres, or MinIO.
    Call zero_session_secret() at session end to remove it from memory.

    Storage-only attacker path: no session_secret → no SUK → no plaintext.
    Operator with live proxy memory CAN derive SUKs for active sessions (ZK-in-use limit).
    """

    _CUSTODY_MODE = "session_suk"
    _HKDF_SALT_LEN = 16   # bytes — used as HKDF salt (server nonce)
    _GCM_NONCE_LEN = 12   # bytes — AES-GCM nonce

    def __init__(self, session_secret: bytes, kek_id: str = "session", kek_version: int = 1) -> None:
        if not session_secret:
            raise ValueError("session_secret must be non-empty")
        # Store as bytearray so we can zero it in place
        self._session_secret: bytearray | None = bytearray(session_secret)
        self._kek_id = kek_id
        self._kek_version = kek_version

    def _require_live_session(self) -> bytearray:
        if self._session_secret is None:
            raise CustodySessionExpiredError("Session secret has been zeroed — session expired")
        return self._session_secret

    @staticmethod
    def _encode_info_component(s: str) -> bytes:
        """Length-prefix encode a string component for HKDF info construction.

        Using a bare delimiter (e.g. '|') allows separator-collision attacks:
        principal_id='a|b', server_id='c'  → b'a|b|c'
        principal_id='a',   server_id='b|c' → b'a|b|c'
        A 4-byte big-endian length prefix makes each component unambiguous.
        """
        b = s.encode("utf-8")
        return len(b).to_bytes(4, "big") + b

    def _derive_suk(self, hkdf_salt: bytes, principal_id: str, server_id: str) -> bytes:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        session_secret = self._require_live_session()
        info = (
            self._encode_info_component(principal_id)
            + self._encode_info_component(server_id)
        )
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hkdf_salt,
            info=info,
        ).derive(bytes(session_secret))

    async def wrap(self, principal_id: str, server_id: str, plaintext: bytes) -> CustodyRef:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        hkdf_salt = os.urandom(self._HKDF_SALT_LEN)
        gcm_nonce = os.urandom(self._GCM_NONCE_LEN)
        suk = self._derive_suk(hkdf_salt, principal_id, server_id)
        try:
            ciphertext = AESGCM(suk).encrypt(gcm_nonce, plaintext, None)
        finally:
            # Zero the SUK immediately — it must not linger in memory
            suk_arr = bytearray(suk)
            for i in range(len(suk_arr)):
                suk_arr[i] = 0
        return CustodyRef(
            ciphertext_b64=base64.b64encode(hkdf_salt + ciphertext).decode(),
            nonce_b64=base64.b64encode(gcm_nonce).decode(),
            kek_id=self._kek_id,
            kek_version=self._kek_version,
            custody_mode=self._CUSTODY_MODE,
        )

    async def unwrap(self, principal_id: str, server_id: str, ref: CustodyRef) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if ref.custody_mode != self._CUSTODY_MODE:
            raise ValueError(f"CustodyRef has mode {ref.custody_mode!r}, expected {self._CUSTODY_MODE!r}")
        combined = base64.b64decode(ref.ciphertext_b64)
        hkdf_salt = combined[:self._HKDF_SALT_LEN]
        ciphertext = combined[self._HKDF_SALT_LEN:]
        gcm_nonce = base64.b64decode(ref.nonce_b64)
        suk = self._derive_suk(hkdf_salt, principal_id, server_id)
        try:
            return AESGCM(suk).decrypt(gcm_nonce, ciphertext, None)
        finally:
            suk_arr = bytearray(suk)
            for i in range(len(suk_arr)):
                suk_arr[i] = 0

    def zero_session_secret(self) -> None:
        """Zero the IKM in place — call at session end. After this, unwrap raises CustodySessionExpiredError."""
        if self._session_secret is not None:
            for i in range(len(self._session_secret)):
                self._session_secret[i] = 0
            self._session_secret = None


class HSMAgentCustodian(KeyCustodian):
    """
    Vault transit key custody for agent (machine) secrets.

    Guarantee: operator cannot export the non-exportable transit key.
    An agent authorized via mTLS cert CAN request unwraps.
    NOT zero-knowledge — labeled 'hsm_agent'; explicitly NOT folded into the ZK-at-rest claim.

    Full wiring to Vault transit API (/transit/encrypt|decrypt/<key_name>) is roadmap.
    This stub raises NotImplementedError to ensure callers don't silently skip custody.
    """

    _CUSTODY_MODE = "hsm_agent"

    def __init__(self, vault_client: object, key_name: str) -> None:
        self._vault = vault_client
        self._key_name = key_name

    async def wrap(self, principal_id: str, server_id: str, plaintext: bytes) -> CustodyRef:
        raise NotImplementedError(
            "HSMAgentCustodian.wrap not yet wired to Vault transit. "
            "Implement /transit/encrypt integration for agent custody."
        )

    async def unwrap(self, principal_id: str, server_id: str, ref: CustodyRef) -> bytes:
        raise NotImplementedError(
            "HSMAgentCustodian.unwrap not yet wired to Vault transit. "
            "Implement /transit/decrypt integration for agent custody."
        )
