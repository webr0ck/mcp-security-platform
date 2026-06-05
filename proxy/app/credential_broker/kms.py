from __future__ import annotations

import base64
import logging
import re

import httpx

logger = logging.getLogger(__name__)


class KMSError(Exception):
    """Raised when Vault is unreachable or returns an error."""


def _decode_master_secret(encoded: str) -> bytes:
    """Decode the stored master secret to raw bytes.

    Lab seeders write it as HEX (``openssl rand -hex 32`` / ``os.urandom(32).hex()``
    → 64 hex chars). The earlier code base64-decoded that, mangling 32 bytes of
    entropy into ~48 garbage bytes (so the "256-bit master key" claim was false).
    Decode hex when the value is unambiguously hex (even length, all hex digits);
    otherwise fall back to base64 for deployments that stored a base64 value.
    """
    s = encoded.strip()
    if len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return bytes.fromhex(s)
    return base64.b64decode(s)


class VaultKMSClient:
    def __init__(self, addr: str, token: str, ca_bundle: str | None = None) -> None:
        self._addr = addr
        self._headers = {"X-Vault-Token": token}
        # CB-009: explicitly verify the Vault TLS certificate. A non-empty
        # ca_bundle pins verification to that bundle; otherwise use the system
        # trust store (httpx default). Verification is never disabled.
        self._verify: str | bool = ca_bundle if ca_bundle else True

    async def get_master_secret(self, path: str) -> bytes:
        """
        Fetch master_secret from Vault KV v2.
        path format: "secret/data/<key-name>"
        Returns raw bytes (base64-decoded from Vault value).
        Raises KMSError on any failure.
        """
        url = f"{self._addr}/v1/{path}"
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=self._verify) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise KMSError(f"Vault unreachable: {exc}") from exc

        try:
            encoded = resp.json()["data"]["data"]["master_secret"]
            return _decode_master_secret(encoded)
        except (KeyError, ValueError) as exc:
            raise KMSError(f"Unexpected Vault response structure: {exc}") from exc


async def load_master_secret_standalone() -> bytes:
    """
    Standalone helper for callers that don't hold a VaultKMSClient instance
    (admin_credentials, approach_a). Delegates to VaultKMSClient so field name,
    encoding, and TLS CA bundle handling are consistent with the broker path.
    """
    from app.core.config import get_settings
    settings = get_settings()
    client = VaultKMSClient(
        addr=settings.VAULT_ADDR,
        token=settings.VAULT_TOKEN,
        ca_bundle=settings.VAULT_CA_BUNDLE or None,
    )
    return await client.get_master_secret(settings.BROKER_MASTER_SECRET_PATH)
