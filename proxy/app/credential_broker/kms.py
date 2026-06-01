from __future__ import annotations

import base64
import logging

import httpx

logger = logging.getLogger(__name__)


class KMSError(Exception):
    """Raised when Vault is unreachable or returns an error."""


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
            return base64.b64decode(encoded)
        except (KeyError, ValueError) as exc:
            raise KMSError(f"Unexpected Vault response structure: {exc}") from exc


async def load_master_secret_standalone() -> bytes:
    """Standalone helper for callers that do not have a VaultKMSClient instance.

    Fetches the broker master secret directly from Vault using app settings.
    Uses raw httpx (same as VaultKMSClient) with the hex-encoded 'value' field.
    """
    from app.core.config import get_settings
    settings = get_settings()
    vault_addr = settings.VAULT_ADDR.rstrip("/")
    vault_token = settings.VAULT_TOKEN
    path = settings.BROKER_MASTER_SECRET_PATH  # e.g. "secret/data/mcp/broker-master"
    url = f"{vault_addr}/v1/{path}"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(url, headers={"X-Vault-Token": vault_token})
        resp.raise_for_status()
    secret_hex: str = resp.json()["data"]["data"]["value"]
    return bytes.fromhex(secret_hex)
