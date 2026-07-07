from __future__ import annotations

import base64
import logging
import re

import httpx

logger = logging.getLogger(__name__)

# Envelope encryption constants
_KEK_SIZE = 32    # 256-bit master secret for AES-256-GCM (approach_a derives per-blob KEKs)


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
        raw = bytes.fromhex(s)
    else:
        raw = base64.b64decode(s)
    # SR-4: enforce a 256-bit entropy floor. HKDF accepts any-length IKM and
    # silently stretches a short/low-entropy secret into a 32-byte KEK, so a
    # misconfigured Vault value (e.g. "0") would yield a deterministic key with
    # no error. Fail closed before any KEK is ever derived from it.
    if len(raw) < _KEK_SIZE:
        raise KMSError(
            f"master_secret must be at least {_KEK_SIZE} bytes (256-bit); "
            f"decoded to {len(raw)} bytes"
        )
    return raw


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
        from app.services.metrics import record_vault_reachable

        url = f"{self._addr}/v1/{path}"
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=self._verify) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            record_vault_reachable(False)
            raise KMSError(f"Vault unreachable: {exc}") from exc

        try:
            # Vault stores the KEK under "value" (written by lab/seeder/vault-init.sh).
            data = resp.json()["data"]["data"]
            encoded = data.get("master_secret") or data["value"]
            secret = _decode_master_secret(encoded)
        except (KeyError, ValueError) as exc:
            record_vault_reachable(False)
            raise KMSError(f"Unexpected Vault response structure: {exc}") from exc
        record_vault_reachable(True)
        return secret


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


# envelope_encrypt/envelope_decrypt were deleted (credential write/read interop
# fix): they implemented a SECOND ciphertext codec (nonce||ct, raw KEK, no AAD)
# that was incompatible with approach_a's salt||nonce||ct format used by every
# writer, so credential_storage.retrieve_credential hit InvalidTag on anything
# the admin path stored. There is exactly ONE credential codec now:
# app.credential_broker.approaches.approach_a.encrypt/decrypt.
