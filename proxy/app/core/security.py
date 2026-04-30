"""
MCP Security Platform — Security Utilities

Provides:
- HMAC-SHA-256 signing and verification (SBOM, audit log, webhook)
- API key hashing (never store raw keys)
- API key generation
- Request ID generation

All cryptographic operations use the standard library `hmac` and `hashlib`
modules. No third-party crypto primitives are used for these utilities.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from typing import Final

from app.core.config import settings

# API key format: mcp_<32 random chars>
API_KEY_PREFIX: Final[str] = "mcp_"
API_KEY_RANDOM_BYTES: Final[int] = 32
API_KEY_DISPLAY_PREFIX_LENGTH: Final[int] = 12  # Stored as key_prefix for identification


def generate_api_key() -> str:
    """
    Generate a new random API key.
    Format: mcp_<urlsafe_base32_random>
    The raw key is returned ONCE; only the hash is stored thereafter.
    """
    alphabet = string.ascii_letters + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(API_KEY_RANDOM_BYTES))
    return f"{API_KEY_PREFIX}{random_part}"


def hash_api_key(raw_key: str) -> str:
    """
    HMAC-SHA-256 hash of an API key using API_KEY_HMAC_KEY.
    This is the value stored in api_keys.key_hash.
    Raw keys must NEVER be stored or logged.
    """
    return hmac.new(
        settings.API_KEY_HMAC_KEY.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


def get_key_prefix(raw_key: str) -> str:
    """Return the display prefix (first N chars) for human identification."""
    return raw_key[:API_KEY_DISPLAY_PREFIX_LENGTH]


def sign_sbom(sbom_json: str) -> str:
    """
    HMAC-SHA-256 signature over the SBOM JSON document.
    Stored in sbom_records.signature (INV-006).
    Format: hmac-sha256:<hex_digest>
    """
    sig = hmac.new(
        settings.SBOM_SIGNING_KEY.encode(),
        sbom_json.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{sig}"


def verify_sbom_signature(sbom_json: str, stored_signature: str) -> bool:
    """Verify an SBOM document against its stored signature."""
    expected = sign_sbom(sbom_json)
    return hmac.compare_digest(expected, stored_signature)


def sign_audit_event(canonical_json: str) -> str:
    """
    HMAC-SHA-256 over the canonical audit event JSON.
    Used as the sha256_hash field in audit_events table.
    """
    return hmac.new(
        settings.AUDIT_LOG_HMAC_KEY.encode(),
        canonical_json.encode(),
        hashlib.sha256,
    ).hexdigest()


def sign_webhook_payload(payload_bytes: bytes) -> str:
    """
    HMAC-SHA-256 signature for outbound webhook payloads.
    Placed in X-MCP-Signature-256 header.
    Format: sha256=<hex_digest>
    """
    sig = hmac.new(
        settings.WEBHOOK_SIGNING_KEY.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={sig}"


def verify_jira_webhook(payload_bytes: bytes, signature_header: str) -> bool:
    """Verify an inbound Jira webhook using the configured shared secret."""
    if not settings.JIRA_WEBHOOK_SECRET:
        return False
    expected = hmac.new(
        settings.JIRA_WEBHOOK_SECRET.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def sha256_of(data: str) -> str:
    """Simple SHA-256 digest of a string. Used for schema hashing in SBOM."""
    return hashlib.sha256(data.encode()).hexdigest()


def generate_request_id() -> str:
    """Generate a short unique request ID for log correlation."""
    return f"req_{secrets.token_urlsafe(16)}"
