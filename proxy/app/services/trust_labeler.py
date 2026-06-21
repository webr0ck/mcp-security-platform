"""Trust envelope labeler (PRD-0001 M3 / RFC-0001 §5).

Signing failure returns None — never raises (W3.5). Enforcement (taint floor)
is independent of signing.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from app.services.jcs import jcs_signed_input, jcs_tool_result

logger = logging.getLogger(__name__)

TRUST_ENVELOPE_KEY = "io.mcp-security-platform/trust-envelope/v0.1"

_TRUST_TIER_LABELS: dict[int, str] = {
    0: "untrustedPublic",
    1: "trustedPublic",
    2: "internal",
    3: "user",
    4: "system",
}

_CACHE_REFRESH_BUFFER_SECONDS = 60


class TrustLabeler:
    def __init__(self, cert_path: str, key_path: str, sub_ca_path: str) -> None:
        self._cert_path = Path(cert_path)
        self._key_path = Path(key_path)
        self._sub_ca_path = Path(sub_ca_path)
        self._cached_cert: x509.Certificate | None = None
        self._cached_key = None
        self._cached_x5c: list[str] | None = None

    def sign_result(
        self,
        *,
        content: list,
        structured_content: dict | None,
        tool_name: str,
        server_id: str,
        result_id: str,
        trust_tier: int | None,
        sensitivity_label: str | None,
    ) -> dict | None:
        """Build and sign a trust envelope. Returns None on any failure (W3.5)."""
        try:
            return self._sign(
                content=content, structured_content=structured_content,
                tool_name=tool_name, server_id=server_id, result_id=result_id,
                trust_tier=trust_tier, sensitivity_label=sensitivity_label,
            )
        except Exception:  # noqa: BLE001
            logger.warning("TrustLabeler.sign_result failed (envelope omitted)", exc_info=True)
            return None

    def _load_leaf(self):
        now = datetime.now(UTC)
        if self._cached_cert is not None:
            expire_buffer = self._cached_cert.not_valid_after_utc - timedelta(
                seconds=_CACHE_REFRESH_BUFFER_SECONDS
            )
            if now < expire_buffer:
                return self._cached_cert, self._cached_key, self._cached_x5c

        cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
        key = serialization.load_pem_private_key(self._key_path.read_bytes(), password=None)
        sub_ca = x509.load_pem_x509_certificate(self._sub_ca_path.read_bytes())

        x5c = [
            base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
            base64.b64encode(sub_ca.public_bytes(serialization.Encoding.DER)).decode(),
        ]

        self._cached_cert = cert
        self._cached_key = key
        self._cached_x5c = x5c
        return cert, key, x5c

    def _sign(
        self,
        *,
        content: list,
        structured_content: dict | None,
        tool_name: str,
        server_id: str,
        result_id: str,
        trust_tier: int | None,
        sensitivity_label: str | None,
    ) -> dict:
        cert, private_key, x5c = self._load_leaf()

        safe_tier = trust_tier if trust_tier is not None and 0 <= trust_tier <= 4 else 0
        source_label = _TRUST_TIER_LABELS[safe_tier]

        label: dict = {
            "source": source_label,
            "integrity_rank": safe_tier,
            "sensitivity": sensitivity_label or "low",
            "attribution": [
                {
                    "principal": cert.subject.rfc4514_string(),
                    "cert_fp": "sha256:" + cert.fingerprint(hashes.SHA256()).hex(),
                }
            ],
        }

        canonical_payload = jcs_tool_result(content=content, structured_content=structured_content)
        content_hash = "sha256:" + hashlib.sha256(canonical_payload).hexdigest()

        nonce = secrets.token_urlsafe(16)
        signed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        signed_input_bytes = jcs_signed_input(
            label=label, content_hash=content_hash, nonce=nonce,
            signed_at=signed_at, result_id=result_id,
            tool_name=tool_name, server_id=server_id,
        )
        # ES256 — hardcoded, never dispatched from sig.alg
        sig_der = private_key.sign(signed_input_bytes, ec.ECDSA(hashes.SHA256()))
        sig_value = base64.urlsafe_b64encode(sig_der).rstrip(b"=").decode()

        return {
            "label": label,
            "binding": {
                "content_hash": content_hash,
                "nonce": nonce,
                "signed_at": signed_at,
            },
            "sig": {
                "alg": "ES256",
                "x5c": x5c,
                "value": sig_value,
            },
        }


_labeler: TrustLabeler | None = None


def get_labeler() -> TrustLabeler | None:
    return _labeler


def init_labeler(cert_path: str, key_path: str, sub_ca_path: str) -> None:
    """Called once at proxy startup when TRUST_ENVELOPE_ENABLED=true."""
    global _labeler
    _labeler = TrustLabeler(cert_path=cert_path, key_path=key_path, sub_ca_path=sub_ca_path)
    logger.info("TrustLabeler initialised (cert=%s)", cert_path)


def build_envelope_result(
    *,
    content: list,
    labeler: TrustLabeler | None,
    tool_name: str,
    server_id: str,
    result_id: str,
    trust_tier: int | None,
    sensitivity_label: str | None,
) -> dict:
    """Return result dict with Layer A envelope and optional Layer B wrapping.

    Layer B (LAYER_B_ENABLED=true): advisory MIME-style boundary on untrusted text.
    Layer A (TRUST_ENVELOPE_ENABLED=true): signed _meta envelope.
    Signing failure omits _meta without raising — enforcement is never affected (W3.5).
    Layer B wrapping is applied to the content BEFORE Layer A signing so the
    content_hash in Layer A covers the wrapped text (Layer A is authoritative over B).
    """
    from app.core.config import get_settings
    _s = get_settings()

    effective_content = content
    if _s.LAYER_B_ENABLED:
        from app.services.layer_b import wrap_content_layer_b
        effective_content = wrap_content_layer_b(
            content=content,
            trust_tier=trust_tier,
            tool_name=tool_name,
            server_id=server_id or "__unknown__",
        )

    result: dict = {"content": effective_content}
    if labeler is not None:
        envelope = labeler.sign_result(
            content=effective_content,
            structured_content=None,
            tool_name=tool_name,
            server_id=server_id or "__unknown__",
            result_id=result_id,
            trust_tier=trust_tier,
            sensitivity_label=sensitivity_label,
        )
        if envelope is not None:
            result["_meta"] = {TRUST_ENVELOPE_KEY: envelope}
    return result
