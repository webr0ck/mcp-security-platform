# ponytail: vendored copy of proxy/app/services/trust_verifier.py — that file is the
# source of truth. Kept in sync by hand (both are small + RFC-pinned). Upgrade path to
# kill drift: make the proxy import this wheel instead of holding its own copy. The
# tests/test_roundtrip.py self-check fails loudly if this diverges from the format.
"""Independent trust-envelope verifier (PRD-0001 M4 / SPEC-0001 §6.3).

A process that did NOT produce the envelope verifies it (D4/D5/D6).
Fail-closed: any failure → VerifierVerdict(accepted=False, integrity_rank=0).

Verification steps (RFC §6.3):
  0. Presence check — no envelope → integrity_rank=0
  1. MAX_ENVELOPE_AGE check (first) — reject if signed_at > 10 min ago
  2. Chain validation — manual SPKI-pinned sub-CA anchor (NOT PolicyBuilder, whose
     built-in verifiers require TLS EKUs the labeler OID can't satisfy): issuer-DN
     match + leaf signature verify against the pinned sub-CA key + leaf validity at
     signed_at. No system trust store consulted.
  2b. Leaf extension policy — BasicConstraints ca=FALSE, KeyUsage digitalSignature,
     and rejection of any unrecognized critical extension (RFC 5280 6.1.4/6.1.5)
  3. EKU check — require labeler OID; reject anyExtendedKeyUsage
  4. Signature verify — ECDSA(SHA-256), hardcoded (never dispatched from sig.alg)
  5. Content hash recomputation — JCS({content, structuredContent}); compare
"""
from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from mcp_trust_verifier.jcs import jcs_signed_input, jcs_tool_result

logger = logging.getLogger(__name__)

MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
ANY_EKU_OID = x509.ObjectIdentifier("2.5.29.37.0")

# RFC 5280 6.1.4/6.1.5: a cert carrying a CRITICAL extension the verifier does not
# process MUST be rejected. This is the whole set we process on the leaf - anything
# else marked critical is, by definition, a constraint we would be ignoring.
RECOGNIZED_CRITICAL_OIDS = frozenset({
    x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
    x509.oid.ExtensionOID.KEY_USAGE,
    x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
})
TRUST_ENVELOPE_KEY = "io.mcp-security-platform/trust-envelope/v0.1"

MAX_ENVELOPE_AGE_SECONDS: int = 600   # §6.3(4): 10 min
CLOCK_SKEW_SECONDS: int = 60          # §6.3(3): ≤60 s


@dataclass
class VerifierVerdict:
    accepted: bool
    integrity_rank: int      # 0 on any failure (fail-closed)
    reason: str | None = field(default=None)


class TrustVerifier:
    """SPEC-0001 §6.3 conformant verifier.

    Pinned to a specific sub-CA cert (SPKI anchor, not DN, not system store).
    """

    def __init__(
        self,
        sub_ca_cert: x509.Certificate,
        max_envelope_age_seconds: int = MAX_ENVELOPE_AGE_SECONDS,
        clock_skew_seconds: int = CLOCK_SKEW_SECONDS,
    ) -> None:
        self._sub_ca_cert = sub_ca_cert
        self._max_age = max_envelope_age_seconds
        self._skew = clock_skew_seconds

    @classmethod
    def from_pem(cls, sub_ca_pem: bytes | str, **kwargs) -> "TrustVerifier":
        """Construct a verifier from the pinned sub-CA cert (PEM bytes/str or a path).

        The consumer's single input for cross-boundary verification: the anchor it
        pins. Everything else (freshness window, skew) has RFC defaults.
        """
        if isinstance(sub_ca_pem, str) and "-----BEGIN" not in sub_ca_pem:
            from pathlib import Path
            sub_ca_pem = Path(sub_ca_pem).read_bytes()
        if isinstance(sub_ca_pem, str):
            sub_ca_pem = sub_ca_pem.encode()
        return cls(x509.load_pem_x509_certificate(sub_ca_pem), **kwargs)

    def verify(
        self,
        result: dict,
        *,
        tool_name: str | None = None,
        server_id: str | None = None,
        result_id: str | None = None,
    ) -> VerifierVerdict:
        """Verify the trust envelope in result._meta. Fail-closed on any error.

        Call-context (tool_name/server_id/result_id) is used to reconstruct the signed
        input. A caller that already holds a field (its own request id, the tool it
        called) SHOULD pass it — that is the anti-replay property. Any field left None
        falls back to the envelope's unsigned ``call_context`` hint (A6); this is safe
        because the signature covers the real values, so a forged hint fails verify.
        """
        try:
            return self._verify(
                result, tool_name=tool_name, server_id=server_id, result_id=result_id
            )
        except Exception:  # noqa: BLE001
            logger.warning("TrustVerifier.verify unexpected exception (fail-closed)", exc_info=True)
            return VerifierVerdict(accepted=False, integrity_rank=0, reason="unexpected_error")

    def _reject(self, reason: str) -> VerifierVerdict:
        logger.debug("TrustVerifier rejected: %s", reason)
        return VerifierVerdict(accepted=False, integrity_rank=0, reason=reason)

    def _verify(
        self,
        result: dict,
        *,
        tool_name: str | None,
        server_id: str | None,
        result_id: str | None,
    ) -> VerifierVerdict:
        # ── Step 0: Envelope presence ─────────────────────────────────────
        meta = result.get("_meta") or {}
        envelope = meta.get(TRUST_ENVELOPE_KEY)
        if not envelope:
            return self._reject("no_envelope")

        # A6: fall back to the unsigned call_context hint for any field the caller
        # did not supply (a downstream consumer typically knows tool_name/result_id
        # but not the upstream server_id). Transitively verified by the signature.
        call_ctx = envelope.get("call_context") or {}
        eff_tool_name = tool_name if tool_name is not None else call_ctx.get("tool_name", "")
        eff_server_id = server_id if server_id is not None else call_ctx.get("server_id", "")
        eff_result_id = result_id if result_id is not None else call_ctx.get("result_id", "")

        label = envelope.get("label") or {}
        binding = envelope.get("binding") or {}
        sig = envelope.get("sig") or {}

        signed_at_str = binding.get("signed_at", "")
        content_hash = binding.get("content_hash", "")
        nonce = binding.get("nonce", "")
        x5c = sig.get("x5c") or []
        sig_value = sig.get("value", "")

        # ── Step 1: MAX_ENVELOPE_AGE (first check, §6.3(4)) ──────────────
        try:
            signed_at_dt = datetime.fromisoformat(signed_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return self._reject("invalid_signed_at_format")

        now = datetime.now(UTC)
        age_seconds = (now - signed_at_dt).total_seconds()
        if age_seconds > self._max_age:
            return self._reject(f"envelope_too_old_age={age_seconds:.0f}s")
        if age_seconds < -self._skew:
            return self._reject(f"envelope_future_dated_age={age_seconds:.0f}s")

        # ── Step 2: Chain validation (SPKI anchor, point-in-time) ────────
        if len(x5c) < 1:
            return self._reject("x5c_empty")

        try:
            leaf_cert = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
        except Exception:
            return self._reject("x5c_leaf_decode_error")

        intermediates = []
        for raw in x5c[1:]:
            try:
                intermediates.append(x509.load_der_x509_certificate(base64.b64decode(raw)))
            except Exception:
                return self._reject("x5c_intermediate_decode_error")

        # Point-in-time: verify chain was valid at signed_at (SPKI-pinned anchor)
        # We use manual chain validation instead of PolicyBuilder.build_client_verifier()
        # because the cryptography library's built-in verifiers enforce TLS-specific EKUs
        # (id-kp-clientAuth / id-kp-serverAuth) which our custom MCP labeler OID does not
        # satisfy. No system trust store is consulted.
        #
        # This is NOT full RFC 5280 path validation, and an earlier version of this comment
        # claimed it was. What we do: issuer-DN match, leaf signature verified with the
        # pinned sub-CA's public key, leaf validity window at signed_at, then the leaf
        # extension policy in step 2b (BasicConstraints, KeyUsage, unknown-critical) and
        # the EKU check in step 3. What we still DO NOT do: revocation - there is no
        # CRL/OCSP here, mitigated only by the 15-minute leaf lifetime.
        # Path length and name constraints are genuinely moot rather than skipped: the path
        # here is exactly one hop. `intermediates` above is parsed for shape validation and
        # then DELIBERATELY UNUSED - nothing but a leaf directly issued by the pinned sub-CA
        # can ever verify, so an attacker-supplied intermediate has no route to being trusted.
        try:
            # 1. Leaf must be issued by the pinned sub-CA (issuer DN match + signature verify)
            if leaf_cert.issuer != self._sub_ca_cert.subject:
                return self._reject("chain_validation_failed")
            self._sub_ca_cert.public_key().verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                ec.ECDSA(hashes.SHA256()),
            )
            # 2. Leaf must have been valid at signed_at (point-in-time, §6.3(5))
            leaf_valid = (
                leaf_cert.not_valid_before_utc <= signed_at_dt <= leaf_cert.not_valid_after_utc
            )
            if not leaf_valid:
                return self._reject("chain_validation_failed")
            # 3. Sub-CA is the SPKI-pinned trust anchor; as the explicit trust root
            #    we do not enforce its validity window at signed_at — the trust is
            #    unconditional by configuration (identical to how a root CA is treated
            #    in certificate stores). We only validate the leaf's validity window.
        except Exception:
            return self._reject("chain_validation_failed")

        # ── Step 2b: leaf extension policy (RFC 5280 hygiene) ────────────
        try:
            basic_constraints = leaf_cert.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            return self._reject("missing_basic_constraints")
        if basic_constraints.ca:
            # A leaf that asserts ca=TRUE is a signing-capable cert masquerading as an
            # end entity - it could mint siblings under a chain we would then accept.
            return self._reject("leaf_is_ca")

        try:
            key_usage = leaf_cert.extensions.get_extension_for_class(x509.KeyUsage).value
        except x509.ExtensionNotFound:
            return self._reject("missing_key_usage")
        if not key_usage.digital_signature:
            return self._reject("key_usage_not_digital_signature")

        unknown_critical = sorted(
            ext.oid.dotted_string
            for ext in leaf_cert.extensions
            if ext.critical and ext.oid not in RECOGNIZED_CRITICAL_OIDS
        )
        if unknown_critical:
            return self._reject(f"unknown_critical_extension:{unknown_critical[0]}")

        # ── Step 3: EKU check (parsed OID; reject anyExtendedKeyUsage) ───
        try:
            eku_ext = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            eku_oids = set(eku_ext.value)
        except x509.ExtensionNotFound:
            return self._reject("missing_eku")

        if ANY_EKU_OID in eku_oids:
            return self._reject("anyExtendedKeyUsage_rejected")
        if MCP_LABELER_OID not in eku_oids:
            return self._reject("missing_labeler_eku")

        # ── Step 3b: Attribution binding ─────────────────────────────────
        # `label.attribution` names the labeler that asserted this. It sits inside
        # `label`, so it IS signed - but a valid signature only proves that SOME key
        # chaining to the pinned sub-CA signed it. Without this comparison any sibling
        # leaf (a rotated key, a second region, another tenant) can attribute its
        # assertion to a DIFFERENT principal and verify clean, so "the named labeler
        # asserted this" would be unproven. Bind the name to the cert presenting it.
        attribution = label.get("attribution")
        if not isinstance(attribution, list) or not attribution:
            return self._reject("attribution_missing")
        # Exactly one. Binding only attribution[0] would leave the rest unbound, and every
        # extra entry sits INSIDE the signed label - so a sibling leaf could self-attribute
        # at index 0 (passing the check below) and forge a second entry naming a different
        # labeler, which then carries the signature's authority to anything that reads
        # `attribution` as the list it is declared to be. Same lie, one index over.
        if len(attribution) != 1:
            return self._reject("attribution_multi")
        signer = attribution[0] if isinstance(attribution[0], dict) else {}
        leaf_fp = "sha256:" + leaf_cert.fingerprint(hashes.SHA256()).hex()
        if signer.get("cert_fp") != leaf_fp:
            return self._reject("attribution_mismatch")
        if signer.get("principal") != leaf_cert.subject.rfc4514_string():
            return self._reject("attribution_mismatch")

        # ── Step 4: Signature verify (ES256, hardcoded — never dispatched) ─
        try:
            padding = "=" * (-len(sig_value) % 4)
            sig_der = base64.urlsafe_b64decode(sig_value + padding)
        except Exception:
            return self._reject("sig_value_decode_error")

        signed_input_bytes = jcs_signed_input(
            label=label,
            content_hash=content_hash,
            nonce=nonce,
            signed_at=signed_at_str,
            result_id=eff_result_id,
            tool_name=eff_tool_name,
            server_id=eff_server_id,
        )
        try:
            leaf_cert.public_key().verify(sig_der, signed_input_bytes, ec.ECDSA(hashes.SHA256()))
        except Exception:
            return self._reject("signature_invalid")

        # ── Step 5: Content hash recomputation ───────────────────────────
        content = result.get("content", [])
        structured_content = result.get("structuredContent")
        canonical = jcs_tool_result(content=content, structured_content=structured_content)
        expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        if content_hash != expected_hash:
            return self._reject(
                f"content_hash_mismatch got={content_hash[:12]}… want={expected_hash[:12]}…"
            )

        integrity_rank = max(0, min(4, int(label.get("integrity_rank", 0))))
        return VerifierVerdict(accepted=True, integrity_rank=integrity_rank, reason=None)


# ── Module-level singleton ─────────────────────────────────────────────────

_verifier: TrustVerifier | None = None


def get_verifier() -> TrustVerifier | None:
    return _verifier


def init_verifier(sub_ca_cert_path: str) -> None:
    """Called once at proxy startup when TRUST_OBSERVER_ENABLED=true."""
    global _verifier
    from pathlib import Path
    cert_pem = Path(sub_ca_cert_path).read_bytes()
    sub_ca = x509.load_pem_x509_certificate(cert_pem)
    _verifier = TrustVerifier(sub_ca_cert=sub_ca)
    logger.info("TrustVerifier initialised (sub_ca=%s)", sub_ca_cert_path)
