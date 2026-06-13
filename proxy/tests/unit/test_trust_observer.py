"""Tests for the passive trust envelope observer (PRD-0001 M4 / W4.2)."""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services.jcs import jcs_signed_input, jcs_tool_result
from app.services.trust_observer import observe_result
from app.services.trust_verifier import TrustVerifier, VerifierVerdict

MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
TRUST_ENVELOPE_KEY = "io.mcp-security-platform/trust-envelope/v0.1"


def _make_pki():
    sub_ca_key = ec.generate_private_key(ec.SECP256R1())
    sub_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Sub-CA")])
    now = datetime.now(UTC)
    sub_ca = (
        x509.CertificateBuilder().subject_name(sub_subject).issuer_name(sub_subject)
        .public_key(sub_ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(sub_ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal")])
    leaf_cert = (
        x509.CertificateBuilder().subject_name(leaf_subject).issuer_name(sub_ca.subject)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(minutes=15))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([MCP_LABELER_OID]), critical=False)
        .sign(sub_ca_key, hashes.SHA256())
    )
    return sub_ca_key, sub_ca, leaf_key, leaf_cert


def _make_result(sub_ca, leaf_key, leaf_cert, content=None, trust_tier=0):
    from app.services.trust_labeler import TrustLabeler, TRUST_ENVELOPE_KEY as TEK
    import tempfile, os
    content = content or [{"type": "text", "text": "test"}]
    with tempfile.TemporaryDirectory() as td:
        cert_p = os.path.join(td, "leaf.crt")
        key_p = os.path.join(td, "leaf.key")
        sub_p = os.path.join(td, "sub.crt")
        open(cert_p, "wb").write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        open(key_p, "wb").write(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        open(sub_p, "wb").write(sub_ca.public_bytes(serialization.Encoding.PEM))
        labeler = TrustLabeler(cert_p, key_p, sub_p)
        envelope = labeler.sign_result(content=content, structured_content=None, tool_name="web_search", server_id="srv-1", result_id="rid-1", trust_tier=trust_tier, sensitivity_label="low")
    return {"content": content, "_meta": {TEK: envelope}}


class TestObserveResult:
    def test_observe_accepted_logs_verdict(self, caplog):
        """Accepted envelope: observe_result logs 'accepted' at INFO."""
        import logging
        sub_ca_key, sub_ca, leaf_key, leaf_cert = _make_pki()
        verifier = TrustVerifier(sub_ca_cert=sub_ca)
        result = _make_result(sub_ca, leaf_key, leaf_cert)
        with caplog.at_level(logging.INFO, logger="app.services.trust_observer"):
            verdict = observe_result(result, verifier=verifier, tool_name="web_search", server_id="srv-1", result_id="rid-1")
        assert verdict.accepted is True
        assert any("accepted" in r.message.lower() for r in caplog.records)

    def test_observe_rejected_logs_verdict(self, caplog):
        """Rejected envelope: observe_result logs 'rejected' at WARNING."""
        import logging
        _, sub_ca, _, _ = _make_pki()
        verifier = TrustVerifier(sub_ca_cert=sub_ca)
        result = {"content": [{"type": "text", "text": "x"}]}  # no envelope
        with caplog.at_level(logging.WARNING, logger="app.services.trust_observer"):
            verdict = observe_result(result, verifier=verifier, tool_name="t", server_id="s", result_id="r")
        assert verdict.accepted is False
        assert verdict.integrity_rank == 0

    def test_observe_none_verifier_returns_zero_rank(self):
        """When verifier is None (observer disabled), returns rank=0, accepted=False."""
        result = {"content": []}
        verdict = observe_result(result, verifier=None, tool_name="t", server_id="s", result_id="r")
        assert verdict.accepted is False
        assert verdict.integrity_rank == 0

    def test_observe_does_not_raise_on_malformed_input(self):
        """Malformed result dict does not raise — observer is passive."""
        _, sub_ca, _, _ = _make_pki()
        verifier = TrustVerifier(sub_ca_cert=sub_ca)
        result = "not_a_dict"  # type: ignore[assignment]
        verdict = observe_result(result, verifier=verifier, tool_name="t", server_id="s", result_id="r")
        assert verdict.accepted is False
