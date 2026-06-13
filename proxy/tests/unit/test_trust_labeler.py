"""Unit tests for TrustLabeler (PRD-0001 M3 / RFC-0001 §5)."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


def _make_sub_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MCP Labeler Sub-CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(sub_ca_key, sub_ca_cert, ttl_minutes=15):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(sub_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([MCP_LABELER_OID]), critical=False)
        .sign(sub_ca_key, hashes.SHA256())
    )
    return key, cert


def _write_pem(path, obj):
    if hasattr(obj, "private_bytes"):
        data = obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    else:
        data = obj.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(data)


@pytest.fixture()
def pki(tmp_path):
    sub_ca_key, sub_ca_cert = _make_sub_ca()
    leaf_key, leaf_cert = _make_leaf(sub_ca_key, sub_ca_cert)
    cert_path = tmp_path / "leaf.crt"
    key_path = tmp_path / "leaf.key"
    sub_ca_path = tmp_path / "sub_ca.crt"
    _write_pem(cert_path, leaf_cert)
    _write_pem(key_path, leaf_key)
    _write_pem(sub_ca_path, sub_ca_cert)
    return {
        "cert_path": str(cert_path), "key_path": str(key_path), "sub_ca_path": str(sub_ca_path),
        "sub_ca_cert": sub_ca_cert, "leaf_cert": leaf_cert, "leaf_key": leaf_key,
    }


class TestTrustLabelerSign:
    def test_envelope_structure(self, pki):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        env = labeler.sign_result(
            content=[{"type": "text", "text": "hello"}], structured_content=None,
            tool_name="web_search", server_id="srv-001", result_id="rid-001",
            trust_tier=0, sensitivity_label=None,
        )
        assert env is not None
        assert "label" in env
        assert "binding" in env
        assert "sig" in env

    def test_label_fields(self, pki):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        env = labeler.sign_result(
            content=[{"type": "text", "text": "x"}], structured_content=None,
            tool_name="t", server_id="s", result_id="r", trust_tier=2, sensitivity_label="low",
        )
        assert env["label"]["source"] == "internal"
        assert env["label"]["integrity_rank"] == 2
        assert env["label"]["sensitivity"] == "low"
        assert isinstance(env["label"]["attribution"], list)

    def test_content_hash_covers_both_fields(self, pki):
        from app.services.trust_labeler import TrustLabeler
        from app.services.jcs import jcs_tool_result
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        content = [{"type": "text", "text": "data"}]
        env = labeler.sign_result(
            content=content, structured_content=None, tool_name="t",
            server_id="s", result_id="r", trust_tier=0, sensitivity_label=None,
        )
        canonical = jcs_tool_result(content=content, structured_content=None)
        expected_hash = "sha256:" + hashlib.sha256(canonical).hexdigest()
        assert env["binding"]["content_hash"] == expected_hash

    def test_sig_alg_hardcoded_es256(self, pki):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        env = labeler.sign_result(
            content=[], structured_content=None, tool_name="t",
            server_id="s", result_id="r", trust_tier=0, sensitivity_label=None,
        )
        assert env["sig"]["alg"] == "ES256"

    def test_sig_value_verifiable(self, pki):
        from app.services.trust_labeler import TrustLabeler
        from app.services.jcs import jcs_signed_input
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        content = [{"type": "text", "text": "verify me"}]
        env = labeler.sign_result(
            content=content, structured_content=None, tool_name="web_search",
            server_id="srv-1", result_id="rid-1", trust_tier=0, sensitivity_label=None,
        )
        signed_input = jcs_signed_input(
            label=env["label"], content_hash=env["binding"]["content_hash"],
            nonce=env["binding"]["nonce"], signed_at=env["binding"]["signed_at"],
            result_id="rid-1", tool_name="web_search", server_id="srv-1",
        )
        padding = "=" * (-len(env["sig"]["value"]) % 4)
        sig_der = base64.urlsafe_b64decode(env["sig"]["value"] + padding)
        leaf_pub = pki["leaf_cert"].public_key()
        leaf_pub.verify(sig_der, signed_input, _ec.ECDSA(hashes.SHA256()))  # raises on bad sig

    def test_x5c_order_leaf_first(self, pki):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        env = labeler.sign_result(
            content=[], structured_content=None, tool_name="t",
            server_id="s", result_id="r", trust_tier=0, sensitivity_label=None,
        )
        x5c = env["sig"]["x5c"]
        assert len(x5c) == 2
        leaf_der = base64.b64decode(x5c[0])
        sub_ca_der = base64.b64decode(x5c[1])
        leaf = x509.load_der_x509_certificate(leaf_der)
        sub_ca = x509.load_der_x509_certificate(sub_ca_der)
        assert leaf.issuer == sub_ca.subject

    def test_signing_failure_returns_none(self, tmp_path):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(
            cert_path=str(tmp_path / "missing.crt"),
            key_path=str(tmp_path / "missing.key"),
            sub_ca_path=str(tmp_path / "missing_ca.crt"),
        )
        result = labeler.sign_result(
            content=[], structured_content=None, tool_name="t",
            server_id="s", result_id="r", trust_tier=0, sensitivity_label=None,
        )
        assert result is None

    def test_unknown_trust_tier_maps_to_untrusted(self, pki):
        from app.services.trust_labeler import TrustLabeler
        labeler = TrustLabeler(cert_path=pki["cert_path"], key_path=pki["key_path"], sub_ca_path=pki["sub_ca_path"])
        env = labeler.sign_result(
            content=[], structured_content=None, tool_name="t",
            server_id="s", result_id="r", trust_tier=99, sensitivity_label=None,
        )
        assert env["label"]["source"] == "untrustedPublic"
        assert env["label"]["integrity_rank"] == 0
