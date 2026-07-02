"""Integration tests: trust envelope attached to tool results (PRD-0001 M3 / RFC-0001 §5)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services.trust_labeler import TrustLabeler, TRUST_ENVELOPE_KEY, build_envelope_result

MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


def _make_labeler(tmp_path: Path) -> TrustLabeler:
    sub_key = ec.generate_private_key(ec.SECP256R1())
    sub_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Sub-CA")])
    now = datetime.now(timezone.utc)
    sub_cert = (
        x509.CertificateBuilder()
        .subject_name(sub_subject).issuer_name(sub_subject)
        .public_key(sub_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(sub_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject).issuer_name(sub_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(minutes=15))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([MCP_LABELER_OID]), critical=False)
        .sign(sub_key, hashes.SHA256())
    )
    cert_p = tmp_path / "leaf.crt"
    key_p = tmp_path / "leaf.key"
    sub_p = tmp_path / "sub_ca.crt"
    cert_p.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(leaf_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    ))
    sub_p.write_bytes(sub_cert.public_bytes(serialization.Encoding.PEM))
    return TrustLabeler(str(cert_p), str(key_p), str(sub_p))


class TestBuildEnvelopeResult:
    def test_attaches_envelope_when_labeler_configured(self, tmp_path):
        """Result dict has _meta with trust envelope when labeler is present."""
        labeler = _make_labeler(tmp_path)
        result = build_envelope_result(
            content=[{"type": "text", "text": "hello"}],
            labeler=labeler,
            tool_name="web_search",
            server_id="srv-001",
            result_id="rid-001",
            trust_tier=0,
            sensitivity_label=None,
        )
        assert "content" in result
        assert "_meta" in result
        assert TRUST_ENVELOPE_KEY in result["_meta"]
        env = result["_meta"][TRUST_ENVELOPE_KEY]
        assert "label" in env
        assert "binding" in env
        assert "sig" in env

    def test_no_envelope_when_labeler_none(self):
        """No _meta key when labeler is None (trust envelopes disabled — W3.5)."""
        result = build_envelope_result(
            content=[{"type": "text", "text": "x"}],
            labeler=None,
            tool_name="t",
            server_id="s",
            result_id="r",
            trust_tier=0,
            sensitivity_label=None,
        )
        assert "_meta" not in result
        assert result["content"] == [{"type": "text", "text": "x"}]

    def test_empty_server_id_uses_unknown(self, tmp_path):
        """Empty server_id is replaced with '__unknown__' (never passes empty to signer)."""
        labeler = _make_labeler(tmp_path)
        result = build_envelope_result(
            content=[],
            labeler=labeler,
            tool_name="t",
            server_id="",
            result_id="r",
            trust_tier=0,
            sensitivity_label=None,
        )
        assert result is not None

    def test_signing_failure_omits_meta(self, tmp_path):
        """If signing fails (missing key file), _meta is omitted — no exception raised (W3.5)."""
        labeler = TrustLabeler(
            cert_path=str(tmp_path / "no.crt"),
            key_path=str(tmp_path / "no.key"),
            sub_ca_path=str(tmp_path / "no_ca.crt"),
        )
        result = build_envelope_result(
            content=[{"type": "text", "text": "x"}],
            labeler=labeler,
            tool_name="t",
            server_id="s",
            result_id="r",
            trust_tier=0,
            sensitivity_label=None,
        )
        assert "_meta" not in result


def test_layer_b_wraps_untrusted_text_in_build_envelope_result(monkeypatch):
    """Layer B wrapping appears in the content when LAYER_B_ENABLED=true."""
    import app.core.config as cfg_mod
    cfg_mod.get_settings.cache_clear()
    class _FakeSettings:
        LAYER_B_ENABLED = True
    monkeypatch.setattr(cfg_mod, "get_settings", lambda: _FakeSettings())

    from app.services.trust_labeler import build_envelope_result, TRUST_ENVELOPE_KEY
    from app.services.layer_b import LAYER_B_BOUNDARY_PREFIX

    result = build_envelope_result(
        content=[{"type": "text", "text": "untrusted web content"}],
        labeler=None,
        tool_name="web_search",
        server_id="search-srv",
        result_id="r1",
        trust_tier=0,
        sensitivity_label=None,
    )
    assert LAYER_B_BOUNDARY_PREFIX in result["content"][0]["text"]
    assert TRUST_ENVELOPE_KEY not in result  # labeler is None → no _meta


def test_layer_b_disabled_by_default_in_build_envelope_result():
    """Layer B wrapping must NOT fire unless explicitly enabled."""
    from app.services.trust_labeler import build_envelope_result
    from app.services.layer_b import LAYER_B_BOUNDARY_PREFIX

    result = build_envelope_result(
        content=[{"type": "text", "text": "untrusted web content"}],
        labeler=None,
        tool_name="web_search",
        server_id="search-srv",
        result_id="r1",
        trust_tier=0,
        sensitivity_label=None,
    )
    assert LAYER_B_BOUNDARY_PREFIX not in result["content"][0]["text"]
