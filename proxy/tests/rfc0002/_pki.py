"""PKI + envelope helpers for the RFC-0002 substrate tests.

Cloned from scripts/demo_trust_envelope.py (a known-good labeler→verifier path):
a self-signed sub-CA + a labeler leaf carrying the MCP labeler EKU, plus a helper
that signs a v0.1 envelope via the REAL TrustLabeler. Kept out of conftest so test
modules can import the helpers without importing the conftest module.
"""
from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


def make_pki(ttl_minutes: int = 15, eku_oids=None, not_before=None, not_after=None):
    """Return (sub_ca_key, sub_ca_cert, leaf_key, leaf_cert): a self-signed sub-CA
    plus a labeler leaf with the MCP labeler EKU, matching the topology the
    TrustVerifier already accepts."""
    eku_oids = eku_oids if eku_oids is not None else [MCP_LABELER_OID]
    now = datetime.now(UTC)
    nb = not_before or now
    na = not_after or (now + timedelta(minutes=ttl_minutes))

    sub_ca_key = ec.generate_private_key(ec.SECP256R1())
    sub_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test MCP Labeler Sub-CA")])
    sub_ca = (
        x509.CertificateBuilder()
        .subject_name(sub_subject).issuer_name(sub_subject)
        .public_key(sub_ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(sub_ca_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal")]
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject).issuer_name(sub_ca.subject)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)
    leaf_cert = builder.sign(sub_ca_key, hashes.SHA256())
    return sub_ca_key, sub_ca, leaf_key, leaf_cert


def sign_envelope(
    leaf_key, leaf_cert, sub_ca, content, *,
    tool_name="web_search", server_id="demo-srv", result_id="demo-rid-1",
    trust_tier=0, sensitivity_label="low", structured_content=None,
):
    """Produce a signed v0.1 trust envelope via the REAL TrustLabeler."""
    from app.services.trust_labeler import TrustLabeler  # lazy: substrate-only dep

    with tempfile.TemporaryDirectory() as td:
        cert_p, key_p, sub_p = (os.path.join(td, n) for n in ("l.crt", "l.key", "s.crt"))
        with open(cert_p, "wb") as f:
            f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
        with open(key_p, "wb") as f:
            f.write(
                leaf_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        with open(sub_p, "wb") as f:
            f.write(sub_ca.public_bytes(serialization.Encoding.PEM))
        labeler = TrustLabeler(cert_p, key_p, sub_p)
        return labeler.sign_result(
            content=content, structured_content=structured_content,
            tool_name=tool_name, server_id=server_id, result_id=result_id,
            trust_tier=trust_tier, sensitivity_label=sensitivity_label,
        )
