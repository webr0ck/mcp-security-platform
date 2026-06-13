#!/usr/bin/env python3
"""One-shot PKI init: generate MCP Labeler sub-CA + initial leaf cert.

Outputs (written to OUTPUT_DIR, default /labeler):
  sub_ca.crt   — sub-CA cert (public; distribute to verifiers)
  sub_ca.key   — sub-CA private key (sidecar only; NEVER mount into proxy)
  leaf.crt     — initial labeler leaf cert
  leaf.key     — initial labeler leaf private key

Idempotent: skips sub-CA if sub_ca.key already exists; always issues fresh leaf.
"""
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUTPUT_DIR = Path(os.environ.get("LABELER_PKI_DIR", "/labeler"))
MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
LEAF_TTL_MINUTES = int(os.environ.get("LABELER_LEAF_TTL_MINUTES", "15"))
SUB_CA_TTL_DAYS = int(os.environ.get("LABELER_SUB_CA_TTL_DAYS", "365"))


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Atomic write with explicit permissions. Does not rely on umask (private key safety)."""
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise
    os.replace(str(tmp), str(path))


def generate_sub_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MCP Labeler Sub-CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mcp-security-platform"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=SUB_CA_TTL_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.NameConstraints(
                permitted_subtrees=[x509.DNSName("platform.internal")],
                excluded_subtrees=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def generate_leaf(sub_ca_key, sub_ca_cert):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mcp-security-platform"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(sub_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(minutes=LEAF_TTL_MINUTES))
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


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(str(OUTPUT_DIR), 0o700)  # tighten if dir existed with wider perms
    sub_ca_key_path = OUTPUT_DIR / "sub_ca.key"

    if sub_ca_key_path.exists():
        print(f"[labeler-init] sub_ca.key exists at {sub_ca_key_path}; skipping sub-CA generation.")
        sub_ca_key = serialization.load_pem_private_key(sub_ca_key_path.read_bytes(), password=None)
        sub_ca_cert = x509.load_pem_x509_certificate((OUTPUT_DIR / "sub_ca.crt").read_bytes())
    else:
        print("[labeler-init] Generating sub-CA...")
        sub_ca_key, sub_ca_cert = generate_sub_ca()
        _atomic_write(OUTPUT_DIR / "sub_ca.key", _pem_key(sub_ca_key))
        _atomic_write(OUTPUT_DIR / "sub_ca.crt", _pem_cert(sub_ca_cert))
        print(f"[labeler-init] sub-CA written to {OUTPUT_DIR}/sub_ca.{{crt,key}}")

    print("[labeler-init] Generating labeler leaf cert...")
    leaf_key, leaf_cert = generate_leaf(sub_ca_key, sub_ca_cert)
    _atomic_write(OUTPUT_DIR / "leaf.key", _pem_key(leaf_key))
    _atomic_write(OUTPUT_DIR / "leaf.crt", _pem_cert(leaf_cert))
    print(f"[labeler-init] Leaf cert written to {OUTPUT_DIR}/leaf.{{crt,key}} (TTL={LEAF_TTL_MINUTES}m)")
    print(f"[labeler-init] Sub-CA fingerprint: {sub_ca_cert.fingerprint(hashes.SHA256()).hex()}")
    print("[labeler-init] Done. Distribute sub_ca.crt to verifiers.")


if __name__ == "__main__":
    main()
