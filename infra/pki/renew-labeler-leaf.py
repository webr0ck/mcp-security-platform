#!/usr/bin/env python3
"""Labeler leaf renewal — runs in the labeler-renewal sidecar.

Reads sub_ca.key (sidecar-only volume), issues a fresh leaf cert,
atomically writes leaf.crt + leaf.key to the shared labeler-data volume.

Renewal interval: LABELER_RENEWAL_INTERVAL_SECONDS (default 720 = 12 min).
"""
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

LABELER_DIR = Path(os.environ.get("LABELER_PKI_DIR", "/labeler"))
LEAF_TTL_MINUTES = int(os.environ.get("LABELER_LEAF_TTL_MINUTES", "15"))
RENEWAL_INTERVAL = int(os.environ.get("LABELER_RENEWAL_INTERVAL_SECONDS", "720"))
MCP_LABELER_OID = x509.ObjectIdentifier("1.3.6.1.4.1.99999.1.1")


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


def renew_once() -> None:
    sub_ca_key = serialization.load_pem_private_key(
        (LABELER_DIR / "sub_ca.key").read_bytes(), password=None
    )
    sub_ca_cert = x509.load_pem_x509_certificate((LABELER_DIR / "sub_ca.crt").read_bytes())

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "mcp-labeler.platform.internal"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mcp-security-platform"),
    ])
    now = datetime.now(timezone.utc)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(sub_ca_cert.subject)
        .public_key(leaf_key.public_key())
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

    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    leaf_cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)

    _atomic_write(LABELER_DIR / "leaf.key", leaf_key_pem)
    _atomic_write(LABELER_DIR / "leaf.crt", leaf_cert_pem)
    print(f"[renew] Leaf rotated at {now.isoformat()}; expires in {LEAF_TTL_MINUTES}m", flush=True)


def main() -> None:
    print(f"[renew] Sidecar started; renewing every {RENEWAL_INTERVAL}s", flush=True)
    while True:
        try:
            renew_once()
        except Exception as exc:  # noqa: BLE001
            print(f"[renew] ERROR: {exc}", file=sys.stderr, flush=True)
        time.sleep(RENEWAL_INTERVAL)


if __name__ == "__main__":
    main()
