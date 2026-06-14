"""
Unit tests for proxy/app/services/ssrf.py — SSRF allowlist.
"""
from __future__ import annotations

import pytest

from app.services.ssrf import SSRFError, validate_server_url


def test_valid_https_url_passes():
    """A well-formed public HTTPS URL with a resolvable public IP should not raise."""
    import socket
    from unittest.mock import patch
    # Mock DNS to return a public IP so this test is not DNS-dependent.
    # The fix makes DNS failure fail-closed; a successful public-IP resolution must still pass.
    public_addr = [
        (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
    ]
    with patch("socket.getaddrinfo", return_value=public_addr):
        validate_server_url("https://api.example.com/v1")


def test_http_blocked_by_default():
    """Plain HTTP URLs are rejected unless allow_http_localhost=True."""
    with pytest.raises(SSRFError, match="HTTP scheme is not allowed"):
        validate_server_url("http://api.example.com")


def test_http_localhost_allowed_with_flag():
    """HTTP is allowed for localhost when allow_http_localhost=True."""
    validate_server_url("http://localhost:8080/mcp", allow_http_localhost=True)


def test_private_ipv4_blocked_10():
    """Addresses in 10.0.0.0/8 must be blocked."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://10.0.0.1/")


def test_private_ipv4_blocked_192_168():
    """Addresses in 192.168.0.0/16 must be blocked."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://192.168.1.1/")


def test_link_local_blocked():
    """Cloud metadata endpoint 169.254.169.254 must be blocked."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://169.254.169.254/latest/meta-data/")


def test_ipv6_loopback_blocked():
    """IPv6 loopback ::1 must be blocked."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://[::1]/")


def test_ipv6_unspecified_blocked():
    """IPv6 unspecified `::` must be blocked (routes to loopback/local on
    dual-stack hosts). Regression for the `_BLOCKED_V6` enumeration gap."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://[::]/")


def test_nat64_embedded_metadata_blocked():
    """NAT64 64:ff9b::/96 wrapping the cloud-metadata IP (169.254.169.254)
    must be blocked by decoding the embedded IPv4. This prefix is is_global=True
    so a pure not-is_global check is insufficient."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://[64:ff9b::a9fe:a9fe]/")


def test_6to4_embedded_rfc1918_blocked():
    """6to4 2002:V4::/16 wrapping a private IPv4 (10.0.0.1) must be blocked."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://[2002:a00:1::]/")


def test_ipv4_compatible_loopback_blocked():
    """Deprecated IPv4-compatible ::/96 wrapping loopback (::127.0.0.1) must be
    blocked. This form is is_global=True in CPython, so embedded-v4 decode is
    required."""
    with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
        validate_server_url("https://[::7f00:1]/")


def test_public_ipv6_still_allowed():
    """Regression guard: a genuine globally-routable IPv6 (Cloudflare resolver)
    must NOT be blocked by the deny-by-default IPv6 logic."""
    validate_server_url("https://[2606:4700:4700::1111]/")


def test_credentials_in_url_blocked():
    """URLs with embedded credentials (user:pass@) must be rejected."""
    with pytest.raises(SSRFError, match="credentials"):
        validate_server_url("https://user:pass@api.example.com/")


def test_no_scheme_raises():
    """A URL without a scheme must be rejected."""
    with pytest.raises(SSRFError):
        validate_server_url("api.example.com/v1")


def test_custom_scheme_blocked():
    """Non-http/https schemes like ftp:// must be rejected."""
    with pytest.raises(SSRFError, match="is not allowed"):
        validate_server_url("ftp://api.example.com/")
