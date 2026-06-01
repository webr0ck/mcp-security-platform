"""
Unit tests for proxy/app/services/ssrf.py — SSRF allowlist.
"""
from __future__ import annotations

import pytest

from app.services.ssrf import SSRFError, validate_server_url


def test_valid_https_url_passes():
    """A well-formed public HTTPS URL should not raise."""
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
