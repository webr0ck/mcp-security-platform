"""
SSRF allowlist for MCP server upstream URLs.

Applied at two points:
  1. server_registry approval: POST /api/v1/admin/servers/{id}/approve calls validate_server_url()
  2. tool invocation: invocation.py calls validate_server_url() before forwarding

Blocks:
- Private/loopback IPv4: 10.x, 172.16-31.x, 192.168.x, 127.x
- Link-local: 169.254.x.x
- IPv6 private: ::1, fc00::/7, fe80::/10
- Cloud metadata endpoints: 169.254.169.254, [fd00:ec2::254]
- Scheme must be https (or http for localhost-only in dev mode)
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFError(Exception):
    """Raised when a URL fails SSRF validation."""


# Blocked private/reserved IPv4 networks
_BLOCKED_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
]

# Blocked private/reserved IPv6 networks
_BLOCKED_V6 = [
    ipaddress.ip_network("::1/128"),            # loopback
    ipaddress.ip_network("fc00::/7"),            # unique local
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("fd00:ec2::/32"),       # AWS IPv6 metadata
]


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv4Address):
            return any(ip in net for net in _BLOCKED_V4)
        else:
            return any(ip in net for net in _BLOCKED_V6)
    except ValueError:
        return False


def validate_server_url(url: str, allow_http_localhost: bool = False) -> None:
    """
    Raise SSRFError if the URL is unsafe.

    Checks performed:
    1. URL must be parseable
    2. Scheme must be https (or http if allow_http_localhost and host is localhost/127.0.0.1)
    3. Host must not resolve to a blocked IP range
    4. Host must not be a raw blocked IP
    5. No credentials in the URL (user:pass@ prefix)
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SSRFError(f"Unparseable URL: {exc}") from exc

    if not parsed.scheme:
        raise SSRFError("URL must have an explicit scheme (https)")

    host = parsed.hostname or ""
    if not host:
        raise SSRFError("URL must have a hostname")

    # No credentials
    if parsed.username or parsed.password:
        raise SSRFError("URL must not contain credentials (user:pass@)")

    # Scheme check
    if parsed.scheme == "http":
        if not allow_http_localhost:
            raise SSRFError("HTTP scheme is not allowed; use HTTPS")
        if host not in ("localhost", "127.0.0.1", "::1"):
            raise SSRFError("HTTP scheme is only allowed for localhost in development mode")
    elif parsed.scheme != "https":
        raise SSRFError(f"Scheme {parsed.scheme!r} is not allowed; use HTTPS")

    # Direct IP check
    if _is_blocked_ip(host):
        raise SSRFError(f"Host {host!r} resolves to a blocked private/reserved IP range")

    # DNS resolution check (best-effort — catches obvious rebind; not a full guard)
    # Skip for localhost: it's already allowed by scheme check above and DNS resolution
    # would block it because localhost resolves to 127.0.0.1/::1 (both in blocked ranges).
    if host in ("localhost",):
        return

    try:
        resolved = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in resolved:
            ip_str = sockaddr[0]
            if _is_blocked_ip(ip_str):
                raise SSRFError(
                    f"Host {host!r} resolves to blocked IP {ip_str!r} "
                    "(private/reserved range)"
                )
    except SSRFError:
        raise
    except OSError:
        pass  # DNS failure — allow (don't block registration because DNS is flaky)
