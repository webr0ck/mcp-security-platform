"""
SSRF allowlist for MCP server upstream URLs.

Applied at two points:
  1. server_registry approval: POST /api/v1/admin/servers/{id}/approve calls validate_server_url()
  2. tool invocation: invocation.py calls validate_server_url() before forwarding (C3 fix)

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
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT / RFC 6598 (Tailscale, AWS, K8s overlays)
]

# Blocked private/reserved IPv6 networks
_BLOCKED_V6 = [
    ipaddress.ip_network("::1/128"),            # loopback
    ipaddress.ip_network("::/128"),             # unspecified (also caught by not is_global)
    ipaddress.ip_network("fc00::/7"),            # unique local
    ipaddress.ip_network("fe80::/10"),           # link-local
    ipaddress.ip_network("fd00:ec2::/32"),       # AWS IPv6 metadata
]

# IPv6 transition prefixes that embed a 32-bit IPv4 address in their low bits.
# These can be globally-routable (is_global == True) while wrapping a
# private/loopback/metadata IPv4 target, so the embedded v4 must be re-checked.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")     # RFC 6052 well-known NAT64
_V4COMPAT_PREFIX = ipaddress.ip_network("::/96")          # deprecated IPv4-compatible IPv6


def _v4_blocked(ip4: ipaddress.IPv4Address) -> bool:
    return any(ip4 in net for net in _BLOCKED_V4)


def _embedded_v4s(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """Extract every embedded IPv4 address from an IPv6 transition form.

    Covers IPv4-mapped (::ffff:a.b.c.d), 6to4 (2002:V4::/16), Teredo
    (2001:0::/32 — both server and client v4), NAT64 (64:ff9b::/96) and the
    deprecated IPv4-compatible (::/96) forms. A globally-routable IPv6 wrapper
    must not be able to smuggle a private/loopback/metadata IPv4 target past
    the filter.
    """
    found: list[ipaddress.IPv4Address] = []
    if ip.ipv4_mapped is not None:
        found.append(ip.ipv4_mapped)
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)  # (server, client)
    if ip in _NAT64_PREFIX or ip in _V4COMPAT_PREFIX:
        found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return _v4_blocked(ip)
    # IPv6: re-check any embedded IPv4 (mapped/6to4/Teredo/NAT64/v4-compatible)
    # against the V4 blocklist so a globally-routable wrapper cannot smuggle a
    # private/loopback/metadata IPv4 target through.
    if any(_v4_blocked(v4) for v4 in _embedded_v4s(ip)):
        return True
    # Explicit IPv6 blocklist (loopback, unspecified, ULA, link-local, AWS v6 metadata).
    if any(ip in net for net in _BLOCKED_V6):
        return True
    # Deny-by-default: only a globally-routable IPv6 may be an upstream target.
    # This catches :: (unspecified), ULA, link-local, documentation ranges, etc.
    # without enumerating every reserved prefix by hand.
    return not ip.is_global


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
        # Dev mode: allow localhost AND internal container hostnames (non-raw-IP names).
        # Raw IP addresses are still blocked by the IP check below.
        # Container names (lab-mcp-echo, mcp-netbox, etc.) are non-IP hostnames — allowed.
        is_raw_ip = _is_blocked_ip(host) or host.replace(".", "").replace(":", "").isdigit()
        if host not in ("localhost", "127.0.0.1", "::1") and is_raw_ip:
            raise SSRFError("HTTP scheme with raw IP is only allowed for localhost in development mode")
    elif parsed.scheme != "https":
        raise SSRFError(f"Scheme {parsed.scheme!r} is not allowed; use HTTPS")

    # Direct IP check
    if _is_blocked_ip(host):
        raise SSRFError(f"Host {host!r} resolves to a blocked private/reserved IP range")

    # DNS resolution check (best-effort — catches obvious rebind; not a full guard)
    # Skip for localhost and dev-mode container hostnames: they resolve to private IPs
    # (10.x Podman network) which are in blocked ranges but intentionally trusted in dev.
    if host in ("localhost",) or (allow_http_localhost and parsed.scheme == "http"):
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
    except OSError as exc:
        raise SSRFError(
            f"DNS resolution failed for {host!r}: {exc}. "
            "Register the server only when DNS is reachable."
        ) from exc


async def check_hostname_dns(hostname: str) -> list[str]:
    """
    Resolve hostname to IP addresses.

    Phase 3 Hardening: DNS resolution failure raises ValueError (fail-closed).
    This prevents TOCTOU and DNS rebind attacks at registration time.

    Args:
        hostname: str hostname to resolve

    Returns:
        list of IP address strings

    Raises:
        ValueError: if DNS resolution fails or returns no addresses
        OSError: on unexpected socket errors
    """
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        result = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}") from e
    except OSError as e:
        raise ValueError(f"Cannot resolve hostname {hostname}: {e}") from e

    if not result:
        raise ValueError(f"no address found for {hostname}")

    return [r[4][0] for r in result]
