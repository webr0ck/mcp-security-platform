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

# ---------------------------------------------------------------------------
# Always-blocked cloud-metadata floor (ssrf-legacy-gate-unification, 2026-07-17)
#
# NON-CONFIGURABLE. Never exemptable via allowed_cidr, no matter how broad or
# sloppy the stored allowlist entry is (e.g. an admin allowlisting
# 169.254.0.0/16 must NOT open the metadata endpoint). Checked unconditionally,
# before allowed_cidr is even consulted, against the host IP AND every
# resolved IP AND every embedded IPv4 form (IPv4-mapped/6to4/Teredo/NAT64/
# v4-compatible) extracted via _embedded_v4s.
# ---------------------------------------------------------------------------
_METADATA_FLOOR_V4 = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure/OCI link-local metadata
    ipaddress.ip_network("169.254.170.2/32"),    # AWS ECS task metadata
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba Cloud metadata
]
_METADATA_FLOOR_V6 = [
    ipaddress.ip_network("fd00:ec2::254/128"),   # AWS IPv6 metadata
]


def _is_floor_blocked(addr: str) -> bool:
    """
    True if *addr* is (or embeds) a cloud-metadata address. This check is
    unconditional and has no exemption path — not even a matching
    allowed_cidr can bypass it.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        return any(ip in net for net in _METADATA_FLOOR_V4)
    # IPv6: check the address itself, plus any embedded IPv4 form (reuses the
    # same unwrap used by the regular blocklist, so a globally-routable
    # IPv6 wrapper cannot smuggle a metadata IPv4 target past the floor).
    if any(ip in net for net in _METADATA_FLOOR_V6):
        return True
    return any(
        any(v4 in net for net in _METADATA_FLOOR_V4) for v4 in _embedded_v4s(ip)
    )

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


def _is_blocked_ip(
    addr: str,
    allowed_cidr: "ipaddress.IPv4Network | ipaddress.IPv6Network | None" = None,
) -> bool:
    """
    True if *addr* is a private/reserved IP that should be blocked.

    The cloud-metadata floor (_is_floor_blocked) is checked first and is
    NEVER exemptable, regardless of allowed_cidr. Everything else (10/8,
    172.16/12, 192.168/16, 127/8, 100.64/10, the rest of 169.254/16, ULA,
    link-local, etc.) is exemptable when the resolved IP — or its embedded
    IPv4 form, symmetrically — falls inside allowed_cidr.
    """
    if _is_floor_blocked(addr):
        return True
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv4Address):
        blocked = _v4_blocked(ip)
    else:
        # IPv6: re-check any embedded IPv4 (mapped/6to4/Teredo/NAT64/v4-compatible)
        # against the V4 blocklist so a globally-routable wrapper cannot smuggle a
        # private/loopback/metadata IPv4 target through.
        if any(_v4_blocked(v4) for v4 in _embedded_v4s(ip)):
            blocked = True
        # Explicit IPv6 blocklist (loopback, unspecified, ULA, link-local, AWS v6 metadata).
        elif any(ip in net for net in _BLOCKED_V6):
            blocked = True
        else:
            # Deny-by-default: only a globally-routable IPv6 may be an upstream
            # target. This catches :: (unspecified), ULA, link-local,
            # documentation ranges, etc. without enumerating every reserved
            # prefix by hand.
            blocked = not ip.is_global

    if not blocked or allowed_cidr is None:
        return blocked

    # Exemption: the IP itself, OR (symmetrically) any of its embedded IPv4
    # forms, falls inside the single allowed_cidr network. A mismatched
    # address family against allowed_cidr simply never matches (Python's
    # ipaddress __contains__ returns False rather than raising across
    # families) — never treat that as "exempt" (fail closed).
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        candidates.extend(_embedded_v4s(ip))
    if any(_candidate_in_cidr(c, allowed_cidr) for c in candidates):
        return False
    return True


def _candidate_in_cidr(
    ip: "ipaddress.IPv4Address | ipaddress.IPv6Address",
    net: "ipaddress.IPv4Network | ipaddress.IPv6Network",
) -> bool:
    """Version-safe membership check — never raises across mismatched families."""
    try:
        return ip in net
    except TypeError:
        return False


def validate_server_url(
    url: str,
    allow_http_localhost: bool = False,
    allowed_cidr: str | None = None,
) -> None:
    """
    Raise SSRFError if the URL is unsafe.

    Checks performed, in strict order:
    1. URL must be parseable
    2. Scheme must be https (or http if allow_http_localhost and host is localhost/127.0.0.1)
    3. No credentials in the URL (user:pass@ prefix)
    4. Unconditional cloud-metadata floor check (host + every resolved IP) —
       raises regardless of allowed_cidr; never exemptable.
    5. Host/resolved-IP must not be a blocked private/reserved IP UNLESS it
       falls inside allowed_cidr (checked only after floor clears).

    allowed_cidr: a single CIDR string (server_registry.upstream_allowlist_entry)
    that exempts a private/reserved IP host from the blanket private-IP block.
    Pass None (default) to preserve today's blind behaviour — every existing
    caller that doesn't opt in is unaffected. Exemption applies ONLY to the
    private/reserved-range checks; it never overrides scheme enforcement, the
    no-credentials-in-URL check, or the ALWAYS-BLOCKED cloud-metadata floor.
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

    # Parse allowed_cidr once, fail closed on a malformed stored value —
    # never silently degrade to "no exemption" nor "everything exempt".
    # Parsed before the scheme check: the dev-mode raw-IP gate below must also
    # honor the registered allowlist entry.
    _allowed_net: "ipaddress.IPv4Network | ipaddress.IPv6Network | None" = None
    if allowed_cidr:
        try:
            _allowed_net = ipaddress.ip_network(allowed_cidr, strict=False)
        except ValueError as exc:
            raise SSRFError(
                f"Stored allowed_cidr {allowed_cidr!r} is not a valid CIDR: {exc}"
            ) from exc

    # Scheme check
    if parsed.scheme == "http":
        if not allow_http_localhost:
            raise SSRFError("HTTP scheme is not allowed; use HTTPS")
        # Dev mode: allow localhost AND internal container hostnames (non-raw-IP names).
        # Raw IP addresses are still blocked by the IP check below.
        # Container names (lab-mcp-echo, mcp-netbox, etc.) are non-IP hostnames — allowed.
        # Exception: a raw IP inside the registered allowlist CIDR (and off the
        # metadata floor) is a legitimately onboarded plain-HTTP private
        # upstream — server_onboarding already permits plain-HTTP to
        # allowlisted private CIDRs, and this gate must not re-block it.
        # Raw PUBLIC IPs over http stay blocked (the isdigit clause), same as before.
        try:
            _host_ip: "ipaddress.IPv4Address | ipaddress.IPv6Address | None" = ipaddress.ip_address(host)
        except ValueError:
            _host_ip = None
        allowlisted_raw_ip = (
            _host_ip is not None
            and _allowed_net is not None
            and not _is_floor_blocked(host)
            and _candidate_in_cidr(_host_ip, _allowed_net)
        )
        is_raw_ip = _is_blocked_ip(host, _allowed_net) or host.replace(".", "").replace(":", "").isdigit()
        if host not in ("localhost", "127.0.0.1", "::1") and is_raw_ip and not allowlisted_raw_ip:
            raise SSRFError("HTTP scheme with raw IP is only allowed for localhost in development mode")
    elif parsed.scheme != "https":
        raise SSRFError(f"Scheme {parsed.scheme!r} is not allowed; use HTTPS")

    # Unconditional cloud-metadata floor — checked before allowed_cidr is even
    # consulted, and has no exemption path at all, not even for a matching
    # allowed_cidr.
    if _is_floor_blocked(host):
        raise SSRFError(f"Host {host!r} resolves to a blocked private/reserved IP range (cloud-metadata floor)")

    # Direct IP check (with allowlist exemption for non-floor private ranges)
    if _is_blocked_ip(host, _allowed_net):
        raise SSRFError(f"Host {host!r} resolves to a blocked private/reserved IP range")

    # DNS resolution check (best-effort — catches obvious rebind; not a full guard)
    if host == "localhost":
        return

    if allow_http_localhost and parsed.scheme == "http":
        # Security fix: this branch previously skipped DNS resolution entirely
        # for ANY hostname once dev-mode HTTP was allowed — including a real
        # public, attacker-controlled domain, not just internal lab containers.
        # Dev-mode HTTP exists ONLY so lab container hostnames (which resolve
        # to private Podman-network IPs, themselves in the "blocked" ranges
        # above) can be used; it must still resolve DNS and POSITIVELY require
        # a private/reserved address — never silently trust an unresolved or
        # public hostname.
        try:
            resolved = socket.getaddrinfo(host, None)
        except OSError as exc:
            raise SSRFError(f"DNS resolution failed for {host!r}: {exc}.") from exc
        for _, _, _, _, sockaddr in resolved:
            ip_str = sockaddr[0]
            ip_str_clean = ip_str.split("%")[0]
            # Unconditional metadata floor — every resolved IP, no exemption.
            if _is_floor_blocked(ip_str_clean):
                raise SSRFError(
                    f"Host {host!r} resolves to blocked private/reserved IP {ip_str!r} (cloud-metadata floor)"
                )
            try:
                ip_obj = ipaddress.ip_address(ip_str_clean)
            except ValueError:
                continue
            if ip_obj.is_global:
                raise SSRFError(
                    f"Host {host!r} resolves to a public IP ({ip_str}) — "
                    "dev-mode HTTP is only permitted for internal/private targets"
                )
        return

    try:
        resolved = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in resolved:
            ip_str = sockaddr[0]
            # Unconditional metadata floor — every resolved IP, no exemption
            # (checked ahead of the exemptable _is_blocked_ip call below).
            if _is_floor_blocked(ip_str):
                raise SSRFError(
                    f"Host {host!r} resolves to blocked private/reserved IP {ip_str!r} (cloud-metadata floor)"
                )
            if _is_blocked_ip(ip_str, _allowed_net):
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
