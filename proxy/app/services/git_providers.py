"""Git provider config for the submission scanner (PRD-0005 R-2).

Adds corporate Bitbucket alongside GitHub. Non-secret config lives in the
git_providers table; the service-account token lives encrypted in
platform_secrets under name 'git-<provider>' (falling back to env for github,
for back-compat).

SSRF (3-critic F-3): the git clone path does not traverse the egress proxy, so
a configured host is validated here — loopback/link-local/metadata are ALWAYS
rejected; RFC1918/private ranges require an explicit allow_private ack. The host
is resolved and re-validated immediately before the clone to keep the TOCTOU
window small. (Byte-exact IP pinning across the git process is a documented
follow-on; the compensating controls are the range checks + read-only token +
tmpfs sandbox + transport hardening in submission_scanner._clone_repo.)
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Always rejected as a clone target, regardless of allow_private.
_ALWAYS_BLOCK_V4 = [
    ipaddress.ip_network("127.0.0.0/8"),      # loopback
    ipaddress.ip_network("169.254.0.0/16"),   # link-local + cloud metadata (169.254.169.254)
    ipaddress.ip_network("0.0.0.0/8"),        # unspecified
]
_ALWAYS_BLOCK_V6 = [
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("fd00:ec2::/32"),    # AWS IPv6 metadata
]
# Rejected UNLESS the provider row sets allow_private=true.
_PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
]
_PRIVATE_V6 = [ipaddress.ip_network("fc00::/7")]   # unique local


class GitHostError(Exception):
    """Raised when a git provider host fails SSRF validation."""


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    enabled: bool
    host: str
    clone_account: str | None
    allow_private: bool


# Per-provider URL shapes. Host is substituted exactly (re.escape) so only the
# configured host matches — no wildcard.
def _github_re(host: str) -> re.Pattern:
    return re.compile(
        rf'^https://{re.escape(host)}/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?/?$'
    )


def _bitbucket_re(host: str) -> re.Pattern:
    # Bitbucket Data Center: /scm/<proj>/<repo>.git  and  /<proj>/repos/<repo>
    # Bitbucket Cloud:       /<workspace>/<repo>
    seg = r'[A-Za-z0-9][A-Za-z0-9_.~-]*'
    return re.compile(
        rf'^https://{re.escape(host)}/('
        rf'scm/{seg}/{seg}\.git'
        rf'|{seg}/repos/{seg}'
        rf'|{seg}/{seg}'
        rf')(\.git)?/?$'
    )


def _url_re(provider: str, host: str) -> re.Pattern:
    return _bitbucket_re(host) if provider == "bitbucket" else _github_re(host)


async def _load_providers() -> list[ProviderConfig]:
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        return []
    rows = await pool.fetch(
        "SELECT provider, enabled, host, clone_account, allow_private FROM git_providers"
    )
    return [ProviderConfig(r["provider"], r["enabled"], r["host"],
                           r["clone_account"], r["allow_private"]) for r in rows]


async def match_provider(url: str) -> ProviderConfig | None:
    """Return the enabled provider whose host+shape matches this URL, else None.

    Provider is inferred from the URL host (no submitter input). An unknown or
    disabled host returns None → the caller rejects the submission.
    """
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    for p in await _load_providers():
        if p.enabled and p.host.lower() == host and _url_re(p.provider, p.host).match(url):
            return p
    return None


async def provider_token(provider: str) -> str | None:
    """Encrypted token from platform_secrets; github falls back to env."""
    from app.services import platform_secrets
    try:
        if await platform_secrets.secret_exists(f"git-{provider}"):
            return await platform_secrets.get_secret(f"git-{provider}")
    except Exception as exc:
        # A configured-but-unobtainable token must not silently become "no token"
        # for a private host; surface it as a clone failure upstream.
        raise GitHostError(f"git token for {provider} unobtainable: {exc}") from exc
    if provider == "github":
        return os.environ.get("GITHUB_CLONE_TOKEN", "") or None
    return None


def _classify_ip(ip_str: str) -> str:
    """Return 'block' | 'private' | 'ok' for a resolved IP."""
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return "block"  # unparseable → refuse
    v4 = ip if ip.version == 4 else (ip.ipv4_mapped or None)
    if v4 is not None:
        if any(v4 in n for n in _ALWAYS_BLOCK_V4):
            return "block"
        if any(v4 in n for n in _PRIVATE_V4):
            return "private"
        return "ok"
    if any(ip in n for n in _ALWAYS_BLOCK_V6):
        return "block"
    if any(ip in n for n in _PRIVATE_V6):
        return "private"
    return "ok"


def validate_host(host: str, allow_private: bool) -> list[str]:
    """Resolve host and SSRF-validate every address. Returns the resolved IPs.

    Raises GitHostError on any always-blocked address, or a private address when
    allow_private is false. Fail-closed on DNS failure.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as exc:
        raise GitHostError(f"DNS resolution failed for {host!r}: {exc}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise GitHostError(f"no addresses resolved for {host!r}")
    for ip in ips:
        cls = _classify_ip(ip)
        if cls == "block":
            raise GitHostError(
                f"host {host!r} resolves to a forbidden address {ip!r} "
                "(loopback/link-local/metadata) — never allowed"
            )
        if cls == "private" and not allow_private:
            raise GitHostError(
                f"host {host!r} resolves to a private address {ip!r}; set allow_private "
                "on the provider to permit an internal corporate host"
            )
    return ips


def build_clone_url(url: str, account: str | None, token: str | None) -> str:
    """Inject account:token into an https clone URL. Falls back to url if no token."""
    if not token:
        return url
    acct = account or "x-token-auth"
    stripped = url.rstrip("/")
    if stripped.startswith("https://"):
        rest = stripped[len("https://"):]
        return f"https://{acct}:{token}@{rest}"
    return url


if __name__ == "__main__":
    # ponytail: self-check — URL shapes + IP classification, no DB/network.
    gh = _github_re("github.com")
    assert gh.match("https://github.com/o/r")
    assert gh.match("https://github.com/o/r.git")
    assert not gh.match("https://evil.com/o/r")
    bb = _bitbucket_re("bitbucket.corp.example")
    assert bb.match("https://bitbucket.corp.example/scm/PROJ/repo.git")
    assert bb.match("https://bitbucket.corp.example/PROJ/repos/repo")
    assert bb.match("https://bitbucket.corp.example/workspace/repo")
    assert not bb.match("https://bitbucket.corp.example/../etc")
    assert _classify_ip("169.254.169.254") == "block"   # cloud metadata
    assert _classify_ip("127.0.0.1") == "block"
    assert _classify_ip("10.1.2.3") == "private"
    assert _classify_ip("140.82.121.4") == "ok"          # github public
    assert build_clone_url("https://github.com/o/r", "bot", "tok") == "https://bot:tok@github.com/o/r"
    assert build_clone_url("https://github.com/o/r", None, None) == "https://github.com/o/r"
    print("git_providers self-check OK")
