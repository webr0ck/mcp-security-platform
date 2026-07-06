"""
scanner-worker's own git-provider validation + clone.

Deliberately a trimmed, standalone re-implementation of
proxy/app/services/git_providers.py's SSRF/host-shape validation — this
process must not import proxy application code (it would drag in
platform_secrets/credential_store access patterns this worker must never
have). Keep the SSRF logic in lock-step with git_providers.py if that file
changes; this is a known duplication accepted for isolation (see README.md).

Token handling: the worker does NOT read platform_secrets/credential_store
(no DB grant to do so — V063). Instead it takes a per-provider token from
its own environment: GIT_CLONE_TOKEN_<PROVIDER_UPPER>, e.g.
GIT_CLONE_TOKEN_GITHUB. This is the worker's own narrowly-scoped,
read-only credential — not one of the proxy's secrets.
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

_ALWAYS_BLOCK_V4 = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]
_ALWAYS_BLOCK_V6 = [
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::/32"),
]
_PRIVATE_V4 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
]
_PRIVATE_V6 = [ipaddress.ip_network("fc00::/7")]


class GitHostError(Exception):
    """Raised when a git provider host fails SSRF validation, or clone fails."""


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    enabled: bool
    host: str
    clone_account: str | None
    allow_private: bool


def _github_re(host: str) -> re.Pattern:
    return re.compile(
        rf'^https://{re.escape(host)}/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?/?$'
    )


def _bitbucket_re(host: str) -> re.Pattern:
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


async def load_providers(pool) -> list[ProviderConfig]:
    rows = await pool.fetch(
        "SELECT provider, enabled, host, clone_account, allow_private FROM git_providers"
    )
    return [ProviderConfig(r["provider"], r["enabled"], r["host"],
                            r["clone_account"], r["allow_private"]) for r in rows]


async def match_provider(pool, url: str) -> ProviderConfig | None:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    for p in await load_providers(pool):
        if p.enabled and p.host.lower() == host and _url_re(p.provider, p.host).match(url):
            return p
    return None


def provider_token(provider: str) -> str | None:
    """Worker's OWN env-var-scoped clone token — never platform_secrets."""
    return os.environ.get(f"GIT_CLONE_TOKEN_{provider.upper()}") or None


def _classify_ip(ip_str: str) -> str:
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return "block"
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
                f"host {host!r} resolves to a private address {ip!r}; provider "
                "must set allow_private to permit an internal corporate host"
            )
    return ips


def build_clone_url(url: str, account: str | None, token: str | None) -> str:
    if not token:
        return url
    acct = account or "x-token-auth"
    stripped = url.rstrip("/")
    if stripped.startswith("https://"):
        rest = stripped[len("https://"):]
        return f"https://{acct}:{token}@{rest}"
    return url
