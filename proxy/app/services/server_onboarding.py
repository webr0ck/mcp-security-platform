"""
MCP Security Platform — Server Onboarding Validation Service

Core orchestration service for server registration onboarding.
Validates mode↔IdP combinations, performs SSRF checks with fail-closed DNS,
and validates upstream URLs.

Key responsibilities:
  1. validate_mode_and_idp: Ensure injection mode and IdP type are compatible
  2. validate_upstream_url_ssrf: SSRF check with fail-closed DNS (Phase 3 hardening)
  3. validate_upstream_idp_config: Validate IdP configuration structure

Phase 3 Hardening:
  - DNS resolution failure now raises (fail-closed, not pass)
  - This prevents DNS rebind attacks and TOCTOU races
"""
from __future__ import annotations

import asyncio
import logging
import socket
from urllib.parse import urlparse

from app.services.ssrf import _is_blocked_ip

logger = logging.getLogger(__name__)


class InvalidOnboardingConfig(Exception):
    """Raised when server onboarding config is invalid or incompatible."""


# ============================================================================
# Injection Mode ↔ IdP Type Validation
# ============================================================================


def validate_mode_and_idp(
    injection_mode: str,
    upstream_idp_type: str | None,
    upstream_idp_config: dict | None,
) -> None:
    """
    Validate that injection mode and IdP type are compatible.

    Compatibility matrix:
      - oauth_user_token → requires upstream_idp_type='gateway_idp', no config
      - entra_user_token → requires upstream_idp_type='entra' + config
      - entra_client_credentials → requires upstream_idp_type='entra' + config
      - user, service_account, service, none → accept None for upstream_idp_type

    Args:
        injection_mode: str value from InjectionMode enum
        upstream_idp_type: IdP type ('gateway_idp', 'entra', etc.) or None
        upstream_idp_config: dict with IdP config (issuer, client_id, etc.) or None

    Raises:
        InvalidOnboardingConfig: if incompatible combination
    """
    # Validate injection_mode is known
    valid_modes = {
        "none",
        "service",
        "user",
        "service_account",
        "oauth_user_token",
        "entra_client_credentials",
        "entra_user_token",
    }
    if injection_mode not in valid_modes:
        raise InvalidOnboardingConfig(
            f"unknown injection_mode '{injection_mode}'; "
            f"must be one of {valid_modes}"
        )

    # oauth_user_token requires gateway_idp
    if injection_mode == "oauth_user_token":
        if upstream_idp_type != "gateway_idp":
            raise InvalidOnboardingConfig(
                f"injection_mode='oauth_user_token' requires "
                f"upstream_idp_type='gateway_idp', got '{upstream_idp_type}'"
            )

    # entra_user_token requires entra IdP + config
    elif injection_mode == "entra_user_token":
        if upstream_idp_type != "entra":
            raise InvalidOnboardingConfig(
                f"injection_mode='entra_user_token' requires "
                f"upstream_idp_type='entra', got '{upstream_idp_type}'"
            )
        if not upstream_idp_config:
            raise InvalidOnboardingConfig(
                f"injection_mode='entra_user_token' requires upstream_idp_config "
                "with issuer and client_id"
            )

    # entra_client_credentials requires entra IdP + config
    elif injection_mode == "entra_client_credentials":
        if upstream_idp_type != "entra":
            raise InvalidOnboardingConfig(
                f"injection_mode='entra_client_credentials' requires "
                f"upstream_idp_type='entra', got '{upstream_idp_type}'"
            )
        if not upstream_idp_config:
            raise InvalidOnboardingConfig(
                f"injection_mode='entra_client_credentials' requires upstream_idp_config "
                "with issuer and client_id"
            )

    # user, service_account, service, none: no IdP type requirement


# ============================================================================
# IdP Configuration Validation
# ============================================================================


def validate_upstream_idp_config(
    upstream_idp_type: str,
    upstream_idp_config: dict | None,
) -> None:
    """
    Validate upstream IdP configuration structure.

    If config is provided, validates:
      - issuer: valid URI format, non-empty
      - client_id: non-empty string
      - scopes: optional, must be list of strings if present

    Args:
        upstream_idp_type: IdP type name ('entra', 'gateway_idp', etc.)
        upstream_idp_config: dict with issuer, client_id, scopes, or None/empty

    Raises:
        InvalidOnboardingConfig: if config is invalid
    """
    if not upstream_idp_config:
        # None or empty dict is acceptable
        return

    # issuer is required
    if "issuer" not in upstream_idp_config:
        raise InvalidOnboardingConfig(
            f"upstream_idp_config for '{upstream_idp_type}' is missing required field 'issuer'"
        )

    issuer = upstream_idp_config["issuer"]
    if not isinstance(issuer, str) or not issuer.strip():
        raise InvalidOnboardingConfig(
            f"upstream_idp_config['issuer'] must be a non-empty string, got {type(issuer).__name__}"
        )

    # Validate issuer is a valid URI
    try:
        parsed = urlparse(issuer)
        if not parsed.scheme or not parsed.netloc:
            raise InvalidOnboardingConfig(
                f"upstream_idp_config['issuer'] must be a valid URI (has scheme and netloc), got '{issuer}'"
            )
    except Exception as exc:
        raise InvalidOnboardingConfig(
            f"upstream_idp_config['issuer'] is not a valid URI: {exc}"
        ) from exc

    # client_id is required
    if "client_id" not in upstream_idp_config:
        raise InvalidOnboardingConfig(
            f"upstream_idp_config for '{upstream_idp_type}' is missing required field 'client_id'"
        )

    client_id = upstream_idp_config["client_id"]
    if not isinstance(client_id, str) or not client_id.strip():
        raise InvalidOnboardingConfig(
            f"upstream_idp_config['client_id'] must be a non-empty string, got {type(client_id).__name__}"
        )

    # scopes is optional but if present must be list of strings
    if "scopes" in upstream_idp_config:
        scopes = upstream_idp_config["scopes"]
        if not isinstance(scopes, list):
            raise InvalidOnboardingConfig(
                f"upstream_idp_config['scopes'] must be a list, got {type(scopes).__name__}"
            )
        for scope in scopes:
            if not isinstance(scope, str):
                raise InvalidOnboardingConfig(
                    f"upstream_idp_config['scopes'] must contain only strings, found {type(scope).__name__}"
                )


# ============================================================================
# Upstream URL SSRF Validation (Fail-Closed DNS)
# ============================================================================


async def validate_upstream_url_ssrf(upstream_url: str) -> None:
    """
    Validate upstream URL against SSRF, with fail-closed DNS resolution.

    Phase 3 Hardening:
      - DNS resolution failure raises InvalidOnboardingConfig (fail-closed)
      - Prevents TOCTOU and DNS rebind attacks
      - Blocks private/reserved IPv4 and IPv6 ranges

    Checks performed:
      1. URL must be parseable
      2. Scheme must be HTTPS (no HTTP for upstream services)
      3. Host must not be raw private/reserved IP
      4. DNS resolution must succeed and resolve to public IP
      5. No embedded credentials (user:pass@)

    Args:
        upstream_url: str URL to validate

    Raises:
        InvalidOnboardingConfig: if URL fails any check

    Returns:
        None on success
    """
    # Parse URL
    try:
        parsed = urlparse(upstream_url)
    except Exception as exc:
        raise InvalidOnboardingConfig(f"Cannot parse URL: {exc}") from exc

    if not parsed.scheme:
        raise InvalidOnboardingConfig("URL must have an explicit scheme (https://)")

    host = parsed.hostname or ""
    if not host:
        raise InvalidOnboardingConfig("URL must have a hostname")

    # No embedded credentials
    if parsed.username or parsed.password:
        raise InvalidOnboardingConfig("URL must not contain credentials (user:pass@)")

    # HTTPS only
    if parsed.scheme != "https":
        raise InvalidOnboardingConfig(
            f"Scheme '{parsed.scheme}' is not allowed for upstream; use HTTPS"
        )

    # Block direct private IP addresses
    if _is_blocked_ip(host):
        raise InvalidOnboardingConfig(
            f"Hostname '{host}' is a blocked private/reserved IP address"
        )

    # Phase 3 Hardening: DNS resolution MUST succeed (fail-closed)
    # This prevents TOCTOU races and DNS rebind attacks
    try:
        loop = asyncio.get_event_loop()
        resolved = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise InvalidOnboardingConfig(
            f"DNS resolution failed for '{host}': {exc}. "
            "Phase 3 hardening: DNS failures are fail-closed."
        ) from exc
    except OSError as exc:
        raise InvalidOnboardingConfig(
            f"Cannot resolve hostname '{host}': {exc}"
        ) from exc

    if not resolved:
        raise InvalidOnboardingConfig(
            f"No address found for hostname '{host}'"
        )

    # Check all resolved IPs against blocked ranges
    for family, socktype, proto, canonname, sockaddr in resolved:
        ip_str = sockaddr[0]  # sockaddr is (host, port) for AF_INET or (host, port, flowinfo, scope) for AF_INET6
        if _is_blocked_ip(ip_str):
            raise InvalidOnboardingConfig(
                f"Hostname '{host}' resolves to blocked private/reserved IP '{ip_str}'"
            )

    logger.info(f"Validated upstream URL SSRF: {upstream_url}")
