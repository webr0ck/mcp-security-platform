"""
MCP Security Platform — Server Onboarding Validation Service

Core orchestration service for server registration onboarding.
Validates mode↔IdP combinations, performs SSRF checks with fail-closed DNS,
and validates upstream URLs.

Key responsibilities:
  1. validate_mode_and_idp: Ensure injection mode and IdP type are compatible
  2. validate_upstream_url_ssrf: SSRF check with fail-closed DNS (Phase 3 hardening)
  3. validate_upstream_idp_config: Validate IdP configuration structure
  4. revalidate_upstream_ip_at_invoke: Invoke-time re-validation (Task 3.1)

Task 3.1 additions (ISO-F2.6 — private-upstream SSRF allowlist):
  - UPSTREAM_PRIVATE_CIDR_ALLOWLIST support in validate_upstream_url_ssrf
  - revalidate_upstream_ip_at_invoke for DNS-rebind / TOCTOU mitigation at call time
  - Matched allowlist entry returned for server_registry provenance recording

Phase 3 Hardening:
  - DNS resolution failure now raises (fail-closed, not pass)
  - This prevents DNS rebind attacks and TOCTOU races
"""
from __future__ import annotations

import asyncio
import ipaddress
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
# Private CIDR Allowlist helpers (Task 3.1)
# ============================================================================


def _parse_cidr_allowlist(cidr_list: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Parse a list of CIDR strings into network objects.

    Raises:
        InvalidOnboardingConfig: if any entry is not a valid CIDR.
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in cidr_list:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise InvalidOnboardingConfig(
                f"UPSTREAM_PRIVATE_CIDR_ALLOWLIST entry '{entry}' is not a valid CIDR: {exc}"
            ) from exc
    return networks


def _ip_in_allowlist(
    ip_str: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str | None:
    """
    Return the matching CIDR string if ip_str is contained in any network,
    or None if it is not.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in networks:
        if ip in net:
            return str(net)
    return None


def _validate_resolved_ips_against_allowlist(
    host: str,
    ip_addresses: list[str],
    allowlist_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str:
    """
    Validate that ALL resolved IPs for *host* are either:
      (a) public (not blocked), OR
      (b) within the same single allowlist CIDR entry.

    A hostname resolving to a MIX of allowlisted and non-allowlisted (or public
    and private) addresses is DENIED — this is the strictest interpretation and
    closes partial-rebind attacks.

    Returns:
        The matched CIDR string if ALL addresses are private-and-allowlisted.
        Empty string "" if ALL addresses are public.

    Raises:
        InvalidOnboardingConfig: if any IP is private and not in the allowlist,
            or if addresses fall into different CIDR buckets (mixed resolution).
    """
    if not ip_addresses:
        raise InvalidOnboardingConfig(f"No address found for hostname '{host}'")

    # Categorise each resolved IP
    matched_cidrs: set[str] = set()
    public_count = 0

    for ip_str in ip_addresses:
        if _is_blocked_ip(ip_str):
            # Private address — must be within the allowlist
            match = _ip_in_allowlist(ip_str, allowlist_networks)
            if match is None:
                raise InvalidOnboardingConfig(
                    f"Hostname '{host}' resolves to private/reserved IP '{ip_str}' "
                    "which is not covered by UPSTREAM_PRIVATE_CIDR_ALLOWLIST. "
                    "Add the containing CIDR to UPSTREAM_PRIVATE_CIDR_ALLOWLIST to "
                    "permit this private upstream, or use a public IP."
                )
            matched_cidrs.add(match)
        else:
            public_count += 1

    # Mixed resolution: some public, some private-allowlisted → deny
    if matched_cidrs and public_count > 0:
        raise InvalidOnboardingConfig(
            f"Hostname '{host}' resolves to a mix of public and private-allowlisted IPs. "
            "All resolved addresses must be consistently public or consistently within "
            "the same allowlisted CIDR. This hostname is not safe to register."
        )

    # Private addresses in MORE THAN ONE different allowlist CIDR → deny
    # (prevents a hostname that straddles two trust zones)
    if len(matched_cidrs) > 1:
        raise InvalidOnboardingConfig(
            f"Hostname '{host}' resolves to IPs spanning multiple allowlist CIDRs "
            f"({', '.join(sorted(matched_cidrs))}). "
            "All resolved addresses must fall within a single allowlist entry."
        )

    if matched_cidrs:
        return next(iter(matched_cidrs))  # the single matched CIDR
    return ""  # all public


# ============================================================================
# Upstream URL SSRF Validation (Fail-Closed DNS)
# ============================================================================


async def validate_upstream_url_ssrf(
    upstream_url: str,
    private_cidr_allowlist: list[str] | None = None,
    allow_http_dev: bool = False,
) -> str | None:
    """
    Validate upstream URL against SSRF, with fail-closed DNS resolution.

    Task 3.1: accepts an optional private_cidr_allowlist.  When the list is
    non-empty, private IPs that fall within an allowlist entry are permitted;
    the matched entry is returned so the caller can persist it as provenance on
    the server_registry row.

    Phase 3 Hardening:
      - DNS resolution failure raises InvalidOnboardingConfig (fail-closed)
      - Prevents TOCTOU and DNS rebind attacks
      - Blocks private/reserved IPv4 and IPv6 ranges UNLESS allowlisted

    Checks performed:
      1. URL must be parseable
      2. Scheme must be HTTPS (plain HTTP only via allow_http_dev, see below)
      3. Host must not be raw private/reserved IP (unless in allowlist)
      4. DNS resolution must succeed
      5. ALL resolved IPs must be public OR ALL within a single allowlist CIDR
         (mixed resolution is denied — closes partial-rebind attacks)
      6. No embedded credentials (user:pass@)

    Args:
        upstream_url: str URL to validate
        private_cidr_allowlist: optional list of CIDR strings that permit private
            upstream addresses.  Default None / empty list = current behaviour
            (all private IPs blocked).
        allow_http_dev: dev-environment-only relaxation (callers must gate it on
            settings.ENVIRONMENT == "development").  Permits scheme http, but
            ONLY when every resolved IP is private AND covered by a single
            private_cidr_allowlist entry — a plain-HTTP URL whose target is
            public, or private-but-not-allowlisted, is still denied.  This is
            deliberately STRICTER than ssrf.validate_server_url's dev-mode
            branch: dev HTTP here always yields a persistable allowlist-entry
            provenance record, never a public or unrecorded target.

    Returns:
        The matched allowlist CIDR string if a private upstream was allowlisted,
        empty string "" for public upstreams, or None when the allowlist is not
        used (legacy / empty list path — same as "").

    Raises:
        InvalidOnboardingConfig: if URL fails any check
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

    # HTTPS only (plain HTTP only in dev mode, and even then only for
    # allowlisted private targets — enforced further down)
    if parsed.scheme != "https" and not (allow_http_dev and parsed.scheme == "http"):
        raise InvalidOnboardingConfig(
            f"Scheme '{parsed.scheme}' is not allowed for upstream; use HTTPS"
        )
    _is_dev_http = parsed.scheme == "http"

    # Build the parsed allowlist networks (raises InvalidOnboardingConfig on bad CIDR)
    allowlist: list[str] = private_cidr_allowlist or []
    allowlist_networks = _parse_cidr_allowlist(allowlist)

    # Block direct private IP addresses when NOT in the allowlist
    if _is_blocked_ip(host):
        if not allowlist_networks:
            raise InvalidOnboardingConfig(
                f"Hostname '{host}' is a blocked private/reserved IP address"
            )
        # host is a raw IP and the allowlist is non-empty: check it directly
        match = _ip_in_allowlist(host, allowlist_networks)
        if match is None:
            raise InvalidOnboardingConfig(
                f"Hostname '{host}' is a private/reserved IP address not covered "
                "by UPSTREAM_PRIVATE_CIDR_ALLOWLIST"
            )
        logger.info(
            "validate_upstream_url_ssrf: raw private IP allowed via allowlist entry",
            extra={"host": host, "allowlist_entry": match},
        )
        return match

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

    ip_addresses = [sockaddr[0] for _, _, _, _, sockaddr in resolved]

    if allowlist_networks:
        # Allowlist path: validate ALL resolved IPs together — mixed resolution is denied
        matched_entry = _validate_resolved_ips_against_allowlist(
            host, ip_addresses, allowlist_networks
        )
        if _is_dev_http and not matched_entry:
            # Dev-mode HTTP is ONLY for internal/private lab targets. A plain-HTTP
            # URL that resolves public would otherwise register with no allowlist
            # provenance and an unencrypted, attacker-reachable upstream.
            raise InvalidOnboardingConfig(
                f"Plain-HTTP upstream '{host}' resolves to public IP(s) — "
                "dev-mode HTTP is only permitted for private targets covered by "
                "UPSTREAM_PRIVATE_CIDR_ALLOWLIST. Use HTTPS for public upstreams."
            )
        if matched_entry:
            logger.info(
                "validate_upstream_url_ssrf: private upstream allowed via CIDR allowlist",
                extra={"host": host, "allowlist_entry": matched_entry},
            )
        else:
            logger.info(
                "validate_upstream_url_ssrf: public upstream validated (allowlist present but not used)",
                extra={"host": host},
            )
        return matched_entry
    else:
        # Legacy path: block any private IP (no allowlist)
        if _is_dev_http:
            # No allowlist configured → no provenance record is possible, so
            # dev-mode HTTP has nothing safe to bind to. Fail closed.
            raise InvalidOnboardingConfig(
                f"Plain-HTTP upstream '{host}' requires UPSTREAM_PRIVATE_CIDR_ALLOWLIST "
                "to be configured with the CIDR covering the private target. "
                "Use HTTPS for public upstreams."
            )
        for ip_str in ip_addresses:
            if _is_blocked_ip(ip_str):
                raise InvalidOnboardingConfig(
                    f"Hostname '{host}' resolves to blocked private/reserved IP '{ip_str}'"
                )

    logger.info(f"Validated upstream URL SSRF: {upstream_url}")
    return None


# ============================================================================
# Invoke-time upstream IP re-validation (Task 3.1 — DNS-rebind / TOCTOU)
# ============================================================================


async def revalidate_upstream_ip_at_invoke(
    upstream_url: str,
    registered_allowlist_entry: str | None,
) -> list[str]:
    """
    Re-validate the upstream host's resolved IPs at invocation time.

    This is the TOCTOU / DNS-rebind mitigation called from the invoke path
    (services/invocation.py Step 3c) AFTER the existing SSRF check
    (validate_server_url / Step 3b).

    Policy:
      - If registered_allowlist_entry is None or "": the upstream was registered
        as a public upstream.  All resolved IPs must be non-private.  Any private
        IP causes a deny (the hostname has re-resolved to an internal address after
        registration — classic rebind).
      - If registered_allowlist_entry is set: the upstream is a known-private server.
        ALL resolved IPs must fall within the registered CIDR.  Any IP outside it
        causes a deny (rebind to a different internal host, or the CIDR changed).
      - Mixed resolution (some IPs in CIDR, some outside) → deny regardless.

    The caller uses the returned list to pin the httpx connection to one of the
    validated IPs, preventing the OS from re-resolving the hostname before
    connecting.  Pass the first IP to ``PinnedIPTransport`` in
    ``app.services.pinned_transport`` together with the original hostname so
    that TLS SNI and the Host header remain correct.

    Args:
        upstream_url: Full URL string — hostname is extracted.
        registered_allowlist_entry: The CIDR recorded on server_registry at
            registration time (upstream_allowlist_entry column).  None / "" for
            public upstreams.

    Returns:
        List of IP address strings that passed validation.  Non-empty; the caller
        may use any of them to pin the connection.

    Raises:
        UpstreamRevalidationError: if DNS resolution fails OR any resolved IP
            falls outside the registered policy.
    """
    try:
        parsed = urlparse(upstream_url)
    except Exception as exc:
        raise UpstreamRevalidationError(
            f"Cannot parse upstream URL for revalidation: {exc}"
        ) from exc

    host = parsed.hostname or ""
    if not host:
        raise UpstreamRevalidationError(
            "Upstream URL has no hostname — cannot revalidate"
        )

    # Resolve the hostname — fail-closed on DNS error
    try:
        loop = asyncio.get_event_loop()
        resolved = await loop.getaddrinfo(
            host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError) as exc:
        raise UpstreamRevalidationError(
            f"DNS resolution failed for upstream host '{host}' at invoke time: {exc}"
        ) from exc

    if not resolved:
        raise UpstreamRevalidationError(
            f"DNS returned no addresses for upstream host '{host}' at invoke time"
        )

    ip_addresses = [sockaddr[0] for _, _, _, _, sockaddr in resolved]

    if registered_allowlist_entry:
        # Private-upstream path: ALL resolved IPs must stay within the registered CIDR
        try:
            registered_net = ipaddress.ip_network(registered_allowlist_entry, strict=False)
        except ValueError as exc:
            raise UpstreamRevalidationError(
                f"Stored allowlist entry '{registered_allowlist_entry}' is not a valid CIDR: {exc}"
            ) from exc

        outside: list[str] = []
        for ip_str in ip_addresses:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                outside.append(ip_str)
                continue
            if ip_obj not in registered_net:
                outside.append(ip_str)

        if outside:
            raise UpstreamRevalidationError(
                f"Upstream host '{host}' resolved to IP(s) {outside} which are "
                f"outside the registered allowlist CIDR '{registered_allowlist_entry}'. "
                "Possible DNS-rebind attack or configuration drift. "
                "Invocation denied (reason: upstream_revalidation_failed)."
            )
    else:
        # Public-upstream path: no private IPs allowed
        private_ips = [ip for ip in ip_addresses if _is_blocked_ip(ip)]
        if private_ips:
            raise UpstreamRevalidationError(
                f"Upstream host '{host}' was registered as a public upstream but now "
                f"resolves to private/reserved IP(s) {private_ips}. "
                "Possible DNS-rebind attack. "
                "Invocation denied (reason: upstream_revalidation_failed)."
            )

    logger.debug(
        "revalidate_upstream_ip_at_invoke: all IPs validated",
        extra={
            "host": host,
            "ips": ip_addresses,
            "registered_allowlist_entry": registered_allowlist_entry or "(public)",
        },
    )
    return ip_addresses


class UpstreamRevalidationError(Exception):
    """
    Raised when invoke-time upstream IP re-validation fails.

    The invoke path catches this and emits an audit event with
    reason=upstream_revalidation_failed, then returns 503 (fail-closed).
    """
