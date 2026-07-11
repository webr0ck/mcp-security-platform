"""
MCP Security Platform — OAuth provider profile catalog (WP-A6, Finding 1 + 2)

See docs/spec/08-finalization-findings-generic-oauth.md. Extends WP-A2's
oauth_provider_policy (issuer/tenant enforcement) with a product-level,
admin-curated CATALOG a non-expert submitter picks from — "Same platform
IdP", "Generic OAuth 2.0", "Microsoft Entra", "Custom OIDC" — optionally
pre-filled via RFC 8414 authorization-server-metadata discovery, and gated
by the same reviewer-approval + high-risk-scope-acknowledgement pattern
oauth_policy.py already uses.

This module does NOT replace oauth_provider_policy: a profile's issuer/
scopes still validate against a matching policy row (or create one) at
server-submission-approval time via submission.py's existing
_validate_oauth_policy_at_approval. oauth_provider_profile is a layer ABOVE
that, selected earlier in the journey (server onboarding wizard), primarily
to (a) avoid the submitter ever seeing implementation terms like
"kc_token_exchange", and (b) let a brand-new external OAuth provider be
configured via RFC 8414 discovery instead of hand-typing every endpoint.

Fail-soft vs fail-closed, deliberately different postures in this module:
  - RFC 8414 discovery (discover_metadata) is a UX convenience, not a
    security control — a provider that doesn't publish metadata (or is
    temporarily unreachable) MUST still be configurable by manual entry.
    discover_metadata therefore returns None on any failure, never raises.
  - Profile approval (approve_profile) mirrors oauth_policy.py's fail-closed
    posture: unknown/invalid state transitions and un-acknowledged
    high-risk scopes are rejected, never silently approved.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.oauth_policy import HIGH_RISK_SCOPES
from app.services.ssrf import SSRFError, validate_server_url

logger = logging.getLogger(__name__)

PROVIDER_TYPES: frozenset[str] = frozenset(
    {"same_platform_idp", "generic_oauth2", "entra", "custom_oidc", "jira_cloud"}
)

# RFC 8414 §3.1 (authorization server metadata) is tried first; RFC 8414 §3
# notes an OIDC provider is discoverable at the alternate openid-configuration
# path — both are attempted, first-success wins, matching the pattern already
# used by proxy/app/middleware/auth.py::_discover_jwks_uri.
_METADATA_PATHS: tuple[str, ...] = (
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
)

_DISCOVERY_TIMEOUT_SECONDS = 5.0


class OAuthProviderProfileError(Exception):
    """Base class for profile catalog failures."""


class ProfileNotFoundError(OAuthProviderProfileError):
    def __init__(self, profile_id: str) -> None:
        self.profile_id = profile_id
        super().__init__(f"oauth_provider_profile {profile_id!r} not found")


class InvalidProfileStateTransitionError(OAuthProviderProfileError):
    def __init__(self, current_status: str, requested: str) -> None:
        self.current_status = current_status
        self.requested = requested
        super().__init__(
            f"cannot transition oauth_provider_profile from {current_status!r} to {requested!r}"
        )


class HighRiskScopeAckRequiredError(OAuthProviderProfileError):
    def __init__(self, high_risk_scopes: list[str]) -> None:
        self.high_risk_scopes = high_risk_scopes
        super().__init__(
            f"profile requests high-risk scope(s) {high_risk_scopes}; "
            "explicit reviewer acknowledgement (high_risk_scopes_approved=true) is required"
        )


@dataclass(frozen=True)
class DiscoveredMetadata:
    """RFC 8414 (or OIDC discovery) fields, pre-filled into a draft profile.
    Every field is Optional — a provider may publish a partial document."""

    issuer: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    scopes_supported: list[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: list[str] = field(default_factory=list)
    grant_types_supported: list[str] = field(default_factory=list)
    metadata_url: str = ""


async def discover_metadata(issuer_or_metadata_url: str) -> DiscoveredMetadata | None:
    """
    Attempt RFC 8414 / OIDC discovery-metadata retrieval for a submitter-
    provided issuer URL (or an explicit metadata document URL).

    Returns None (never raises) when no metadata document is reachable or
    parseable — the caller (create_draft_profile / the onboarding wizard)
    MUST fall back to manual endpoint entry in that case; this is a UX
    convenience, not a trust boundary, so failing soft is correct here
    (contrast with oauth_policy.py's fail-closed enforcement checks).
    """
    base = issuer_or_metadata_url.rstrip("/")

    # SSRF guard: discovery fetches a submitter/admin-supplied URL — an admin
    # session (or a request crafted to look like one) pointing this at an
    # internal metadata service, loopback admin panel, or private-range host
    # would make the platform issue the request from its own network
    # position. Validated ONCE up front (all candidate paths share the same
    # host) so a blocked host never reaches httpx at all — this check is
    # fail-closed even though the surrounding discovery flow is fail-soft:
    # an unsafe host returns None (falls back to manual entry) exactly like
    # any other discovery miss, it just never makes the network call.
    from app.core.config import settings as _settings
    try:
        validate_server_url(base, allow_http_localhost=(_settings.ENVIRONMENT == "development"))
    except SSRFError as exc:
        logger.warning("oauth_provider_profile discovery refused unsafe host for %r: %s", base, exc)
        return None

    if base.endswith((".well-known/oauth-authorization-server", ".well-known/openid-configuration")):
        candidates = (base,)
    else:
        candidates = tuple(f"{base}{path}" for path in _METADATA_PATHS)

    async with httpx.AsyncClient(timeout=_DISCOVERY_TIMEOUT_SECONDS, follow_redirects=False) as client:
        for url in candidates:
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                data = resp.json()
            except Exception as exc:
                logger.info("oauth_provider_profile discovery miss for %s: %s", url, exc)
                continue

            if not isinstance(data, dict) or not data.get("token_endpoint"):
                # A 200 with no token_endpoint isn't a usable AS/OIDC metadata
                # document (e.g. an unrelated JSON API at that path) — keep trying.
                continue

            return DiscoveredMetadata(
                issuer=data.get("issuer"),
                authorization_endpoint=data.get("authorization_endpoint"),
                token_endpoint=data.get("token_endpoint"),
                jwks_uri=data.get("jwks_uri"),
                scopes_supported=list(data.get("scopes_supported") or []),
                token_endpoint_auth_methods_supported=list(
                    data.get("token_endpoint_auth_methods_supported") or []
                ),
                grant_types_supported=list(data.get("grant_types_supported") or []),
                metadata_url=url,
            )

    logger.info(
        "oauth_provider_profile: no RFC 8414/OIDC metadata document found for %r "
        "— caller must fall back to manual entry",
        issuer_or_metadata_url,
    )
    return None


@dataclass(frozen=True)
class ProviderRecommendation:
    """The mapping from a non-expert's plain-language wizard answers to a
    concrete provider_type + injection_mode (Finding 1/2). Never surfaces
    implementation terms like "kc_token_exchange" in `display_label` —
    that string is what the wizard UI should render."""

    provider_type: str
    injection_mode: str
    display_label: str
    requires_admin_setup: list[str]


def recommend_provider_type(
    *,
    same_platform_idp: bool,
    supports_authz_code: bool | None = None,
    per_user: bool | None = None,
    needs_api_key_or_basic: bool = False,
) -> ProviderRecommendation:
    """
    Pure mapping function (Finding 1's wizard question set -> Finding 2's
    non-expert-facing recommendation). No I/O, no DB — the onboarding wizard
    endpoint calls this to decide what to show/require next.

    Question order mirrors the finding doc exactly:
      1. Is the backend service protected by the SAME IdP as this platform?
      2. (if not) Does it support OAuth 2.0 authorization code?
      3. Is access per-user or app-only?
      4. Does the service need an API key/bearer/basic auth instead?
    """
    if needs_api_key_or_basic:
        return ProviderRecommendation(
            provider_type="generic_oauth2",  # not actually OAuth, but keeps one profile shape
            injection_mode="basic_auth",
            display_label="API key / Basic auth (not OAuth)",
            requires_admin_setup=["service_name", "credential (API key or username+secret)"],
        )

    if same_platform_idp:
        # Finding 2: the ONLY user-facing label is "Same platform IdP" — the
        # kc_token_exchange implementation name MUST NOT reach the submitter.
        return ProviderRecommendation(
            provider_type="same_platform_idp",
            injection_mode="kc_token_exchange",
            display_label="Same platform IdP",
            requires_admin_setup=[
                "approved upstream token audience",
                "allowed scopes (if the upstream checks scope)",
            ],
        )

    if supports_authz_code is False:
        # No authorization-code support and not the same IdP → app-only is
        # the only remaining OAuth shape.
        return ProviderRecommendation(
            provider_type="generic_oauth2",
            injection_mode="external_oauth_client_credentials",
            display_label="External service, app-only access",
            requires_admin_setup=["issuer/token endpoint (or metadata URL)", "client_id/client_secret", "scopes"],
        )

    if per_user is False:
        return ProviderRecommendation(
            provider_type="generic_oauth2",
            injection_mode="external_oauth_client_credentials",
            display_label="External OAuth 2.0 service, app-only access",
            requires_admin_setup=["issuer/token endpoint (or metadata URL)", "client_id/client_secret", "scopes"],
        )

    # Default: generic per-user external OAuth 2.0 authorization-code flow.
    return ProviderRecommendation(
        provider_type="generic_oauth2",
        injection_mode="external_oauth_user_token",
        display_label="External OAuth 2.0 service, per-user access",
        requires_admin_setup=[
            "issuer/authorization+token endpoints (or metadata URL)",
            "client_id/client_secret",
            "scopes",
            "redirect URI",
        ],
    )


@dataclass
class ProfileRow:
    id: str
    slug: str
    display_name: str
    provider_type: str
    injection_mode: str | None
    issuer: str | None
    authorization_endpoint: str | None
    token_endpoint: str | None
    jwks_uri: str | None
    metadata_url: str | None
    default_scopes: list[str]
    allowed_scopes: list[str]
    blocked_scopes: list[str]
    allowed_redirect_patterns: list[str]
    allowed_client_auth_methods: list[str]
    token_audience_or_resource: str | None
    supports_pkce: bool
    supports_refresh_token: bool
    supports_client_credentials: bool
    service_adapter: str | None
    status: str
    high_risk_scopes_approved_by: str | None
    created_by: str | None
    approved_by: str | None


def _row_to_profile(m: Any) -> ProfileRow:
    return ProfileRow(
        id=str(m["id"]),
        slug=m["slug"],
        display_name=m["display_name"],
        provider_type=m["provider_type"],
        injection_mode=m["injection_mode"],
        issuer=m["issuer"],
        authorization_endpoint=m["authorization_endpoint"],
        token_endpoint=m["token_endpoint"],
        jwks_uri=m["jwks_uri"],
        metadata_url=m["metadata_url"],
        default_scopes=list(m["default_scopes"] or []),
        allowed_scopes=list(m["allowed_scopes"] or []),
        blocked_scopes=list(m["blocked_scopes"] or []),
        allowed_redirect_patterns=list(m["allowed_redirect_patterns"] or []),
        allowed_client_auth_methods=list(m["allowed_client_auth_methods"] or []),
        token_audience_or_resource=m["token_audience_or_resource"],
        supports_pkce=bool(m["supports_pkce"]),
        supports_refresh_token=bool(m["supports_refresh_token"]),
        supports_client_credentials=bool(m["supports_client_credentials"]),
        service_adapter=m["service_adapter"],
        status=m["status"],
        high_risk_scopes_approved_by=m["high_risk_scopes_approved_by"],
        created_by=m["created_by"],
        approved_by=m["approved_by"],
    )


_SELECT_COLUMNS = """
    id, slug, display_name, provider_type, injection_mode, issuer, authorization_endpoint,
    token_endpoint, jwks_uri, metadata_url, default_scopes, allowed_scopes,
    blocked_scopes, allowed_redirect_patterns, allowed_client_auth_methods,
    token_audience_or_resource, supports_pkce, supports_refresh_token,
    supports_client_credentials, service_adapter, status,
    high_risk_scopes_approved_by, created_by, approved_by
"""


async def create_draft_profile(
    session: AsyncSession,
    *,
    slug: str,
    display_name: str,
    provider_type: str,
    injection_mode: str,
    created_by: str,
    metadata: DiscoveredMetadata | None = None,
    default_scopes: list[str] | None = None,
    allowed_scopes: list[str] | None = None,
    blocked_scopes: list[str] | None = None,
    token_audience_or_resource: str | None = None,
    service_adapter: str | None = None,
    supports_client_credentials: bool = False,
) -> ProfileRow:
    """Create a draft oauth_provider_profile row (status='draft'). Not usable
    by any submission until approve_profile() promotes it to 'approved'.

    allowed_scopes/blocked_scopes were previously accepted only implicitly
    (the columns default to '[]' and were never settable here) — a profile
    created with e.g. default_scopes=["Mail.Read"] had no way to also record
    that "Mail.ReadWrite"/"admin" are explicitly blocked, or that the
    allowed set is wider than the default. Any scope present in BOTH
    allowed_scopes/default_scopes and blocked_scopes is rejected up front
    (ValueError) — an inconsistent profile, not something to silently accept
    and sort out later at approval time.
    """
    if provider_type not in PROVIDER_TYPES:
        raise ValueError(f"unknown provider_type: {provider_type!r}")

    from app.services.auth_modes import all_mode_values
    if injection_mode not in all_mode_values():
        raise ValueError(f"unknown injection_mode: {injection_mode!r}")

    # M-02 fix (2026-07-11 audit): get_service_adapter's runtime fallback is
    # deliberately permissive (unknown slug -> GenericServiceAdapter, so
    # enrollment is never blocked) — but that means a typo'd service_adapter
    # here would silently lose service-specific discovery/verification with
    # no error anywhere. Reject unknown non-null slugs at the write path
    # instead, same pattern as provider_type/injection_mode above.
    if service_adapter is not None:
        from app.credential_broker.adapters.service_adapter_registry import _SERVICE_ADAPTERS
        if service_adapter not in _SERVICE_ADAPTERS:
            raise ValueError(f"unknown service_adapter: {service_adapter!r}")

    default_scopes = default_scopes or []
    allowed_scopes = allowed_scopes or []
    blocked_scopes = blocked_scopes or []
    conflicting = sorted((set(default_scopes) | set(allowed_scopes)) & set(blocked_scopes))
    if conflicting:
        raise ValueError(
            f"scope(s) {conflicting} appear in both allowed/default_scopes and blocked_scopes"
        )

    import json as _json

    row = (
        await session.execute(
            text(
                f"""
                INSERT INTO oauth_provider_profile (
                    slug, display_name, provider_type, injection_mode, issuer,
                    authorization_endpoint, token_endpoint, jwks_uri, metadata_url,
                    default_scopes, allowed_scopes, blocked_scopes,
                    token_audience_or_resource, service_adapter,
                    supports_client_credentials, created_by, status
                ) VALUES (
                    :slug, :display_name, :provider_type, :injection_mode, :issuer,
                    :authz_ep, :token_ep, :jwks_uri, :metadata_url,
                    CAST(:default_scopes AS jsonb), CAST(:allowed_scopes AS jsonb),
                    CAST(:blocked_scopes AS jsonb),
                    :audience, :service_adapter,
                    :supports_cc, :created_by, 'draft'
                )
                RETURNING {_SELECT_COLUMNS}
                """
            ),
            {
                "slug": slug,
                "display_name": display_name,
                "provider_type": provider_type,
                "injection_mode": injection_mode,
                "issuer": metadata.issuer if metadata else None,
                "authz_ep": metadata.authorization_endpoint if metadata else None,
                "token_ep": metadata.token_endpoint if metadata else None,
                "jwks_uri": metadata.jwks_uri if metadata else None,
                "metadata_url": metadata.metadata_url if metadata else None,
                "default_scopes": _json.dumps(default_scopes),
                "allowed_scopes": _json.dumps(allowed_scopes),
                "blocked_scopes": _json.dumps(blocked_scopes),
                "audience": token_audience_or_resource,
                "service_adapter": service_adapter,
                "supports_cc": supports_client_credentials,
                "created_by": created_by,
            },
        )
    ).fetchone()
    await session.commit()
    return _row_to_profile(row._mapping)


async def get_profile(session: AsyncSession, profile_id: str) -> ProfileRow:
    row = (
        await session.execute(
            text(f"SELECT {_SELECT_COLUMNS} FROM oauth_provider_profile WHERE id = CAST(:id AS uuid)"),
            {"id": profile_id},
        )
    ).fetchone()
    if row is None:
        raise ProfileNotFoundError(profile_id)
    return _row_to_profile(row._mapping)


async def list_profiles(session: AsyncSession, *, status: str | None = None) -> list[ProfileRow]:
    if status is not None:
        rows = (
            await session.execute(
                text(f"SELECT {_SELECT_COLUMNS} FROM oauth_provider_profile WHERE status = :status ORDER BY created_at DESC"),
                {"status": status},
            )
        ).fetchall()
    else:
        rows = (
            await session.execute(text(f"SELECT {_SELECT_COLUMNS} FROM oauth_provider_profile ORDER BY created_at DESC"))
        ).fetchall()
    return [_row_to_profile(r._mapping) for r in rows]


async def approve_profile(
    session: AsyncSession,
    profile_id: str,
    *,
    reviewer: str,
    high_risk_scopes_approved: bool = False,
) -> ProfileRow:
    """
    Reviewer-approval gate (Finding 1, "Require an admin/reviewer to approve
    the provider profile before use"). Fail-closed:
      - only 'draft' or 'pending_review' -> 'approved' is a valid transition.
      - if default_scopes OR allowed_scopes intersects HIGH_RISK_SCOPES and the
        reviewer has not set high_risk_scopes_approved=true, raise rather than
        silently pass — mirrors oauth_policy.py's HighRiskScopeApprovalRequiredError
        posture. allowed_scopes is included (not just default_scopes) because a
        profile now settable with a broad allowed_scopes set could otherwise
        approve a high-risk scope invisibly, just by it not being the default.
    """
    profile = await get_profile(session, profile_id)
    if profile.status not in ("draft", "pending_review"):
        raise InvalidProfileStateTransitionError(profile.status, "approved")

    high_risk = sorted((set(profile.default_scopes) | set(profile.allowed_scopes)) & HIGH_RISK_SCOPES)
    if high_risk and not high_risk_scopes_approved:
        raise HighRiskScopeAckRequiredError(high_risk)

    await session.execute(
        text(
            """
            UPDATE oauth_provider_profile
               SET status = 'approved',
                   approved_by = :reviewer,
                   approved_at = now(),
                   high_risk_scopes_approved_by = CASE WHEN :high_risk_ack THEN :reviewer ELSE high_risk_scopes_approved_by END,
                   high_risk_scopes_approved_at = CASE WHEN :high_risk_ack THEN now() ELSE high_risk_scopes_approved_at END
             WHERE id = CAST(:id AS uuid)
            """
        ),
        {"id": profile_id, "reviewer": reviewer, "high_risk_ack": bool(high_risk) and high_risk_scopes_approved},
    )
    await session.commit()

    # WP-A6 Finding 6: sync the matching oauth_provider_policy row so a real
    # submission against this issuer doesn't separately fail closed with
    # UnknownIssuerError just because no admin hand-authored a policy row —
    # see sync_policy_from_provider_profile's docstring for why this only
    # widens, never narrows, an existing policy.
    if profile.issuer:
        from app.services.oauth_policy import sync_policy_from_provider_profile
        await sync_policy_from_provider_profile(
            session,
            issuer=profile.issuer,
            allowed_scopes=profile.allowed_scopes or profile.default_scopes,
            blocked_scopes=profile.blocked_scopes,
            allowed_redirect_patterns=profile.allowed_redirect_patterns,
            allowed_client_auth_methods=profile.allowed_client_auth_methods,
            token_audience_or_resource=profile.token_audience_or_resource,
            created_by=reviewer,
        )
        await session.commit()

    return await get_profile(session, profile_id)


async def reject_profile(session: AsyncSession, profile_id: str, *, reviewer: str, reason: str) -> ProfileRow:
    profile = await get_profile(session, profile_id)
    if profile.status not in ("draft", "pending_review"):
        raise InvalidProfileStateTransitionError(profile.status, "rejected")
    await session.execute(
        text(
            """
            UPDATE oauth_provider_profile
               SET status = 'rejected', approved_by = :reviewer, rejection_reason = :reason
             WHERE id = CAST(:id AS uuid)
            """
        ),
        {"id": profile_id, "reviewer": reviewer, "reason": reason},
    )
    await session.commit()
    return await get_profile(session, profile_id)
