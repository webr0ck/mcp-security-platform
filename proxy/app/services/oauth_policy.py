"""
MCP Security Platform — OAuth/IdP policy engine (WP-A2: CR-13 + CR-03 remainder)

Governs which issuer/tenant/scope/redirect/client-auth-method combination an
onboarded OAuth server may request, and separates REQUESTED config
(server_registry.upstream_idp_config, submitter-controlled) from APPROVED
config (server_registry.approved_upstream_idp_config /
approved_token_audience / approved_oauth_scopes, reviewer-controlled).

Two independent validation dimensions — deliberately NOT collapsed into one
allowlist (see V065 migration header and Claude_status.md CR-13 row for the
prior rejected attempt):

  1. Scope-set dimension (this module's `validate_requested_config` /
     `validate_service_account_scope`): a SET of scope strings validated
     against an `oauth_provider_policy` row's allowed_scopes/blocked_scopes.
     Governs entra_user_token, entra_client_credentials, future
     external_oauth_* adapters, AND service_account's `scope` field (e.g.
     "openid") — via a SEPARATE allowlist (SERVICE_ACCOUNT_ALLOWED_SCOPES),
     never the audience allowlist below.

  2. Audience-string dimension (`validate_token_exchange_audience`): a single
     opaque audience string (e.g. "lab-tickets") for kc_token_exchange (RFC
     8693), validated against server_registry.approved_token_audience (the
     per-server reviewer-set value) plus the KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES
     env allowlist as an outer/bootstrap ceiling.

Fail-closed throughout: unknown issuer, overbroad scope, missing policy row,
or policy ambiguity => reject. Never a silent allow.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# High-risk scopes require explicit reviewer approval (recorded identity +
# timestamp), not just a policy-subset pass. Canonical set per the issue
# sketch (___issue-13-oauth-idp-policy-validation.md); PRD-4 names the same
# five as the canonical high-risk set.
HIGH_RISK_SCOPES: frozenset[str] = frozenset(
    {"write", "admin", "mail", "files", "offline_access"}
)

# Default allowlist for service_account mode's `scope` field when no
# server-specific override is configured. "openid" is the standard OIDC
# default scope used by every existing lab service_account tool (lab-gitea,
# lab-grafana-mcp, lab-wazuh). This is a SCOPE-SHAPED allowlist, distinct
# from the kc_token_exchange AUDIENCE allowlist — do not merge the two.
DEFAULT_SERVICE_ACCOUNT_ALLOWED_SCOPES: frozenset[str] = frozenset({"openid", "profile", "email"})


class OAuthPolicyError(Exception):
    """Base class for OAuth/IdP policy engine failures. Always fail-closed."""


class UnknownIssuerError(OAuthPolicyError):
    """No oauth_provider_policy row matches the requested issuer/tenant."""

    def __init__(self, issuer: str, tenant: str | None) -> None:
        self.issuer = issuer
        self.tenant = tenant
        super().__init__(
            f"no oauth_provider_policy row for issuer={issuer!r} tenant={tenant!r}; "
            "fail-closed (unknown issuer)"
        )


class ScopePolicyViolation(OAuthPolicyError):
    """Requested scope(s) are not a subset of the matching policy's allowed_scopes,
    or are explicitly blocked."""

    def __init__(self, disallowed: list[str], blocked: list[str]) -> None:
        self.disallowed = disallowed
        self.blocked = blocked
        parts = []
        if disallowed:
            parts.append(f"not in allowed_scopes: {disallowed}")
        if blocked:
            parts.append(f"explicitly blocked: {blocked}")
        super().__init__("requested scopes rejected — " + "; ".join(parts))


class RedirectPolicyViolation(OAuthPolicyError):
    def __init__(self, redirect_uri: str) -> None:
        self.redirect_uri = redirect_uri
        super().__init__(
            f"redirect_uri {redirect_uri!r} does not match any allowed_redirect_patterns"
        )


class ClientAuthMethodPolicyViolation(OAuthPolicyError):
    def __init__(self, method: str) -> None:
        self.method = method
        super().__init__(f"client_auth_method {method!r} is not in allowed_client_auth_methods")


class HighRiskScopeApprovalRequiredError(OAuthPolicyError):
    """Requested scopes include one or more HIGH_RISK_SCOPES; the reviewer
    must explicitly acknowledge this (not just pass the policy-subset check)."""

    def __init__(self, high_risk_scopes: list[str]) -> None:
        self.high_risk_scopes = high_risk_scopes
        super().__init__(
            f"requested scopes include high-risk scope(s) {high_risk_scopes}; "
            "explicit reviewer approval (high_risk_scopes_approved=true) is required"
        )


class TokenExchangeAudienceViolation(OAuthPolicyError):
    def __init__(self, audience: str, reason: str) -> None:
        self.audience = audience
        self.reason = reason
        super().__init__(f"kc_token_exchange audience {audience!r} rejected: {reason}")


class ServiceAccountScopeViolation(OAuthPolicyError):
    def __init__(self, disallowed: list[str]) -> None:
        self.disallowed = disallowed
        super().__init__(
            f"service_account scope token(s) not allowed: {disallowed} "
            "(scope-shaped validation, independent of the audience allowlist)"
        )


@dataclass
class PolicyRow:
    id: str
    issuer: str
    tenant: str | None
    allowed_scopes: list[str]
    blocked_scopes: list[str]
    max_risk: str
    allowed_redirect_patterns: list[str]
    allowed_client_auth_methods: list[str]
    allowed_token_audiences: list[str]


@dataclass
class ApprovedConfigResult:
    """Result of validating a requested IdP config against policy — the
    caller (submission.py's approve endpoint) uses this to populate
    server_registry.approved_upstream_idp_config / approved_oauth_scopes /
    oauth_policy_id."""

    policy: PolicyRow
    approved_scopes: list[str] = field(default_factory=list)
    high_risk_scopes: list[str] = field(default_factory=list)


async def get_policy_for_issuer(
    session: AsyncSession, issuer: str, tenant: str | None
) -> PolicyRow | None:
    """Fail-closed lookup: returns None if no policy row matches. Tenant match
    is exact (including both-NULL); a tenant-specific policy does NOT fall
    back to a tenant-less row for a different tenant, and vice versa."""
    row = (
        await session.execute(
            text(
                """
                SELECT id, issuer, tenant, allowed_scopes, blocked_scopes, max_risk,
                       allowed_redirect_patterns, allowed_client_auth_methods,
                       allowed_token_audiences
                FROM oauth_provider_policy
                WHERE issuer = :issuer AND tenant IS NOT DISTINCT FROM :tenant
                LIMIT 1
                """
            ),
            {"issuer": issuer, "tenant": tenant},
        )
    ).fetchone()
    if row is None:
        return None
    m = row._mapping
    return PolicyRow(
        id=str(m["id"]),
        issuer=m["issuer"],
        tenant=m["tenant"],
        allowed_scopes=list(m["allowed_scopes"] or []),
        blocked_scopes=list(m["blocked_scopes"] or []),
        max_risk=m["max_risk"],
        allowed_redirect_patterns=list(m["allowed_redirect_patterns"] or []),
        allowed_client_auth_methods=list(m["allowed_client_auth_methods"] or []),
        allowed_token_audiences=list(m["allowed_token_audiences"] or []),
    )


def _split_high_risk(requested_scopes: list[str]) -> list[str]:
    return sorted(set(requested_scopes) & HIGH_RISK_SCOPES)


def validate_scopes_against_policy(requested_scopes: list[str], policy: PolicyRow) -> None:
    """Raises ScopePolicyViolation if any requested scope is blocked, or is
    not in allowed_scopes (when allowed_scopes is non-empty — an empty
    allowed_scopes list means the policy row has not been configured to
    permit ANY scope yet, which fails closed rather than being read as
    'anything goes')."""
    blocked = sorted(set(requested_scopes) & set(policy.blocked_scopes))
    allowed = set(policy.allowed_scopes)
    disallowed = sorted(s for s in requested_scopes if s not in allowed)
    if blocked or disallowed:
        raise ScopePolicyViolation(disallowed=disallowed, blocked=blocked)


def validate_redirect_uri(redirect_uri: str, policy: PolicyRow) -> None:
    if not policy.allowed_redirect_patterns:
        # No patterns configured for this policy row: nothing to check against.
        # (Redirect URIs are optional in upstream_idp_config; most modes here
        # — client_credentials, kc_token_exchange — don't use one at all.)
        return
    for pattern in policy.allowed_redirect_patterns:
        if fnmatch.fnmatch(redirect_uri, pattern):
            return
    raise RedirectPolicyViolation(redirect_uri)


def validate_client_auth_method(method: str, policy: PolicyRow) -> None:
    if not policy.allowed_client_auth_methods:
        return
    if method not in policy.allowed_client_auth_methods:
        raise ClientAuthMethodPolicyViolation(method)


async def validate_requested_config(
    session: AsyncSession,
    *,
    upstream_idp_config: dict[str, Any],
    high_risk_scopes_approved: bool,
) -> ApprovedConfigResult:
    """
    Approval-time validation entry point (called from submission.py's
    /approve endpoint). Requested config must be issuer-known and a subset
    of the matching policy row; high-risk scopes require the reviewer to
    have explicitly set high_risk_scopes_approved=True.

    Raises UnknownIssuerError / ScopePolicyViolation / RedirectPolicyViolation
    / ClientAuthMethodPolicyViolation / HighRiskScopeApprovalRequiredError on
    any failure — all fail-closed, none silently downgrade.
    """
    issuer = (upstream_idp_config or {}).get("issuer")
    if not issuer:
        raise UnknownIssuerError(issuer="", tenant=None)
    tenant = (upstream_idp_config or {}).get("tenant")

    policy = await get_policy_for_issuer(session, issuer=issuer, tenant=tenant)
    if policy is None:
        raise UnknownIssuerError(issuer=issuer, tenant=tenant)

    requested_scopes = list((upstream_idp_config or {}).get("scopes") or [])
    if requested_scopes:
        validate_scopes_against_policy(requested_scopes, policy)

    high_risk = _split_high_risk(requested_scopes)
    if high_risk and not high_risk_scopes_approved:
        raise HighRiskScopeApprovalRequiredError(high_risk)

    redirect_uri = (upstream_idp_config or {}).get("redirect_uri")
    if redirect_uri:
        validate_redirect_uri(redirect_uri, policy)

    client_auth_method = (upstream_idp_config or {}).get("client_auth_method")
    if client_auth_method:
        validate_client_auth_method(client_auth_method, policy)

    return ApprovedConfigResult(policy=policy, approved_scopes=requested_scopes, high_risk_scopes=high_risk)


def validate_token_exchange_audience(
    *,
    requested_audience: str,
    approved_token_audience: str | None,
    env_allowed_audiences: frozenset[str],
) -> None:
    """
    Audience-STRING dimension (kc_token_exchange / RFC 8693) — independent of
    the scope-set dimension above. Two gates, both must pass:

      1. Per-server reviewer approval: requested_audience must equal the
         server's approved_token_audience exactly. A server with no
         approved_token_audience recorded fails closed (reviewer has not yet
         approved OAuth/IdP config for this server under the WP-A2 model).
      2. Outer/bootstrap ceiling: the audience must also be in the
         KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES env allowlist (CR-03's original
         config-driven fix) — defense in depth; the DB is now the enforced
         per-server source of truth, the env var remains a platform-wide
         ceiling / seed default.

    Raises TokenExchangeAudienceViolation on any mismatch.
    """
    if not approved_token_audience:
        raise TokenExchangeAudienceViolation(
            requested_audience,
            "no approved_token_audience recorded for this server; reviewer must "
            "approve OAuth/IdP config before kc_token_exchange can be used",
        )
    if requested_audience != approved_token_audience:
        raise TokenExchangeAudienceViolation(
            requested_audience,
            f"does not match this server's approved_token_audience {approved_token_audience!r}",
        )
    if requested_audience not in env_allowed_audiences:
        raise TokenExchangeAudienceViolation(
            requested_audience,
            f"not in platform KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES ceiling {sorted(env_allowed_audiences)}",
        )


def validate_service_account_scope(
    scope: str,
    allowed_scopes: frozenset[str] = DEFAULT_SERVICE_ACCOUNT_ALLOWED_SCOPES,
) -> None:
    """
    Scope-SET dimension for service_account mode's `scope` field (e.g.
    "openid" or "openid profile"). Space-separated per OAuth2 convention.
    Deliberately a SEPARATE allowlist from kc_token_exchange's audience
    allowlist above — validating "openid" against an audience-shaped
    allowlist (e.g. {"lab-tickets"}) would reject every existing
    service_account tool, which is the exact regression this split guards
    against (see module docstring / Claude_status.md CR-13 row).

    Raises ServiceAccountScopeViolation if any space-separated token is not
    in allowed_scopes.
    """
    tokens = [t for t in scope.split() if t]
    disallowed = sorted(t for t in tokens if t not in allowed_scopes)
    if disallowed:
        raise ServiceAccountScopeViolation(disallowed)
