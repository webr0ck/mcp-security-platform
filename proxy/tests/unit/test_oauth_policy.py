"""
WP-A2 (CR-13 + CR-03 remainder) — OAuth/IdP policy engine unit tests.

Covers app.services.oauth_policy: the two independent validation dimensions
(scope-set for entra_*/service_account, audience-string for
kc_token_exchange) plus the approval-time gate in
app.routers.submission._validate_oauth_policy_at_approval.

Required coverage per the WP-A2 handoff:
  - overbroad Entra scope -> reject
  - unknown issuer -> reject
  - broad service_account audience/scope -> service_account and
    kc_token_exchange are validated independently, neither breaks the other
  - regression: existing lab service_account tools (openid scope) still pass
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.oauth_policy import (
    HIGH_RISK_SCOPES,
    ClientAuthMethodPolicyViolation,
    HighRiskScopeApprovalRequiredError,
    PolicyRow,
    RedirectPolicyViolation,
    ScopePolicyViolation,
    ServiceAccountScopeViolation,
    TokenExchangeAudienceViolation,
    UnknownIssuerError,
    get_policy_for_issuer,
    validate_client_auth_method,
    validate_redirect_uri,
    validate_requested_config,
    validate_scopes_against_policy,
    validate_service_account_scope,
    validate_token_exchange_audience,
)


def _policy(**overrides) -> PolicyRow:
    defaults = dict(
        id="11111111-1111-1111-1111-111111111111",
        issuer="https://login.microsoftonline.com/tenant-a/v2.0",
        tenant="tenant-a",
        allowed_scopes=["User.Read", "openid", "profile"],
        blocked_scopes=[],
        max_risk="medium",
        allowed_redirect_patterns=["https://portal.example.com/*"],
        allowed_client_auth_methods=["client_secret_post"],
        allowed_token_audiences=[],
    )
    defaults.update(overrides)
    return PolicyRow(**defaults)


def _fake_session_with_row(row_mapping: dict | None):
    """Build a mock AsyncSession whose .execute().fetchone() returns a row
    with a ._mapping matching row_mapping, or None if row_mapping is None."""
    session = MagicMock()
    result = MagicMock()
    if row_mapping is None:
        result.fetchone.return_value = None
    else:
        fake_row = MagicMock()
        fake_row._mapping = row_mapping
        result.fetchone.return_value = fake_row
    session.execute = AsyncMock(return_value=result)
    return session


# ---------------------------------------------------------------------------
# Scope-set dimension: oauth_provider_policy (entra_* modes)
# ---------------------------------------------------------------------------

class TestScopeSetValidation:
    def test_scopes_within_policy_pass(self):
        policy = _policy()
        validate_scopes_against_policy(["openid", "profile"], policy)  # no raise

    def test_overbroad_scope_rejected(self):
        """Required coverage: overbroad Entra scope must reject."""
        policy = _policy(allowed_scopes=["openid"])
        with pytest.raises(ScopePolicyViolation) as exc_info:
            validate_scopes_against_policy(["openid", "Mail.ReadWrite"], policy)
        assert "Mail.ReadWrite" in exc_info.value.disallowed

    def test_blocked_scope_rejected_even_if_in_allowed(self):
        policy = _policy(allowed_scopes=["openid", "Mail.Read"], blocked_scopes=["Mail.Read"])
        with pytest.raises(ScopePolicyViolation) as exc_info:
            validate_scopes_against_policy(["Mail.Read"], policy)
        assert "Mail.Read" in exc_info.value.blocked

    def test_empty_allowed_scopes_fails_closed(self):
        """An unconfigured policy row (allowed_scopes=[]) must reject any
        scope request, not silently permit everything."""
        policy = _policy(allowed_scopes=[])
        with pytest.raises(ScopePolicyViolation):
            validate_scopes_against_policy(["openid"], policy)

    def test_redirect_uri_matches_pattern(self):
        policy = _policy()
        validate_redirect_uri("https://portal.example.com/callback", policy)  # no raise

    def test_redirect_uri_rejected_outside_pattern(self):
        policy = _policy()
        with pytest.raises(RedirectPolicyViolation):
            validate_redirect_uri("https://evil.example.com/callback", policy)

    def test_client_auth_method_rejected(self):
        policy = _policy()
        with pytest.raises(ClientAuthMethodPolicyViolation):
            validate_client_auth_method("private_key_jwt", policy)


# ---------------------------------------------------------------------------
# Unknown issuer -> fail closed
# ---------------------------------------------------------------------------

class TestUnknownIssuer:
    @pytest.mark.asyncio
    async def test_get_policy_for_issuer_returns_none_when_no_row(self):
        session = _fake_session_with_row(None)
        result = await get_policy_for_issuer(session, issuer="https://unknown.example.com", tenant=None)
        assert result is None

    @pytest.mark.asyncio
    async def test_validate_requested_config_unknown_issuer_rejects(self):
        """Required coverage: a server requesting against an issuer with no
        matching policy row must reject."""
        session = _fake_session_with_row(None)
        with pytest.raises(UnknownIssuerError):
            await validate_requested_config(
                session,
                upstream_idp_config={"issuer": "https://rogue-idp.example.com", "scopes": ["openid"]},
                high_risk_scopes_approved=False,
            )

    @pytest.mark.asyncio
    async def test_validate_requested_config_missing_issuer_rejects(self):
        session = _fake_session_with_row(None)
        with pytest.raises(UnknownIssuerError):
            await validate_requested_config(
                session, upstream_idp_config={"scopes": ["openid"]}, high_risk_scopes_approved=False
            )


# ---------------------------------------------------------------------------
# High-risk scope gate
# ---------------------------------------------------------------------------

class TestHighRiskScopes:
    def _row_mapping(self):
        return {
            "id": "11111111-1111-1111-1111-111111111111",
            "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
            "tenant": "tenant-a",
            "allowed_scopes": ["openid", "Mail.ReadWrite", "offline_access"],
            "blocked_scopes": [],
            "max_risk": "high",
            "allowed_redirect_patterns": [],
            "allowed_client_auth_methods": [],
            "allowed_token_audiences": [],
        }

    @pytest.mark.asyncio
    async def test_high_risk_scope_without_approval_rejects(self):
        session = _fake_session_with_row(self._row_mapping())
        with pytest.raises(HighRiskScopeApprovalRequiredError):
            await validate_requested_config(
                session,
                upstream_idp_config={
                    "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
                    "tenant": "tenant-a",
                    "scopes": ["openid", "offline_access"],
                },
                high_risk_scopes_approved=False,
            )

    @pytest.mark.asyncio
    async def test_high_risk_scope_with_explicit_approval_passes(self):
        session = _fake_session_with_row(self._row_mapping())
        result = await validate_requested_config(
            session,
            upstream_idp_config={
                "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
                "tenant": "tenant-a",
                "scopes": ["openid", "offline_access"],
            },
            high_risk_scopes_approved=True,
        )
        assert result.high_risk_scopes == ["offline_access"]

    def test_high_risk_scope_set_matches_canonical_five(self):
        assert HIGH_RISK_SCOPES == frozenset({"write", "admin", "mail", "files", "offline_access"})

    def test_wildcard_consent_default_scope_is_high_risk(self):
        # PRD-0011 WS-4 (appsec): Microsoft Graph '<resource>/.default' grants
        # app-only consent to whatever perms the app registration already holds —
        # open-ended, so it MUST be flagged high-risk even though it is not a
        # literal member of HIGH_RISK_SCOPES.
        from app.services.oauth_policy import _split_high_risk
        assert _split_high_risk(["https://graph.microsoft.com/.default"]) == [
            "https://graph.microsoft.com/.default"
        ]
        assert _split_high_risk([".default"]) == [".default"]
        # A normal bounded scope is NOT high-risk.
        assert _split_high_risk(["openid", "profile"]) == []

    @pytest.mark.asyncio
    async def test_entra_default_scope_requires_reviewer_ack(self):
        # End-to-end through the validator: a .default-only Entra submission is
        # rejected without high_risk_scopes_approved, accepted with it.
        row = {
            "id": "22222222-2222-2222-2222-222222222222",
            "issuer": "https://login.microsoftonline.com/e756f76f/v2.0",
            "tenant": None,
            "allowed_scopes": ["https://graph.microsoft.com/.default"],
            "blocked_scopes": [],
            "max_risk": "medium",
            "allowed_redirect_patterns": [],
            "allowed_client_auth_methods": [],
            "allowed_token_audiences": [],
        }
        cfg = {
            "issuer": "https://login.microsoftonline.com/e756f76f/v2.0",
            "scopes": ["https://graph.microsoft.com/.default"],
        }
        with pytest.raises(HighRiskScopeApprovalRequiredError):
            await validate_requested_config(
                _fake_session_with_row(row), upstream_idp_config=cfg,
                high_risk_scopes_approved=False,
            )
        result = await validate_requested_config(
            _fake_session_with_row(row), upstream_idp_config=cfg,
            high_risk_scopes_approved=True,
        )
        assert result.high_risk_scopes == ["https://graph.microsoft.com/.default"]


# ---------------------------------------------------------------------------
# Audience-string dimension: kc_token_exchange (RFC 8693)
# ---------------------------------------------------------------------------

class TestTokenExchangeAudience:
    def test_approved_audience_within_ceiling_passes(self):
        validate_token_exchange_audience(
            requested_audience="lab-tickets",
            approved_token_audience="lab-tickets",
            env_allowed_audiences=frozenset({"lab-tickets"}),
        )  # no raise

    def test_no_approved_audience_fails_closed(self):
        with pytest.raises(TokenExchangeAudienceViolation):
            validate_token_exchange_audience(
                requested_audience="lab-tickets",
                approved_token_audience=None,
                env_allowed_audiences=frozenset({"lab-tickets"}),
            )

    def test_audience_mismatch_rejected(self):
        """A server approved for one audience must not be able to request another."""
        with pytest.raises(TokenExchangeAudienceViolation):
            validate_token_exchange_audience(
                requested_audience="other-audience",
                approved_token_audience="lab-tickets",
                env_allowed_audiences=frozenset({"lab-tickets", "other-audience"}),
            )

    def test_audience_outside_env_ceiling_rejected_even_if_approved(self):
        """Outer/bootstrap ceiling is defense in depth even against a
        (hypothetically stale) DB-approved value."""
        with pytest.raises(TokenExchangeAudienceViolation):
            validate_token_exchange_audience(
                requested_audience="lab-tickets",
                approved_token_audience="lab-tickets",
                env_allowed_audiences=frozenset({"some-other-audience"}),
            )


# ---------------------------------------------------------------------------
# Scope-SET dimension: service_account mode's `scope` field
# ---------------------------------------------------------------------------

class TestServiceAccountScope:
    def test_default_openid_scope_allowed(self):
        """Regression: every existing lab service_account tool (lab-gitea,
        lab-grafana-mcp, lab-wazuh) defaults to scope='openid' and must keep
        working."""
        validate_service_account_scope("openid")  # no raise

    def test_multi_token_default_scope_allowed(self):
        validate_service_account_scope("openid profile email")  # no raise

    def test_disallowed_scope_token_rejected(self):
        with pytest.raises(ServiceAccountScopeViolation) as exc_info:
            validate_service_account_scope("openid admin")
        assert "admin" in exc_info.value.disallowed

    def test_broad_service_account_scope_does_not_use_audience_allowlist(self):
        """Required coverage: service_account's scope-shaped validation must be
        independent of kc_token_exchange's audience-shaped allowlist. Validating
        'openid' against an audience allowlist like {'lab-tickets'} would
        incorrectly reject it (the prior rejected approach) — the scope-set
        allowlist must accept it instead."""
        # 'openid' is NOT in a kc_token_exchange-shaped audience allowlist...
        assert "openid" not in frozenset({"lab-tickets"})
        # ...but IS accepted by the scope-set validator using its own default allowlist.
        validate_service_account_scope("openid")  # no raise

    def test_custom_allowed_scopes_override(self):
        validate_service_account_scope("custom-scope", allowed_scopes=frozenset({"custom-scope"}))


# ---------------------------------------------------------------------------
# WP-A6 Finding 6: sync_policy_from_provider_profile
# ---------------------------------------------------------------------------


class TestSyncPolicyFromProviderProfile:
    @pytest.mark.asyncio
    async def test_noop_when_profile_has_no_issuer(self):
        from app.services.oauth_policy import sync_policy_from_provider_profile
        session = MagicMock()
        session.execute = AsyncMock()
        await sync_policy_from_provider_profile(
            session, issuer="", allowed_scopes=[], blocked_scopes=[],
            allowed_redirect_patterns=[], allowed_client_auth_methods=[],
            token_audience_or_resource=None, created_by="admin@corp",
        )
        session.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_upserts_policy_row_for_issuer(self):
        from app.services.oauth_policy import sync_policy_from_provider_profile
        session = MagicMock()
        session.execute = AsyncMock()
        await sync_policy_from_provider_profile(
            session, issuer="https://idp.example", allowed_scopes=["openid", "profile"],
            blocked_scopes=["admin"], allowed_redirect_patterns=["https://portal.example.com/*"],
            allowed_client_auth_methods=["client_secret_post"],
            token_audience_or_resource="mcp-gateway", created_by="admin@corp",
        )
        session.execute.assert_awaited_once()
        stmt, params = session.execute.await_args.args
        assert "INSERT INTO oauth_provider_policy" in str(stmt)
        assert "ON CONFLICT" in str(stmt)
        assert params["issuer"] == "https://idp.example"
        assert params["created_by"] == "admin@corp"
        import json
        assert json.loads(params["allowed_scopes"]) == ["openid", "profile"]
        assert json.loads(params["allowed_token_audiences"]) == ["mcp-gateway"]
