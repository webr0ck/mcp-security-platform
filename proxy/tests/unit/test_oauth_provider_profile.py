"""
Unit tests — WP-A6 Finding 1/2: oauth_provider_profile catalog.

Covers:
  - recommend_provider_type: the full wizard-answer decision table (Finding 1/2),
    including the "same_platform_idp" -> kc_token_exchange mapping whose
    implementation-shaped name must never appear in display_label.
  - discover_metadata: RFC 8414 discovery (mocked httpx) — primary path,
    openid-configuration fallback, and the fail-soft None-on-total-miss case.
  - create_draft_profile / approve_profile / reject_profile: the DB-CRUD +
    approval-gate state machine, against an in-memory fake session (no real
    DB needed for these — same fake-session pattern as
    credential_broker/test_principal_resolution.py).
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.services import oauth_provider_profile as svc

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# recommend_provider_type — pure function, no I/O
# ---------------------------------------------------------------------------


def test_recommend_same_platform_idp_hides_kc_token_exchange_name():
    rec = svc.recommend_provider_type(same_platform_idp=True)
    assert rec.injection_mode == "kc_token_exchange"
    assert rec.provider_type == "same_platform_idp"
    assert "kc_token_exchange" not in rec.display_label
    assert "token exchange" not in rec.display_label.lower()
    assert rec.display_label == "Same platform IdP"


def test_recommend_needs_api_key_short_circuits_everything():
    rec = svc.recommend_provider_type(same_platform_idp=True, needs_api_key_or_basic=True)
    assert rec.injection_mode == "basic_auth"


def test_recommend_no_authz_code_support_is_app_only():
    rec = svc.recommend_provider_type(same_platform_idp=False, supports_authz_code=False)
    assert rec.injection_mode == "external_oauth_client_credentials"


def test_recommend_app_only_when_not_per_user():
    rec = svc.recommend_provider_type(same_platform_idp=False, supports_authz_code=True, per_user=False)
    assert rec.injection_mode == "external_oauth_client_credentials"


def test_recommend_default_generic_per_user_oauth():
    rec = svc.recommend_provider_type(same_platform_idp=False, supports_authz_code=True, per_user=True)
    assert rec.injection_mode == "external_oauth_user_token"
    assert rec.provider_type == "generic_oauth2"


# ---------------------------------------------------------------------------
# discover_metadata — RFC 8414 / OIDC discovery (mocked httpx)
# ---------------------------------------------------------------------------


class _FakeAsyncClient:
    """Minimal async-context-manager httpx.AsyncClient stand-in."""

    def __init__(self, responses: dict[str, httpx.Response]):
        self._responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url):
        if url in self._responses:
            return self._responses[url]
        raise httpx.ConnectError("no route", request=httpx.Request("GET", url))


def _json_response(url: str, payload: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, json=payload, request=httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_discover_metadata_primary_rfc8414_path():
    base = "https://idp.example.com"
    primary_url = f"{base}/.well-known/oauth-authorization-server"
    payload = {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "jwks_uri": f"{base}/jwks",
        "scopes_supported": ["openid", "read"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }
    fake_client = _FakeAsyncClient({primary_url: _json_response(primary_url, payload)})
    # validate_server_url does a real DNS lookup; mocked here the same way
    # app.routers.tools's own SSRF-guarded tests mock it, so this test
    # exercises the discovery/httpx logic in isolation from DNS availability.
    with patch("app.services.oauth_provider_profile.validate_server_url"), \
         patch("httpx.AsyncClient", return_value=fake_client):
        result = await svc.discover_metadata(base)
    assert result is not None
    assert result.token_endpoint == f"{base}/token"
    assert result.metadata_url == primary_url
    assert "read" in result.scopes_supported


@pytest.mark.asyncio
async def test_discover_metadata_falls_back_to_openid_configuration():
    base = "https://idp2.example.com"
    primary_url = f"{base}/.well-known/oauth-authorization-server"
    fallback_url = f"{base}/.well-known/openid-configuration"
    payload = {"issuer": base, "token_endpoint": f"{base}/token"}
    fake_client = _FakeAsyncClient({
        primary_url: httpx.Response(404, request=httpx.Request("GET", primary_url)),
        fallback_url: _json_response(fallback_url, payload),
    })
    with patch("app.services.oauth_provider_profile.validate_server_url"), \
         patch("httpx.AsyncClient", return_value=fake_client):
        result = await svc.discover_metadata(base)
    assert result is not None
    assert result.metadata_url == fallback_url


@pytest.mark.asyncio
async def test_discover_metadata_fails_soft_to_none_when_unreachable():
    """No RFC 8414/OIDC document reachable — MUST return None, never raise,
    so the caller falls back to manual entry (Finding 1)."""
    base = "https://no-metadata.example.com"
    fake_client = _FakeAsyncClient({})  # every .get() raises ConnectError
    with patch("app.services.oauth_provider_profile.validate_server_url"), \
         patch("httpx.AsyncClient", return_value=fake_client):
        result = await svc.discover_metadata(base)
    assert result is None


@pytest.mark.asyncio
async def test_discover_metadata_refuses_ssrf_unsafe_host_without_any_request():
    """Security regression: an admin/submitter-supplied issuer pointed at an
    internal/private-range host (metadata service, loopback admin panel,
    RFC1918 range) MUST be refused before any network call is made — never
    silently retried across the RFC 8414 / OIDC candidate paths for the same
    unsafe host. Fails soft to None (same as any other discovery miss, so
    the caller falls back to manual entry) but the SSRF check itself is
    fail-closed: httpx.AsyncClient.get must never be invoked."""
    from app.services.ssrf import SSRFError

    fake_client = _FakeAsyncClient({})
    with patch(
        "app.services.oauth_provider_profile.validate_server_url",
        side_effect=SSRFError("Host resolves to a blocked private/reserved IP range"),
    ), patch("httpx.AsyncClient", return_value=fake_client) as mock_client_ctor:
        result = await svc.discover_metadata("http://169.254.169.254/latest/meta-data")
    assert result is None
    mock_client_ctor.assert_not_called()


@pytest.mark.asyncio
async def test_discover_metadata_disables_redirect_following():
    """A malicious metadata endpoint could 3xx-redirect to an internal host
    after the initial hostname passed SSRF validation (redirect-based SSRF
    bypass) — httpx must be constructed with follow_redirects=False so a
    redirect response is treated as a miss, never transparently followed."""
    base = "https://idp3.example.com"
    with patch("app.services.oauth_provider_profile.validate_server_url"), \
         patch("httpx.AsyncClient") as mock_client_ctor:
        mock_client_ctor.return_value = _FakeAsyncClient({})
        await svc.discover_metadata(base)
    _, kwargs = mock_client_ctor.call_args
    assert kwargs.get("follow_redirects") is False


@pytest.mark.asyncio
async def test_discover_metadata_rejects_200_without_token_endpoint():
    """A 200 response that isn't actually AS/OIDC metadata (no token_endpoint)
    must not be mistaken for a real discovery document."""
    base = "https://not-really-an-idp.example.com"
    primary_url = f"{base}/.well-known/oauth-authorization-server"
    fallback_url = f"{base}/.well-known/openid-configuration"
    fake_client = _FakeAsyncClient({
        primary_url: _json_response(primary_url, {"hello": "world"}),
        fallback_url: httpx.Response(404, request=httpx.Request("GET", fallback_url)),
    })
    with patch("httpx.AsyncClient", return_value=fake_client):
        result = await svc.discover_metadata(base)
    assert result is None


# ---------------------------------------------------------------------------
# create_draft_profile / approve_profile / reject_profile — fake in-memory session
# ---------------------------------------------------------------------------


class _Mapping(dict):
    """dict subclass so row._mapping["col"] access matches SQLAlchemy's Row API."""


class _FakeResult:
    def __init__(self, row: dict | None):
        self._row = _Mapping(row) if row is not None else None

    def fetchone(self):
        if self._row is None:
            return None
        return SimpleNamespace(_mapping=self._row)


_PROFILE_DEFAULTS = {
    "injection_mode": None,
    "issuer": None, "authorization_endpoint": None, "token_endpoint": None,
    "jwks_uri": None, "metadata_url": None, "default_scopes": [], "allowed_scopes": [],
    "blocked_scopes": [], "allowed_redirect_patterns": [], "allowed_client_auth_methods": [],
    "token_audience_or_resource": None, "supports_pkce": True, "supports_refresh_token": True,
    "supports_client_credentials": False, "service_adapter": None,
    "high_risk_scopes_approved_by": None, "created_by": None, "approved_by": None,
}


class _FakeProfileSession:
    """In-memory single-table fake for oauth_provider_profile CRUD, enough to
    exercise create_draft_profile/get_profile/approve_profile/reject_profile
    without a real Postgres connection."""

    def __init__(self):
        self.rows: dict[str, dict] = {}

    async def execute(self, stmt, params):
        text = str(stmt)
        if "INSERT INTO oauth_provider_profile" in text:
            new_id = str(uuid.uuid4())
            row = {**_PROFILE_DEFAULTS, "id": new_id, "status": "draft"}
            row["slug"] = params["slug"]
            row["display_name"] = params["display_name"]
            row["provider_type"] = params["provider_type"]
            row["injection_mode"] = params.get("injection_mode")
            row["issuer"] = params.get("issuer")
            row["authorization_endpoint"] = params.get("authz_ep")
            row["token_endpoint"] = params.get("token_ep")
            row["jwks_uri"] = params.get("jwks_uri")
            row["metadata_url"] = params.get("metadata_url")
            import json as _json
            row["default_scopes"] = _json.loads(params["default_scopes"])
            row["allowed_scopes"] = _json.loads(params["allowed_scopes"])
            row["blocked_scopes"] = _json.loads(params["blocked_scopes"])
            row["token_audience_or_resource"] = params.get("audience")
            row["service_adapter"] = params.get("service_adapter")
            row["supports_client_credentials"] = params.get("supports_cc", False)
            row["created_by"] = params.get("created_by")
            self.rows[new_id] = row
            return _FakeResult(row)

        if text.strip().startswith("SELECT") and "WHERE id = " in text:
            row = self.rows.get(params["id"])
            return _FakeResult(row)

        if text.strip().startswith("UPDATE oauth_provider_profile"):
            row = self.rows[params["id"]]
            if "status = 'approved'" in text:
                row["status"] = "approved"
                row["approved_by"] = params["reviewer"]
                if params.get("high_risk_ack"):
                    row["high_risk_scopes_approved_by"] = params["reviewer"]
            elif "status = 'rejected'" in text:
                row["status"] = "rejected"
                row["approved_by"] = params["reviewer"]
                row["rejection_reason"] = params["reason"]
            return _FakeResult(None)

        raise AssertionError(f"unhandled fake query: {text!r}")

    async def commit(self):
        pass


@pytest.mark.asyncio
async def test_create_draft_profile_starts_as_draft():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-oauth", display_name="Acme OAuth", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
    )
    assert profile.status == "draft"
    assert profile.slug == "acme-oauth"


@pytest.mark.asyncio
async def test_create_draft_profile_rejects_unknown_service_adapter():
    """M-02 (2026-07-11 audit): get_service_adapter's runtime fallback
    silently treats an unknown slug as 'generic' so enrollment is never
    blocked — but that means a typo'd service_adapter would silently lose
    service-specific discovery/verification with no error anywhere. Reject
    at profile-creation (write) time instead."""
    session = _FakeProfileSession()
    with pytest.raises(ValueError, match="service_adapter"):
        await svc.create_draft_profile(
            session, slug="acme-oauth", display_name="Acme OAuth", provider_type="generic_oauth2",
            injection_mode="external_oauth_user_token", created_by="alice@corp",
            service_adapter="acme-typo",
        )


@pytest.mark.asyncio
async def test_create_draft_profile_accepts_known_service_adapter():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-oauth", display_name="Acme OAuth", provider_type="generic_oauth2",
        injection_mode="external_oauth_user_token", created_by="alice@corp",
        service_adapter="generic",
    )
    assert profile.service_adapter == "generic"


@pytest.mark.asyncio
async def test_approve_profile_happy_path():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-oauth", display_name="Acme OAuth", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
    )
    approved = await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    assert approved.status == "approved"
    assert approved.approved_by == "admin@corp"


@pytest.mark.asyncio
async def test_approve_profile_requires_high_risk_ack():
    """CORE ACCEPTANCE TEST: a profile whose default_scopes include a
    HIGH_RISK_SCOPES member must NOT silently approve without explicit ack —
    mirrors oauth_policy.py's HighRiskScopeApprovalRequiredError posture."""
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-write", display_name="Acme (write access)", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp", default_scopes=["read", "write"],
    )
    with pytest.raises(svc.HighRiskScopeAckRequiredError) as exc_info:
        await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    assert "write" in exc_info.value.high_risk_scopes

    # With explicit ack, approval succeeds.
    approved = await svc.approve_profile(session, profile.id, reviewer="admin@corp", high_risk_scopes_approved=True)
    assert approved.status == "approved"
    assert approved.high_risk_scopes_approved_by == "admin@corp"


@pytest.mark.asyncio
async def test_approve_profile_rejects_invalid_state_transition():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-oauth2", display_name="Acme OAuth 2", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
    )
    await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    with pytest.raises(svc.InvalidProfileStateTransitionError):
        await svc.approve_profile(session, profile.id, reviewer="admin2@corp")


@pytest.mark.asyncio
async def test_reject_profile():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-oauth3", display_name="Acme OAuth 3", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
    )
    rejected = await svc.reject_profile(session, profile.id, reviewer="admin@corp", reason="unapproved issuer")
    assert rejected.status == "rejected"


@pytest.mark.asyncio
async def test_get_profile_not_found_raises():
    session = _FakeProfileSession()
    with pytest.raises(svc.ProfileNotFoundError):
        await svc.get_profile(session, str(uuid.uuid4()))


# ---------------------------------------------------------------------------
# allowed_scopes/blocked_scopes wiring (follow-up to the WP-A6 handoff gap)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_draft_profile_persists_allowed_and_blocked_scopes():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-scoped", display_name="Acme Scoped", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
        default_scopes=["openid"], allowed_scopes=["openid", "profile", "email"],
        blocked_scopes=["admin"],
    )
    assert profile.allowed_scopes == ["openid", "profile", "email"]
    assert profile.blocked_scopes == ["admin"]


@pytest.mark.asyncio
async def test_create_draft_profile_rejects_scope_in_both_allowed_and_blocked():
    """A scope cannot be simultaneously allowed/default and blocked — that is
    an inconsistent profile, rejected at creation rather than deferred to
    approval time."""
    session = _FakeProfileSession()
    with pytest.raises(ValueError, match="Mail.Read"):
        await svc.create_draft_profile(
            session, slug="acme-conflict", display_name="Acme Conflict", provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
            created_by="alice@corp",
            allowed_scopes=["openid", "Mail.Read"], blocked_scopes=["Mail.Read"],
        )


@pytest.mark.asyncio
async def test_approve_profile_requires_high_risk_ack_for_allowed_scopes_too():
    """CORE ACCEPTANCE TEST: a high-risk scope present only in allowed_scopes
    (not default_scopes) must still require explicit reviewer ack — settable
    allowed_scopes must not create a silent bypass of the high-risk gate."""
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-allowed-write", display_name="Acme (allowed write)",
        provider_type="generic_oauth2", injection_mode="external_oauth_user_token", created_by="alice@corp",
        default_scopes=["openid"], allowed_scopes=["openid", "write"],
    )
    with pytest.raises(svc.HighRiskScopeAckRequiredError) as exc_info:
        await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    assert "write" in exc_info.value.high_risk_scopes

    approved = await svc.approve_profile(
        session, profile.id, reviewer="admin@corp", high_risk_scopes_approved=True
    )
    assert approved.status == "approved"


# ---------------------------------------------------------------------------
# WP-A6 Finding 6: approve_profile syncs oauth_provider_policy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_profile_syncs_oauth_provider_policy_when_issuer_set():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-synced", display_name="Acme Synced",
        provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp", default_scopes=["openid"],
        metadata=svc.DiscoveredMetadata(issuer="https://idp.example"),
    )
    with patch("app.services.oauth_policy.sync_policy_from_provider_profile", new=AsyncMock()) as mock_sync:
        await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    mock_sync.assert_awaited_once()
    _, kwargs = mock_sync.await_args
    assert kwargs["issuer"] == "https://idp.example"
    assert kwargs["created_by"] == "admin@corp"


@pytest.mark.asyncio
async def test_approve_profile_skips_policy_sync_when_no_issuer():
    session = _FakeProfileSession()
    profile = await svc.create_draft_profile(
        session, slug="acme-no-issuer", display_name="Acme No Issuer",
        provider_type="generic_oauth2", injection_mode="external_oauth_user_token",
        created_by="alice@corp",
    )
    with patch("app.services.oauth_policy.sync_policy_from_provider_profile", new=AsyncMock()) as mock_sync:
        await svc.approve_profile(session, profile.id, reviewer="admin@corp")
    mock_sync.assert_not_awaited()
