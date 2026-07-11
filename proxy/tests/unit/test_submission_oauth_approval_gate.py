"""
WP-A2 (CR-13 + CR-03 remainder) — approval-time OAuth/IdP policy gate wired
into POST /api/v1/admin/submissions/{id}/approve.

Covers app.routers.submission._validate_oauth_policy_at_approval and its use
in approve_submission: unknown issuer rejects, overbroad scope rejects,
kc_token_exchange audience approval flows through to approved_token_audience,
and non-OAuth modes (service/user/none) are unaffected (no policy lookup).
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.routers.submission import ReviewAction, _validate_oauth_policy_at_approval


def _fake_session_with_policy_row(row_mapping: dict | None):
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


def _entra_policy_row():
    return {
        "id": str(uuid4()),
        "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
        "tenant": "tenant-a",
        "allowed_scopes": ["openid", "User.Read"],
        "blocked_scopes": [],
        "max_risk": "medium",
        "allowed_redirect_patterns": [],
        "allowed_client_auth_methods": [],
        "allowed_token_audiences": [],
    }


@pytest.mark.asyncio
async def test_non_oauth_mode_skips_policy_entirely():
    """service/user/none modes have no OAuth config; approval must not touch
    oauth_policy at all and must return an all-None/empty result."""
    session = MagicMock()
    session.execute = AsyncMock()
    sub = {"injection_mode": "service", "upstream_idp_config": None}
    result = await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert result["approved_upstream_idp_config"] is None
    assert result["oauth_policy_id"] is None
    session.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_entra_unknown_issuer_rejects():
    session = _fake_session_with_policy_row(None)
    sub = {
        "injection_mode": "entra_client_credentials",
        "upstream_idp_config": {
            "issuer": "https://rogue-idp.example.com",
            "client_id": "abc",
            "scopes": ["openid"],
        },
    }
    with pytest.raises(HTTPException) as exc_info:
        await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["code"] == "OAUTH_POLICY_VIOLATION"


@pytest.mark.asyncio
async def test_entra_overbroad_scope_rejects():
    session = _fake_session_with_policy_row(_entra_policy_row())
    sub = {
        "injection_mode": "entra_client_credentials",
        "upstream_idp_config": {
            "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
            "tenant": "tenant-a",
            "client_id": "abc",
            "scopes": ["openid", "Mail.ReadWrite"],
        },
    }
    with pytest.raises(HTTPException) as exc_info:
        await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_entra_within_policy_approves_and_sets_columns():
    session = _fake_session_with_policy_row(_entra_policy_row())
    sub = {
        "injection_mode": "entra_client_credentials",
        "upstream_idp_config": {
            "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
            "tenant": "tenant-a",
            "client_id": "abc",
            "scopes": ["openid"],
        },
    }
    result = await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert result["approved_upstream_idp_config"]["client_id"] == "abc"
    assert result["approved_token_scopes"] == ["openid"]
    assert result["oauth_policy_id"] is not None
    assert result["high_risk_scopes_approved_by"] is False


@pytest.mark.asyncio
async def test_kc_token_exchange_audience_outside_ceiling_rejects(monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES", "lab-tickets", raising=False)

    session = MagicMock()
    session.execute = AsyncMock()
    sub = {
        "injection_mode": "kc_token_exchange",
        "upstream_idp_config": {"audience": "totally-unapproved-audience"},
    }
    with pytest.raises(HTTPException) as exc_info:
        await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert exc_info.value.status_code == 422
    session.execute.assert_not_awaited()  # no oauth_provider_policy lookup for this dimension


@pytest.mark.asyncio
async def test_kc_token_exchange_audience_within_ceiling_approves(monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES", "lab-tickets", raising=False)

    session = MagicMock()
    session.execute = AsyncMock()
    sub = {
        "injection_mode": "kc_token_exchange",
        "upstream_idp_config": {"audience": "lab-tickets"},
    }
    result = await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok"))
    assert result["approved_token_audience"] == "lab-tickets"


@pytest.mark.asyncio
async def test_high_risk_scope_requires_explicit_reviewer_ack():
    row = _entra_policy_row()
    row["allowed_scopes"] = ["openid", "offline_access"]
    session = _fake_session_with_policy_row(row)
    sub = {
        "injection_mode": "entra_client_credentials",
        "upstream_idp_config": {
            "issuer": "https://login.microsoftonline.com/tenant-a/v2.0",
            "tenant": "tenant-a",
            "client_id": "abc",
            "scopes": ["openid", "offline_access"],
        },
    }
    with pytest.raises(HTTPException):
        await _validate_oauth_policy_at_approval(session, sub, ReviewAction(notes="ok", high_risk_scopes_approved=False))

    # re-fetch a fresh session (the mock's execute call count matters less than the outcome)
    session2 = _fake_session_with_policy_row(row)
    result = await _validate_oauth_policy_at_approval(
        session2, sub, ReviewAction(notes="ok", high_risk_scopes_approved=True)
    )
    assert result["high_risk_scopes_approved_by"] is True
