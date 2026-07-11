"""
WP-A5 (CR-02 completion) — draft/update-time mode<->upstream_idp_type
compatibility validator in routers/submission.py::update_draft.

Previously nothing checked this combination at draft/update time at all
(only the much-later WP-A2 oauth_policy approval gate did, and only for
oauth-ish modes) — a submitter could PATCH a contradictory combination and
only discover it was invalid at first invocation. This validator is
deliberately permissive when upstream_idp_type is simply ABSENT (the current
wizard UI never sends it) — it only rejects a combination where an
upstream_idp_type IS present (this request or already stored) and disagrees
with the mode.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.routers.submission import DraftUpdate, update_draft


def _mock_request(client_id="alice@corp"):
    req = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = []
    req.headers = {}  # no X-On-Behalf-Of — caller acts as itself (T2)
    return req


def _mock_session():
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock())
    session.commit = AsyncMock()

    class _Ctx:
        async def __aenter__(self):
            return session
        async def __aexit__(self, *a):
            return False

    return _Ctx(), session


@pytest.mark.asyncio
async def test_entra_user_token_with_wrong_idp_type_rejected():
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)):
        with pytest.raises(HTTPException) as exc_info:
            await update_draft(
                server_id,
                DraftUpdate(injection_mode="entra_user_token", upstream_idp_type="gateway_idp"),
                _mock_request(),
            )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_kc_token_exchange_with_wrong_idp_type_rejected():
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)):
        with pytest.raises(HTTPException) as exc_info:
            await update_draft(
                server_id,
                DraftUpdate(injection_mode="kc_token_exchange", upstream_idp_type="entra"),
                _mock_request(),
            )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_external_oauth_with_wrong_idp_type_rejected():
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)):
        with pytest.raises(HTTPException) as exc_info:
            await update_draft(
                server_id,
                DraftUpdate(injection_mode="external_oauth_user_token", upstream_idp_type="entra"),
                _mock_request(),
            )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_matching_mode_and_idp_type_accepted():
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    ctx, session = _mock_session()
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)), \
         patch("app.routers.submission.AsyncSessionLocal", return_value=ctx):
        resp = await update_draft(
            server_id,
            DraftUpdate(
                injection_mode="entra_user_token",
                upstream_idp_type="entra",
                upstream_idp_config={"issuer": "https://login.microsoftonline.com/t/", "client_id": "abc"},
            ),
            _mock_request(),
        )
    body = json.loads(resp.body)
    assert body["updated"] is True


@pytest.mark.asyncio
async def test_no_idp_type_specified_is_permissive_not_rejected():
    """The current wizard UI never sends upstream_idp_type — an in-progress
    draft with only injection_mode set must NOT be rejected."""
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    ctx, session = _mock_session()
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_row)), \
         patch("app.routers.submission.AsyncSessionLocal", return_value=ctx):
        resp = await update_draft(
            server_id,
            DraftUpdate(injection_mode="entra_user_token"),
            _mock_request(),
        )
    body = json.loads(resp.body)
    assert body["updated"] is True


@pytest.mark.asyncio
async def test_effective_state_merges_across_two_patch_calls():
    """Step 1 sets injection_mode only (no idp_type anywhere yet) -> must not
    reject. Step 2 (idp_type now stored from step 1... simulated via sub_row)
    sets a CONTRADICTORY upstream_idp_type -> must reject using the merged
    state, not just this request's fields."""
    server_id = str(uuid4())
    # Step 1: mode set, no idp_type recorded yet.
    sub_after_step1 = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": "entra_user_token",
        "upstream_idp_type": None, "upstream_idp_config": None,
    }
    with patch("app.routers.submission._get_submission", AsyncMock(return_value=sub_after_step1)):
        with pytest.raises(HTTPException) as exc_info:
            # Step 2: submitter (or a bug) now sets a WRONG idp_type; effective
            # mode comes from the stored row (entra_user_token).
            await update_draft(
                server_id,
                DraftUpdate(upstream_idp_type="gateway_idp"),
                _mock_request(),
            )
    assert exc_info.value.status_code == 400


@pytest.mark.asyncio
async def test_self_service_mode_set_rejects_deprecated_alias():
    """WP-A5: self-service submitters can no longer choose the deprecated
    oauth_user_token alias name — kc_token_exchange is canonical."""
    server_id = str(uuid4())
    sub_row = {
        "server_id": server_id, "owner_sub": "alice@corp",
        "submission_status": "draft", "injection_mode": None, "upstream_idp_type": None,
        "upstream_idp_config": None,
    }
    with pytest.raises(Exception):  # pydantic ValidationError at DraftUpdate construction
        DraftUpdate(injection_mode="oauth_user_token")


@pytest.mark.asyncio
async def test_self_service_mode_set_rejects_passthrough():
    """passthrough is admin_only — never self-service-selectable."""
    with pytest.raises(Exception):
        DraftUpdate(injection_mode="passthrough")


@pytest.mark.asyncio
async def test_self_service_mode_set_accepts_basic_auth():
    """Regression: basic_auth is 'supported'/self-service-selectable but the
    OLD hardcoded _VALID_MODES set omitted it entirely."""
    body = DraftUpdate(injection_mode="basic_auth")
    assert body.injection_mode == "basic_auth"
