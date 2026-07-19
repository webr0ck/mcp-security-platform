"""
Unit tests — R-10 approval -> provisioning pipeline (PRD-0003).

Covers the two pieces of new logic that don't require a running upstream/DB:
- F-14 fix: resolve_kc_token_audience() — the wizard's upstream_idp_config.audience
  is only ever wired onto a tool's kc_token_audience for kc_token_exchange/
  oauth_user_token mode; every other mode must yield None (never leak a stray
  audience value onto a mode that doesn't use it).
- F-15 fix: approve_submission()'s no-code vs repo-path status branching —
  a no-code submission (no github_repo_url) must land on 'scaffold_ready', never
  'approved_pending_url' ('active'/'running' language is a portal contract, not a
  DB-write concern, so this test asserts the value actually persisted).

Run: pytest tests/unit/test_r10_provisioning.py -v
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4


# ===========================================================================
# resolve_kc_token_audience (F-14)
# ===========================================================================

def test_kc_audience_resolved_for_kc_token_exchange():
    from app.routers.tools import resolve_kc_token_audience
    assert resolve_kc_token_audience(
        "kc_token_exchange", {"audience": "lab-tickets"}
    ) == "lab-tickets"


def test_kc_audience_resolved_for_deprecated_alias():
    from app.routers.tools import resolve_kc_token_audience
    assert resolve_kc_token_audience(
        "oauth_user_token", {"audience": "lab-tickets"}
    ) == "lab-tickets"


def test_kc_audience_none_for_other_modes():
    """A stray audience value on e.g. 'service' mode must not be carried forward —
    it's inert there and wiring it would misleadingly imply it's live."""
    from app.routers.tools import resolve_kc_token_audience
    for mode in ("none", "service", "user", "passthrough", None):
        assert resolve_kc_token_audience(mode, {"audience": "lab-tickets"}) is None


def test_kc_audience_none_when_config_missing():
    from app.routers.tools import resolve_kc_token_audience
    assert resolve_kc_token_audience("kc_token_exchange", None) is None
    assert resolve_kc_token_audience("kc_token_exchange", {}) is None


def test_kc_audience_handles_json_string_config():
    """asyncpg/sqlalchemy usually decode jsonb to dict, but defensively handle the
    str case too (same defensive pattern already used in routers/oauth.py)."""
    from app.routers.tools import resolve_kc_token_audience
    raw = json.dumps({"audience": "lab-tickets"})
    assert resolve_kc_token_audience("kc_token_exchange", raw) == "lab-tickets"


def test_kc_audience_handles_malformed_json_string():
    from app.routers.tools import resolve_kc_token_audience
    assert resolve_kc_token_audience("kc_token_exchange", "{not json") is None


# ===========================================================================
# approve_submission no-code vs repo-path branching (F-15)
# ===========================================================================

@pytest.mark.asyncio
async def test_approve_submission_repo_path_stays_approved_pending_url():
    from app.routers.submission import approve_submission, ReviewAction

    server_id = str(uuid4())
    mock_request = MagicMock()
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    sub_row = {
        "server_id": server_id,
        "submission_status": "awaiting_review",
        "scan_status": "passed",
        "github_repo_url": "https://github.com/octocat/Hello-World",
        "reviewed_by": None,
        # PRD-0012: is_self_hosted=False (platform-deployed) is the only repo
        # path that still lands in approved_pending_url — a self-hosted
        # (is_self_hosted=True, the default) submission now runs the C2
        # inline verify/debug-mode pipeline instead. See
        # test_submission_prd0012.py for that new behavior.
        "is_self_hosted": False,
    }

    captured_params = {}

    async def fake_get_submission(sid, owner_sub=None):
        return sub_row

    mock_session = AsyncMock()

    async def fake_execute(stmt, params=None):
        if params:
            captured_params.update(params)
        return MagicMock()

    mock_session.execute = fake_execute
    mock_session.commit = AsyncMock()

    mock_session_cm = MagicMock()
    mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.submission._get_submission", fake_get_submission),
        patch("app.routers.submission.AsyncSessionLocal", return_value=mock_session_cm),
        patch("app.routers.submission.emit_admin_config_event", AsyncMock()),
    ):
        resp = await approve_submission(server_id, ReviewAction(notes="ok"), mock_request)

    body = json.loads(resp.body)
    assert body["submission_status"] == "approved_pending_url"
    assert captured_params.get("new_status") == "approved_pending_url"


@pytest.mark.asyncio
async def test_approve_submission_no_code_path_goes_scaffold_ready():
    """F-15: a no-code submission (github_repo_url is None) must never reach
    approved_pending_url — there is no URL it will ever legitimately provide."""
    from app.routers.submission import approve_submission, ReviewAction

    server_id = str(uuid4())
    mock_request = MagicMock()
    mock_request.state.client_roles = ["admin"]
    mock_request.state.client_id = "test-admin"

    sub_row = {
        "server_id": server_id,
        "submission_status": "awaiting_review",
        "scan_status": "not_applicable",
        "github_repo_url": None,
        "reviewed_by": None,
    }

    captured_params = {}

    async def fake_get_submission(sid, owner_sub=None):
        return sub_row

    mock_session = AsyncMock()

    async def fake_execute(stmt, params=None):
        if params:
            captured_params.update(params)
        return MagicMock()

    mock_session.execute = fake_execute
    mock_session.commit = AsyncMock()

    mock_session_cm = MagicMock()
    mock_session_cm.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_cm.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.submission._get_submission", fake_get_submission),
        patch("app.routers.submission.AsyncSessionLocal", return_value=mock_session_cm),
        patch("app.routers.submission.emit_admin_config_event", AsyncMock()),
    ):
        resp = await approve_submission(server_id, ReviewAction(notes="ok"), mock_request)

    body = json.loads(resp.body)
    assert body["submission_status"] == "scaffold_ready"
    assert captured_params.get("new_status") == "scaffold_ready"
    # Never the repo-path value, and never any "active"/"running" value.
    assert body["submission_status"] not in ("approved_pending_url", "active")
