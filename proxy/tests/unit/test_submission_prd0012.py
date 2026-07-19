"""
PRD-0012 (url-first onboarding, re-approval on change, debug-mode-first) —
unit tests for the submission router changes:

  - C1: submit_for_review runs the FULL validate_upstream_url_ssrf on
    requested_upstream_url (never just the cheap structural guard), and
    blocks submit on failure without consuming the draft's name.
  - C2: approve_submission runs the self-hosted approval pipeline
    (server_lifecycle.approve_self_hosted_server) for a repo-backed,
    is_self_hosted row, landing submission_status='active' + debug_mode
    reported true; a verification failure returns 422 and leaves the
    submission awaiting_review. Platform-deployed (is_self_hosted=false)
    and no-code rows keep the legacy approved_pending_url/scaffold_ready
    behavior untouched.
  - Reject rollback (product HIGH-3): a submission with a recorded
    last_good_upstream_url rolls back to last-known-good instead of
    terminally rejecting; a first-time submission (no last-good) still
    rejects terminally.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from app.routers import submission
from app.services.server_lifecycle import ChangeApprovalError
from app.services.server_onboarding import InvalidOnboardingConfig


def _fake_request(client_id: str = "owner-1", roles: list | None = None) -> Request:
    req = MagicMock(spec=Request)
    req.state = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = roles or []
    req.headers = {}
    return req


class _FakeResult:
    def __init__(self, rowcount: int = 1, row=None):
        self.rowcount = rowcount
        self._row = row

    def fetchone(self):
        return self._row

    def mappings(self):
        outer = self

        class _M:
            def first(self):
                return outer._row

        return _M()


class _FakeSession:
    def __init__(self, result: _FakeResult | None = None):
        self.executed: list = []
        self._result = result or _FakeResult()

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params))
        return self._result

    async def commit(self):
        pass


class _FakeSessionCtx:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# C1 — full SSRF validation at submit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_submit_blocks_on_ssrf_rejected_url_without_mutating_row():
    sub = {
        "server_id": "s-1", "owner_sub": "owner-1", "description": "does things",
        "requested_upstream_url": "https://169.254.169.254/mcp", "injection_mode": "none",
    }
    session = _FakeSession()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "validate_upstream_url_ssrf",
                      new=AsyncMock(side_effect=InvalidOnboardingConfig("blocked metadata IP"))), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)):
        with pytest.raises(HTTPException) as exc_info:
            await submission.submit_for_review("s-1", _fake_request(), MagicMock())

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["code"] == "SSRF_VALIDATION_FAILED"
    # Nothing was ever written — a rejected URL must not consume/mutate the row.
    assert session.executed == []


@pytest.mark.asyncio
async def test_submit_passes_ssrf_then_runs_cas_update():
    sub = {
        "server_id": "s-1", "owner_sub": "owner-1", "description": "does things",
        "requested_upstream_url": "https://good.example.com/mcp", "injection_mode": "none",
    }
    row = MagicMock()
    row.github_repo_url = "https://github.com/example/repo"
    row.submission_status = "scan_pending"
    session = _FakeSession(result=_FakeResult(rowcount=1, row=row))

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "validate_upstream_url_ssrf", new=AsyncMock(return_value=None)) as ssrf, \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch.object(submission.scan_queue, "enqueue_scan", new=AsyncMock(return_value="job-1")):
        result = await submission.submit_for_review("s-1", _fake_request(), MagicMock())

    ssrf.assert_awaited_once()
    assert ssrf.await_args.args[0] == "https://good.example.com/mcp"
    assert "scan_pending" in result.body.decode()


# ---------------------------------------------------------------------------
# Platform-deployed reachability (fix for the appsec-confirmed regression):
# self_host=false must be settable at draft creation, must NOT require a
# requested_upstream_url to submit, and must land in the LEGACY
# approved_pending_url/apply path at approve — never the self-hosted C2
# pipeline. Exercises the real create_draft -> submit_for_review ->
# approve_submission chain end to end, not a hand-set fixture.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_draft_persists_self_host_false():
    session = _FakeSession(result=_FakeResult(rowcount=0, row=None))  # no name collision

    body = submission.DraftCreate(
        name="platform-deployed-server", description="a platform-built server",
        github_repo_url="https://github.com/example/repo", self_host=False,
    )
    with patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)):
        await submission.create_draft(body, _fake_request("owner-1"))

    insert_calls = [(sql, params) for sql, params in session.executed if params and "self_host" in params]
    assert insert_calls, "expected the INSERT to bind a self_host param"
    assert insert_calls[0][1]["self_host"] is False
    assert "is_self_hosted" in insert_calls[0][0]


@pytest.mark.asyncio
async def test_submit_platform_deployed_requires_no_url_and_skips_ssrf():
    """is_self_hosted=false: requested_upstream_url must NOT be required, and
    the C1 SSRF check must not run at all (there is nothing to validate yet)."""
    sub = {
        "server_id": "s-1", "owner_sub": "owner-1", "description": "a platform-built server",
        "requested_upstream_url": None, "injection_mode": "none", "is_self_hosted": False,
    }
    row = MagicMock()
    row.github_repo_url = "https://github.com/example/repo"
    row.submission_status = "scan_pending"
    session = _FakeSession(result=_FakeResult(rowcount=1, row=row))

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "validate_upstream_url_ssrf", new=AsyncMock()) as ssrf, \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch.object(submission.scan_queue, "enqueue_scan", new=AsyncMock(return_value="job-1")):
        result = await submission.submit_for_review("s-1", _fake_request(), MagicMock())

    ssrf.assert_not_awaited()
    assert "scan_pending" in result.body.decode()


@pytest.mark.asyncio
async def test_approve_platform_deployed_reaches_approved_pending_url_via_apply_path():
    """End-to-end reachability: a self_host=false, repo-backed submission that
    reached awaiting_review WITHOUT a URL lands in approved_pending_url on
    approve (never the self-hosted C2 pipeline), and that state is exactly
    what apply_submission's _APPLY_ELIGIBLE_STATUSES accepts — closing the
    loop the appsec review flagged as unreachable."""
    sub = {
        "server_id": "s-1", "owner_sub": "owner-1", "submission_status": "awaiting_review",
        "scan_status": "passed", "github_repo_url": "https://github.com/example/repo",
        "requested_upstream_url": None, "is_self_hosted": False,
        "injection_mode": "none", "upstream_idp_config": None,
    }
    session = _FakeSession()
    approve_mock = AsyncMock()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.server_lifecycle.approve_self_hosted_server", approve_mock), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.approve_submission(
            "s-1", submission.ReviewAction(notes="ok"), _fake_request("reviewer-1", roles=["admin"]),
        )

    approve_mock.assert_not_awaited()
    body = result.body.decode()
    assert "approved_pending_url" in body
    assert "approved_pending_url" in submission._APPLY_ELIGIBLE_STATUSES


# ---------------------------------------------------------------------------
# C2 — approve_submission self-hosted pipeline vs legacy
# ---------------------------------------------------------------------------

def _awaiting_review_sub(**overrides) -> dict:
    row = {
        "server_id": "s-1", "owner_sub": "owner-1", "submission_status": "awaiting_review",
        "scan_status": "passed", "github_repo_url": "https://github.com/example/repo",
        "requested_upstream_url": "https://example.com/mcp", "is_self_hosted": True,
        "injection_mode": "none", "upstream_idp_config": None,
    }
    row.update(overrides)
    return row


def _review_action(notes: str = "looks good"):
    return submission.ReviewAction(notes=notes)


@pytest.mark.asyncio
async def test_approve_self_hosted_runs_c2_pipeline_and_lands_active_debug_mode():
    sub = _awaiting_review_sub()
    session = _FakeSession()

    approve_mock = AsyncMock(return_value={
        "status": "approved", "submission_status": "active",
        "verification_report": {"healthcheck": True}, "tools_released": 2,
    })

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.server_lifecycle.approve_self_hosted_server", approve_mock), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.approve_submission("s-1", _review_action(), _fake_request("reviewer-1", roles=["admin"]))

    approve_mock.assert_awaited_once()
    assert approve_mock.await_args.args[0] == "s-1"
    assert approve_mock.await_args.args[1] == "https://example.com/mcp"
    assert approve_mock.await_args.args[2] == "reviewer-1"
    body = result.body.decode()
    assert '"submission_status": "active"' in body or '"submission_status":"active"' in body
    assert '"debug_mode": true' in body or '"debug_mode":true' in body
    assert '"tools_released": 2' in body or '"tools_released":2' in body


@pytest.mark.asyncio
async def test_approve_self_hosted_verification_failure_returns_422_and_stays_awaiting_review():
    sub = _awaiting_review_sub()
    session = _FakeSession()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.server_lifecycle.approve_self_hosted_server",
               new=AsyncMock(side_effect=ChangeApprovalError("probe failed", {"healthcheck": False}))), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        with pytest.raises(HTTPException) as exc_info:
            await submission.approve_submission("s-1", _review_action(), _fake_request("reviewer-1", roles=["admin"]))

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["code"] == "VERIFICATION_FAILED"
    # The review-metadata UPDATE (reviewed_by/notes/oauth) is allowed to have
    # run, but no statement in this session may set submission_status='active'
    # or status='approved' — the row must remain awaiting_review on failure.
    all_sql = " | ".join(sql for sql, _ in session.executed)
    assert "submission_status = 'active'" not in all_sql
    assert "status = 'approved'" not in all_sql


@pytest.mark.asyncio
async def test_approve_platform_deployed_keeps_legacy_approved_pending_url():
    """is_self_hosted=false must take the OLD branch unchanged — the new C2
    pipeline must never run for a platform-deployed row."""
    sub = _awaiting_review_sub(is_self_hosted=False)
    session = _FakeSession()

    approve_mock = AsyncMock()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.server_lifecycle.approve_self_hosted_server", approve_mock), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.approve_submission("s-1", _review_action(), _fake_request("reviewer-1", roles=["admin"]))

    approve_mock.assert_not_awaited()
    body = result.body.decode()
    assert "approved_pending_url" in body


@pytest.mark.asyncio
async def test_approve_no_code_submission_keeps_scaffold_ready():
    sub = _awaiting_review_sub(github_repo_url=None)
    session = _FakeSession()
    approve_mock = AsyncMock()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.server_lifecycle.approve_self_hosted_server", approve_mock), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.approve_submission("s-1", _review_action(), _fake_request("reviewer-1", roles=["admin"]))

    approve_mock.assert_not_awaited()
    assert "scaffold_ready" in result.body.decode()


# ---------------------------------------------------------------------------
# Reject rollback vs terminal (product HIGH-3)
# ---------------------------------------------------------------------------

class _MapResult:
    """Result whose .mappings().first() returns a plain dict (supports [])."""

    def __init__(self, mapping, rowcount: int = 1):
        self._m = mapping
        self.rowcount = rowcount

    def mappings(self):
        outer = self

        class _M:
            def first(self_inner):
                return outer._m

        return _M()


@pytest.mark.asyncio
async def test_reject_rolls_back_to_last_good_when_previously_live():
    sub = {"server_id": "s-1", "owner_sub": "owner-1", "last_good_upstream_url": "https://good.example.com/mcp"}

    rollback_row = _MapResult({
        "last_good_upstream_url": "https://good.example.com/mcp",
        "last_good_tool_schema": [{"name": "t1", "schema": {}}],
    })
    reactivate_result = _FakeResult(rowcount=1)
    session = _FakeSession()

    call_count = {"n": 0}

    async def _execute(stmt, params=None):
        session.executed.append((str(stmt), params))
        call_count["n"] += 1
        if call_count["n"] == 1:
            return rollback_row
        return reactivate_result

    session.execute = _execute

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.reject_submission("s-1", _review_action("nope"), _fake_request("reviewer-1", roles=["admin"]))

    body = result.body.decode()
    assert '"rolled_back_to_last_good": true' in body or '"rolled_back_to_last_good":true' in body
    all_sql = " | ".join(sql for sql, _ in session.executed)
    assert "status = 'approved'" in all_sql
    assert "submission_status = 'active'" in all_sql
    assert "'rejected'" not in all_sql


@pytest.mark.asyncio
async def test_reject_first_time_submission_is_terminal():
    sub = {"server_id": "s-1", "owner_sub": "owner-1", "last_good_upstream_url": None}
    session = _FakeSession(result=_FakeResult(rowcount=1))

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "_client_id", return_value="reviewer-1"), \
         patch.object(submission, "_require_not_self_review"), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch.object(submission, "emit_admin_config_event", new=AsyncMock()):
        result = await submission.reject_submission("s-1", _review_action("no"), _fake_request("reviewer-1", roles=["admin"]))

    body = result.body.decode()
    assert '"submission_status": "rejected"' in body or '"submission_status":"rejected"' in body
    all_sql = " | ".join(sql for sql, _ in session.executed)
    assert "submission_status = 'rejected'" in all_sql
