"""
Unit tests — POST /apply + GET /verification-report (CR-01 / WP-B3 phase 5).

Covers app.routers.submission.apply_submission / get_verification_report:
apply is only valid from scaffold_ready/approved_pending_url, requires a
github_repo_url and a recorded scan_commit (the TOCTOU pin), and enqueues a
build_requested job with expected_digest set. verification-report is a
plain read, 404 if never populated.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from app.routers import submission


def _fake_request(client_id: str = "submitter-1") -> Request:
    req = MagicMock(spec=Request)
    req.state = MagicMock()
    req.state.client_id = client_id
    return req


class _FakeSession:
    def __init__(self):
        self.executed: list = []

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params))
        return MagicMock()

    async def commit(self):
        pass


class _FakeSessionCtx:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_apply_requires_scaffold_ready_or_approved(monkeypatch):
    sub = {"server_id": "s-1", "submission_status": "draft",
           "github_repo_url": "https://github.com/example/repo", "scan_commit": "abc123"}
    monkeypatch.setattr(submission, "_get_submission", AsyncMock(return_value=sub))

    with pytest.raises(HTTPException) as exc_info:
        await submission.apply_submission("s-1", _fake_request())
    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_apply_requires_github_url():
    sub = {"server_id": "s-1", "submission_status": "scaffold_ready",
           "github_repo_url": None, "scan_commit": "abc123"}
    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)):
        with pytest.raises(HTTPException) as exc_info:
            await submission.apply_submission("s-1", _fake_request())
    assert exc_info.value.status_code == 422
    assert "github_repo_url" in exc_info.value.detail


@pytest.mark.asyncio
async def test_apply_requires_scan_commit():
    sub = {"server_id": "s-1", "submission_status": "scaffold_ready",
           "github_repo_url": "https://github.com/example/repo", "scan_commit": None}
    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)):
        with pytest.raises(HTTPException) as exc_info:
            await submission.apply_submission("s-1", _fake_request())
    assert exc_info.value.status_code == 422
    assert "scan_commit" in exc_info.value.detail


@pytest.mark.asyncio
async def test_apply_enqueues_build_job(monkeypatch):
    sub = {"server_id": "s-1", "submission_status": "approved_pending_url",
           "github_repo_url": "https://github.com/example/repo", "scan_commit": "abc123def456"}
    session = _FakeSession()

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission.scan_queue, "enqueue_scan", new=AsyncMock(return_value="job-1")) as mock_enqueue, \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)):
        result = await submission.apply_submission("s-1", _fake_request())

    mock_enqueue.assert_awaited_once_with("s-1", "https://github.com/example/repo", job_type="build_requested")
    body = result.body.decode()
    assert "build_requested" in body
    assert "job-1" in body
    digest_params = [p for _, p in session.executed if p and p.get("digest")]
    assert digest_params and digest_params[0]["digest"] == "abc123def456"
    assert digest_params[0]["job_id"] == "job-1"


def _fake_json_request(body: dict, client_id: str = "submitter-1") -> Request:
    req = _fake_request(client_id)
    req.json = AsyncMock(return_value=body)
    return req


@pytest.mark.asyncio
async def test_provide_url_defers_status_approved_until_probes_succeed(monkeypatch):
    """H-01 (2026-07-11 audit): status='approved' is the real entitlement/
    credential-issuance gate. It must not be set in the same UPDATE as
    upstream_url — only after run_verification_probes succeeds."""
    sub = {"server_id": "s-1", "submission_status": "approved_pending_url", "reviewed_by": "admin-1"}
    session = _FakeSession()

    fake_report = {"healthcheck": True, "tools_discovered": 1, "tools_skipped": [],
                    "invocation_probe_ok": True, "contract_check": None}

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "validate_upstream_url_ssrf", new=AsyncMock(return_value=None)), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.deploy_verifier.run_verification_probes",
               new=AsyncMock(return_value=fake_report)) as probes:
        await submission.provide_running_url(
            "s-1", _fake_json_request({"upstream_url": "https://example.com/mcp"}, client_id="submitter-1"),
        )

    assert probes.await_args.kwargs.get("require_approved") is False
    pre_probe_sql = [sql for sql, p in session.executed if p and p.get("url") == "https://example.com/mcp"]
    assert pre_probe_sql and "status = 'approved'" not in pre_probe_sql[0]
    all_sql = " | ".join(sql for sql, _ in session.executed)
    assert "status = 'approved'" in all_sql  # set somewhere, just not in the pre-probe write


@pytest.mark.asyncio
async def test_provide_url_never_approves_when_probes_fail(monkeypatch):
    """H-01: a probe failure must leave status unpromoted entirely."""
    sub = {"server_id": "s-1", "submission_status": "approved_pending_url", "reviewed_by": "admin-1"}
    session = _FakeSession()

    from app.services.deploy_verifier import VerificationFailedError

    async def _failing_probes(*a, **kw):
        raise VerificationFailedError("boom", {"healthcheck": False, "tools_discovered": 0,
                                                "tools_skipped": [], "invocation_probe_ok": False,
                                                "contract_check": None})

    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)), \
         patch.object(submission, "validate_upstream_url_ssrf", new=AsyncMock(return_value=None)), \
         patch.object(submission, "AsyncSessionLocal", lambda: _FakeSessionCtx(session)), \
         patch("app.services.deploy_verifier.run_verification_probes", new=_failing_probes):
        await submission.provide_running_url(
            "s-1", _fake_json_request({"upstream_url": "https://example.com/mcp"}, client_id="submitter-1"),
        )

    all_sql = " | ".join(sql for sql, _ in session.executed)
    assert "status = 'approved'" not in all_sql


@pytest.mark.asyncio
async def test_verification_report_404_when_absent():
    sub = {"server_id": "s-1", "verification_report": None, "deployment_status": "building"}
    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)):
        with pytest.raises(HTTPException) as exc_info:
            await submission.get_verification_report("s-1", _fake_request())
    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_verification_report_returns_when_present():
    report = {"healthcheck": True, "tools_discovered": 2, "tools_skipped": [],
              "invocation_probe_ok": True, "contract_check": None}
    sub = {"server_id": "s-1", "verification_report": report, "deployment_status": "verified"}
    with patch.object(submission, "_get_submission", new=AsyncMock(return_value=sub)):
        result = await submission.get_verification_report("s-1", _fake_request())
    body = result.body.decode()
    assert "verified" in body
    assert "tools_discovered" in body
