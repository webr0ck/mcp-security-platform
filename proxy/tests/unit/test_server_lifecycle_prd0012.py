"""
PRD-0012 (url-first onboarding, re-approval on change, debug-mode-first) —
unit tests for app.services.server_lifecycle.

Covers the load-bearing invariants called out by the 3-critic review:
  - H-01 ordering: status='approved' only after verification probes pass.
  - TRAP-4: debug_mode=TRUE is always written with a real debug_enabled_by
    (never 'system') + debug_enabled_at, in the same statement.
  - TRAP-2/TRAP-5: request-change quarantines every tool_registry row for the
    server and demotes server_registry.status atomically, CAS-guarded on the
    legal source states.
  - IP-only vs code-change classification: byte-identical live schema fetch
    auto-approves; any mismatch/uncertainty escalates to the guarded
    re-review scan path (TRAP-6).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import server_lifecycle as sl


class _FakeResult:
    def __init__(self, rowcount: int = 1, rows=None):
        self.rowcount = rowcount
        self._rows = rows or []

    def mappings(self):
        outer = self

        class _M:
            def first(self):
                return outer._rows[0] if outer._rows else None

            def all(self):
                return outer._rows

        return _M()

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, results: list | None = None):
        # results: optional list of _FakeResult to return in order; falls back
        # to a generic rowcount=1 empty result when exhausted.
        self.executed: list = []
        self._results = list(results or [])
        self.committed = False
        self.rolled_back = False

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params))
        if self._results:
            return self._results.pop(0)
        return _FakeResult(rowcount=1)

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


class _FakeSessionCtx:
    def __init__(self, session):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


def _session_factory(*sessions):
    """Returns a callable usable as AsyncSessionLocal — yields each session
    in turn (one per `async with AsyncSessionLocal() as session:` call)."""
    it = iter(sessions)

    def _factory():
        return _FakeSessionCtx(next(it))

    return _factory


# ---------------------------------------------------------------------------
# approve_self_hosted_server — H-01 ordering + TRAP-4
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_approve_defers_status_approved_until_probes_succeed():
    url_session = _FakeSession()
    final_session = _FakeSession(results=[_FakeResult(rowcount=1), _FakeResult(rows=[])])

    fake_report = {"healthcheck": True, "tools_discovered": 1, "tools_skipped": [],
                   "invocation_probe_ok": True, "contract_check": None}

    with patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "AsyncSessionLocal", _session_factory(url_session, final_session)), \
         patch.object(sl, "run_verification_probes", new=AsyncMock(return_value=fake_report)) as probes:
        result = await sl.approve_self_hosted_server(
            "srv-1", "https://example.com/mcp", "reviewer-1", new_submission_status="active",
        )

    assert probes.await_args.kwargs.get("require_approved") is False
    # The pre-probe write (url_session) must NOT set status='approved'.
    pre_probe_sql = " | ".join(sql for sql, _ in url_session.executed)
    assert "status = 'approved'" not in pre_probe_sql
    # Only the post-probe-success write does.
    post_probe_sql = " | ".join(sql for sql, _ in final_session.executed)
    assert "status = 'approved'" in post_probe_sql
    assert result["status"] == "approved"


@pytest.mark.asyncio
async def test_approve_never_sets_approved_when_probes_fail():
    url_session = _FakeSession()
    fail_session = _FakeSession()

    class _VFE(Exception):
        def __init__(self, report):
            self.report = report

    with patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "AsyncSessionLocal", _session_factory(url_session, fail_session)), \
         patch.object(sl, "VerificationFailedError", _VFE), \
         patch.object(sl, "run_verification_probes",
                      new=AsyncMock(side_effect=_VFE({"healthcheck": False}))):
        with pytest.raises(sl.ChangeApprovalError):
            await sl.approve_self_hosted_server("srv-1", "https://example.com/mcp", "reviewer-1")

    all_sql = " | ".join(sql for sql, _ in url_session.executed + fail_session.executed)
    assert "status = 'approved'" not in all_sql


@pytest.mark.asyncio
async def test_approve_sets_real_debug_enabled_by_never_system():
    url_session = _FakeSession()
    final_session = _FakeSession(results=[_FakeResult(rowcount=1), _FakeResult(rows=[])])
    fake_report = {"healthcheck": True, "tools_discovered": 0, "tools_skipped": [],
                   "invocation_probe_ok": True, "contract_check": None}

    with patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "AsyncSessionLocal", _session_factory(url_session, final_session)), \
         patch.object(sl, "run_verification_probes", new=AsyncMock(return_value=fake_report)):
        await sl.approve_self_hosted_server("srv-1", "https://example.com/mcp", "owner-42")

    # Find the UPDATE that sets debug_mode = TRUE and assert the bound actor
    # param is the real caller ("owner-42"), never the literal string 'system'.
    debug_writes = [
        (sql, params) for sql, params in final_session.executed
        if params and "debug_mode = TRUE" in sql
    ]
    assert debug_writes, "expected a debug_mode=TRUE write"
    for sql, params in debug_writes:
        assert params["actor"] == "owner-42"
        assert params["actor"] != "system"
        assert "debug_enabled_by = :actor" in sql
        assert "debug_enabled_at = now()" in sql


# ---------------------------------------------------------------------------
# request_change_for_server — TRAP-2 (quarantine all tools) / TRAP-5 (CAS demote)
# ---------------------------------------------------------------------------

def _live_self_hosted_row(**overrides) -> dict:
    row = {
        "server_id": "srv-1", "status": "approved", "submission_status": "active",
        "is_self_hosted": True, "github_repo_url": "https://github.com/example/repo",
        "requested_upstream_url": "https://old.example.com/mcp",
        "upstream_url": "https://old.example.com/mcp", "scan_commit": "abc123",
        "upstream_allowlist_entry": None, "owner_sub": "owner-1", "maintainers": [],
        "deleted_at": None,
    }
    row.update(overrides)
    return row


@pytest.mark.asyncio
async def test_request_change_rejects_non_self_hosted():
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row(is_self_hosted=False)])])

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session)):
        with pytest.raises(sl.RequestChangeNotEligibleError):
            await sl.request_change_for_server("srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp")


@pytest.mark.asyncio
async def test_request_change_quarantines_all_tools_and_demotes_atomically():
    """TRAP-2 + TRAP-5: one transaction (one session) does the tool
    quarantine UPDATE and the server_registry CAS demote UPDATE together."""
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row()])])
    demote_session = _FakeSession(results=[
        _FakeResult(rows=[]),          # snapshot_tool_schema (no rows -> [])
        _FakeResult(rowcount=1),       # CAS UPDATE server_registry -> succeeds
        _FakeResult(rowcount=3),       # UPDATE tool_registry quarantine -> 3 rows
        _FakeResult(rowcount=1),       # audit_events insert
    ])

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session, demote_session)), \
         patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "_enqueue_change_rereview", new=AsyncMock(return_value="job-99")):
        result = await sl.request_change_for_server(
            "srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp",
            asserted_ip_only=False,  # conservative default -> code_change path
        )

    demote_sql = [sql for sql, _ in demote_session.executed]
    assert any("status = 'quarantined'" in s and "submission_status = 'awaiting_review'" in s for s in demote_sql)
    assert any("UPDATE tool_registry" in s and "status = 'quarantined'" in s for s in demote_sql)
    assert demote_session.committed is True
    assert result["classification"] == "code_change"
    assert result["tools_quarantined"] == 3
    assert result["job_id"] == "job-99"


@pytest.mark.asyncio
async def test_request_change_cas_failure_rolls_back_and_raises():
    """A concurrent reject/delete already moved the row out of the legal
    source states — the CAS UPDATE must return rowcount=0, and nothing else
    in the transaction may have taken effect."""
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row()])])
    demote_session = _FakeSession(results=[
        _FakeResult(rows=[]),      # snapshot_tool_schema
        _FakeResult(rowcount=0),   # CAS UPDATE misses
    ])

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session, demote_session)), \
         patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)):
        with pytest.raises(sl.RequestChangeNotEligibleError):
            await sl.request_change_for_server("srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp")

    assert demote_session.rolled_back is True
    assert demote_session.committed is False
    # Only the CAS attempt ran — tool quarantine / audit insert never fired.
    assert len(demote_session.executed) == 2


# ---------------------------------------------------------------------------
# IP-only vs code-change classification
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ip_only_auto_approves_when_schema_identical():
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row()])])
    tool_schema = [{"name": "t1", "schema": {"type": "object"}}]
    demote_session = _FakeSession(results=[
        _FakeResult(rows=tool_schema),  # snapshot_tool_schema
        _FakeResult(rowcount=1),        # CAS demote succeeds
        _FakeResult(rowcount=1),        # tool quarantine
        _FakeResult(rowcount=1),        # audit insert
    ])

    approve_mock = AsyncMock(return_value={
        "status": "approved", "submission_status": "active",
        "verification_report": {}, "tools_released": 1,
    })

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session, demote_session)), \
         patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "fetch_live_tool_schema", new=AsyncMock(return_value=tool_schema)), \
         patch.object(sl, "approve_self_hosted_server", approve_mock):
        result = await sl.request_change_for_server(
            "srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp",
            asserted_ip_only=True,
        )

    approve_mock.assert_awaited_once()
    assert approve_mock.await_args.args[0] == "srv-1"
    assert approve_mock.await_args.args[1] == "https://new.example.com/mcp"
    assert approve_mock.await_args.args[2] == "owner-1"  # triggering owner, never 'system'
    assert result["classification"] == "ip_only"
    assert result["debug_mode"] is True


@pytest.mark.asyncio
async def test_schema_mismatch_escalates_to_code_change_never_auto_approves():
    """Fail-safe: any tool-schema mismatch (or fetch failure) must escalate,
    never auto-approve — this is the security-critical half of the IP-only
    classifier."""
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row()])])
    last_good_schema = [{"name": "t1", "schema": {"type": "object"}}]
    demote_session = _FakeSession(results=[
        _FakeResult(rows=last_good_schema),  # snapshot_tool_schema
        _FakeResult(rowcount=1),             # CAS demote succeeds
        _FakeResult(rowcount=1),             # tool quarantine
        _FakeResult(rowcount=1),             # audit insert
    ])
    approve_mock = AsyncMock()

    # Live schema differs (extra tool) -> must NOT auto-approve.
    live_schema_different = [
        {"name": "t1", "schema": {"type": "object"}},
        {"name": "t2-new", "schema": {"type": "object"}},
    ]

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session, demote_session)), \
         patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "fetch_live_tool_schema", new=AsyncMock(return_value=live_schema_different)), \
         patch.object(sl, "approve_self_hosted_server", approve_mock), \
         patch.object(sl, "_enqueue_change_rereview", new=AsyncMock(return_value="job-7")):
        result = await sl.request_change_for_server(
            "srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp",
            asserted_ip_only=True,
        )

    approve_mock.assert_not_awaited()
    assert result["classification"] == "code_change"
    assert result["job_id"] == "job-7"


@pytest.mark.asyncio
async def test_live_fetch_failure_escalates_never_auto_approves():
    """fetch_live_tool_schema returning None (unreachable/SSRF-rejected) must
    never be treated as a match."""
    fetch_session = _FakeSession(results=[_FakeResult(rows=[_live_self_hosted_row()])])
    demote_session = _FakeSession(results=[
        _FakeResult(rows=[{"name": "t1", "schema": {}}]),
        _FakeResult(rowcount=1),
        _FakeResult(rowcount=1),
        _FakeResult(rowcount=1),
    ])
    approve_mock = AsyncMock()

    with patch.object(sl, "AsyncSessionLocal", _session_factory(fetch_session, demote_session)), \
         patch.object(sl, "validate_upstream_url_full", new=AsyncMock(return_value=None)), \
         patch.object(sl, "fetch_live_tool_schema", new=AsyncMock(return_value=None)), \
         patch.object(sl, "approve_self_hosted_server", approve_mock), \
         patch.object(sl, "_enqueue_change_rereview", new=AsyncMock(return_value="job-1")):
        result = await sl.request_change_for_server(
            "srv-1", "owner-1", new_upstream_url="https://new.example.com/mcp",
            asserted_ip_only=True,
        )

    approve_mock.assert_not_awaited()
    assert result["classification"] == "code_change"


def test_tool_schemas_identical_none_never_matches():
    assert sl.tool_schemas_identical(None, [{"name": "a", "schema": {}}]) is False
    assert sl.tool_schemas_identical([{"name": "a", "schema": {}}], None) is False
    assert sl.tool_schemas_identical([{"name": "a", "schema": {}}], []) is False


def test_tool_schemas_identical_order_independent_match():
    live = [{"name": "b", "schema": {"type": "object"}}, {"name": "a", "schema": {"type": "object"}}]
    last_good = [{"name": "a", "schema": {"type": "object"}}, {"name": "b", "schema": {"type": "object"}}]
    assert sl.tool_schemas_identical(live, last_good) is True


def test_tool_schemas_identical_detects_schema_drift_on_same_name():
    """A same-named tool whose schema actually changed must NOT read as
    identical — this is exactly what discovery's skip-idempotent dedup would
    miss, which is why the classifier uses a live fetch instead."""
    live = [{"name": "a", "schema": {"type": "object", "properties": {"x": {}}}}]
    last_good = [{"name": "a", "schema": {"type": "object", "properties": {}}}]
    assert sl.tool_schemas_identical(live, last_good) is False
