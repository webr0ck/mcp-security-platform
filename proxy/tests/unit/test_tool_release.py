"""
Unit tests — CR-07 (WP-B3 remainder) POST /tools/{tool_id}/release.

Covers: reviewer-role gate, not-quarantined guard, the evidence gate (parent
server approved + scan passed), the invocation-probe fail-closed path, and
the happy path (released_by/released_at/release_notes set, TOOL_RELEASED
audit event emitted, generic TOOL_STATUS_CHANGED is NOT what fires here).

Run: cd proxy && .venv/bin/python -m pytest tests/unit/test_tool_release.py -v
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import httpx
import pytest
from fastapi import HTTPException

from app.routers.tools import release_tool

TOOL_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
TOOL_UUID = UUID(TOOL_ID)


def _request(roles=None, client_id="reviewer-1"):
    req = MagicMock()
    req.json = AsyncMock(return_value={"notes": "verified fix, safe to release"})
    req.state.client_roles = roles if roles is not None else ["security_reviewer"]
    req.state.client_id = client_id
    req.state.request_id = "req-release-001"
    return req


def _row(**overrides):
    base = {
        "tool_id": TOOL_ID, "name": "some_tool", "status": "quarantined",
        "upstream_url": "https://upstream.example.com/tool", "server_id": "srv-1",
        "server_status": "approved", "server_scan_status": "passed",
        "upstream_allowlist_entry": None,
    }
    base.update(overrides)
    return base


def _db_with_row(row: dict) -> AsyncMock:
    db = AsyncMock()
    select_result = MagicMock()
    select_result.mappings.return_value.first.return_value = row
    update_result = MagicMock()
    db.execute = AsyncMock(side_effect=[select_result, update_result])
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _ok_probe_response():
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.headers = {"content-type": "application/json"}
    return resp


class _FakeAsyncClient:
    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, *a, **kw):
        return _ok_probe_response()


def _patches(pinned_ips=None):
    return [
        patch("app.routers.tools.validate_server_url", return_value=None),
        patch("app.routers.tools.revalidate_upstream_ip_at_invoke", AsyncMock(return_value=pinned_ips or [])),
        patch("httpx.AsyncClient", _FakeAsyncClient),
        patch("app.routers.tools.get_tool", AsyncMock(return_value={"tool_id": TOOL_ID, "status": "active"})),
        patch("mcp_audit_logger.MCPAuditLogger"),
    ]


def _run_with_patches(coro_factory, pinned_ips=None):
    patches = _patches(pinned_ips)
    for p in patches:
        p.start()
    try:
        import asyncio
        return asyncio.run(coro_factory())
    finally:
        for p in patches:
            p.stop()


# ---------------------------------------------------------------------------
# Role gate
# ---------------------------------------------------------------------------

def test_non_reviewer_role_forbidden():
    req = _request(roles=["auditor"])
    db = _db_with_row(_row())
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 403


@pytest.mark.parametrize("role", ["admin", "platform_admin", "security_reviewer"])
def test_reviewer_roles_pass_the_gate(role):
    req = _request(roles=[role])
    db = _db_with_row(_row())
    result = _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert result["status"] == "active"


# ---------------------------------------------------------------------------
# Not-quarantined guard
# ---------------------------------------------------------------------------

def test_not_quarantined_returns_409():
    req = _request()
    db = _db_with_row(_row(status="active"))
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 409


def test_tool_not_found_returns_404():
    req = _request()
    db = _db_with_row(None)
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Evidence gate — parent server approved + scan passed
# ---------------------------------------------------------------------------

def test_parent_server_not_approved_denied():
    req = _request()
    db = _db_with_row(_row(server_status="pending"))
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail["code"] == "RELEASE_DENIED"


def test_parent_server_scan_blocked_denied():
    req = _request()
    db = _db_with_row(_row(server_scan_status="blocked"))
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 422


def test_parent_server_scan_review_required_denied():
    """A review_required scan (CR-12) is deliberately NOT sufficient for
    release — it must be resolved to 'passed' upstream first."""
    req = _request()
    db = _db_with_row(_row(server_scan_status="review_required"))
    with pytest.raises(HTTPException) as exc_info:
        _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert exc_info.value.status_code == 422


def test_no_parent_server_skips_evidence_gate():
    """A tool with no server_id (standalone registration) has nothing to gate on."""
    req = _request()
    db = _db_with_row(_row(server_id=None, server_status=None, server_scan_status=None))
    result = _run_with_patches(lambda: release_tool(TOOL_UUID, req, db))
    assert result["status"] == "active"


# ---------------------------------------------------------------------------
# Invocation probe — fail closed
# ---------------------------------------------------------------------------

def test_upstream_unreachable_probe_fails_release_never_granted():
    req = _request()
    db = _db_with_row(_row())

    class _FailingClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **kw):
            raise httpx.ConnectError("connection refused")

    patches = [
        patch("app.routers.tools.validate_server_url", return_value=None),
        patch("app.routers.tools.revalidate_upstream_ip_at_invoke", AsyncMock(return_value=[])),
        patch("httpx.AsyncClient", _FailingClient),
    ]
    for p in patches:
        p.start()
    try:
        import asyncio
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(release_tool(TOOL_UUID, req, db))
        assert exc_info.value.status_code == 502
    finally:
        for p in patches:
            p.stop()
    # Never wrote to the DB past the SELECT — the probe failure must
    # short-circuit before any UPDATE.
    assert db.commit.await_count == 0


# ---------------------------------------------------------------------------
# Happy path — attribution fields + dedicated audit event
# ---------------------------------------------------------------------------

def test_successful_release_sets_attribution_and_emits_tool_released():
    req = _request(client_id="alice-reviewer")
    db = _db_with_row(_row())
    with patch("mcp_audit_logger.MCPAuditLogger") as mock_logger_cls, \
         patch("app.routers.tools.validate_server_url", return_value=None), \
         patch("app.routers.tools.revalidate_upstream_ip_at_invoke", AsyncMock(return_value=[])), \
         patch("httpx.AsyncClient", _FakeAsyncClient), \
         patch("app.routers.tools.get_tool", AsyncMock(return_value={"tool_id": TOOL_ID, "status": "active"})):
        import asyncio
        asyncio.run(release_tool(TOOL_UUID, req, db))

    update_call = db.execute.await_args_list[1]
    params = update_call.args[1]
    assert params["released_by"] == "alice-reviewer"
    assert params["notes"] == "verified fix, safe to release"
    db.commit.assert_awaited_once()

    mock_logger_instance = mock_logger_cls.return_value
    assert mock_logger_instance.emit_admin_event.called
    emitted_event = mock_logger_instance.emit_admin_event.call_args.args[0]
    from mcp_audit_logger import AuditEventType
    assert emitted_event.event_type == AuditEventType.TOOL_RELEASED
