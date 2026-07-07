"""
Unit tests — deploy verifier (CR-01 / WP-B3 phase 4).

Covers app.services.deploy_verifier: discovery failure must never result in
deployment_status='verified' (fail closed), a healthy probe+discovery+probe
sequence promotes runtime_url->upstream_url and sets status='approved', and
run_verification_probes is the single shared code path (imported directly
by both verify_server and, in Task 6, provide_running_url).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import deploy_verifier


class _FakeSession:
    def __init__(self, row: dict | None):
        self._row = row
        self.executed: list = []

    async def execute(self, stmt, params=None):
        self.executed.append((str(stmt), params))
        result = MagicMock()
        result.mappings.return_value.first.return_value = self._row
        return result

    async def commit(self):
        pass


class _FakeSessionCtx:
    def __init__(self, session: _FakeSession):
        self._session = session

    async def __aenter__(self):
        return self._session

    async def __aexit__(self, *exc):
        return False


def _patch_session(monkeypatch, row: dict | None):
    session = _FakeSession(row)
    monkeypatch.setattr(deploy_verifier, "AsyncSessionLocal", lambda: _FakeSessionCtx(session))
    return session


@pytest.mark.asyncio
async def test_refuses_verify_when_not_deployed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "deploying", "runtime_url": None}
    session = _patch_session(monkeypatch, row)

    with patch.object(deploy_verifier, "_probe_initialize", new_callable=AsyncMock) as probe:
        result = await deploy_verifier.verify_server("s-1")

    probe.assert_not_called()
    assert result["healthcheck"] is False
    assert result["invocation_probe_ok"] is False
    # deployment_status written to 'failed'
    assert any("'failed'" in sql for sql, _ in session.executed)


@pytest.mark.asyncio
async def test_discovery_failure_never_sets_verified(monkeypatch):
    """Mock _run_tool_discovery to raise — deployment_status must become
    'failed', never 'verified'."""
    row = {"server_id": "s-1", "deployment_status": "deployed", "runtime_url": "http://127.0.0.1:8000/"}
    session = _patch_session(monkeypatch, row)

    async def _fake_discovery(*a, **kw):
        raise RuntimeError("upstream unreachable during discovery")

    with patch.object(deploy_verifier, "_probe_initialize", new_callable=AsyncMock, return_value=True), \
         patch("app.routers.tools._run_tool_discovery", new=_fake_discovery):
        result = await deploy_verifier.verify_server("s-1")

    assert result["healthcheck"] is True
    assert result["invocation_probe_ok"] is False
    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "'verified'" not in executed_sql
    assert "deployment_status = 'failed'" in executed_sql


@pytest.mark.asyncio
async def test_healthcheck_failure_never_sets_verified(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "deployed", "runtime_url": "http://127.0.0.1:8000/"}
    session = _patch_session(monkeypatch, row)

    with patch.object(deploy_verifier, "_probe_initialize", new_callable=AsyncMock, return_value=False):
        result = await deploy_verifier.verify_server("s-1")

    assert result["healthcheck"] is False
    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "'verified'" not in executed_sql


@pytest.mark.asyncio
async def test_successful_verify_promotes_runtime_url_and_approves(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "deployed", "runtime_url": "http://127.0.0.1:8000/"}
    session = _patch_session(monkeypatch, row)

    async def _fake_discovery(*a, **kw):
        resp = MagicMock()
        resp.status_code = 200
        resp.body = b'{"discovered": 3, "skipped": []}'
        return resp

    with patch.object(deploy_verifier, "_probe_initialize", new_callable=AsyncMock, return_value=True), \
         patch("app.routers.tools._run_tool_discovery", new=_fake_discovery):
        result = await deploy_verifier.verify_server("s-1")

    assert result["healthcheck"] is True
    assert result["tools_discovered"] == 3
    assert result["invocation_probe_ok"] is True
    assert result["contract_check"] is None
    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "deployment_status = 'verified'" in executed_sql
    assert "status = 'approved'" in executed_sql
    upstream_params = [params for _, params in session.executed if params and "upstream_url" in params]
    assert upstream_params and upstream_params[0]["upstream_url"] == "http://127.0.0.1:8000/"
