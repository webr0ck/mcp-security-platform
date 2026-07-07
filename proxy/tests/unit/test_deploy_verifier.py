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

    fake_contract_report = {"initialize_ok": True, "tools_list_ok": True, "health_ok": True, "violations": []}

    with patch.object(deploy_verifier, "_probe_initialize", new_callable=AsyncMock, return_value=True), \
         patch("app.routers.tools._run_tool_discovery", new=_fake_discovery), \
         patch("app.services.contract_check.run_contract_check", new=AsyncMock(return_value=fake_contract_report)):
        result = await deploy_verifier.verify_server("s-1")

    assert result["healthcheck"] is True
    assert result["tools_discovered"] == 3
    assert result["invocation_probe_ok"] is True
    assert result["contract_check"] == fake_contract_report
    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "deployment_status = 'verified'" in executed_sql
    assert "status = 'approved'" in executed_sql
    assert "contract_version = 'v0.1'" in executed_sql
    upstream_params = [params for _, params in session.executed if params and "upstream_url" in params]
    assert upstream_params and upstream_params[0]["upstream_url"] == "http://127.0.0.1:8000/"
    # status='approved' must be set on the 'verifying' UPDATE (BEFORE probes
    # run), not only on final success -- found live: _run_tool_discovery
    # requires status='approved' as a precondition, so setting it only after
    # a successful probe would make discovery itself always 403.
    verifying_sql = [sql for sql, _ in session.executed if "'verifying'" in sql]
    assert verifying_sql and "status = 'approved'" in verifying_sql[0]


@pytest.mark.asyncio
async def test_status_approved_set_before_probes_run_not_only_on_success(monkeypatch):
    """Regression: discovery (inside run_verification_probes) requires
    status='approved' as a precondition -- if that UPDATE only happened on
    full success, discovery would always 403 for the platform-managed path."""
    row = {"server_id": "s-1", "deployment_status": "deployed", "runtime_url": "http://127.0.0.1:8000/"}
    session = _patch_session(monkeypatch, row)

    seen_status_at_probe_time = {}

    async def _capturing_probes(server_id, url, actor_client_id):
        seen_status_at_probe_time["sql"] = " | ".join(sql for sql, _ in session.executed)
        raise deploy_verifier.VerificationFailedError("boom", {"healthcheck": False, "tools_discovered": 0,
                                                                "tools_skipped": [], "invocation_probe_ok": False,
                                                                "contract_check": None})

    with patch.object(deploy_verifier, "run_verification_probes", new=_capturing_probes):
        await deploy_verifier.verify_server("s-1")

    assert "status = 'approved'" in seen_status_at_probe_time["sql"], (
        "status='approved' must already be committed before run_verification_probes is called"
    )
