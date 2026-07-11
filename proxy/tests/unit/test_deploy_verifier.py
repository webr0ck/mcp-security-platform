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
        assert kw.get("require_approved") is False, (
            "H-01: verify-time discovery must bypass the status='approved' precondition, "
            "since status is not promoted until probes succeed"
        )
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
    # H-01 fix (2026-07-11 audit): status='approved' — the real entitlement/
    # credential-issuance gate — must NOT be set on the pre-probe 'verifying'
    # UPDATE. It may only ever appear alongside deployment_status='verified',
    # i.e. after probes actually succeeded.
    verifying_sql = [sql for sql, _ in session.executed if "'verifying'" in sql]
    assert verifying_sql and "status = 'approved'" not in verifying_sql[0]
    verified_sql = [sql for sql, _ in session.executed if "'verified'" in sql]
    assert verified_sql and "status = 'approved'" in verified_sql[0]


@pytest.mark.asyncio
async def test_status_not_approved_until_probes_succeed(monkeypatch):
    """H-01 (2026-07-11 audit): status is the actual entitlement/credential-
    issuance gate. A server whose verification probes fail must never have
    briefly been status='approved' — no UPDATE in this run may ever set it."""
    row = {"server_id": "s-1", "deployment_status": "deployed", "runtime_url": "http://127.0.0.1:8000/"}
    session = _patch_session(monkeypatch, row)

    async def _failing_probes(server_id, url, actor_client_id, **kw):
        assert kw.get("require_approved") is False
        raise deploy_verifier.VerificationFailedError("boom", {"healthcheck": False, "tools_discovered": 0,
                                                                "tools_skipped": [], "invocation_probe_ok": False,
                                                                "contract_check": None})

    with patch.object(deploy_verifier, "run_verification_probes", new=_failing_probes):
        await deploy_verifier.verify_server("s-1")

    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "status = 'approved'" not in executed_sql
    assert "deployment_status = 'failed'" in executed_sql


# ---------------------------------------------------------------------------
# WP-A6 Finding 3: ServiceAdapter.verify_access() at verify time
# ---------------------------------------------------------------------------


class _FakeMultiQuerySession:
    """Like _FakeSession but returns a different fixed row per query,
    keyed by a distinguishing substring — server_registry.service_context
    lookup vs tool_registry credential lookup are two separate queries."""

    def __init__(self, server_row: dict | None, tool_row: dict | None):
        self._server_row = server_row
        self._tool_row = tool_row

    async def execute(self, stmt, params=None):
        result = MagicMock()
        if "FROM tool_registry" in str(stmt):
            result.mappings.return_value.first.return_value = self._tool_row
        else:
            result.mappings.return_value.first.return_value = self._server_row
        return result

    async def commit(self):
        pass


def _patch_multi_session(monkeypatch, server_row, tool_row):
    session = _FakeMultiQuerySession(server_row, tool_row)
    monkeypatch.setattr(deploy_verifier, "AsyncSessionLocal", lambda: _FakeSessionCtx(session))
    return session


@pytest.mark.asyncio
async def test_service_adapter_verify_skips_when_no_service_context(monkeypatch):
    _patch_multi_session(monkeypatch, {"service_context": None, "injection_mode": "external_oauth_client_credentials", "service_adapter": None}, None)
    result, reason = await deploy_verifier._run_service_adapter_verify("s-1")
    assert result == "not_applicable" and reason is None


@pytest.mark.asyncio
async def test_service_adapter_verify_skips_for_non_client_credentials_mode(monkeypatch):
    _patch_multi_session(
        monkeypatch,
        {"service_context": {"adapter": "generic"}, "injection_mode": "external_oauth_user_token", "service_adapter": None},
        None,
    )
    result, reason = await deploy_verifier._run_service_adapter_verify("s-1")
    assert result == "not_applicable" and reason is None


@pytest.mark.asyncio
async def test_service_adapter_verify_skips_when_no_credential_provisioned(monkeypatch):
    _patch_multi_session(
        monkeypatch,
        {"service_context": {"adapter": "generic"}, "injection_mode": "external_oauth_client_credentials", "service_adapter": None},
        None,  # no tool_registry row with a credential_id
    )
    result, reason = await deploy_verifier._run_service_adapter_verify("s-1")
    assert result == "not_applicable" and reason is None


@pytest.mark.asyncio
async def test_service_adapter_verify_fails_closed_when_adapter_rejects_token(monkeypatch):
    _patch_multi_session(
        monkeypatch,
        {"service_context": {"adapter": "generic", "api_base_url": "https://api.acme.example"},
         "injection_mode": "external_oauth_client_credentials", "service_adapter": None},
        {"tool_id": "t-1", "server_id": "s-1", "credential_id": "c-1", "service_name": "acme"},
    )
    with patch(
        "app.credential_broker.dispatcher._inject_external_oauth_client_credentials",
        new=AsyncMock(return_value={"Authorization": "Bearer test-token"}),
    ), patch(
        "app.credential_broker.adapters.generic_service_adapter.GenericServiceAdapter.verify_access",
        new=AsyncMock(return_value=False),
    ):
        result, reason = await deploy_verifier._run_service_adapter_verify("s-1")
    assert result == "failed"
    assert reason


@pytest.mark.asyncio
async def test_service_adapter_verify_passes_when_adapter_accepts_token(monkeypatch):
    _patch_multi_session(
        monkeypatch,
        {"service_context": {"adapter": "generic", "api_base_url": "https://api.acme.example"},
         "injection_mode": "external_oauth_client_credentials", "service_adapter": None},
        {"tool_id": "t-1", "server_id": "s-1", "credential_id": "c-1", "service_name": "acme"},
    )
    with patch(
        "app.credential_broker.dispatcher._inject_external_oauth_client_credentials",
        new=AsyncMock(return_value={"Authorization": "Bearer test-token"}),
    ), patch(
        "app.credential_broker.adapters.generic_service_adapter.GenericServiceAdapter.verify_access",
        new=AsyncMock(return_value=True),
    ):
        result, reason = await deploy_verifier._run_service_adapter_verify("s-1")
    assert result == "passed" and reason is None


# ---------------------------------------------------------------------------
# WP-A6 Finding 4: same-IdP negative-token probe wired into verify
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_same_idp_verify_skips_non_same_idp_servers(monkeypatch):
    _patch_session(monkeypatch, {"injection_mode": "external_oauth_user_token", "approved_token_audience": None})
    ok, report, reason = await deploy_verifier._run_same_idp_verify("s-1", "http://upstream/")
    assert ok is True and report is None and reason is None


@pytest.mark.asyncio
async def test_same_idp_verify_fails_closed_when_no_approved_audience(monkeypatch):
    _patch_session(monkeypatch, {"injection_mode": "kc_token_exchange", "approved_token_audience": None})
    ok, report, reason = await deploy_verifier._run_same_idp_verify("s-1", "http://upstream/")
    assert ok is False
    assert "approved_token_audience" in reason


@pytest.mark.asyncio
async def test_same_idp_verify_fails_closed_when_probe_finds_accepted_bad_token(monkeypatch):
    _patch_session(monkeypatch, {"injection_mode": "kc_token_exchange", "approved_token_audience": "mcp-gateway"})

    from app.services.same_idp_verify import ProbeResult, SameIdpVerifyResult
    bad_result = SameIdpVerifyResult(
        server_url="http://upstream/",
        probes=[ProbeResult("missing_token", True, 401, "ok"),
                ProbeResult("wrong_audience", False, 200, "accepted!"),
                ProbeResult("expired_token", True, 401, "ok")],
    )
    with patch("app.services.same_idp_verify.run_same_idp_verify_probe", new=AsyncMock(return_value=bad_result)):
        ok, report, reason = await deploy_verifier._run_same_idp_verify("s-1", "http://upstream/")
    assert ok is False
    assert report["all_rejected"] is False
    assert reason


@pytest.mark.asyncio
async def test_same_idp_verify_passes_when_all_probes_rejected(monkeypatch):
    _patch_session(monkeypatch, {"injection_mode": "kc_token_exchange", "approved_token_audience": "mcp-gateway"})

    from app.services.same_idp_verify import ProbeResult, SameIdpVerifyResult
    good_result = SameIdpVerifyResult(
        server_url="http://upstream/",
        probes=[ProbeResult("missing_token", True, 401, "ok"),
                ProbeResult("wrong_audience", True, 401, "ok"),
                ProbeResult("expired_token", True, 401, "ok")],
    )
    with patch("app.services.same_idp_verify.run_same_idp_verify_probe", new=AsyncMock(return_value=good_result)):
        ok, report, reason = await deploy_verifier._run_same_idp_verify("s-1", "http://upstream/")
    assert ok is True and report["all_rejected"] is True and reason is None
