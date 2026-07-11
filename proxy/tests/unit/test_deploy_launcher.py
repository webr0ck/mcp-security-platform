"""
Unit tests — deploy launcher (CR-01 / WP-B3 phase 3).

Covers app.services.deploy_launcher.deploy_server: the "only
evaluator-approved artifacts get launched" rule (refuses when
deployment_status != 'built', without ever constructing a podman command),
the exact hardening-flag podman invocation (asserted via a mocked
subprocess, no real podman needed), and the healthcheck-gates-'deployed'
rule.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import deploy_launcher


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
    monkeypatch.setattr(deploy_launcher, "AsyncSessionLocal", lambda: _FakeSessionCtx(session))
    return session


@pytest.mark.asyncio
async def test_refuses_deploy_when_not_built(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "building",
           "build_artifact_digest": None, "build_provenance": {}}
    _patch_session(monkeypatch, row)

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        result = await deploy_launcher.deploy_server("s-1")

    mock_exec.assert_not_called()
    assert result["deployment_status"] == "failed"
    assert result["runtime_url"] is None
    assert "not 'built'" in result["error"]


@pytest.mark.asyncio
async def test_refuses_deploy_when_server_missing(monkeypatch):
    _patch_session(monkeypatch, None)

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        result = await deploy_launcher.deploy_server("s-missing")

    mock_exec.assert_not_called()
    assert result["deployment_status"] == "failed"
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_refuses_deploy_when_no_image_ref(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123", "build_provenance": {}}
    _patch_session(monkeypatch, row)

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as mock_exec:
        result = await deploy_launcher.deploy_server("s-1")

    mock_exec.assert_not_called()
    assert result["deployment_status"] == "failed"
    assert "image_ref" in result["error"]


def test_podman_run_cmd_uses_lab_hardening_flags_verbatim():
    """Pins the exact hardening profile against podman-compose.lab.yml's
    x-mcp-hardening anchor — memory 256m, cpus 0.5, pids-limit 64, read-only,
    tmpfs /tmp, no-new-privileges, cap-drop ALL, non-root user."""
    cmd = deploy_launcher._build_podman_run_cmd(
        "11111111-2222-3333-4444-555555555555", "mcp-server-abc:latest", "mcp-deploy-11111111", 8000,
    )
    joined = " ".join(cmd)
    assert "--read-only" in cmd
    assert "--memory" in cmd and "256m" in cmd
    assert "--cpus" in cmd and "0.5" in cmd
    assert "--pids-limit" in cmd and "64" in cmd
    assert "--cap-drop" in cmd and "ALL" in cmd
    assert "no-new-privileges:true" in joined
    assert "1001:1001" in cmd
    assert "mcp-deploy-11111111-net" in cmd  # per-server-generated network name
    assert "mcp-server-abc:latest" in cmd


def test_podman_run_cmd_passes_service_context_as_env_not_baked_into_image():
    """WP-A6 Finding 3: service_context (non-secret ServiceAdapter runtime
    context) reaches the container as a single JSON env var; absent when
    there is none, so existing (no-profile) servers are unaffected."""
    cmd = deploy_launcher._build_podman_run_cmd(
        "11111111-2222-3333-4444-555555555555", "mcp-server-abc:latest", "mcp-deploy-11111111", 8000,
        service_context={"adapter": "generic", "api_base_url": "https://api.acme.example"},
    )
    assert "-e" in cmd
    env_idx = cmd.index("-e")
    assert cmd[env_idx + 1].startswith("MCP_SERVICE_CONTEXT=")
    assert "api.acme.example" in cmd[env_idx + 1]

    cmd_no_ctx = deploy_launcher._build_podman_run_cmd(
        "11111111-2222-3333-4444-555555555555", "mcp-server-abc:latest", "mcp-deploy-11111111", 8000,
    )
    assert "-e" not in cmd_no_ctx


@pytest.mark.asyncio
async def test_healthcheck_failure_never_sets_deployed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    session = _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman", AsyncMock(return_value=(0, "container-id", "")))
    monkeypatch.setattr(deploy_launcher, "_ensure_network", AsyncMock(return_value=(True, "")))
    monkeypatch.setattr(deploy_launcher, "_resolve_published_port", AsyncMock(return_value=54321))
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", AsyncMock(return_value=False))
    monkeypatch.setattr(deploy_launcher, "_HEALTHCHECK_POLL_INTERVAL_SECONDS", 0)

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "failed"
    assert result["runtime_url"] is None
    assert "healthcheck" in result["error"]
    # never wrote runtime_url/deployment_status='deployed'
    assert not any("deployed" in str(sql) and "runtime_url" in str(sql)
                   and params and params.get("runtime_url")
                   for sql, params in session.executed)


@pytest.mark.asyncio
async def test_successful_deploy_sets_deployed_and_runtime_url(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman", AsyncMock(return_value=(0, "container-id", "")))
    monkeypatch.setattr(deploy_launcher, "_ensure_network", AsyncMock(return_value=(True, "")))
    monkeypatch.setattr(deploy_launcher, "_resolve_published_port", AsyncMock(return_value=54321))
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", AsyncMock(return_value=True))

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "deployed"
    assert result["runtime_url"] == "http://127.0.0.1:54321/"
    assert result["error"] is None


@pytest.mark.asyncio
async def test_network_create_failure_fails_closed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    _patch_session(monkeypatch, row)

    run_podman = AsyncMock(return_value=(0, "container-id", ""))
    monkeypatch.setattr(deploy_launcher, "_run_podman", run_podman)
    monkeypatch.setattr(deploy_launcher, "_ensure_network",
                        AsyncMock(return_value=(False, "permission denied")))
    probe = AsyncMock(return_value=True)
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", probe)

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "failed"
    assert "network create failed" in result["error"]
    run_podman.assert_not_called()
    probe.assert_not_called()


@pytest.mark.asyncio
async def test_network_create_tolerates_already_exists(monkeypatch):
    """Retried/concurrent deploys compute the same network name — that must
    not fail closed."""
    with patch.object(deploy_launcher, "_run_podman",
                      AsyncMock(return_value=(125, "", "Error: network foo already exists"))):
        ok, err = await deploy_launcher._ensure_network("foo")
    assert ok is True


@pytest.mark.asyncio
async def test_resolve_published_port_parses_podman_port_output(monkeypatch):
    with patch.object(deploy_launcher, "_run_podman",
                      AsyncMock(return_value=(0, "127.0.0.1:54321\n", ""))):
        port = await deploy_launcher._resolve_published_port("mcp-deploy-abc", 8000)
    assert port == 54321


@pytest.mark.asyncio
async def test_resolve_published_port_returns_none_on_failure(monkeypatch):
    with patch.object(deploy_launcher, "_run_podman", AsyncMock(return_value=(1, "", "no such container"))):
        port = await deploy_launcher._resolve_published_port("mcp-deploy-abc", 8000)
    assert port is None


@pytest.mark.asyncio
async def test_podman_run_failure_fails_closed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman",
                        AsyncMock(return_value=(1, "", "no such image")))
    monkeypatch.setattr(deploy_launcher, "_ensure_network", AsyncMock(return_value=(True, "")))
    probe = AsyncMock(return_value=True)
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", probe)

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "failed"
    probe.assert_not_called()


@pytest.mark.asyncio
async def test_podman_invocation_raising_fails_closed_not_stuck(monkeypatch):
    """Found live against the lab: if podman itself cannot even be invoked
    (binary missing, no container-runtime access) _run_podman raises instead
    of returning an rc — this must still fail closed to 'failed', never
    propagate uncaught and leave deployment_status stuck at 'deploying'."""
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    session = _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman",
                        AsyncMock(side_effect=FileNotFoundError("podman: command not found")))
    monkeypatch.setattr(deploy_launcher, "_ensure_network", AsyncMock(return_value=(True, "")))
    probe = AsyncMock(return_value=True)
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", probe)

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "failed"
    assert result["runtime_url"] is None
    assert "podman invocation failed" in result["error"]
    probe.assert_not_called()
    executed_sql = " | ".join(sql for sql, _ in session.executed)
    assert "deployment_status = 'failed'" in executed_sql
