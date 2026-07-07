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


@pytest.mark.asyncio
async def test_healthcheck_failure_never_sets_deployed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    session = _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman", AsyncMock(return_value=(0, "container-id", "")))
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
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", AsyncMock(return_value=True))

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "deployed"
    assert result["runtime_url"] is not None
    assert result["error"] is None


@pytest.mark.asyncio
async def test_podman_run_failure_fails_closed(monkeypatch):
    row = {"server_id": "s-1", "deployment_status": "built",
           "build_artifact_digest": "sha256:stub-abc123",
           "build_provenance": {"image_ref": "mcp-server-s1:latest"}}
    _patch_session(monkeypatch, row)

    monkeypatch.setattr(deploy_launcher, "_run_podman",
                        AsyncMock(return_value=(1, "", "no such image")))
    probe = AsyncMock(return_value=True)
    monkeypatch.setattr(deploy_launcher, "_probe_healthcheck", probe)

    result = await deploy_launcher.deploy_server("s-1")

    assert result["deployment_status"] == "failed"
    probe.assert_not_called()
