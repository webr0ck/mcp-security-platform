"""
Unit tests for ops-agent: token auth (fail-closed), name allowlist, and the
three ops endpoints with subprocess mocked out (no real podman required).
"""
from __future__ import annotations

import importlib
import subprocess
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _fresh_app(monkeypatch, token: str | None = "test-token-123", compose_files: str = "compose.yml"):
    """Reload app.py with env vars set BEFORE module import, since module-level
    globals (OPS_AGENT_TOKEN etc.) are read once at import time."""
    if token is None:
        monkeypatch.delenv("OPS_AGENT_TOKEN", raising=False)
    else:
        monkeypatch.setenv("OPS_AGENT_TOKEN", token)
    monkeypatch.setenv("OPS_AGENT_COMPOSE_FILES", compose_files)
    import app as app_module
    importlib.reload(app_module)
    return app_module


@pytest.fixture
def client(monkeypatch):
    app_module = _fresh_app(monkeypatch)
    return TestClient(app_module.app), app_module


@pytest.fixture
def client_no_token(monkeypatch):
    app_module = _fresh_app(monkeypatch, token=None)
    return TestClient(app_module.app), app_module


def test_health_unauthenticated_ok(client):
    c, _ = client
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json()["token_configured"] is True


def test_health_reports_token_missing(client_no_token):
    c, _ = client_no_token
    resp = c.get("/health")
    assert resp.status_code == 200
    assert resp.json()["token_configured"] is False


def test_logs_fails_closed_when_token_unset(client_no_token):
    c, _ = client_no_token
    resp = c.get("/ops/logs", params={"container": "mcp-echo"}, headers={"X-Ops-Token": "anything"})
    assert resp.status_code == 503


def test_logs_rejects_missing_token(client):
    c, _ = client
    resp = c.get("/ops/logs", params={"container": "mcp-echo"})
    assert resp.status_code == 401


def test_logs_rejects_wrong_token(client):
    c, _ = client
    resp = c.get("/ops/logs", params={"container": "mcp-echo"}, headers={"X-Ops-Token": "wrong"})
    assert resp.status_code == 401


@pytest.mark.parametrize("bad_name", ["mcp-db", "vault", "../etc/passwd", "mcp", "lab-mcp-", "postgres"])
def test_logs_rejects_non_allowlisted_container(client, bad_name):
    c, _ = client
    resp = c.get("/ops/logs", params={"container": bad_name}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 403


@pytest.mark.parametrize("good_name", ["mcp-echo", "lab-mcp-grafana", "mcp-netbox-server"])
def test_logs_accepts_allowlisted_container(client, good_name):
    c, _ = client
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="log line 1\nlog line 2\n", stderr="")
    with patch("subprocess.run", return_value=fake) as mock_run:
        resp = c.get("/ops/logs", params={"container": good_name, "tail": 50},
                      headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["container"] == good_name
    assert "log line 1" in body["logs"]
    called_argv = mock_run.call_args.args[0]
    assert called_argv[:2] == ["podman", "logs"]
    assert "--tail" in called_argv
    assert good_name in called_argv


def test_logs_tail_capped_at_1000(client):
    c, _ = client
    resp = c.get("/ops/logs", params={"container": "mcp-echo", "tail": 5000},
                  headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 422  # FastAPI query validation (le=1000)


def test_restart_rejects_non_allowlisted(client):
    c, _ = client
    resp = c.post("/ops/restart", json={"container": "mcp-db"}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 422  # pydantic field_validator raises -> 422


def test_restart_success(client):
    c, _ = client
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="mcp-echo\n", stderr="")
    with patch("subprocess.run", return_value=fake) as mock_run:
        resp = c.post("/ops/restart", json={"container": "mcp-echo"}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 200
    assert resp.json()["restarted"] is True
    called_argv = mock_run.call_args.args[0]
    assert called_argv == ["podman", "restart", "mcp-echo"]


def test_restart_podman_failure_returns_502(client):
    c, _ = client
    fake = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="no such container")
    with patch("subprocess.run", return_value=fake):
        resp = c.post("/ops/restart", json={"container": "mcp-echo"}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 502


def test_rebuild_success_uses_fixed_argv(client):
    c, app_module = client
    fake = subprocess.CompletedProcess(args=[], returncode=0, stdout="done\n", stderr="")
    with patch("subprocess.run", return_value=fake) as mock_run:
        resp = c.post("/ops/rebuild", json={"service": "lab-mcp-echo"}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 200
    assert resp.json()["rebuilt"] is True
    called_argv = mock_run.call_args.args[0]
    assert called_argv[0] == "podman-compose"
    assert "-f" in called_argv
    assert called_argv[-3:] == ["up", "-d", "--build"] or called_argv[-4:-1] == ["up", "-d", "--build"]
    assert called_argv[-1] == "lab-mcp-echo"


def test_rebuild_fails_closed_when_compose_files_unset(monkeypatch):
    app_module = _fresh_app(monkeypatch, compose_files="")
    c = TestClient(app_module.app)
    resp = c.post("/ops/rebuild", json={"service": "lab-mcp-echo"}, headers={"X-Ops-Token": "test-token-123"})
    assert resp.status_code == 503


def _fake_addrinfo(ip: str):
    return [(2, 1, 6, "", (ip, 0))]


def test_rebuild_from_git_rejects_non_https_url(client):
    c, _ = client
    resp = c.post(
        "/ops/rebuild-from-git",
        json={"service": "lab-mcp-echo", "git_url": "git://github.com/example/repo.git"},
        headers={"X-Ops-Token": "test-token-123"},
    )
    assert resp.status_code == 422


def test_rebuild_from_git_rejects_non_allowlisted_service(client):
    c, _ = client
    resp = c.post(
        "/ops/rebuild-from-git",
        json={"service": "mcp-db", "git_url": "https://github.com/example/repo.git"},
        headers={"X-Ops-Token": "test-token-123"},
    )
    assert resp.status_code == 422


def test_rebuild_from_git_rejects_unsafe_ref(client):
    c, _ = client
    resp = c.post(
        "/ops/rebuild-from-git",
        json={"service": "lab-mcp-echo", "git_url": "https://github.com/example/repo.git",
              "ref": "--upload-pack=evil"},
        headers={"X-Ops-Token": "test-token-123"},
    )
    assert resp.status_code == 422


def test_rebuild_from_git_rejects_embedded_credentials(client):
    c, app_module = client
    with patch.object(app_module.socket, "getaddrinfo", return_value=_fake_addrinfo("93.184.216.34")):
        resp = c.post(
            "/ops/rebuild-from-git",
            json={"service": "lab-mcp-echo", "git_url": "https://user:pass@github.com/example/repo.git"},
            headers={"X-Ops-Token": "test-token-123"},
        )
    assert resp.status_code == 422


@pytest.mark.parametrize("bad_ip", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "::1"])
def test_rebuild_from_git_rejects_non_public_host(client, bad_ip):
    c, app_module = client
    with patch.object(app_module.socket, "getaddrinfo", return_value=_fake_addrinfo(bad_ip)):
        resp = c.post(
            "/ops/rebuild-from-git",
            json={"service": "lab-mcp-echo", "git_url": "https://github.com/example/repo.git"},
            headers={"X-Ops-Token": "test-token-123"},
        )
    assert resp.status_code == 422


def test_rebuild_from_git_fails_closed_when_compose_files_unset(monkeypatch):
    app_module = _fresh_app(monkeypatch, compose_files="")
    c = TestClient(app_module.app)
    resp = c.post(
        "/ops/rebuild-from-git",
        json={"service": "lab-mcp-echo", "git_url": "https://github.com/example/repo.git"},
        headers={"X-Ops-Token": "test-token-123"},
    )
    assert resp.status_code == 503


def test_rebuild_from_git_success_clones_builds_and_ups(client, tmp_path):
    c, app_module = client
    monkeypatch_root = tmp_path / "git-workdirs"
    app_module.GIT_WORKDIR_ROOT = str(monkeypatch_root)

    calls = []

    def fake_run(argv, capture_output=True, text=True, timeout=None, shell=False, cwd=None):
        calls.append(argv)
        if argv[0] == "git" and "rev-parse" in argv:
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="deadbeef\n", stderr="")
        return subprocess.CompletedProcess(args=argv, returncode=0, stdout="ok\n", stderr="")

    with patch.object(app_module.socket, "getaddrinfo", return_value=_fake_addrinfo("93.184.216.34")), \
         patch("subprocess.run", side_effect=fake_run):
        resp = c.post(
            "/ops/rebuild-from-git",
            json={"service": "lab-mcp-echo", "git_url": "https://github.com/example/repo.git", "ref": "main"},
            headers={"X-Ops-Token": "test-token-123"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["rebuilt"] is True
    assert body["service"] == "lab-mcp-echo"
    assert body["commit"] == "deadbeef"
    assert body["image_tag"] == "lab-mcp-echo:lab"

    # git clone used fixed argv with a `--` separator before url/dest — no
    # string interpolation, ref passed as a discrete argv element.
    clone_argv = next(a for a in calls if a[0] == "git" and "clone" in a)
    assert clone_argv[-3] == "--"
    assert clone_argv[-2] == "https://github.com/example/repo.git"
    assert "--branch" in clone_argv and "main" in clone_argv

    build_argv = next(a for a in calls if a[0] == "podman" and "build" in a)
    assert build_argv[:3] == ["podman", "build", "-t"]
    assert build_argv[3] == "lab-mcp-echo:lab"

    up_argv = next(a for a in calls if a[0] == "podman-compose")
    assert up_argv[-2:] == ["up", "-d"] or up_argv[-1] == "lab-mcp-echo"
    assert "--build" not in up_argv  # image already built in the podman-build step above


def test_rebuild_from_git_clone_failure_returns_502_not_silent(client, tmp_path):
    c, app_module = client
    app_module.GIT_WORKDIR_ROOT = str(tmp_path / "git-workdirs")

    fake_fail = subprocess.CompletedProcess(args=[], returncode=128, stdout="", stderr="fatal: repo not found")
    with patch.object(app_module.socket, "getaddrinfo", return_value=_fake_addrinfo("93.184.216.34")), \
         patch("subprocess.run", return_value=fake_fail):
        resp = c.post(
            "/ops/rebuild-from-git",
            json={"service": "lab-mcp-echo", "git_url": "https://github.com/example/repo.git"},
            headers={"X-Ops-Token": "test-token-123"},
        )
    assert resp.status_code == 502
    assert "clone" in resp.json()["detail"].lower()


def test_no_shell_true_anywhere_in_source():
    """Static guard: subprocess.run must never be called with shell=True.

    Uses the AST (not a string match) because the module docstring
    legitimately discusses "shell=True" as prose describing what NOT to do.
    """
    import ast
    import pathlib
    src = (pathlib.Path(__file__).parent.parent / "app.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    pytest.fail(f"found shell=True call at line {node.lineno}")
