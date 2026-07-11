"""
Unit tests — build engine digest pinning + stub build + scan handoff
(CR-01 / WP-B3 phase 2b).

No pytest fixture for a real-clone-through-the-SSRF-allowlist exists
anywhere in this repo yet (scanner_worker/git_clone.py has no tests of its
own; proxy/tests/unit/test_git_providers.py tests the analogous module by
mocking socket.getaddrinfo, never a real clone). Rather than invent a new
fixture format, these tests monkeypatch build_engine._clone_repo to copy a
real local tmp git repo into the destination directory (so the rest of the
function — `git rev-parse HEAD`, the digest comparison, the stub build, the
rescan handoff — all run against REAL git plumbing and a REAL commit sha,
only the network clone step itself is stubbed out). This also sidesteps
`protocol.file.allow=never` in the real clone command, which deliberately
refuses local-path clones for SSRF-safety reasons that are out of scope for
this module's own tests.

Run (from repo root): python -m pytest build_worker/tests -v
"""
from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from build_worker import build_engine


class _FakeRow(dict):
    def __getitem__(self, key):
        return dict.__getitem__(self, key)


class _FakePool:
    """Records fetchrow calls; returns a fake rescan job row."""

    def __init__(self) -> None:
        self.fetchrow_calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.fetchrow_calls.append((sql, args))
        return _FakeRow(job_id="11111111-1111-1111-1111-111111111111")


@pytest.fixture()
def fixture_repo(tmp_path: Path) -> tuple[Path, str]:
    """A tiny real git repo with one commit. Returns (path, head_commit_sha)."""
    repo = tmp_path / "fixture_repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    (repo / "README.md").write_text("hello\n")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "initial"], cwd=repo, check=True)
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True,
    ).stdout.strip()
    return repo, head


def _patch_clone_to_copy(monkeypatch, fixture_path: Path) -> None:
    async def _fake_clone_repo(pool, repo_url, dest):
        shutil.copytree(fixture_path, dest)
        return True, ""
    monkeypatch.setattr(build_engine, "_clone_repo", _fake_clone_repo)


def test_digest_mismatch_refuses_build(monkeypatch, fixture_repo):
    """TOCTOU guard (PRD-8 sec 2): a fresh clone whose HEAD does not match the
    expected_digest must be refused, never built."""
    repo_path, _real_head = fixture_repo
    _patch_clone_to_copy(monkeypatch, repo_path)
    pool = _FakePool()

    result = asyncio.run(build_engine.run_build(
        pool, "server-1", "https://github.com/example/repo.git", expected_digest="deadbeef",
    ))

    assert result["build_artifact_digest"] is None
    assert result["image_ref"] is None
    assert "digest mismatch" in result["worker_error"]
    # Must never even attempt the (stub) build or rescan enqueue on mismatch.
    assert pool.fetchrow_calls == []


def test_no_expected_digest_refuses_build(monkeypatch, fixture_repo):
    """An empty/missing expected_digest must fail closed, not fall back to
    building unpinned branch HEAD."""
    repo_path, _real_head = fixture_repo
    _patch_clone_to_copy(monkeypatch, repo_path)
    pool = _FakePool()

    result = asyncio.run(build_engine.run_build(
        pool, "server-1", "https://github.com/example/repo.git", expected_digest=None,
    ))

    assert result["build_artifact_digest"] is None
    assert "digest mismatch" in result["worker_error"]


def test_matching_digest_builds_and_hands_off_to_rescan(monkeypatch, fixture_repo):
    repo_path, real_head = fixture_repo
    _patch_clone_to_copy(monkeypatch, repo_path)
    pool = _FakePool()

    result = asyncio.run(build_engine.run_build(
        pool, "server-1", "https://github.com/example/repo.git", expected_digest=real_head,
        job_id="job-123",
    ))

    assert result["worker_error"] is None
    assert result["build_artifact_digest"] == f"sha256:stub-{real_head[:12]}"
    assert result["image_ref"]
    assert result["provenance"]["commit"] == real_head
    assert result["provenance"]["built_at_job_id"] == "job-123"
    # Rescan handoff attempted (best-effort — see build_engine.py comment on
    # why this call is expected to fail under the real build_worker_app DB
    # role and is handled by the evaluator instead; here it succeeds because
    # _FakePool always returns a row).
    assert len(pool.fetchrow_calls) == 1
    assert result["provenance"]["scan_job_ids"] == ["11111111-1111-1111-1111-111111111111"]


def test_clone_failure_refuses_build(monkeypatch, fixture_repo):
    async def _fake_clone_fail(pool, repo_url, dest):
        return False, "simulated clone failure"
    monkeypatch.setattr(build_engine, "_clone_repo", _fake_clone_fail)
    pool = _FakePool()

    result = asyncio.run(build_engine.run_build(
        pool, "server-1", "https://github.com/example/repo.git", expected_digest="deadbeef",
    ))

    assert result["build_artifact_digest"] is None
    assert "clone_failed" in result["worker_error"]
