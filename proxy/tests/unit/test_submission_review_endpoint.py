"""Unit tests for GET /api/v1/admin/submissions/{server_id}/review.

These call the route coroutine directly with a mock Request — the same
router-unit-test pattern used by tests/unit/test_catalog_router.py — rather
than going through TestClient + AuthMiddleware (which would require a real
Keycloak JWT to get past the 401 gate). Auth is exercised separately by the
middleware RBAC tests; here we test the route's own logic: config shaping,
the repo clone/read branch, and clone-failure surfacing.
"""
import json
import os
import tempfile
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from fastapi import HTTPException

from app.routers.submission import (
    _clone_and_read_repo,
    _require_reviewer,
    _require_submission_reviewer,
    review_submission_detail,
)


def _fake_submission(github_repo_url=None):
    return {
        "server_id": str(uuid.uuid4()),
        "name": "local-policy-api-readonly",
        "owner_sub": "alice@corp",
        "submission_status": "awaiting_review",
        "injection_mode": "none",
        "data_categories": ["internal_docs", "public"],
        "has_write_ops": False,
        "scan_report": [],
        "sbom_components": [],
        "review_notes": None,
        "github_repo_url": github_repo_url,
    }


def _reviewer_request():
    """A Request whose state carries an authenticated reviewer (admin role),
    so the real _require_reviewer passes without needing the middleware."""
    req = MagicMock()
    req.state = SimpleNamespace(client_id="reviewer@corp", client_roles=["admin"])
    return req


def _body(resp):
    return json.loads(bytes(resp.body))


class TestReviewEndpoint:
    @pytest.mark.asyncio
    async def test_no_repo_url_omits_repo_key(self):
        sub = _fake_submission(github_repo_url=None)
        with patch("app.routers.submission._get_submission", new=AsyncMock(return_value=sub)):
            resp = await review_submission_detail(sub["server_id"], _reviewer_request())
        assert resp.status_code == 200
        body = _body(resp)
        assert body["repo"] is None
        assert body["config"]["injection_mode"] == "none"

    @pytest.mark.asyncio
    async def test_repo_url_present_triggers_clone_and_returns_files(self):
        sub = _fake_submission(github_repo_url="https://github.com/example/repo")
        fake_tree = ["server.py", "requirements.txt"]
        fake_files = {"server.py": "print('hi')\n"}
        with patch("app.routers.submission._get_submission", new=AsyncMock(return_value=sub)), \
             patch("app.routers.submission._clone_and_read_repo",
                   new=AsyncMock(return_value=(True, "", fake_tree, fake_files, False))):
            resp = await review_submission_detail(sub["server_id"], _reviewer_request())
        assert resp.status_code == 200
        body = _body(resp)
        assert body["repo"]["url"] == "https://github.com/example/repo"
        assert body["repo"]["tree"] == fake_tree
        assert body["repo"]["files"] == fake_files
        assert body["repo"]["truncated"] is False

    @pytest.mark.asyncio
    async def test_clone_failure_surfaces_error_not_exception(self):
        sub = _fake_submission(github_repo_url="https://github.com/example/private-repo")
        with patch("app.routers.submission._get_submission", new=AsyncMock(return_value=sub)), \
             patch("app.routers.submission._clone_and_read_repo",
                   new=AsyncMock(return_value=(False, "clone failed: repository not found", [], {}, False))):
            resp = await review_submission_detail(sub["server_id"], _reviewer_request())
        assert resp.status_code == 200
        body = _body(resp)
        assert body["repo"]["error"] == "clone failed: repository not found"


class TestCloneAndReadRepoSymlinks:
    @pytest.mark.asyncio
    async def test_symlinked_file_content_is_never_read(self):
        """A malicious submitted repo can contain a symlink checked out by git
        pointing at an arbitrary host path (e.g. /etc/passwd). The file-walk
        loop must skip reading through symlinks — the file may still be
        *listed* in the tree, but its target's content must never end up in
        `files`."""
        with tempfile.TemporaryDirectory() as outside_dir:
            secret_path = os.path.join(outside_dir, "secret.txt")
            with open(secret_path, "w") as f:
                f.write("SENTINEL_SECRET_CONTENT")

            async def fake_clone(_url, repo_path):
                os.makedirs(repo_path)
                with open(os.path.join(repo_path, "real.txt"), "w") as f:
                    f.write("real file content")
                os.symlink(secret_path, os.path.join(repo_path, "evil_link.txt"))
                return True, ""

            with patch(
                "app.routers.submission.submission_scanner._clone_repo",
                new=AsyncMock(side_effect=fake_clone),
            ):
                success, err, tree, files, truncated = await _clone_and_read_repo(
                    "https://github.com/example/repo"
                )

        assert success is True
        assert "real.txt" in tree
        assert "evil_link.txt" in tree  # still listed, so reviewer sees it exists
        assert files.get("real.txt") == "real file content"
        assert "evil_link.txt" not in files  # target content never read
        assert "SENTINEL_SECRET_CONTENT" not in files.values()


def _request_with_roles(*roles):
    req = MagicMock()
    req.state = SimpleNamespace(client_id="someone@corp", client_roles=list(roles))
    return req


class TestRequireReviewerRoleGate:
    """_require_reviewer gates the two READ endpoints (list_pending_reviews /
    review_submission). It must accept every role that can also mutate a
    submission via _require_submission_reviewer (security_reviewer), plus the
    read-only audit roles (security_auditor, auditor) — see finding 1 in the
    final whole-branch review: security_reviewer could approve/reject but not
    read, which is a broken workflow."""

    @pytest.mark.parametrize(
        "role",
        ["admin", "platform_admin", "security_auditor", "auditor", "security_reviewer"],
    )
    def test_allowed_roles_pass(self, role):
        _require_reviewer(_request_with_roles(role))  # must not raise

    def test_unrelated_role_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _require_reviewer(_request_with_roles("submitter"))
        assert exc_info.value.status_code == 403

    def test_no_roles_rejected(self):
        with pytest.raises(HTTPException) as exc_info:
            _require_reviewer(_request_with_roles())
        assert exc_info.value.status_code == 403


class TestRequireSubmissionReviewerRoleGate:
    """_require_submission_reviewer gates the two MUTATE endpoints
    (approve_submission / reject_submission). Read-only audit roles must NOT
    be able to mutate."""

    @pytest.mark.parametrize("role", ["admin", "platform_admin", "security_reviewer"])
    def test_allowed_roles_pass(self, role):
        _require_submission_reviewer(_request_with_roles(role))  # must not raise

    @pytest.mark.parametrize("role", ["security_auditor", "auditor"])
    def test_read_only_roles_rejected(self, role):
        with pytest.raises(HTTPException) as exc_info:
            _require_submission_reviewer(_request_with_roles(role))
        assert exc_info.value.status_code == 403
