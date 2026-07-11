"""
build-worker's build engine (CR-01 / WP-B3 phase 2b) — clones the exact
scanned+approved commit, refuses on any digest mismatch (TOCTOU guard,
PRD-8 sec 2), builds an OCI image (STUBbed — see below), and hands the
built artifact off to WP-B2's existing scan layer via a rescan job.

This module makes NO deployment_status decision — same execution/
adjudication split as scanner_worker/scan_engine.py. It returns a RAW
result dict; build_evaluator.py (Task 3, proxy-side) is the only place
that writes server_registry.deployment_status.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from typing import Any

from . import git_clone

logger = logging.getLogger(__name__)


async def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120,
               env: dict | None = None):
    import asyncio
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 1, "", "timed out"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _clone_repo(pool, repo_url: str, dest: str) -> tuple[bool, str]:
    provider = await git_clone.match_provider(pool, repo_url)
    if provider is None:
        return False, ("Repository URL does not match any enabled git provider. "
                        "Allowed: an enabled host in Admin -> Git Providers.")
    if not shutil.which("git"):
        return False, "git not available in the build worker environment"

    try:
        git_clone.validate_host(provider.host, provider.allow_private)
    except git_clone.GitHostError as exc:
        return False, f"clone blocked: {exc}"

    token = git_clone.provider_token(provider.provider)
    clone_url = git_clone.build_clone_url(repo_url, provider.clone_account, token)
    rc, _, stderr = await _run(
        [
            "git",
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "protocol.ext.allow=never",
            "-c", "protocol.file.allow=never",
            "clone", "--quiet",
            "--",
            clone_url, dest,
        ],
        timeout=120,
    )
    if rc != 0:
        safe_err = stderr.replace(token, "***") if token else stderr
        return False, safe_err.strip() or "clone failed"
    return True, ""


def _run_buildah_build(repo_path: str, image_tag: str, commit: str) -> tuple[str | None, str | None]:
    """
    # STUB: no buildah binary in this sandbox; wire scanner_worker.scan_engine
    # ._run's exact subprocess pattern (`buildah bud --no-cache -t {image_tag}
    # {repo_path}`, then `buildah push`/`buildah inspect` for the digest) once
    # build_worker/Dockerfile installs buildah (see scanner_worker/Dockerfile
    # for the install-binary pattern this should mirror).
    #
    # Returns a deterministic fake digest so the rest of the pipeline (scan
    # handoff, evaluator, deploy launcher) has a real, testable value to
    # thread through — mirrors how dependency_scanners.py's tests never need
    # a real osv-scanner binary.
    """
    if not commit:
        return None, "cannot fabricate a build digest with no commit"
    fake_digest = f"sha256:stub-{commit[:12]}"
    return fake_digest, None


async def run_build(pool, server_id: str, github_url: str, expected_digest: str | None,
                     job_id: str | None = None) -> dict[str, Any]:
    """
    Clone the repo, verify HEAD matches expected_digest EXACTLY (fail closed
    on any mismatch or empty expected_digest — this is the TOCTOU guard),
    then (stub) build an OCI image and enqueue a rescan against the built
    artifact so it goes through WP-B2's existing scan layer.

    Returns:
        {"build_artifact_digest": str|None, "image_ref": str|None,
         "provenance": dict, "worker_error": str|None}
    """
    if not expected_digest:
        return {
            "build_artifact_digest": None, "image_ref": None, "provenance": {},
            "worker_error": "digest mismatch: no expected_digest provided — refusing to build "
                            "an unpinned/unapproved commit",
        }

    tmpdir = tempfile.mkdtemp(prefix="mcp_build_")
    try:
        repo_path = os.path.join(tmpdir, "repo")
        cloned, clone_err = await _clone_repo(pool, github_url, repo_path)
        if not cloned:
            return {
                "build_artifact_digest": None, "image_ref": None, "provenance": {},
                "worker_error": f"clone_failed: {clone_err}",
            }

        rc_c, out_c, stderr_c = await _run(["git", "-C", repo_path, "rev-parse", "HEAD"], timeout=15)
        if rc_c != 0:
            return {
                "build_artifact_digest": None, "image_ref": None, "provenance": {},
                "worker_error": f"could not determine HEAD commit: {stderr_c.strip()}",
            }
        head_commit = out_c.strip()[:64]

        if head_commit != expected_digest:
            logger.error(
                "digest mismatch server_id=%s expected=%s actual=%s — refusing build",
                server_id, expected_digest, head_commit,
            )
            return {
                "build_artifact_digest": None, "image_ref": None, "provenance": {},
                "worker_error": (
                    f"digest mismatch: expected commit {expected_digest} but cloned HEAD is "
                    f"{head_commit} — refusing to build an unapproved commit (TOCTOU guard)"
                ),
            }

        image_tag = f"mcp-server-{str(server_id)[:12]}:{head_commit[:12]}"
        digest, build_err = _run_buildah_build(repo_path, image_tag, head_commit)
        if build_err:
            return {
                "build_artifact_digest": None, "image_ref": None, "provenance": {},
                "worker_error": f"build_failed: {build_err}",
            }

        provenance = {
            "commit": head_commit,
            "builder": "build_worker/build_engine.py",
            "built_at_job_id": str(job_id) if job_id else None,
        }

        # Hand off to WP-B2's existing scan layer for the built artifact —
        # reuse the scan queue rather than inventing an image-specific
        # scanner pipeline. Best-effort: a rescan-enqueue failure does not
        # invalidate the build itself, but IS recorded so it is never
        # silently dropped.
        rescan_job_id = None
        try:
            row = await pool.fetchrow(
                """
                INSERT INTO scan_jobs (server_id, github_url, job_type, force)
                VALUES ($1, $2, 'rescan', true)
                RETURNING job_id
                """,
                server_id, github_url,
            )
            rescan_job_id = str(row["job_id"]) if row else None
        except Exception as exc:
            # build_worker_app has no INSERT grant on scan_jobs (V072) in the
            # deployed role model — this path is expected to fail under the
            # real DB role and is handled by build_evaluator.py enqueuing the
            # rescan instead (the trusted side, which DOES have that grant).
            # Recorded here, never silently swallowed.
            logger.info("rescan enqueue skipped (expected under build_worker_app's grant "
                       "model — evaluator enqueues instead): %s", exc)

        if rescan_job_id:
            provenance["scan_job_ids"] = [rescan_job_id]

        return {
            "build_artifact_digest": digest,
            "image_ref": image_tag,
            "provenance": provenance,
            "worker_error": None,
        }
    except Exception as exc:
        logger.exception("build worker crashed building %s: %s", github_url, exc)
        return {
            "build_artifact_digest": None, "image_ref": None, "provenance": {},
            "worker_error": f"crashed: {exc}",
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
