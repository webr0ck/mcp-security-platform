"""
build-worker main loop (CR-01 / WP-B3 phase 2).

Claims queued build_requested/deploy_requested/verify_requested jobs from
scan_jobs (SELECT ... FOR UPDATE SKIP LOCKED — same queue WP-B1's
scanner-worker claims submission_scan/rescan from, filtered to a disjoint
set of job_type values), executes the build engine, and writes RAW results
to build_results.

This process NEVER writes server_registry.deployment_status or any other
adjudication-relevant column — it structurally lacks the DB grant to do so
(see infra/db/migrations/V072__build_worker_queue.sql). It also never writes
build_results.evaluated_at — that is build_evaluator.py's column.

Idempotent retry + dead-letter: identical semantics to scanner_worker/worker.py
— on any exception during processing the job is requeued (status='queued')
with attempts incremented, up to max_attempts; the Nth failure sets
status='dead_letter' instead of being silently dropped.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys

from . import build_engine, db, metrics

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("build_worker")

POLL_INTERVAL_SECONDS = float(os.environ.get("BUILD_WORKER_POLL_INTERVAL", "3"))
WORKER_IDENTITY = f"build-worker:{socket.gethostname()}:{os.getpid()}"

_JOB_TYPES = ("build_requested", "deploy_requested", "verify_requested")


async def _claim_job(pool) -> dict | None:
    """Atomically claim one queued build/deploy/verify job. Returns the job row dict, or None."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT job_id, server_id, github_url, job_type, expected_digest,
                       attempts, max_attempts
                FROM scan_jobs
                WHERE status = 'queued' AND job_type = ANY($1::text[])
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """,
                list(_JOB_TYPES),
            )
            if row is None:
                return None
            await conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'running', claimed_by = $2, claimed_at = now(),
                    heartbeat_at = now(), updated_at = now()
                WHERE job_id = $1
                """,
                row["job_id"], WORKER_IDENTITY,
            )
            return dict(row)


async def _write_build_result(pool, job_id, server_id, job_type: str, result: dict) -> None:
    await pool.execute(
        """
        INSERT INTO build_results
            (job_id, server_id, job_type, build_artifact_digest, image_ref,
             sbom_cyclonedx, provenance, worker_error)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, $8)
        """,
        job_id, server_id, job_type,
        result.get("build_artifact_digest"),
        result.get("image_ref"),
        json.dumps(result["sbom_cyclonedx"]) if result.get("sbom_cyclonedx") is not None else None,
        json.dumps(result.get("provenance") or {}),
        result.get("worker_error"),
    )


async def _mark_completed(pool, job_id) -> None:
    await pool.execute(
        "UPDATE scan_jobs SET status = 'completed', heartbeat_at = now(), updated_at = now() "
        "WHERE job_id = $1",
        job_id,
    )


async def _mark_failed_or_dead_letter(pool, job_id, attempts: int, max_attempts: int, error: str) -> None:
    new_attempts = attempts + 1
    if new_attempts >= max_attempts:
        status = "dead_letter"
        logger.error("job %s exhausted %d attempts -> dead_letter: %s", job_id, new_attempts, error)
    else:
        status = "queued"  # requeue for retry
        logger.warning("job %s failed (attempt %d/%d), requeueing: %s",
                       job_id, new_attempts, max_attempts, error)
    await pool.execute(
        """
        UPDATE scan_jobs
        SET status = $2, attempts = $3, last_error = $4, heartbeat_at = now(), updated_at = now()
        WHERE job_id = $1
        """,
        job_id, status, new_attempts, error[:4000],
    )


async def _process_one(pool, job: dict) -> None:
    job_id = job["job_id"]
    job_type = job["job_type"]
    metrics.jobs_claimed_total.inc()
    logger.info("claimed job %s server_id=%s type=%s attempt=%d/%d",
               job_id, job["server_id"], job_type, job["attempts"] + 1, job["max_attempts"])
    with metrics.job_duration_seconds.time():
        try:
            if job_type == "build_requested":
                result = await build_engine.run_build(
                    pool, job["server_id"], job["github_url"], job.get("expected_digest"),
                    job_id=job_id,
                )
            else:
                # deploy_requested/verify_requested are handled by the trusted,
                # privileged launcher/verifier inside the proxy (Tasks 4-5) — the
                # unprivileged build worker has no podman/container-runtime
                # access at all. It still claims the job (single queue, single
                # claim path) but records that this job_type is out of its
                # scope, and the corresponding proxy-side service does the real
                # work against server_registry directly rather than via
                # build_results for these two types.
                result = {
                    "build_artifact_digest": None, "image_ref": None,
                    "provenance": {}, "sbom_cyclonedx": None,
                    "worker_error": (
                        f"{job_type} is handled by the proxy's privileged launcher/verifier, "
                        "not the build worker — see deploy_launcher.py / deploy_verifier.py"
                    ),
                }
            await _write_build_result(pool, job_id, job["server_id"], job_type, result)
            await _mark_completed(pool, job_id)
            metrics.jobs_completed_total.inc()
            logger.info("job %s completed digest=%s worker_error=%s",
                       job_id, result.get("build_artifact_digest"), result.get("worker_error"))
        except Exception as exc:
            logger.exception("job %s crashed during processing: %s", job_id, exc)
            new_attempts = job["attempts"] + 1
            if new_attempts >= job["max_attempts"]:
                metrics.jobs_dead_letter_total.inc()
            else:
                metrics.jobs_requeued_total.inc()
            await _mark_failed_or_dead_letter(pool, job_id, job["attempts"], job["max_attempts"], str(exc))


async def main() -> None:
    logger.info("build-worker starting identity=%s poll_interval=%ss",
               WORKER_IDENTITY, POLL_INTERVAL_SECONDS)
    metrics.start_metrics_server()
    pool = await db.get_pool()
    try:
        while True:
            job = await _claim_job(pool)
            if job is None:
                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                continue
            await _process_one(pool, job)
    finally:
        await db.close_pool()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
