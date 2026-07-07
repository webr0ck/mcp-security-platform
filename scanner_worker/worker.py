"""
scanner-worker main loop (CR-14 / WP-B1).

Claims queued jobs from scan_jobs (SELECT ... FOR UPDATE SKIP LOCKED),
executes the scan engine, and writes RAW results to scan_raw_results.

This process NEVER writes server_registry.scan_status/block or any other
adjudication-relevant column — it structurally lacks the DB grant to do so
(see infra/db/migrations/V063__scanner_worker_queue.sql). It also never
writes scan_raw_results.evaluated_at — that is the evaluator's column.

Idempotent retry + dead-letter: on any exception during scan execution the
job is requeued (status='queued') with attempts incremented, up to
max_attempts; the Nth failure sets status='dead_letter' instead of being
silently dropped.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys

from . import db, scan_engine, metrics

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("scanner_worker")

POLL_INTERVAL_SECONDS = float(os.environ.get("SCAN_WORKER_POLL_INTERVAL", "3"))
WORKER_IDENTITY = f"scanner-worker:{socket.gethostname()}:{os.getpid()}"


async def _claim_job(pool) -> dict | None:
    """Atomically claim one queued job. Returns the job row dict, or None."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT job_id, server_id, github_url, job_type, attempts, max_attempts
                FROM scan_jobs
                WHERE status = 'queued'
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
                """
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


async def _write_raw_result(pool, job_id, server_id, result: dict) -> None:
    await pool.execute(
        """
        INSERT INTO scan_raw_results
            (job_id, server_id, raw_findings, scan_commit, sbom_components,
             sbom_cyclonedx, worker_error)
        VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6::jsonb, $7)
        """,
        job_id, server_id,
        json.dumps(result["raw_findings"]),
        result.get("scan_commit"),
        json.dumps(result.get("sbom_components") or []),
        json.dumps(result["sbom_cyclonedx"]) if result.get("sbom_cyclonedx") is not None else None,
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
    metrics.jobs_claimed_total.inc()
    logger.info("claimed job %s server_id=%s type=%s attempt=%d/%d",
               job_id, job["server_id"], job["job_type"], job["attempts"] + 1, job["max_attempts"])
    with metrics.job_duration_seconds.time():
        try:
            result = await scan_engine.run_scan(pool, job["github_url"])
            await _write_raw_result(pool, job_id, job["server_id"], result)
            await _mark_completed(pool, job_id)
            metrics.jobs_completed_total.inc()
            logger.info("job %s completed findings=%d worker_error=%s",
                       job_id, len(result["raw_findings"]), result.get("worker_error"))
        except Exception as exc:
            logger.exception("job %s crashed during processing: %s", job_id, exc)
            new_attempts = job["attempts"] + 1
            if new_attempts >= job["max_attempts"]:
                metrics.jobs_dead_letter_total.inc()
            else:
                metrics.jobs_requeued_total.inc()
            await _mark_failed_or_dead_letter(pool, job_id, job["attempts"], job["max_attempts"], str(exc))


async def main() -> None:
    logger.info("scanner-worker starting identity=%s poll_interval=%ss",
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
