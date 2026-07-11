"""
Scan job queue (CR-14 / WP-B1) — proxy_app side.

The proxy no longer clones repos or runs scanners itself. It enqueues a
scan_jobs row; the isolated scanner-worker service claims it, executes the
scanner pipeline, and writes RAW output to scan_raw_results. scan_evaluator
(also in this module's sibling file) is the ONLY thing that reads raw
results, applies policy, and writes server_registry.scan_status/block.

Idempotency: re-submitting the same (server_id, github_url) while a job is
already queued/running returns the existing job instead of enqueuing a
duplicate, unless force=True (a partial unique index in V063 enforces this
at the DB level too — see ux_scan_jobs_inflight).
"""
from __future__ import annotations

import logging

from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


async def enqueue_scan(server_id: str, github_url: str, job_type: str = "submission_scan",
                       force: bool = False) -> str:
    """Enqueue a scan job. Returns the job_id (existing or newly created)."""
    async with AsyncSessionLocal() as session:
        if not force:
            existing = (await session.execute(text(
                """
                SELECT job_id FROM scan_jobs
                WHERE server_id = :sid AND github_url = :url
                  AND status IN ('queued', 'running')
                ORDER BY created_at DESC
                LIMIT 1
                """
            ), {"sid": server_id, "url": github_url})).fetchone()
            if existing:
                logger.info("scan already in-flight for server_id=%s job_id=%s; not re-enqueuing",
                           server_id, existing.job_id)
                return str(existing.job_id)

        row = (await session.execute(text(
            """
            INSERT INTO scan_jobs (server_id, github_url, job_type, force)
            VALUES (:sid, :url, :job_type, :force)
            RETURNING job_id
            """
        ), {"sid": server_id, "url": github_url, "job_type": job_type, "force": force})).fetchone()
        await session.commit()
        logger.info("enqueued scan job_id=%s server_id=%s job_type=%s", row.job_id, server_id, job_type)
        return str(row.job_id)


async def queue_depth() -> dict[str, int]:
    """Metrics hook: current job counts by queue status. Cheap enough to poll."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text(
            "SELECT status, COUNT(*) AS n FROM scan_jobs GROUP BY status"
        ))).fetchall()
    depth = {"queued": 0, "running": 0, "completed": 0, "failed": 0, "dead_letter": 0}
    for r in rows:
        depth[r.status] = r.n
    return depth


async def dead_letter_jobs(limit: int = 100) -> list[dict]:
    """List dead-lettered jobs — so they are visible, never silently dropped."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text(
            """
            SELECT job_id, server_id, github_url, job_type, attempts, max_attempts,
                   last_error, created_at, updated_at
            FROM scan_jobs
            WHERE status = 'dead_letter'
            ORDER BY updated_at DESC
            LIMIT :limit
            """
        ), {"limit": limit})).fetchall()
    return [dict(r._mapping) for r in rows]
