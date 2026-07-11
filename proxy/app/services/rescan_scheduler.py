"""
Supply-chain re-scan scheduler (Stage 3).

Runs in the background and periodically re-evaluates every approved server's
security posture:
  - Servers with github_repo_url: enqueues a 'rescan' scan_jobs row. The
    isolated scanner-worker service (CR-14 / WP-B1) executes the pipeline
    (secrets scan + dependency audit + custom regex rules) and writes RAW
    output; scan_evaluator applies policy once the worker completes.
  - Servers without github_repo_url (direct-add / lab servers): no scannable
    source; last_rescanned_at is updated immediately so they don't trip the
    freshness gate.

Only scan_status, scan_report, and last_rescanned_at are updated by the
evaluator for rescan jobs — submission_status is untouched so approved
servers stay approved. This scheduler itself no longer clones or executes
scanners in-process (CR-14) — it only enqueues and, for repo-less servers,
stamps last_rescanned_at directly.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

_task: asyncio.Task | None = None


async def _rescan_all() -> None:
    from app.services import scan_queue

    async with AsyncSessionLocal() as session:
        result = await session.execute(text(
            """
            SELECT server_id, name, github_repo_url
            FROM server_registry
            WHERE status = 'approved'
              AND deleted_at IS NULL
            ORDER BY last_rescanned_at ASC NULLS FIRST
            """
        ))
        rows = result.fetchall()

    for row in rows:
        server_id, name, repo_url = row

        if repo_url:
            logger.info("Rescan: enqueueing scan job for %s (%s)", name, repo_url)
            try:
                await scan_queue.enqueue_scan(str(server_id), repo_url, job_type="rescan")
            except Exception as exc:
                # Enqueue itself failing (DB error) is logged but not fatal to
                # the loop — the next periodic pass will retry this server.
                logger.warning("Rescan: failed to enqueue job for %s: %s", name, exc)
            continue

        # No source repo — nothing to scan; mark fresh directly (no job needed).
        now = datetime.now(timezone.utc)
        async with AsyncSessionLocal() as session:
            await session.execute(text(
                """
                UPDATE server_registry
                SET scan_status       = 'passed',
                    scan_report       = '[]'::jsonb,
                    last_rescanned_at = :now,
                    updated_at        = :now
                WHERE server_id = :sid
                """
            ), {"now": now, "sid": str(server_id)})
            await session.commit()
        logger.info("Rescan: %s has no source repo; marked fresh", name)


async def _loop(interval_hours: int) -> None:
    interval_secs = interval_hours * 3600
    while True:
        try:
            await _rescan_all()
        except Exception as exc:
            logger.error("Rescan loop iteration failed: %s", exc)
        await asyncio.sleep(interval_secs)


def start(interval_hours: int) -> None:
    global _task
    _task = asyncio.create_task(_loop(interval_hours))
    logger.info("Supply-chain rescan loop started (interval=%dh)", interval_hours)


async def stop() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None
    logger.info("Supply-chain rescan loop stopped")
