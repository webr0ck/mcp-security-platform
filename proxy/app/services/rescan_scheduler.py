"""
Supply-chain re-scan scheduler (Stage 3).

Runs in the background and periodically re-evaluates every approved server's
security posture:
  - Servers with github_repo_url: full submission_scanner pipeline
    (secrets scan + dependency audit + custom regex rules).
  - Servers without github_repo_url (direct-add / lab servers): no scannable
    source; last_rescanned_at is updated immediately so they don't trip the
    freshness gate.

Only scan_status, scan_report, and last_rescanned_at are updated — submission_status
is untouched so approved servers stay approved.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

_task: asyncio.Task | None = None


async def _rescan_all() -> None:
    from app.services.submission_scanner import scan_repo

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
        now = datetime.now(timezone.utc)

        if repo_url:
            logger.info("Rescan: scanning %s (%s)", name, repo_url)
            try:
                findings, status = await scan_repo(repo_url)
            except Exception as exc:
                logger.warning("Rescan: scanner error for %s: %s", name, exc)
                findings, status = [{"error": str(exc)}], "error"
        else:
            # No source repo — nothing to scan; mark fresh.
            findings, status = [], "passed"

        async with AsyncSessionLocal() as session:
            await session.execute(text(
                """
                UPDATE server_registry
                SET scan_status       = :scan_status,
                    scan_report       = CAST(:report AS jsonb),
                    last_rescanned_at = :now,
                    updated_at        = :now
                WHERE server_id = :sid
                """
            ), {
                "scan_status": status,
                "report": json.dumps(findings),
                "now": now,
                "sid": str(server_id),
            })
            await session.commit()

        logger.info("Rescan: %s → status=%s findings=%d", name, status, len(findings))


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
