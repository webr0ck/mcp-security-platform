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

from app.core.config import settings
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


async def _attest_self_hosted() -> None:
    """
    Continuous attestation for self-hosted servers (R6.1).

    A self-hosted server is trusted on the strength of a point-in-time check: the repo
    was scanned, the reviewer approved, and the verification probes passed once, at
    provide-url time. Nothing re-checked the RUNNING backend afterwards. Changing the
    registered URL is already guarded (request_change_for_server demotes + quarantines +
    re-reviews), but swapping what is served at the SAME url was invisible: tool
    discovery is idempotent-skip, so an already-registered name is never re-read.

    So: submit a clean repo, get approved, then serve something else at that URL. This
    sweep closes that by periodically re-reading the live tool surface and demoting the
    server for re-review when a tool we have authorized no longer matches what answers.

    An unreachable upstream is skipped, NOT quarantined. That direction is opposite to
    the change-request classifier's fail-safe, and deliberately so: there, an owner is
    asking for something and uncertainty should buy more review. Here, quarantining on a
    failed probe would let one network blip or one upstream restart demote the whole
    self-hosted fleet — a self-inflicted outage. An unreachable server cannot serve tool
    calls anyway, so skipping costs no security.
    """
    from app.services.server_lifecycle import (
        fetch_live_tool_schema,
        live_schema_drift,
        record_attestation_baseline,
        request_change_for_server,
    )

    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text(
            """
            SELECT server_id, name, upstream_url, upstream_allowlist_entry,
                   attested_tool_schema, attested_at
            FROM server_registry
            WHERE status = 'approved'
              AND deleted_at IS NULL
              AND is_self_hosted IS TRUE
              AND upstream_url IS NOT NULL
              AND submission_status IN ('approved', 'active')
            """
        ))).mappings().all()

    for row in rows:
        server_id, name = str(row["server_id"]), row["name"]
        try:
            live = await fetch_live_tool_schema(row["upstream_url"], row["upstream_allowlist_entry"])
            if live is None:
                logger.info("Attestation: %s unreachable — skipping (not treated as drift)", name)
                continue

            if row["attested_at"] is None:
                # Trust-on-first-use. Logged at WARNING because it IS a real weakness:
                # a server swapped before its first sweep gets the swapped surface
                # recorded as legitimate. Servers approved after this feature shipped are
                # baselined at provide-url time instead and never take this branch.
                await record_attestation_baseline(server_id, live)
                logger.warning(
                    "Attestation: %s had no baseline — recorded current live surface as "
                    "trust-on-first-use (%d tool(s))", name, len(live),
                )
                continue

            drifted = live_schema_drift(live, row["attested_tool_schema"])
            if not drifted:
                continue

            logger.error(
                "Attestation: %s DRIFTED — live tool surface differs from the attested "
                "baseline for %s; demoting to re-review", name, drifted,
            )
            await request_change_for_server(
                server_id,
                actor="system:attestation",
                reason=f"periodic attestation: live tool surface drifted ({', '.join(drifted)})",
                asserted_ip_only=False,   # force full re-review; never auto-approve a drift
            )
        except Exception as exc:
            # One bad server must not stop the sweep for the rest of the fleet.
            logger.warning("Attestation: check failed for %s: %s", name, exc)


async def _loop(interval_hours: int) -> None:
    interval_secs = interval_hours * 3600
    while True:
        try:
            await _rescan_all()
        except Exception as exc:
            logger.error("Rescan loop iteration failed: %s", exc)
        if settings.SELF_HOSTED_ATTESTATION_ENABLED:
            try:
                await _attest_self_hosted()
            except Exception as exc:
                logger.error("Attestation sweep failed: %s", exc)
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
