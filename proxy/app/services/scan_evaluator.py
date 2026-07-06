"""
Scan evaluator (CR-14 / WP-B1, extended CR-12 / WP-B2) — the trusted,
verdict-writing side.

This is the ONLY code path that computes scan_status/block and drives
server_registry submission_status transitions. It never touches
attacker-controlled repo content directly — it only reads the structured
JSON the (isolated, unprivileged) scanner-worker already produced in
scan_raw_results.

Policy (extended by CR-12 with a fourth outcome, 'review_required'):
  - any finding with block=True                              -> 'blocked'
  - worker_error, or any finding with missing_tool=True       -> 'error'
    (fail closed — a scanner that couldn't run is never a silent pass)
  - dependency_policy.evaluate_dependency_findings() flags block            -> 'blocked'
  - dependency_policy.evaluate_dependency_findings() flags review_required  -> 'review_required'
    (unknown-severity CVE, npm project with no lockfile, govulncheck
    module-load failure — none of these are a clean pass, but none of them
    are a confirmed high/critical CVE either; a human must clear them)
  - otherwise                                                -> 'passed'
Precedence: blocked > error > review_required > passed — the worst-known
outcome always wins, never softened by an unrelated clean signal.

Also handles the "worker gave up" cases:
  - dead_letter jobs with no raw result row at all (worker crashed before
    ever writing one) -> scan_status='error', clearly fail-closed, never
    left in a permanent 'running' limbo.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.services.dependency_policy import evaluate_dependency_findings

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 3.0

_task: asyncio.Task | None = None


def _decide_status(raw_findings: list[dict], worker_error: str | None,
                    waivers: list[dict] | None = None) -> str:
    blocked = any(f.get("block") for f in raw_findings)
    missing_tool = any(f.get("missing_tool") for f in raw_findings)
    dep = evaluate_dependency_findings(raw_findings, waivers)
    if blocked or dep["block"]:
        return "blocked"
    if worker_error or missing_tool:
        return "error"
    if dep["review_required"]:
        return "review_required"
    return "passed"


async def _fetch_active_waivers(session, server_id) -> list[dict]:
    from app.services.scan_waivers import get_active_waivers_for_evaluation
    try:
        return await get_active_waivers_for_evaluation(session, str(server_id))
    except Exception as exc:
        # Fail closed: if waiver lookup itself breaks, evaluate as though no
        # waiver applies rather than raising and leaving the job stuck.
        logger.error("waiver lookup failed for server_id=%s: %s", server_id, exc)
        return []


async def _evaluate_submission_scan(session, job, raw) -> None:
    waivers = await _fetch_active_waivers(session, job.server_id)
    status = _decide_status(raw.raw_findings, raw.worker_error, waivers)
    # 'review_required' routes to the same review queue as 'passed'
    # (awaiting_review) — the review UI distinguishes them via scan_status,
    # not submission_status. A CVE gate ambiguity is still something a human
    # reviewer clears through the ordinary approve/reject/request-changes
    # flow, it just must never present as an unqualified clean pass.
    subm_status = ("scan_blocked" if status == "blocked"
                   else ("awaiting_review" if status in ("passed", "review_required") else "scan_running"))
    await session.execute(text(
        """
        UPDATE server_registry
        SET scan_status = :scan_status,
            scan_report = CAST(:report AS jsonb),
            submission_status = :subm_status,
            sbom_components = CAST(:components AS jsonb),
            sbom_cyclonedx = CAST(:cyclonedx AS jsonb),
            scanned_at = now(),
            scan_commit = :commit,
            updated_at = now()
        WHERE server_id = :sid
        """
    ), {
        "scan_status": status,
        "report": json.dumps(raw.raw_findings),
        "subm_status": subm_status,
        "components": json.dumps(raw.sbom_components or []),
        "cyclonedx": json.dumps(raw.sbom_cyclonedx) if raw.sbom_cyclonedx is not None else None,
        "commit": raw.scan_commit,
        "sid": str(job.server_id),
    })
    logger.info("evaluated submission_scan job_id=%s server_id=%s -> scan_status=%s",
               job.job_id, job.server_id, status)


async def _evaluate_rescan(session, job, raw) -> None:
    waivers = await _fetch_active_waivers(session, job.server_id)
    status = _decide_status(raw.raw_findings, raw.worker_error, waivers)
    now = datetime.now(timezone.utc)
    # Rescan never touches submission_status — approved servers stay approved
    # (matches pre-CR-14 rescan_scheduler semantics).
    await session.execute(text(
        """
        UPDATE server_registry
        SET scan_status       = :scan_status,
            scan_report       = CAST(:report AS jsonb),
            last_rescanned_at = :now,
            updated_at        = :now
        WHERE server_id = :sid
        """
    ), {"scan_status": status, "report": json.dumps(raw.raw_findings), "now": now, "sid": str(job.server_id)})
    logger.info("evaluated rescan job_id=%s server_id=%s -> scan_status=%s", job.job_id, job.server_id, status)


async def evaluate_pending() -> int:
    """Evaluate every completed-but-unevaluated raw result. Returns count evaluated."""
    evaluated = 0
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text(
            """
            SELECT r.result_id, r.job_id, r.server_id, r.raw_findings, r.scan_commit,
                   r.sbom_components, r.sbom_cyclonedx, r.worker_error,
                   j.job_type, j.server_id AS j_server_id
            FROM scan_raw_results r
            JOIN scan_jobs j ON j.job_id = r.job_id
            WHERE r.evaluated_at IS NULL AND j.status = 'completed'
            ORDER BY r.created_at ASC
            LIMIT 50
            """
        ))).fetchall()

        for raw in rows:
            job = raw  # job_type/server_id aliased onto the same row
            try:
                if raw.job_type == "rescan":
                    await _evaluate_rescan(session, job, raw)
                else:
                    await _evaluate_submission_scan(session, job, raw)
                await session.execute(text(
                    "UPDATE scan_raw_results SET evaluated_at = now() WHERE result_id = :rid"
                ), {"rid": raw.result_id})
                evaluated += 1
            except Exception as exc:
                logger.exception("evaluator failed on result_id=%s: %s", raw.result_id, exc)
        await session.commit()

    # Dead-letter jobs that never produced a raw result at all (worker
    # crashed before its first successful write) must not leave the
    # submission stuck in scan_running forever — fail closed to 'error'.
    async with AsyncSessionLocal() as session:
        stuck = (await session.execute(text(
            """
            SELECT j.job_id, j.server_id, j.job_type, j.last_error
            FROM scan_jobs j
            LEFT JOIN scan_raw_results r ON r.job_id = j.job_id
            WHERE j.status = 'dead_letter' AND r.result_id IS NULL
            LIMIT 50
            """
        ))).fetchall()
        for job in stuck:
            report = [{
                "scanner": "system", "severity": "critical", "block": False,
                "file": "", "line": 0,
                "message": f"Scanner worker exhausted retries without producing a result: "
                           f"{job.last_error or 'unknown error'}",
            }]
            if job.job_type == "rescan":
                await session.execute(text(
                    """
                    UPDATE server_registry
                    SET scan_status = 'error', scan_report = CAST(:report AS jsonb),
                        last_rescanned_at = now(), updated_at = now()
                    WHERE server_id = :sid
                    """
                ), {"report": json.dumps(report), "sid": str(job.server_id)})
            else:
                await session.execute(text(
                    """
                    UPDATE server_registry
                    SET scan_status = 'error', scan_report = CAST(:report AS jsonb),
                        submission_status = 'scan_running', updated_at = now()
                    WHERE server_id = :sid
                    """
                ), {"report": json.dumps(report), "sid": str(job.server_id)})
            logger.error("job %s dead-lettered with no raw result; server_id=%s marked scan_status=error",
                        job.job_id, job.server_id)
            evaluated += 1
        await session.commit()

    return evaluated


async def _loop() -> None:
    while True:
        try:
            n = await evaluate_pending()
            if n:
                logger.info("scan evaluator processed %d result(s)", n)
        except Exception as exc:
            logger.error("scan evaluator loop iteration failed: %s", exc)
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


def start() -> None:
    global _task
    _task = asyncio.create_task(_loop())
    logger.info("scan evaluator loop started (poll_interval=%ss)", POLL_INTERVAL_SECONDS)


async def stop() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None
    logger.info("scan evaluator loop stopped")
