"""
Build evaluator (CR-01 / WP-B3 phase 2c) — the trusted, verdict-writing side
of the build pipeline. Mirrors scan_evaluator.py exactly.

This is the ONLY code path that writes server_registry.deployment_status,
server_registry.build_artifact_digest, and server_registry.build_provenance
for the build_requested stage of the pipeline. It never touches
attacker-controlled repo content directly — it only reads the structured
JSON the (isolated, unprivileged) build-worker already produced in
build_results.

Policy — deliberately the simplest possible fail-closed rule (PRD-8 sec 2):
  - worker_error set, OR no build_artifact_digest at all -> 'failed'
  - otherwise                                            -> 'built'
There is no "review_required"/partial-success state for a build: either the
TOCTOU-pinned commit was built and produced a real digest, or it wasn't and
the whole attempt failed closed. (Verdict on the scan of the BUILT artifact
is a separate concern, handled by scan_evaluator.py once the rescan job this
build enqueued completes — deployment_status is not gated on that scan
result here; Task 4's deploy launcher is.)

Also handles the "worker gave up" case, same as scan_evaluator.py: a
dead_letter build_requested job with no build_results row at all (worker
crashed before ever writing one) must not leave deployment_status stuck at
'building' forever — fail closed to 'failed'.
"""
from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

POLL_INTERVAL_SECONDS = 3.0

_task: asyncio.Task | None = None


def _decide_build_status(build_artifact_digest: str | None, worker_error: str | None) -> str:
    """Never infer success from anything other than a real digest with no
    worker_error — this is the ONLY function that decides built vs failed."""
    if worker_error or not build_artifact_digest:
        return "failed"
    return "built"


async def _evaluate_build_requested(session, job, raw) -> None:
    status = _decide_build_status(raw.build_artifact_digest, raw.worker_error)
    provenance = dict(raw.provenance) if raw.provenance is not None else {}
    # image_ref lives on build_results as its own column (not inside the
    # worker-authored provenance dict) — fold it into build_provenance here
    # so deploy_launcher.py (Task 4) has a single place to read it from
    # server_registry without a second table join.
    if raw.image_ref:
        provenance["image_ref"] = raw.image_ref
    await session.execute(text(
        """
        UPDATE server_registry
        SET deployment_status    = :status,
            build_artifact_digest = :digest,
            build_provenance      = CAST(:provenance AS jsonb),
            updated_at            = now()
        WHERE server_id = :sid
        """
    ), {
        "status": status,
        "digest": raw.build_artifact_digest,
        "provenance": json.dumps(provenance),
        "sid": str(job.server_id),
    })
    logger.info("evaluated build_requested job_id=%s server_id=%s -> deployment_status=%s",
               job.job_id, job.server_id, status)


async def evaluate_pending() -> int:
    """Evaluate every completed-but-unevaluated build result. Returns count evaluated."""
    evaluated = 0
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(text(
            """
            SELECT r.result_id, r.job_id, r.server_id, r.build_artifact_digest,
                   r.image_ref, r.sbom_cyclonedx, r.provenance, r.worker_error,
                   j.job_type, j.server_id AS j_server_id
            FROM build_results r
            JOIN scan_jobs j ON j.job_id = r.job_id
            WHERE r.evaluated_at IS NULL AND j.status = 'completed'
                AND j.job_type = 'build_requested'
            ORDER BY r.created_at ASC
            LIMIT 50
            """
        ))).fetchall()

        for raw in rows:
            job = raw  # job_type/server_id aliased onto the same row
            try:
                await _evaluate_build_requested(session, job, raw)
                await session.execute(text(
                    "UPDATE build_results SET evaluated_at = now() WHERE result_id = :rid"
                ), {"rid": raw.result_id})
                evaluated += 1
            except Exception as exc:
                logger.exception("build evaluator failed on result_id=%s: %s", raw.result_id, exc)
        await session.commit()

    # Dead-letter build_requested jobs that never produced a build_results
    # row at all (worker crashed before its first successful write) must not
    # leave deployment_status stuck at 'building' forever — fail closed.
    async with AsyncSessionLocal() as session:
        stuck = (await session.execute(text(
            """
            SELECT j.job_id, j.server_id, j.last_error
            FROM scan_jobs j
            LEFT JOIN build_results r ON r.job_id = j.job_id
            WHERE j.status = 'dead_letter' AND j.job_type = 'build_requested'
                AND r.result_id IS NULL
            LIMIT 50
            """
        ))).fetchall()
        for job in stuck:
            provenance = {
                "error": f"Build worker exhausted retries without producing a result: "
                         f"{job.last_error or 'unknown error'}",
            }
            await session.execute(text(
                """
                UPDATE server_registry
                SET deployment_status = 'failed',
                    build_provenance  = CAST(:provenance AS jsonb),
                    updated_at        = now()
                WHERE server_id = :sid
                """
            ), {"provenance": json.dumps(provenance), "sid": str(job.server_id)})
            logger.error("build job %s dead-lettered with no build_results row; server_id=%s "
                        "marked deployment_status=failed", job.job_id, job.server_id)
            evaluated += 1
        await session.commit()

    return evaluated


async def _loop() -> None:
    while True:
        try:
            n = await evaluate_pending()
            if n:
                logger.info("build evaluator processed %d result(s)", n)
        except Exception as exc:
            logger.error("build evaluator loop iteration failed: %s", exc)
        await asyncio.sleep(POLL_INTERVAL_SECONDS)


def start() -> None:
    global _task
    _task = asyncio.create_task(_loop())
    logger.info("build evaluator loop started (poll_interval=%ss)", POLL_INTERVAL_SECONDS)


async def stop() -> None:
    global _task
    if _task and not _task.done():
        _task.cancel()
        try:
            await _task
        except asyncio.CancelledError:
            pass
    _task = None
    logger.info("build evaluator loop stopped")
