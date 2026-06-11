"""
Compliance checker entrypoint — Task 5.3 (LOG-F10).

Scheduling behaviour:
  - Reads COMPLIANCE_CRON_SCHEDULE (default "0 2 * * *" = 02:00 UTC daily).
  - Calculates the next scheduled wall-clock time using _next_run_utc().
  - Sleeps until that time, then runs:
      1. checker.run()                    — compliance check pipeline
      2. archive_old_audit_events()       — nightly audit-event archival (LOG-F09)

No pg_cron, no system cron, no root access required.  The scheduler is entirely
in this Python process (non-root user UID 1001 in the container per Dockerfile).

On startup it also runs both jobs immediately (before waiting for the first
scheduled window) so the first deploy gets a baseline check + archival pass.

Environment variables:
  COMPLIANCE_CRON_SCHEDULE  cron expression, 5-field, UTC (default: "0 2 * * *")
  COMPLIANCE_CHECK_INTERVAL_SECONDS  deprecated interval fallback — ignored when
                                     COMPLIANCE_CRON_SCHEDULE is set.
  LOG_LEVEL                 logging level (default: INFO)
"""
from __future__ import annotations

import asyncio
import importlib
import logging
import os
import time
from datetime import datetime, timezone

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s entrypoint %(message)s",
)
log = logging.getLogger("entrypoint")

# ---------------------------------------------------------------------------
# Minimal 5-field cron scheduler — no external dependency.
# Supports numeric values, "*", and step-of-one ranges.
# Sufficient for the patterns used in COMPLIANCE_CRON_SCHEDULE.
# ---------------------------------------------------------------------------

def _field_matches(value: int, expr: str) -> bool:
    """
    Return True if `value` satisfies the cron field expression `expr`.

    Supports:
      "*"             — matches any value
      "N"             — matches exactly N
      "*/S"           — matches when value % S == 0
      "N-M"           — matches when N <= value <= M
      "N,M,..."       — matches any listed value

    Args:
        value: The actual calendar value (minute, hour, etc.)
        expr:  A single cron field token (no spaces).
    """
    if expr == "*":
        return True
    if expr.startswith("*/"):
        step = int(expr[2:])
        return value % step == 0
    if "," in expr:
        return any(_field_matches(value, part) for part in expr.split(","))
    if "-" in expr:
        lo, hi = expr.split("-", 1)
        return int(lo) <= value <= int(hi)
    return value == int(expr)


def _next_run_utc(cron_expr: str) -> float:
    """
    Return the Unix timestamp (UTC) of the next trigger time for `cron_expr`.

    Cron fields (5-field, space-separated): minute hour dom month dow.
    Resolution: 1 minute.  The search window is at most 8 days (= 11520 minutes),
    which is sufficient for any valid 5-field cron expression.

    Returns:
        float — seconds since epoch of the next matching minute.

    Raises:
        ValueError: if cron_expr does not contain exactly 5 fields.
    """
    fields = cron_expr.strip().split()
    if len(fields) != 5:
        raise ValueError(
            f"COMPLIANCE_CRON_SCHEDULE must be a 5-field cron expression "
            f"(e.g. '0 2 * * *'); got: {cron_expr!r}"
        )
    f_min, f_hour, f_dom, f_month, f_dow = fields

    now_utc = datetime.now(timezone.utc)
    # Start search from the next minute (never the current minute — avoids
    # immediate re-trigger on startup when we already ran once at T=0).
    candidate = now_utc.replace(second=0, microsecond=0)
    # Advance by 1 minute to exclude the current minute.
    from datetime import timedelta
    candidate = candidate + timedelta(minutes=1)

    for _ in range(11520):  # 8-day search cap
        if (
            _field_matches(candidate.minute, f_min)
            and _field_matches(candidate.hour, f_hour)
            and _field_matches(candidate.day, f_dom)
            and _field_matches(candidate.month, f_month)
            and _field_matches(candidate.weekday(), f_dow)
        ):
            return candidate.timestamp()
        candidate = candidate + timedelta(minutes=1)

    raise RuntimeError(
        f"Could not find next run time for cron expression: {cron_expr!r}"
    )


# ---------------------------------------------------------------------------
# Main scheduling loop
# ---------------------------------------------------------------------------

CRON_SCHEDULE = os.getenv("COMPLIANCE_CRON_SCHEDULE", "0 2 * * *")
log.info("Compliance checker starting — schedule: %s (UTC)", CRON_SCHEDULE)

checker = importlib.import_module("checker")


def _run_compliance_check() -> int:
    """Run the compliance check pipeline. Returns exit code."""
    log.info("Running compliance check (checker.run)")
    try:
        rc = checker.run()
        log.info("Compliance check finished (rc=%d)", rc)
        return rc
    except Exception as exc:
        log.error("Unhandled exception in compliance check: %s", exc, exc_info=True)
        return 1


def _run_archival() -> dict:
    """Run the nightly audit-event archival (Task 5.2, LOG-F09)."""
    log.info("Running audit-event archival (archive_old_audit_events)")
    try:
        result = asyncio.run(checker.archive_old_audit_events())
        log.info(
            "Archival finished: status=%s rows_archived=%d archive_url=%s",
            result.get("status"),
            result.get("rows_archived", 0),
            result.get("archive_url"),
        )
        return result
    except Exception as exc:
        log.error("Unhandled exception in archival: %s", exc, exc_info=True)
        return {"status": "error", "error": str(exc)}


def _run_all_jobs() -> None:
    """Run compliance check then archival in sequence."""
    _run_compliance_check()
    _run_archival()


# ---------------------------------------------------------------------------
# Startup: run immediately on first deploy, then wait for cron schedule.
# ---------------------------------------------------------------------------
log.info("Startup: running initial compliance check + archival pass")
_run_all_jobs()

while True:
    try:
        next_ts = _next_run_utc(CRON_SCHEDULE)
    except (ValueError, RuntimeError) as exc:
        log.error(
            "Invalid COMPLIANCE_CRON_SCHEDULE %r: %s. "
            "Falling back to 24-hour interval.",
            CRON_SCHEDULE, exc,
        )
        next_ts = time.time() + 86400

    next_dt = datetime.fromtimestamp(next_ts, tz=timezone.utc)
    sleep_secs = max(0, next_ts - time.time())
    log.info(
        "Next run scheduled at %s UTC (sleeping %.0fs)",
        next_dt.isoformat(),
        sleep_secs,
    )
    time.sleep(sleep_secs)

    log.info("Scheduled run triggered at %s UTC", datetime.now(timezone.utc).isoformat())
    _run_all_jobs()
