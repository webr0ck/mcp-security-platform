"""
Prometheus metrics (CR-17 / WP-D1).

A minimal, hand-picked set of counters/gauges covering the signals CR-17
names as the highest-value ones for this platform: authorization decisions,
deny rates, OPA/Vault reachability, audit emission failures, credential
broker failures, scan queue depth/latency/dead-letter, and quarantine
backlog. Deliberately not a blanket auto-instrumentation of every endpoint —
alert fatigue is the failure mode CR-17 itself warns about ("too many alerts
will be ignored"), so this favors a few signals tied to hard invariants over
exhaustive coverage.

GET /metrics (routers/metrics.py) is the single scrape endpoint. Two kinds
of series:
  - Counters/gauges updated inline at the real call site (authz decisions,
    OPA/Vault reachability, audit failures, broker failures) — cheap,
    in-process increments, no I/O.
  - Gauges refreshed lazily at scrape time via refresh_db_gauges() (scan
    queue depth by status, quarantine backlog) — a live DB count is cheap
    enough to run per-scrape (Prometheus's default scrape interval is 15s+)
    and avoids running a redundant background poller next to
    scan_evaluator's existing one.
"""
from __future__ import annotations

import logging

from prometheus_client import Counter, Gauge

logger = logging.getLogger(__name__)

# ponytail: scan_jobs has no completion-duration column (created_at/
# updated_at exist but a job can be requeued multiple times, so
# updated_at-created_at isn't a clean "latency" signal). A real latency
# histogram needs a claimed_at->completed_at delta column added to
# scan_jobs — out of scope for this pass (D4: no prod env to calibrate
# histogram buckets against anyway). Queue depth + dead_letter count (both
# implemented below) are the two scan-queue signals that matter most for
# alerting; add latency when a real completion timestamp exists.

# ── Authorization ─────────────────────────────────────────────────────────────
authz_decisions_total = Counter(
    "mcp_authz_decisions_total",
    "OPA authorization decisions by outcome (allow/deny) — INV-003/INV-004.",
    ["decision"],
)
opa_up = Gauge(
    "mcp_opa_up",
    "1 if the most recent OPA call succeeded, 0 if it raised OPAUnavailableError.",
)

# ── Vault / KMS ────────────────────────────────────────────────────────────────
vault_up = Gauge(
    "mcp_vault_up",
    "1 if the most recent Vault/KMS master-secret fetch succeeded, 0 if it raised KMSError.",
)

# ── Audit (INV-001) ────────────────────────────────────────────────────────────
audit_emit_failures_total = Counter(
    "mcp_audit_emit_failures_total",
    "Count of INV-001 boundary trips (audit emission failure -> 500).",
)

# ── Credential broker ──────────────────────────────────────────────────────────
credential_broker_failures_total = Counter(
    "mcp_credential_broker_failures_total",
    "Credential injection failures by error type.",
    ["error_type"],
)

# ── Scan queue (CR-14/WP-B1) ───────────────────────────────────────────────────
scan_queue_depth = Gauge(
    "mcp_scan_queue_depth",
    "Current scan_jobs row count by queue status.",
    ["status"],
)

# ── Quarantine backlog ─────────────────────────────────────────────────────────
quarantine_backlog = Gauge(
    "mcp_quarantine_backlog",
    "Count of tool_registry rows with status='quarantined'.",
)

# ── Stale scans (feeds the "stale scans" hard-invariant alert) ────────────────
stale_scan_count = Gauge(
    "mcp_stale_scan_count",
    "Count of approved server_registry rows whose last_rescanned_at exceeds "
    "settings.RESCAN_INTERVAL_HOURS (SCAN_FRESHNESS_ENFORCED window).",
)


def record_authz_decision(allow: bool) -> None:
    authz_decisions_total.labels(decision="allow" if allow else "deny").inc()


def record_opa_reachable(reachable: bool) -> None:
    opa_up.set(1 if reachable else 0)


def record_vault_reachable(reachable: bool) -> None:
    vault_up.set(1 if reachable else 0)


def record_audit_emit_failure() -> None:
    audit_emit_failures_total.inc()


def record_credential_broker_failure(error_type: str) -> None:
    credential_broker_failures_total.labels(error_type=error_type).inc()


async def refresh_db_gauges() -> None:
    """Refresh the scrape-time DB-backed gauges. Best-effort: a DB error here
    must not break the /metrics endpoint itself (Prometheus would then lose
    ALL series, not just the DB-backed ones) — log and leave gauges at their
    last-known value."""
    try:
        from sqlalchemy import text

        from app.core.config import settings
        from app.core.database import AsyncSessionLocal
        from app.services import scan_queue

        # Reuse scan_queue.queue_depth() (CR-14/WP-B1) rather than
        # reimplementing the same GROUP BY query a second time here.
        depth = await scan_queue.queue_depth()
        for status, n in depth.items():
            scan_queue_depth.labels(status=status).set(n)

        async with AsyncSessionLocal() as session:
            q = (await session.execute(text(
                "SELECT COUNT(*) FROM tool_registry WHERE status = 'quarantined' AND deleted_at IS NULL"
            ))).scalar()
            quarantine_backlog.set(q or 0)

            # SCAN_FRESHNESS_ENFORCED window (03-policy-and-detections.md §3b):
            # an approved server whose last scan predates this window is
            # already denying invocations at the gate — surface it here too
            # so it shows up on a dashboard/alert before someone notices via
            # a support ticket.
            stale = (await session.execute(text(
                """
                SELECT COUNT(*) FROM server_registry
                WHERE status = 'approved' AND deleted_at IS NULL
                  AND (last_rescanned_at IS NULL
                       OR last_rescanned_at < now() - (:hours || ' hours')::interval)
                """
            ), {"hours": settings.RESCAN_INTERVAL_HOURS})).scalar()
            stale_scan_count.set(stale or 0)
    except Exception as exc:
        logger.warning("metrics: refresh_db_gauges failed (leaving gauges stale): %s", exc)
