"""
MCP Security Platform — Anomaly Detector Service

Per-client sliding window anomaly detection using Redis.

Detection patterns:
  - web_search → bulk_file_read: 3+ file reads after 1+ web searches within the window
  - auth → data_export chain
  - rapid successive invocations: >10 invocations in the last 30s window

Anomaly score 0.0–1.0. Score >= 0.85 triggers an AnomalyAlert record in PostgreSQL.

STATUS (2026-06): this is an ADVISORY heuristic, not a learned behavioural model.
Scoring is STATIC keyword/window matching only — the literal tool-name rules below
are evadable by renaming a tool, and there is no per-client statistical baseline.
(6.4 removed the former write-only baseline writer, which wrote an
`anomaly_baselines` row that the scorer never read — dead code that implied a model
that did not exist. A real learned baseline is future work; until then this stays
labelled as the heuristic it is.)
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.redis_client import push_anomaly_invocation
from app.models.anomaly import AnomalyDetectionResult

logger = logging.getLogger(__name__)

# Threshold above which an alert is created (matches OPA authz.rego)
ANOMALY_ALERT_THRESHOLD: float = 0.85

# Pattern: web_search followed by file reads within the sliding window
EXFIL_SEARCH_TOOLS = frozenset({"web_search", "search", "web_browse", "internet_search"})
EXFIL_FILE_TOOLS = frozenset({
    "file_reader", "file_read", "read_file", "bulk_file_read",
    "filesystem_read", "read_files",
})
EXFIL_AUTH_TOOLS = frozenset({"auth", "authenticate", "login", "get_token", "oauth"})
EXFIL_EXPORT_TOOLS = frozenset({
    "data_export", "export", "export_data", "dump", "bulk_export",
})


def _score_window(window: list[str]) -> tuple[float, str | None, str | None]:
    """
    Analyse a tool invocation window and return (score, pattern, description).

    Patterns checked (higher score wins):
      1. web_search → bulk_file_read (exfiltration chain)
      2. auth → data_export (credential exfiltration)
      3. rapid invocations (any 10+ calls)
    """
    if not window:
        return 0.0, None, None

    total = len(window)
    search_count = sum(1 for t in window if t in EXFIL_SEARCH_TOOLS)
    file_read_count = sum(1 for t in window if t in EXFIL_FILE_TOOLS)
    auth_count = sum(1 for t in window if t in EXFIL_AUTH_TOOLS)
    export_count = sum(1 for t in window if t in EXFIL_EXPORT_TOOLS)

    score = 0.0
    pattern = None
    description = None

    # Pattern 1: web_search → bulk_file_read (exfiltration via search + mass read)
    if search_count >= 1 and file_read_count >= 3:
        # Score scales with severity of read count
        raw_score = 0.7 + min(file_read_count * 0.05, 0.25)
        if raw_score > score:
            score = raw_score
            pattern = "web_search → bulk_file_read"
            description = (
                f"Potential exfiltration chain: {search_count} search call(s) "
                f"followed by {file_read_count} file_reader call(s) in the sliding window."
            )

    # Pattern 2: auth → data_export
    if auth_count >= 1 and export_count >= 1:
        raw_score = 0.80
        if raw_score > score:
            score = raw_score
            pattern = "auth → data_export"
            description = (
                f"Credential-exfiltration chain: {auth_count} auth call(s) "
                f"followed by {export_count} export call(s)."
            )

    # Pattern 3: rapid invocations (>10 total in the 20-item window)
    if total > 10:
        # Rapid rate = high proportion of window filled quickly
        raw_score = 0.5 + (total - 10) * 0.035
        raw_score = min(raw_score, 0.90)
        if raw_score > score:
            score = round(raw_score, 4)
            pattern = "rapid_successive_invocations"
            description = (
                f"Rapid successive tool invocations: {total} calls in the sliding window "
                f"(threshold >10/window)."
            )

    return round(score, 4), pattern, description


async def detect(client_id: str, tool_name: str) -> AnomalyDetectionResult:
    """
    Push the current tool invocation into the Redis sliding window and score it.

    If score >= ANOMALY_ALERT_THRESHOLD, creates an AnomalyAlert in PostgreSQL
    (write-behind, async — failure is logged but doesn't block the invocation path).

    Returns AnomalyDetectionResult with the current score.
    """
    try:
        window = await push_anomaly_invocation(client_id, tool_name)
    except Exception as exc:
        logger.error(
            "Anomaly detector Redis error — returning score 0.0",
            extra={"client_id": client_id, "tool_name": tool_name, "error": str(exc)},
        )
        return AnomalyDetectionResult(anomaly_score=0.0, alert_triggered=False)

    score, pattern, description = _score_window(window)

    alert_triggered = score >= ANOMALY_ALERT_THRESHOLD
    if alert_triggered:
        logger.warning(
            "Anomaly threshold exceeded",
            extra={
                "client_id": client_id,
                "score": score,
                "pattern": pattern,
                "window_size": len(window),
            },
        )
        # Write-behind: don't block the request path on DB write
        try:
            await _persist_alert(client_id, score, pattern or "unknown", description or "")
        except Exception as exc:
            logger.error(
                "Failed to persist anomaly alert",
                extra={"client_id": client_id, "error": str(exc)},
            )

    return AnomalyDetectionResult(
        anomaly_score=score,
        pattern_matched=pattern,
        description=description,
        alert_triggered=alert_triggered,
    )


async def _persist_alert(
    client_id: str,
    score: float,
    pattern: str,
    description: str,
) -> None:
    """
    Persist an AnomalyAlert row to PostgreSQL.
    Called asynchronously from detect() when threshold is exceeded.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    alert_id = uuid4()
    async with AsyncSessionLocal() as session:
        await session.execute(
            text(
                """
                INSERT INTO anomaly_alerts
                  (alert_id, client_id, anomaly_score, pattern, description,
                   invocation_ids, resolved, detected_at, created_at, updated_at)
                VALUES
                  (:alert_id, :client_id, :score, :pattern, :description,
                   ARRAY[]::UUID[], false, NOW(), NOW(), NOW())
                """
            ),
            {
                "alert_id": str(alert_id),
                "client_id": client_id,
                "score": score,
                "pattern": pattern,
                "description": description,
            },
        )
        await session.commit()

    logger.info(
        "Anomaly alert persisted",
        extra={"alert_id": str(alert_id), "client_id": client_id, "score": score},
    )


# 6.4: `update_baseline_async` was removed here. It wrote an `anomaly_baselines`
# row that the scorer never read (write-only dead code implying a learned model
# that does not exist). The `anomaly_baselines` table remains for the admin
# read-only view (routers/anomaly.py) and for a future learned-baseline feature;
# it is intentionally unpopulated today.

# Alias for backward compatibility with invocation.py
evaluate_anomaly = detect
