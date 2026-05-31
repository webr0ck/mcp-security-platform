"""
MCP Security Platform — Compliance Checker

Daily cron job that runs the compliance check pipeline per docs/ARCHITECTURE.md Section 5.3.
Executed by the compliance-checker Docker container on COMPLIANCE_CRON_SCHEDULE.

Pipeline:
  1. Sample COMPLIANCE_SAMPLE_SIZE audit events from PostgreSQL (past 24h)
  2. For each event: check all 10 PII/credential pattern categories
  3. Verify SHA-256 hash integrity
  4. Write compliance_reports row to PostgreSQL (compliance_checker_app role)
  5. Archive full report JSON to MinIO WORM bucket (INV-007)
  6. If any category fails: POST alert to Alertmanager
  7. Exit 0 on pass, 1 on fail (for cron health monitoring)

Environment variables: see .env.example [COMPLIANCE_*] section.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
from datetime import date
from uuid import UUID


class _Encoder(json.JSONEncoder):
    """Serialize UUID and datetime objects returned by asyncpg."""
    def default(self, o: Any) -> Any:
        if isinstance(o, (UUID,)):
            return str(o)
        if isinstance(o, (datetime, date)):
            return o.isoformat()
        return super().default(o)

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("compliance-checker")

# ---------------------------------------------------------------------------
# Configuration from environment variables
# ---------------------------------------------------------------------------
DB_HOST = os.environ["DB_HOST"]
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "mcp_security")
COMPLIANCE_DB_USER = os.environ["COMPLIANCE_DB_USER"]
COMPLIANCE_DB_PASSWORD = os.environ["COMPLIANCE_DB_PASSWORD"]
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "http://minio:9000")
MINIO_ROOT_USER = os.environ["MINIO_ROOT_USER"]
MINIO_ROOT_PASSWORD = os.environ["MINIO_ROOT_PASSWORD"]
MINIO_AUDIT_BUCKET = os.getenv("MINIO_AUDIT_BUCKET", "mcp-audit-archive")
COMPLIANCE_SAMPLE_SIZE = int(os.getenv("COMPLIANCE_SAMPLE_SIZE", "1000"))
COMPLIANCE_ALERT_WEBHOOK = os.getenv(
    "COMPLIANCE_ALERT_WEBHOOK", "http://alertmanager:9093/api/v2/alerts"
)

# ---------------------------------------------------------------------------
# PII/credential redaction patterns (must match redaction.py exactly per INV-002)
# ---------------------------------------------------------------------------
import re

COMPLIANCE_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}", re.ASCII)),
    ("aws_secret_key", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    ("github_token", re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})")),
    ("private_key", re.compile(r"-----BEGIN\s[\w\s]+PRIVATE KEY-----", re.DOTALL)),
    ("url_password", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*")),
    ("db_connection_string", re.compile(r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@")),
    ("email_address", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("api_key", re.compile(r"(?i)(api[_\-]?key|apikey|x-api-key)\s*[=:]\s*\S+")),
]


def check_event_for_violations(event: dict[str, Any]) -> dict[str, list[str]]:
    """
    Check a single audit event for PII/credential pattern violations.
    Returns {category: [field_names_with_violations]}.
    """
    violations: dict[str, list[str]] = {}
    event_str = json.dumps(event, cls=_Encoder)

    for category, pattern in COMPLIANCE_PATTERNS:
        if pattern.search(event_str):
            violations[category] = ["(matched in event JSON)"]

    return violations


def verify_hash_integrity(event: dict[str, Any]) -> bool:
    """
    Verify the SHA-256 hash of an audit event.
    The hash is computed over the canonical fields matching AuditEvent._compute_hash().
    """
    stored_hash = event.get("sha256_hash", "")
    if not stored_hash:
        return False

    canonical = json.dumps({
        "event_id": event.get("event_id", ""),
        "event_type": event.get("event_type", ""),
        "timestamp": event.get("timestamp", ""),
        "client_id": event.get("client_id", ""),
        "tool_name": event.get("tool_name", ""),
        "tool_id": event.get("tool_id", ""),
        "outcome": event.get("outcome", ""),
        "request_id": event.get("request_id", ""),
    }, sort_keys=True)

    computed = hashlib.sha256(canonical.encode()).hexdigest()
    return computed == stored_hash


def post_alert(report_id: str, categories_failed: int, period: str) -> None:
    """Post a compliance failure alert to Alertmanager."""
    alert_payload = [
        {
            "labels": {
                "alertname": "MCPComplianceCheckFailed",
                "severity": "critical",
                "component": "compliance-checker",
                "report_id": report_id,
            },
            "annotations": {
                "summary": f"MCP compliance check failed: {categories_failed} categories",
                "description": (
                    f"Compliance check for period {period} found {categories_failed} "
                    f"failing categories. Immediate review required."
                ),
            },
        }
    ]

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                COMPLIANCE_ALERT_WEBHOOK,
                json=alert_payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.is_success:
                logger.info("Compliance failure alert posted to Alertmanager")
            else:
                logger.warning("Alertmanager returned %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.error("Failed to post compliance alert: %s", exc)


def run() -> int:
    """
    Main compliance check runner.
    Returns 0 on pass, 1 on fail.
    """
    import asyncio

    return asyncio.run(_run_async())


async def _run_async() -> int:
    """Async implementation of the compliance check pipeline."""
    import asyncpg

    run_at = datetime.now(timezone.utc)
    period_end = run_at
    period_start = run_at - timedelta(hours=24)
    report_id = str(uuid4())

    logger.info(
        "Starting compliance check",
        extra={
            "report_id": report_id,
            "sample_size": COMPLIANCE_SAMPLE_SIZE,
            "period_start": period_start.isoformat(),
            "period_end": period_end.isoformat(),
        },
    )

    dsn = (
        f"postgresql://{COMPLIANCE_DB_USER}:{COMPLIANCE_DB_PASSWORD}"
        f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )

    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("Failed to connect to database: %s", exc)
        return 1

    try:
        rows = await conn.fetch(
            """
            SELECT event_id, client_id, tool_name, tool_id, outcome,
                   sha256_hash, request_id, created_at
            FROM audit_events
            WHERE created_at >= $1 AND created_at <= $2
            ORDER BY RANDOM()
            LIMIT $3
            """,
            period_start,
            period_end,
            COMPLIANCE_SAMPLE_SIZE,
        )
    except Exception as exc:
        logger.error("Failed to query audit events: %s", exc)
        await conn.close()
        return 1

    # Stringify UUID/datetime values so json.dumps never fails on asyncpg types.
    events = [
        {k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
         for k, v in dict(row).items()}
        for row in rows
    ]
    logger.info("Sampled %d audit events for compliance check", len(events))

    # Check each category
    category_violations: dict[str, int] = {cat: 0 for cat, _ in COMPLIANCE_PATTERNS}
    hash_mismatches = 0

    for event in events:
        violations = check_event_for_violations(event)
        for category in violations:
            category_violations[category] += 1

        if not verify_hash_integrity(event):
            hash_mismatches += 1
            logger.warning("Hash integrity failure for event_id=%s", event.get("event_id"))

    categories_failed = sum(1 for count in category_violations.values() if count > 0)
    if hash_mismatches > 0:
        categories_failed += 1

    overall_status = "pass" if categories_failed == 0 else "fail"

    category_results = [
        {
            "category": cat,
            "events_checked": len(events),
            "violations_found": count,
            "status": "pass" if count == 0 else "fail",
        }
        for cat, count in category_violations.items()
    ]

    report = {
        "report_id": report_id,
        "run_at": run_at.isoformat(),
        "status": overall_status,
        "sample_size": COMPLIANCE_SAMPLE_SIZE,
        "period_start": period_start.isoformat(),
        "period_end": period_end.isoformat(),
        "categories_checked": len(COMPLIANCE_PATTERNS),
        "categories_failed": categories_failed,
        "categories": category_results,
        "hash_integrity": {
            "events_checked": len(events),
            "hash_mismatches": hash_mismatches,
            "status": "pass" if hash_mismatches == 0 else "fail",
        },
    }

    # Write compliance report to PostgreSQL
    try:
        await conn.execute(
            """
            INSERT INTO compliance_reports (
                report_id, run_at, period_start, period_end, status,
                sample_size, categories_checked, categories_failed,
                category_results, hash_integrity
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb)
            """,
            report_id,
            run_at,
            period_start,
            period_end,
            overall_status,
            COMPLIANCE_SAMPLE_SIZE,
            len(COMPLIANCE_PATTERNS),
            categories_failed,
            json.dumps(category_results, cls=_Encoder),
            json.dumps(report.get("hash_integrity", {}), cls=_Encoder),
        )
        logger.info("Compliance report written to PostgreSQL: %s (status=%s)", report_id, overall_status)
    except Exception as exc:
        logger.error("Failed to write compliance report to PostgreSQL: %s", exc)
    finally:
        await conn.close()

    # Archive to MinIO WORM bucket (INV-007)
    try:
        import boto3  # type: ignore[import]

        s3 = boto3.client(
            "s3",
            endpoint_url=MINIO_ENDPOINT,
            aws_access_key_id=MINIO_ROOT_USER,
            aws_secret_access_key=MINIO_ROOT_PASSWORD,
        )
        date_path = run_at.strftime("%Y/%m/%d")
        key = f"compliance/{date_path}/{report_id}.json"
        s3.put_object(
            Bucket=MINIO_AUDIT_BUCKET,
            Key=key,
            Body=json.dumps(report, cls=_Encoder).encode(),
            ContentType="application/json",
            ObjectLockMode="GOVERNANCE",
            ObjectLockRetainUntilDate=(run_at + timedelta(days=90)).isoformat(),
        )
        archive_url = f"s3://{MINIO_AUDIT_BUCKET}/{key}"
        report["archive_url"] = archive_url
        logger.info("Compliance report archived to MinIO WORM: %s", archive_url)
    except Exception as exc:
        logger.warning("Failed to archive compliance report to MinIO: %s", exc)

    if overall_status == "fail":
        logger.error(
            "COMPLIANCE CHECK FAILED: %d categories failed", categories_failed,
            extra={"report": report},
        )
        post_alert(report_id, categories_failed, f"{period_start.date()} to {period_end.date()}")
        return 1

    logger.info(
        "COMPLIANCE CHECK PASSED: %d events sampled, all categories passed",
        len(events),
    )
    print(json.dumps({"status": "pass", "report_id": report_id, "events_sampled": len(events)}, cls=_Encoder))  # noqa: T201
    return 0


if __name__ == "__main__":
    sys.exit(run())
