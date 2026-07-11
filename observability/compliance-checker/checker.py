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

Archival (Task 5.2 — LOG-F09):
  archive_old_audit_events() runs nightly (scheduled by entrypoint.py at 02:00 UTC
  via COMPLIANCE_CRON_SCHEDULE).  It queries audit_events rows older than 90 days,
  serializes them to JSONL, uploads to MinIO compliance-archive bucket with
  COMPLIANCE-mode object lock (or GOVERNANCE if MINIO_OBJECT_LOCK_MODE is unset),
  copies rows to audit_events_archive, then deletes from audit_events.
  An admin audit event is emitted for each archival run (INV-001).

Environment variables: see .env.example [COMPLIANCE_*] section.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac_module
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx
from datetime import date
from urllib.parse import urlparse
from uuid import UUID

# Task 0.2: import the single shared canonicalizer from the audit-logger library.
# This guarantees that the verifier uses exactly the same serialization as the writer.
# DO NOT duplicate the canonical field selection or json.dumps call here.
try:
    from mcp_audit_logger.hasher import canonical_audit_json as _canonical_audit_json
    _SHARED_CANONICALIZER_AVAILABLE = True
except ImportError:  # pragma: no cover — only missing in stripped container builds
    _SHARED_CANONICALIZER_AVAILABLE = False
    _canonical_audit_json = None  # type: ignore[assignment]


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
# Task 5.2 (LOG-F09): dedicated archival bucket for audit_events JSONL exports.
# Separate from the compliance report bucket so MinIO policies can be scoped
# independently.  Defaults to "compliance-archive" if not overridden.
MINIO_COMPLIANCE_ARCHIVE_BUCKET = os.getenv("MINIO_COMPLIANCE_ARCHIVE_BUCKET", "compliance-archive")
# Object Lock mode for archival uploads.  COMPLIANCE = true WORM (recommended for
# production — immutable even for root).  GOVERNANCE = bypass-able by privileged
# users (acceptable for this reference build; aligns with verify_object_lock_startup
# design decision documented in docs/ARCHITECTURE.md).
MINIO_OBJECT_LOCK_MODE = os.getenv("MINIO_OBJECT_LOCK_MODE", "GOVERNANCE")
# Retention period (days) for archived JSONL objects.
MINIO_RETENTION_DAYS = int(os.getenv("MINIO_RETENTION_DAYS", "90"))
# Archival cutoff: audit_events rows older than this many days are archived.
AUDIT_ARCHIVAL_CUTOFF_DAYS = int(os.getenv("AUDIT_ARCHIVAL_CUTOFF_DAYS", "90"))
COMPLIANCE_SAMPLE_SIZE = int(os.getenv("COMPLIANCE_SAMPLE_SIZE", "1000"))


def _normalize_webhook_url(raw: str, default: str) -> str:
    """
    Normalize COMPLIANCE_ALERT_WEBHOOK into a usable absolute http(s) URL.

    docker-compose.yml injects this var as `${COMPLIANCE_ALERT_WEBHOOK:-}` — when
    unset on the host, that resolves to an empty string that IS present in the
    container environment. os.getenv()'s default only applies when the key is
    absent entirely, so an empty-but-set value silently wins over `default`
    and reaches httpx as "", which raises "Request URL is missing an
    'http://' or 'https://' protocol." at alert-send time. Collapsing falsy
    values to `default` here, plus defaulting a bare host:port to http://,
    means a bad value fails loudly at import time instead.
    """
    url = raw or default
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise RuntimeError(
            f"COMPLIANCE_ALERT_WEBHOOK is not a usable http(s) URL: {raw!r} "
            "(expected e.g. http://alertmanager:9093/api/v2/alerts)"
        )
    return url


COMPLIANCE_ALERT_WEBHOOK = _normalize_webhook_url(
    os.getenv("COMPLIANCE_ALERT_WEBHOOK", ""),
    "http://alertmanager:9093/api/v2/alerts",
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


def verify_hash_integrity(event: dict[str, Any]) -> "bool | str":
    """
    Verify the SHA-256 integrity hash (and HMAC when present) of an audit event.

    Returns:
      True        — hash (and HMAC when present) verified successfully.
      False       — verification failed (hash mismatch or HMAC mismatch).
      "legacy"    — the event predates V028 (canonical columns are NULL);
                    treat as unverifiable_legacy, NOT as a mismatch.

    Task 0.2 fixes four canonicalization breaks:
      Break 1 — now delegates to mcp_audit_logger.hasher.canonical_audit_json()
                (shared canonicalizer, same separators, same field set).
      Break 2 — event_type and timestamp are required canonical inputs; rows
                where they are NULL are treated as legacy (see below).
      Break 3 — platform_version is included in the canonical form via the
                shared canonicalizer.
      Break 4 — original_outcome (pre-remap) is used for hash recomputation;
                canonical_audit_json() reads "original_outcome" preferentially
                over "outcome" so error-outcome rows verify correctly.

    Historical-row cutoff (Step 4, extended by appsec 0.2-F1):
      Rows written before V028 lack the canonical columns (event_type,
      timestamp, platform_version, original_outcome are NULL/absent).  These
      cannot be verified and are returned as "legacy".

      appsec 0.2-F1 adds event_ts_iso (V030).  Rows written between V028 and
      V030 (the migration window) have event_ts_iso IS NULL but the other V028
      columns present.  Because the timestamp byte string is required for hash
      recomputation, these rows are also unverifiable and must be treated as
      "legacy", not as mismatches.

      Detection rule: a row is "legacy" when ANY of the four required canonical
      inputs is NULL — event_type, timestamp (event_ts_iso), platform_version,
      or original_outcome.
    """
    # ------------------------------------------------------------------
    # Legacy-row detection (Step 4, extended by appsec 0.2-F1)
    # Pre-V028 rows: all four canonical columns are NULL.
    # V028–V030 window rows: event_ts_iso (aliased as "timestamp") is NULL
    # while the other three columns are present.  Both cases are treated as
    # unverifiable_legacy because the timestamp byte string is required to
    # recompute the hash.
    # ------------------------------------------------------------------
    _legacy_sentinel = None  # NULL from asyncpg or missing key
    event_type_val = event.get("event_type", _legacy_sentinel)
    timestamp_val = event.get("timestamp", _legacy_sentinel)
    platform_version_val = event.get("platform_version", _legacy_sentinel)
    original_outcome_val = event.get("original_outcome", _legacy_sentinel)

    if all(v is None for v in (event_type_val, timestamp_val,
                               platform_version_val, original_outcome_val)):
        # All four canonical columns absent/NULL → pre-V028 row.
        return "legacy"

    if timestamp_val is None:
        # event_ts_iso column is NULL → row written in the V028–V030 migration
        # window.  Cannot recompute hash without the verbatim timestamp string.
        return "legacy"

    stored_hash = event.get("sha256_hash", "")
    if not stored_hash:
        return False

    # ------------------------------------------------------------------
    # Recompute the canonical hash using the SHARED canonicalizer.
    # ------------------------------------------------------------------
    if not _SHARED_CANONICALIZER_AVAILABLE or _canonical_audit_json is None:
        # Fallback: should never happen in a correctly deployed container.
        # Treat as unverifiable rather than silently passing.
        logger.error(
            "mcp_audit_logger not importable — cannot verify hash integrity. "
            "Check that the shared library is installed in this container."
        )
        return False

    canonical = _canonical_audit_json(event)
    computed_plain = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # HMAC verification (Step 3) — primary tamper-evidence check.
    # If hmac_signature is present, verify it; plain hash is secondary.
    # ------------------------------------------------------------------
    hmac_sig = event.get("hmac_signature")
    if hmac_sig:
        hmac_key_id = event.get("hmac_key_id", "default")
        hmac_key = _get_hmac_key(hmac_key_id)
        if hmac_key is None:
            logger.warning(
                "HMAC key '%s' not found — cannot verify HMAC signature for event_id=%s",
                hmac_key_id,
                event.get("event_id"),
            )
            # Fall back to plain hash check only
            return _hmac_module.compare_digest(computed_plain, stored_hash)

        expected_hmac = _hmac_module.new(
            hmac_key.encode(), canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not _hmac_module.compare_digest(expected_hmac, hmac_sig):
            return False  # HMAC mismatch — tampered

    # ------------------------------------------------------------------
    # Plain SHA-256 check (transcription integrity).
    # ------------------------------------------------------------------
    return _hmac_module.compare_digest(computed_plain, stored_hash)


def _get_hmac_key(key_id: str) -> str | None:
    """
    Return the HMAC key for the given key_id.

    Key rotation design: keys are stored as environment variables named
    AUDIT_LOG_HMAC_KEY (for key_id="default") or
    AUDIT_LOG_HMAC_KEY__<KEY_ID> for named versions.

    Retired keys remain available read-only so historical rows can still
    be verified.  The verifier selects the key by the stored hmac_key_id.
    """
    if key_id == "default" or not key_id:
        return os.environ.get("AUDIT_LOG_HMAC_KEY")
    # Named key: AUDIT_LOG_HMAC_KEY__v2, AUDIT_LOG_HMAC_KEY__v3, etc.
    env_var = f"AUDIT_LOG_HMAC_KEY__{key_id.upper()}"
    return os.environ.get(env_var)


def verify_object_lock_startup(s3_client: Any, bucket: str) -> dict[str, Any]:
    """
    Verify that the MinIO/S3 audit bucket has Object Lock enabled (INV-007).

    Called once at the start of each compliance run to confirm the WORM
    configuration is intact before writing reports.

    Design decision: GOVERNANCE mode is the chosen mode for this reference
    implementation. It is NOT MFA-enforced WORM — a privileged key can bypass
    it. Only COMPLIANCE mode (which locks out even the root key without a
    notary or MFA unlock) would be true WORM. COMPLIANCE mode is the correct
    choice for a production deployment; GOVERNANCE is accepted here because
    this is a learning/reference build and COMPLIANCE mode creates irreversible
    object locks that complicate lab teardown.

    Returns a dict with:
      - enabled (bool): True if ObjectLockEnabled == "Enabled"
      - mode (str|None): "GOVERNANCE", "COMPLIANCE", or None if no default retention
      - retention_days (int|None): default retention configured
      - error (str|None): set if boto3 raised an exception
    """
    try:
        resp = s3_client.get_bucket_object_lock_configuration(Bucket=bucket)
        config = resp.get("ObjectLockConfiguration", {})
        enabled = config.get("ObjectLockEnabled") == "Enabled"
        rule = config.get("Rule", {}).get("DefaultRetention", {})
        mode = rule.get("Mode")
        days = rule.get("Days")
        if enabled:
            logger.info(
                "INV-007 Object Lock: ENABLED on bucket %s (mode=%s, days=%s)",
                bucket, mode, days,
            )
        else:
            logger.warning(
                "INV-007 Object Lock: DISABLED on bucket %s — "
                "compliance reports are NOT WORM-protected",
                bucket,
            )
        return {"enabled": enabled, "mode": mode, "retention_days": days, "error": None}
    except Exception as exc:
        logger.warning(
            "INV-007 Object Lock: could not verify bucket %s: %s — "
            "proceeding; check MinIO admin credentials and bucket configuration",
            bucket, exc,
        )
        return {"enabled": False, "mode": None, "retention_days": None, "error": str(exc)}


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


async def archive_old_audit_events(
    conn: Any | None = None,
    s3_client: Any | None = None,
) -> dict[str, Any]:
    """
    Task 5.2 (LOG-F09): Nightly batch archival of audit_events to MinIO.

    Pipeline:
      1. Query audit_events rows older than AUDIT_ARCHIVAL_CUTOFF_DAYS (default 90).
      2. Serialize to JSONL (one JSON object per line, newline-delimited).
      3. Upload JSONL to MinIO compliance-archive bucket with Object Lock
         (COMPLIANCE mode if MINIO_OBJECT_LOCK_MODE=COMPLIANCE, else GOVERNANCE).
      4. Copy rows into audit_events_archive (idempotent: ON CONFLICT DO NOTHING).
      5. Delete archived rows from audit_events (shrinks hot table).
      6. Emit an admin audit log event (INV-001: archival run must be audited).

    Args:
        conn: Optional asyncpg connection for testing. Created internally when None.
        s3_client: Optional boto3 S3 client for testing. Created internally when None.

    Returns:
        dict with keys: rows_archived, object_key, archive_url, started_at, finished_at,
                        status ("ok" | "error"), error (str | None).

    Design notes:
      - Idempotent: rows copied with ON CONFLICT DO NOTHING on the archive PK
        (event_id), so a retry after a partial failure is safe.
      - Delete is deferred until AFTER the MinIO upload succeeds — if MinIO is
        unreachable, rows stay in audit_events and the next run retries.
      - INV-011: the compliance_checker DB user does NOT have DELETE on audit_events.
        This function uses the COMPLIANCE_DB_USER credentials which have archival
        privilege (granted in V036 for the archival role).
        TODO: confirm with architect — current V001 grants compliance_checker SELECT
        only.  Until a dedicated archival DB role exists, archive copy-only (no DELETE)
        mode is the safe default.  Set ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1 to enable
        delete (requires DBA-granted DELETE privilege for the compliance_checker user).
      - INV-001: emits a structured admin audit event for the archival run.
        The event is a JSON log line written to stdout (picked up by Promtail
        mcp-compliance job); no DB INSERT is made from the compliance checker
        (compliance_checker user has no INSERT on audit_events per INV-011).
    """
    import asyncpg  # type: ignore[import]

    started_at = datetime.now(timezone.utc)
    cutoff = started_at - timedelta(days=AUDIT_ARCHIVAL_CUTOFF_DAYS)
    run_id = str(uuid4())

    logger.info(
        "archive_old_audit_events: starting archival run",
        extra={
            "run_id": run_id,
            "cutoff": cutoff.isoformat(),
            "cutoff_days": AUDIT_ARCHIVAL_CUTOFF_DAYS,
        },
    )

    _owns_conn = conn is None
    _owns_s3 = s3_client is None
    result: dict[str, Any] = {
        "run_id": run_id,
        "rows_archived": 0,
        "object_key": None,
        "archive_url": None,
        "started_at": started_at.isoformat(),
        "finished_at": None,
        "status": "error",
        "error": None,
    }

    try:
        if _owns_conn:
            dsn = (
                f"postgresql://{COMPLIANCE_DB_USER}:{COMPLIANCE_DB_PASSWORD}"
                f"@{DB_HOST}:{DB_PORT}/{DB_NAME}"
            )
            conn = await asyncpg.connect(dsn)

        if _owns_s3:
            import boto3  # type: ignore[import]
            s3_client = boto3.client(
                "s3",
                endpoint_url=MINIO_ENDPOINT,
                aws_access_key_id=MINIO_ROOT_USER,
                aws_secret_access_key=MINIO_ROOT_PASSWORD,
            )

        # -----------------------------------------------------------------------
        # Step 1: Query rows older than cutoff
        # -----------------------------------------------------------------------
        # audit_events_archive has a different schema from V029+ audit_events
        # (missing the newer columns).  We SELECT only the columns that exist in
        # both tables so the INSERT … SELECT is safe across schema versions.
        # Columns added after V001 (event_type, platform_version, etc.) are
        # NOT in audit_events_archive — they go into the JSONL object only.
        rows = await conn.fetch(
            """
            SELECT
                event_id, event_ts, client_id, tool_name, tool_id,
                outcome, latency_ms, bytes_in, bytes_out,
                sha256_hash, anomaly_score, opa_reasons, request_id,
                source_ip, created_at
            FROM audit_events
            WHERE event_ts < $1
            ORDER BY event_ts ASC
            """,
            cutoff,
        )

        if not rows:
            logger.info(
                "archive_old_audit_events: no rows older than cutoff — nothing to archive",
                extra={"run_id": run_id, "cutoff": cutoff.isoformat()},
            )
            result.update({"rows_archived": 0, "status": "ok"})
            _emit_archival_audit_event(run_id, rows_archived=0, archive_url=None, status="ok")
            return result

        logger.info(
            "archive_old_audit_events: %d rows to archive",
            len(rows),
            extra={"run_id": run_id},
        )

        # -----------------------------------------------------------------------
        # Step 2: Serialize to JSONL
        # -----------------------------------------------------------------------
        jsonl_lines: list[str] = []
        for row in rows:
            row_dict = {
                k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
                for k, v in dict(row).items()
            }
            jsonl_lines.append(json.dumps(row_dict, cls=_Encoder))
        jsonl_body = "\n".join(jsonl_lines).encode("utf-8")

        # -----------------------------------------------------------------------
        # Step 3: Upload JSONL to MinIO with Object Lock
        # -----------------------------------------------------------------------
        date_path = started_at.strftime("%Y/%m/%d")
        object_key = f"audit-events/{date_path}/{run_id}.jsonl"
        retain_until = (started_at + timedelta(days=MINIO_RETENTION_DAYS)).isoformat()

        # Validate mode — only COMPLIANCE and GOVERNANCE are valid S3/MinIO values.
        lock_mode = MINIO_OBJECT_LOCK_MODE.upper()
        if lock_mode not in ("COMPLIANCE", "GOVERNANCE"):
            logger.warning(
                "archive_old_audit_events: invalid MINIO_OBJECT_LOCK_MODE '%s', "
                "falling back to GOVERNANCE",
                lock_mode,
            )
            lock_mode = "GOVERNANCE"

        s3_client.put_object(
            Bucket=MINIO_COMPLIANCE_ARCHIVE_BUCKET,
            Key=object_key,
            Body=jsonl_body,
            ContentType="application/x-ndjson",
            ObjectLockMode=lock_mode,
            ObjectLockRetainUntilDate=retain_until,
        )
        archive_url = f"s3://{MINIO_COMPLIANCE_ARCHIVE_BUCKET}/{object_key}"
        logger.info(
            "archive_old_audit_events: uploaded %d rows to %s",
            len(rows),
            archive_url,
            extra={"run_id": run_id, "lock_mode": lock_mode},
        )

        # -----------------------------------------------------------------------
        # Step 4: Copy rows into audit_events_archive (idempotent)
        # -----------------------------------------------------------------------
        # audit_events_archive has the same base schema as V001 audit_events.
        # ON CONFLICT DO NOTHING ensures retries after partial failure are safe.
        archived_count = 0
        for row in rows:
            try:
                await conn.execute(
                    """
                    INSERT INTO audit_events_archive (
                        event_id, event_ts, client_id, tool_name, tool_id,
                        outcome, latency_ms, bytes_in, bytes_out,
                        sha256_hash, anomaly_score, opa_reasons, request_id,
                        source_ip, created_at
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
                    ) ON CONFLICT (event_id) DO NOTHING
                    """,
                    row["event_id"], row["event_ts"], row["client_id"],
                    row["tool_name"], row["tool_id"], row["outcome"],
                    row["latency_ms"], row["bytes_in"], row["bytes_out"],
                    row["sha256_hash"], row["anomaly_score"], row["opa_reasons"],
                    row["request_id"], row["source_ip"], row["created_at"],
                )
                archived_count += 1
            except Exception as row_exc:
                logger.error(
                    "archive_old_audit_events: failed to archive row event_id=%s: %s",
                    row["event_id"], row_exc,
                    extra={"run_id": run_id},
                )

        logger.info(
            "archive_old_audit_events: %d/%d rows copied to audit_events_archive",
            archived_count, len(rows),
            extra={"run_id": run_id},
        )

        # -----------------------------------------------------------------------
        # Step 5: Delete from audit_events (only if enabled AND all rows archived)
        # -----------------------------------------------------------------------
        # TODO: confirm with architect — compliance_checker needs DELETE privilege
        # on audit_events.  Set ENABLE_AUDIT_DELETE_AFTER_ARCHIVE=1 once granted.
        enable_delete = os.getenv("ENABLE_AUDIT_DELETE_AFTER_ARCHIVE", "0") == "1"
        if enable_delete and archived_count == len(rows):
            event_ids = [row["event_id"] for row in rows]
            # Batch delete in chunks to avoid exceeding parameter limits
            _CHUNK = 500
            deleted_total = 0
            for i in range(0, len(event_ids), _CHUNK):
                chunk = event_ids[i : i + _CHUNK]
                deleted = await conn.execute(
                    "DELETE FROM audit_events WHERE event_id = ANY($1::uuid[])",
                    chunk,
                )
                # asyncpg returns "DELETE <n>" as a string
                deleted_total += int(deleted.split()[-1]) if deleted else 0
            logger.info(
                "archive_old_audit_events: deleted %d rows from audit_events",
                deleted_total,
                extra={"run_id": run_id},
            )
        elif enable_delete:
            logger.warning(
                "archive_old_audit_events: NOT deleting from audit_events — "
                "only %d/%d rows were archived (partial failure)",
                archived_count, len(rows),
                extra={"run_id": run_id},
            )

        result.update({
            "rows_archived": archived_count,
            "object_key": object_key,
            "archive_url": archive_url,
            "status": "ok",
        })

    except Exception as exc:
        logger.error(
            "archive_old_audit_events: archival run failed: %s",
            exc,
            extra={"run_id": run_id},
        )
        result["error"] = str(exc)
        result["status"] = "error"

    finally:
        finished_at = datetime.now(timezone.utc)
        result["finished_at"] = finished_at.isoformat()
        if _owns_conn and conn is not None:
            try:
                await conn.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Step 6: Emit admin audit event (INV-001)
    # The compliance checker cannot INSERT into audit_events (INV-011: SELECT
    # only).  We emit to stdout as a structured JSON log line — Promtail's
    # mcp-compliance job picks it up and ships it to Loki.
    # -----------------------------------------------------------------------
    _emit_archival_audit_event(
        run_id=run_id,
        rows_archived=result["rows_archived"],
        archive_url=result.get("archive_url"),
        status=result["status"],
    )

    return result


def _emit_archival_audit_event(
    run_id: str,
    rows_archived: int,
    archive_url: str | None,
    status: str,
) -> None:
    """
    Emit a structured admin audit event for an archival run (INV-001).

    Written to stdout as JSON so Promtail (mcp-compliance job) picks it up.
    The compliance checker has no INSERT privilege on audit_events (INV-011),
    so stdout is the correct channel for compliance-checker-emitted events.
    """
    event = {
        "event_type": "AUDIT_ARCHIVAL_RUN",
        "level": "info" if status == "ok" else "error",
        "run_id": run_id,
        "rows_archived": rows_archived,
        "archive_url": archive_url,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "component": "compliance-checker",
        "control": "LOG-F09",
        "check_result": status,
        "category": "archival",
    }
    print(json.dumps(event, cls=_Encoder))  # noqa: T201
    logger.info(
        "Archival audit event emitted (INV-001)",
        extra={"run_id": run_id, "status": status, "rows_archived": rows_archived},
    )


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

    # INV-007: Verify Object Lock before writing any reports.
    import boto3  # type: ignore[import]
    s3 = boto3.client(
        "s3",
        endpoint_url=MINIO_ENDPOINT,
        aws_access_key_id=MINIO_ROOT_USER,
        aws_secret_access_key=MINIO_ROOT_PASSWORD,
    )
    object_lock_status = verify_object_lock_startup(s3, MINIO_AUDIT_BUCKET)

    try:
        conn = await asyncpg.connect(dsn)
    except Exception as exc:
        logger.error("Failed to connect to database: %s", exc)
        return 1

    try:
        rows = await conn.fetch(
            """
            SELECT event_id, client_id, tool_name, tool_id, outcome,
                   sha256_hash, request_id, created_at,
                   event_type,
                   event_ts_iso AS timestamp,
                   platform_version, original_outcome,
                   hmac_signature, hmac_key_id
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
    unverifiable_legacy = 0

    for event in events:
        violations = check_event_for_violations(event)
        for category in violations:
            category_violations[category] += 1

        integrity_result = verify_hash_integrity(event)
        if integrity_result == "legacy":
            unverifiable_legacy += 1
            logger.debug(
                "Skipping legacy row (pre-V028): event_id=%s", event.get("event_id")
            )
        elif integrity_result is not True:
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
            "unverifiable_legacy": unverifiable_legacy,
            "status": "pass" if hash_mismatches == 0 else "fail",
        },
        "object_lock": object_lock_status,
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

    # Archive to MinIO WORM bucket (INV-007) — reuse the s3 client from startup.
    try:
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
