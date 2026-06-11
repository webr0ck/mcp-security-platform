"""
Task 5.2 (LOG-F09) — Unit tests for archive_old_audit_events()

Verifies:
  1. Rows older than the cutoff are fetched, serialized to JSONL, and uploaded
     to MinIO with Object Lock.
  2. Rows are copied into audit_events_archive after successful upload.
  3. An admin audit event is emitted (INV-001) for each archival run — written
     to stdout as a structured JSON line for Promtail pickup.
  4. When no rows are eligible for archival, the function exits cleanly (no
     upload, no DB writes) and still emits an audit event.
  5. MinIO failure does NOT delete rows from audit_events (data safety invariant).

Run: pytest observability/compliance-checker/tests/test_audit_archival.py -v
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, call
from uuid import uuid4

import pytest

# Stub required env vars before importing checker (reads them at module level).
_ENV_STUBS = {
    "DB_HOST": "localhost",
    "DB_PORT": "5432",
    "DB_NAME": "test",
    "COMPLIANCE_DB_USER": "test",
    "COMPLIANCE_DB_PASSWORD": "test",
    "MINIO_ROOT_USER": "minioadmin",
    "MINIO_ROOT_PASSWORD": "minioadmin",
}
for _k, _v in _ENV_STUBS.items():
    os.environ.setdefault(_k, _v)

_CHECKER_DIR = Path(__file__).resolve().parents[1]
if str(_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(_CHECKER_DIR))

import checker  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_row(event_id: str | None = None, days_old: int = 100) -> dict:
    """Build a mock asyncpg Row-like dict representing an audit_events record."""
    ts = datetime.now(timezone.utc) - timedelta(days=days_old)
    return {
        "event_id": event_id or str(uuid4()),
        "event_ts": ts,
        "client_id": "test-agent-001",
        "tool_name": "read_file",
        "tool_id": None,
        "outcome": "allow",
        "latency_ms": 42,
        "bytes_in": 100,
        "bytes_out": 200,
        "sha256_hash": "a" * 64,
        "anomaly_score": 0.0,
        "opa_reasons": "[]",
        "request_id": "req-" + str(uuid4()),
        "source_ip": "10.0.0.1",
        "created_at": ts,
    }


class _MockRow(dict):
    """asyncpg returns records that support both attribute and item access."""
    def __getattr__(self, name: str):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)


def _rows(*args: dict) -> list[_MockRow]:
    return [_MockRow(r) for r in args]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_archive_rows_uploaded_to_minio():
    """
    When rows older than cutoff exist, archive_old_audit_events must upload
    a JSONL object to the MinIO compliance-archive bucket with Object Lock.
    """
    row = _make_row(days_old=100)
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(row))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()

    result = await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    assert result["status"] == "ok", f"Expected ok, got: {result}"
    assert result["rows_archived"] == 1

    # MinIO put_object must have been called exactly once
    mock_s3.put_object.assert_called_once()
    call_kwargs = mock_s3.put_object.call_args.kwargs
    assert call_kwargs["Bucket"] == checker.MINIO_COMPLIANCE_ARCHIVE_BUCKET
    assert call_kwargs["ContentType"] == "application/x-ndjson"
    assert "ObjectLockMode" in call_kwargs
    assert "ObjectLockRetainUntilDate" in call_kwargs

    # Uploaded body must be valid JSONL
    body = call_kwargs["Body"]
    lines = body.decode("utf-8").strip().split("\n")
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["event_id"] == row["event_id"]


@pytest.mark.asyncio
async def test_archive_rows_copied_to_archive_table():
    """
    After successful MinIO upload, rows must be INSERTed into
    audit_events_archive (ON CONFLICT DO NOTHING for idempotency).
    """
    row1 = _make_row(days_old=100)
    row2 = _make_row(days_old=200)
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(row1, row2))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()

    result = await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    assert result["rows_archived"] == 2
    # execute must have been called twice (once per row — archive INSERT)
    assert mock_conn.execute.call_count == 2
    insert_sql = mock_conn.execute.call_args_list[0].args[0]
    assert "audit_events_archive" in insert_sql
    assert "ON CONFLICT" in insert_sql


@pytest.mark.asyncio
async def test_archive_emits_admin_audit_event(capsys):
    """
    INV-001: archive_old_audit_events must emit a structured JSON admin audit
    event to stdout for Promtail pickup, regardless of rows_archived count.
    """
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(_make_row()))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()

    await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    captured = capsys.readouterr()
    # stdout must contain at least one line of JSON
    stdout_lines = [ln for ln in captured.out.strip().split("\n") if ln.strip()]
    assert stdout_lines, "INV-001: no audit event emitted to stdout"

    event = json.loads(stdout_lines[0])
    assert event["event_type"] == "AUDIT_ARCHIVAL_RUN", (
        "Audit event must have event_type=AUDIT_ARCHIVAL_RUN so Promtail can "
        "label it correctly."
    )
    assert event["status"] == "ok"
    assert "run_id" in event
    assert "rows_archived" in event
    assert event["component"] == "compliance-checker"
    assert event["control"] == "LOG-F09"


@pytest.mark.asyncio
async def test_archive_no_eligible_rows_emits_audit_event(capsys):
    """
    When no rows are eligible (all events are recent), archive_old_audit_events
    must still emit an admin audit event (INV-001) and return status=ok.
    """
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])  # no eligible rows

    mock_s3 = MagicMock()

    result = await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    assert result["status"] == "ok"
    assert result["rows_archived"] == 0
    assert result["archive_url"] is None

    # MinIO must NOT be called when there are no rows to archive
    mock_s3.put_object.assert_not_called()

    # Audit event must still be emitted
    captured = capsys.readouterr()
    stdout_lines = [ln for ln in captured.out.strip().split("\n") if ln.strip()]
    assert stdout_lines, "INV-001: audit event must be emitted even for zero-row runs"
    event = json.loads(stdout_lines[0])
    assert event["event_type"] == "AUDIT_ARCHIVAL_RUN"
    assert event["rows_archived"] == 0


@pytest.mark.asyncio
async def test_archive_minio_failure_does_not_delete_rows():
    """
    Data safety invariant: if MinIO upload fails, rows must NOT be deleted
    from audit_events.  The function must return status=error.
    """
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(_make_row()))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock(side_effect=Exception("MinIO unreachable"))

    # Enable delete mode (to test that it is skipped on failure)
    with patch.dict(os.environ, {"ENABLE_AUDIT_DELETE_AFTER_ARCHIVE": "1"}):
        result = await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    assert result["status"] == "error", "MinIO failure must result in status=error"
    # execute (DELETE) must NOT have been called
    delete_calls = [
        c for c in mock_conn.execute.call_args_list
        if "DELETE" in str(c)
    ]
    assert not delete_calls, (
        "DELETE from audit_events must NOT be called when MinIO upload failed. "
        "Rows must remain in audit_events for the next archival run to retry."
    )


@pytest.mark.asyncio
async def test_archive_object_lock_mode_compliance(capsys):
    """
    When MINIO_OBJECT_LOCK_MODE=COMPLIANCE, archive_old_audit_events must pass
    ObjectLockMode='COMPLIANCE' to MinIO — not 'GOVERNANCE'.
    """
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(_make_row()))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()

    with patch.dict(os.environ, {"MINIO_OBJECT_LOCK_MODE": "COMPLIANCE"}):
        # Force module to re-read env var
        original_mode = checker.MINIO_OBJECT_LOCK_MODE
        checker.MINIO_OBJECT_LOCK_MODE = "COMPLIANCE"
        try:
            await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)
        finally:
            checker.MINIO_OBJECT_LOCK_MODE = original_mode

    call_kwargs = mock_s3.put_object.call_args.kwargs
    assert call_kwargs["ObjectLockMode"] == "COMPLIANCE", (
        "When MINIO_OBJECT_LOCK_MODE=COMPLIANCE, the upload must use COMPLIANCE "
        "mode for true WORM protection."
    )


@pytest.mark.asyncio
async def test_archive_jsonl_format_is_valid():
    """
    JSONL output must be one valid JSON object per line, newline-delimited.
    Each line must preserve event_id for correlation.
    """
    rows = [_make_row(days_old=100 + i) for i in range(3)]
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=_rows(*rows))
    mock_conn.execute = AsyncMock(return_value="INSERT 1")

    mock_s3 = MagicMock()
    mock_s3.put_object = MagicMock()

    await checker.archive_old_audit_events(conn=mock_conn, s3_client=mock_s3)

    body_bytes = mock_s3.put_object.call_args.kwargs["Body"]
    lines = body_bytes.decode("utf-8").strip().split("\n")
    assert len(lines) == 3

    for i, line in enumerate(lines):
        parsed = json.loads(line)  # must not raise
        assert parsed["event_id"] == rows[i]["event_id"]
