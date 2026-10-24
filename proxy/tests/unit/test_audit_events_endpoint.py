"""Unit tests for GET /api/v1/audit/events (F-CX-005).

Covers two bugs found by the 2026-07-26 live audit's "audit querying
returned 500":
  1. `anomaly_score` used `if row.anomaly_score else None`, which silently
     turned a genuine 0.0 score into null (0.0 is falsy in Python).
  2. Row serialization ran unguarded after the query's try/except, so any
     unexpected row shape (bad `notices` value, etc.) leaked an unhandled
     500 instead of the documented {code, message} error envelope.
"""
from __future__ import annotations

import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.routers.audit import list_audit_events


def _row(**overrides) -> SimpleNamespace:
    defaults = dict(
        event_id="11111111-1111-1111-1111-111111111111",
        created_at=datetime.datetime(2026, 7, 26, tzinfo=datetime.timezone.utc),
        client_id="alice@corp",
        tool_name="echo",
        tool_id=None,
        outcome="allow",
        latency_ms=12,
        sha256_hash="deadbeef",
        anomaly_score=0.0,
        notices=[],
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _fake_request(roles: list) -> MagicMock:
    req = MagicMock()
    req.state = MagicMock()
    req.state.client_roles = roles
    req.state.client_id = "alice@corp"
    return req


class _FakeCountResult:
    def __init__(self, count: int) -> None:
        self._count = count

    def scalar(self):
        return self._count


class _FakeRowsResult:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def fetchall(self):
        return self._rows


def _fake_db(rows: list) -> AsyncMock:
    db = AsyncMock()
    db.execute = AsyncMock(side_effect=[_FakeCountResult(len(rows)), _FakeRowsResult(rows)])
    return db


@pytest.mark.asyncio
async def test_zero_anomaly_score_is_not_nulled():
    db = _fake_db([_row(anomaly_score=0.0)])
    resp = await list_audit_events(_fake_request(["admin"]), page=1, page_size=50, db=db)
    body = resp.body.decode()
    assert '"anomaly_score":0.0' in body or '"anomaly_score": 0.0' in body


@pytest.mark.asyncio
async def test_none_anomaly_score_stays_null():
    db = _fake_db([_row(anomaly_score=None)])
    resp = await list_audit_events(_fake_request(["admin"]), page=1, page_size=50, db=db)
    body = resp.body.decode()
    assert '"anomaly_score":null' in body or '"anomaly_score": null' in body


@pytest.mark.asyncio
async def test_malformed_row_returns_clean_500_not_raw_exception():
    """A row shape that breaks serialization (e.g. created_at is None,
    matching a legacy/corrupt row) must surface the documented error
    envelope, not an unhandled 500 from an uncaught exception."""
    from fastapi import HTTPException

    db = _fake_db([_row(created_at=None)])  # .isoformat() on None raises AttributeError
    with pytest.raises(HTTPException) as exc_info:
        await list_audit_events(_fake_request(["admin"]), page=1, page_size=50, db=db)
    assert exc_info.value.status_code == 500
    assert exc_info.value.detail["code"] == "INTERNAL_ERROR"
