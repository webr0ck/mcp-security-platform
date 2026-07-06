"""
Unit tests — scanner-worker retry / dead-letter logic (CR-14 / WP-B1).

A job that fails repeatedly must land in dead_letter (visible, queryable)
rather than being silently dropped or retried forever. Uses a fake asyncpg
pool that just records the SQL/params it was called with — no real DB
needed.

Run (from repo root): python -m pytest scanner_worker/tests -v
"""
from __future__ import annotations

import asyncio

from scanner_worker import worker


class _FakePool:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return "OK"


def test_first_failure_requeues_not_dead_letters():
    pool = _FakePool()
    asyncio.run(worker._mark_failed_or_dead_letter(pool, "job-1", attempts=0, max_attempts=3, error="boom"))
    sql, args = pool.calls[-1]
    job_id, status, new_attempts, err = args
    assert status == "queued"
    assert new_attempts == 1


def test_nth_failure_dead_letters():
    pool = _FakePool()
    asyncio.run(worker._mark_failed_or_dead_letter(pool, "job-1", attempts=2, max_attempts=3, error="boom again"))
    sql, args = pool.calls[-1]
    job_id, status, new_attempts, err = args
    assert status == "dead_letter"
    assert new_attempts == 3


def test_dead_letter_error_is_recorded_not_dropped():
    """The failure reason must survive into last_error — visible, not silent."""
    pool = _FakePool()
    long_error = "x" * 5000  # oversized error must be truncated, not lost entirely
    asyncio.run(worker._mark_failed_or_dead_letter(pool, "job-1", attempts=2, max_attempts=3, error=long_error))
    sql, args = pool.calls[-1]
    _job_id, _status, _attempts, err = args
    assert err  # not empty
    assert len(err) <= 4000


def test_claim_query_uses_skip_locked_for_safe_concurrent_workers():
    """Multiple worker replicas must not double-claim the same job."""
    import inspect
    src = inspect.getsource(worker._claim_job)
    assert "FOR UPDATE SKIP LOCKED" in src
