"""
Unit tests — Prometheus metrics (CR-17 / WP-D1).

Covers app.services.metrics: record_*() helpers update the right
counter/gauge series, and refresh_db_gauges() never raises even when the DB
call fails (a /metrics scrape must never itself 500 the endpoint — Prometheus
would then lose ALL series, not just the DB-backed ones).
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import metrics


def _counter_value(counter, **labels):
    child = counter.labels(**labels) if labels else counter
    return child._value.get()


def _gauge_value(gauge, **labels):
    child = gauge.labels(**labels) if labels else gauge
    return child._value.get()


def test_record_authz_decision_increments_correct_label():
    before_allow = _counter_value(metrics.authz_decisions_total, decision="allow")
    before_deny = _counter_value(metrics.authz_decisions_total, decision="deny")

    metrics.record_authz_decision(True)
    metrics.record_authz_decision(False)

    assert _counter_value(metrics.authz_decisions_total, decision="allow") == before_allow + 1
    assert _counter_value(metrics.authz_decisions_total, decision="deny") == before_deny + 1


def test_record_opa_reachable_sets_gauge():
    metrics.record_opa_reachable(True)
    assert _gauge_value(metrics.opa_up) == 1
    metrics.record_opa_reachable(False)
    assert _gauge_value(metrics.opa_up) == 0


def test_record_vault_reachable_sets_gauge():
    metrics.record_vault_reachable(True)
    assert _gauge_value(metrics.vault_up) == 1
    metrics.record_vault_reachable(False)
    assert _gauge_value(metrics.vault_up) == 0


def test_record_audit_emit_failure_increments():
    before = _counter_value(metrics.audit_emit_failures_total)
    metrics.record_audit_emit_failure()
    assert _counter_value(metrics.audit_emit_failures_total) == before + 1


def test_record_credential_broker_failure_increments_by_error_type():
    before = _counter_value(metrics.credential_broker_failures_total, error_type="enrollment_required")
    metrics.record_credential_broker_failure("enrollment_required")
    assert _counter_value(metrics.credential_broker_failures_total, error_type="enrollment_required") == before + 1


@pytest.mark.asyncio
async def test_refresh_db_gauges_sets_scan_queue_and_quarantine_and_stale():
    fake_depth = {"queued": 2, "running": 1, "completed": 5, "failed": 0, "dead_letter": 3}

    class _FakeSession:
        def __init__(self):
            self.calls = 0

        async def execute(self, stmt, params=None):
            self.calls += 1
            result = MagicMock()
            # first call = quarantine count, second = stale count
            result.scalar.return_value = 7 if self.calls == 1 else 2
            return result

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    with patch("app.services.scan_queue.queue_depth", new=AsyncMock(return_value=fake_depth)), \
         patch("app.core.database.AsyncSessionLocal", return_value=_FakeSession()):
        await metrics.refresh_db_gauges()

    for status, n in fake_depth.items():
        assert _gauge_value(metrics.scan_queue_depth, status=status) == n
    assert _gauge_value(metrics.quarantine_backlog) == 7
    assert _gauge_value(metrics.stale_scan_count) == 2


@pytest.mark.asyncio
async def test_refresh_db_gauges_never_raises_on_db_error():
    with patch("app.services.scan_queue.queue_depth", new=AsyncMock(side_effect=RuntimeError("db down"))):
        await metrics.refresh_db_gauges()  # must not raise
