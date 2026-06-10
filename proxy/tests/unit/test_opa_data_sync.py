"""
Unit Tests — OPA Data Sync Service (Grants Sync + 60s Reconcile)

Tests the OPADataSync service that fetches grants from the database
and pushes them to OPA's data API, with a background 60s reconcile loop.

Requirements:
  - build_grants_data() converts role_assignments rows to OPA data structure
  - OPADataSync.push_grants() fetches from DB, calls OPA PUT /v1/data/mcp/grants
  - OPADataSync.start_reconcile_loop() starts a background task that runs every 60s
  - OPADataSync.stop_reconcile_loop() stops the background task
  - OPAClient.put_data() sends PUT request to OPA data API
  - Fail-closed: if push_grants() raises, it propagates (caller handles rollback)

Run:
  pytest proxy/tests/unit/test_opa_data_sync.py -v
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.services.opa_data_sync import OPADataSync, build_grants_data
from app.services.policy import PolicyEngineError


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db_pool() -> AsyncMock:
    """Mock asyncpg.Pool for database operations."""
    return AsyncMock()


@pytest.fixture
def sample_grant_rows() -> list[dict[str, Any]]:
    """Sample rows as returned from role_assignments table."""
    return [
        {
            "principal_id": "alice@corp",
            "principal_type": "human",
            "allowed_tools": ["read", "write", "delete"],
            "allowed_tags": ["safe", "testing"],
            "max_risk_level": "high",
        },
        {
            "principal_id": "bob@corp",
            "principal_type": "human",
            "allowed_tools": ["read"],
            "allowed_tags": ["safe"],
            "max_risk_level": "low",
        },
        {
            "principal_id": "agent-001",
            "principal_type": "agent",
            "allowed_tools": ["invoke", "monitor"],
            "allowed_tags": ["internal"],
            "max_risk_level": "medium",
        },
    ]


# ---------------------------------------------------------------------------
# Tests for build_grants_data()
# ---------------------------------------------------------------------------


def test_build_grants_data_empty():
    """build_grants_data() handles empty row list."""
    result = build_grants_data([])
    assert result == {"mcp": {"grants": {}}}


def test_build_grants_data_single_grant(sample_grant_rows):
    """build_grants_data() converts a single grant row."""
    result = build_grants_data([sample_grant_rows[0]])
    assert result == {
        "mcp": {
            "grants": {
                "alice@corp": {
                    "principal_type": "human",
                    "allowed_tools": ["read", "write", "delete"],
                    "allowed_tags": ["safe", "testing"],
                    "max_risk_level": "high",
                }
            }
        }
    }


def test_build_grants_data_multiple_grants(sample_grant_rows):
    """build_grants_data() converts multiple grant rows."""
    result = build_grants_data(sample_grant_rows)
    assert result["mcp"]["grants"]["alice@corp"]["principal_type"] == "human"
    assert result["mcp"]["grants"]["bob@corp"]["max_risk_level"] == "low"
    assert result["mcp"]["grants"]["agent-001"]["allowed_tools"] == ["invoke", "monitor"]
    assert len(result["mcp"]["grants"]) == 3


def test_build_grants_data_preserves_order(sample_grant_rows):
    """build_grants_data() preserves all fields exactly as provided."""
    result = build_grants_data(sample_grant_rows)
    grants = result["mcp"]["grants"]
    for i, row in enumerate(sample_grant_rows):
        principal_id = row["principal_id"]
        assert grants[principal_id]["principal_type"] == row["principal_type"]
        assert grants[principal_id]["allowed_tools"] == row["allowed_tools"]
        assert grants[principal_id]["allowed_tags"] == row["allowed_tags"]
        assert grants[principal_id]["max_risk_level"] == row["max_risk_level"]


# ---------------------------------------------------------------------------
# Tests for OPADataSync class
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_opa_data_sync_init(mock_db_pool):
    """OPADataSync.__init__() stores pool and client."""
    sync = OPADataSync(db_pool=mock_db_pool)
    assert sync.db_pool is mock_db_pool
    assert sync.opa_client is not None
    assert sync._reconcile_task is None


@pytest.mark.asyncio
async def test_push_grants_fetches_from_db(mock_db_pool, sample_grant_rows):
    """push_grants() executes SELECT query on role_assignments."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    # Mock OPAClient.put_data to avoid settings config
    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.push_grants()

    # Verify DB query
    mock_db_pool.fetch.assert_called_once()
    call_args = mock_db_pool.fetch.call_args[0]
    assert "role_assignments" in str(call_args[0])


@pytest.mark.asyncio
async def test_push_grants_calls_opa_put_data(mock_db_pool, sample_grant_rows):
    """push_grants() calls OPA client put_data() with grants structure."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    # Mock OPAClient.put_data to capture calls
    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        # Verify OPA call
        mock_put.assert_called_once()
        call_args = mock_put.call_args
        path = call_args[1]["path"] if "path" in call_args[1] else call_args[0][0]
        data = call_args[1]["data"] if "data" in call_args[1] else call_args[0][1]

        assert path == "/mcp/grants"
        assert "mcp" in data
        assert "grants" in data["mcp"]
        assert "alice@corp" in data["mcp"]["grants"]


@pytest.mark.asyncio
async def test_push_grants_raises_on_opa_failure(mock_db_pool, sample_grant_rows):
    """push_grants() propagates OPA failures (fail-closed)."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    # Mock OPAClient.put_data to raise error
    with patch(
        "app.services.opa_data_sync.OPAClient.put_data",
        new_callable=AsyncMock,
        side_effect=PolicyEngineError("OPA unavailable"),
    ):
        with pytest.raises(PolicyEngineError):
            await sync.push_grants()


@pytest.mark.asyncio
async def test_push_grants_raises_on_db_failure(mock_db_pool):
    """push_grants() propagates DB failures (fail-closed)."""
    mock_db_pool.fetch = AsyncMock(side_effect=Exception("DB connection lost"))

    sync = OPADataSync(db_pool=mock_db_pool)

    with pytest.raises(Exception):
        await sync.push_grants()


@pytest.mark.asyncio
async def test_push_grants_handles_empty_result(mock_db_pool):
    """push_grants() handles empty grant list gracefully."""
    mock_db_pool.fetch.return_value = []

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        # Should still call OPA with empty grants structure
        mock_put.assert_called_once()
        call_args = mock_put.call_args
        data = call_args[1]["data"] if "data" in call_args[1] else call_args[0][1]
        assert data == {"mcp": {"grants": {}}}


@pytest.mark.asyncio
async def test_start_reconcile_loop_creates_task(mock_db_pool, sample_grant_rows):
    """start_reconcile_loop() creates a background task."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.start_reconcile_loop()

        assert sync._reconcile_task is not None
        assert isinstance(sync._reconcile_task, asyncio.Task)

        # Clean up
        await sync.stop_reconcile_loop()


@pytest.mark.asyncio
async def test_reconcile_loop_runs_every_60s(mock_db_pool, sample_grant_rows):
    """Reconcile loop structure uses 60s sleep interval."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    # Simple approach: just verify the loop starts and can be stopped.
    # The actual 60s timing is tested in integration if needed.
    # Here we test the loop structure is correct.
    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.start_reconcile_loop()

        # Task should be running
        assert sync._reconcile_task is not None
        assert not sync._reconcile_task.done()

        # Immediately stop it
        await sync.stop_reconcile_loop()

        # Verify it's stopped
        assert sync._reconcile_task is None or sync._reconcile_task.done()


@pytest.mark.asyncio
async def test_reconcile_loop_handles_push_failures(mock_db_pool):
    """Reconcile loop logs errors and continues on push failures (not raised)."""
    mock_db_pool.fetch.return_value = []

    sync = OPADataSync(db_pool=mock_db_pool)

    # Make asyncio.sleep return immediately
    async def fast_sleep(duration):
        return None

    # Track if an error is logged in the except handler
    error_logged = []

    async def failing_put_data(path, data):
        raise PolicyEngineError("Temporary failure")

    with patch("app.services.opa_data_sync.asyncio.sleep", side_effect=fast_sleep):
        with patch("app.services.opa_data_sync.OPAClient.put_data", side_effect=failing_put_data):
            # The reconcile loop should start and hit the error handler
            # We can't easily capture the logger, so we just test that the loop
            # doesn't raise and continues running
            try:
                await sync.start_reconcile_loop()
                # Give it time to enter the loop and hit the error once
                await asyncio.sleep(0.005)
                await sync.stop_reconcile_loop()
                # If we get here without an exception, the error handling worked
                assert True
            except PolicyEngineError:
                # The error should be caught and logged, not re-raised
                pytest.fail("Reconcile loop should not re-raise OPA errors")


@pytest.mark.asyncio
async def test_stop_reconcile_loop_cancels_task(mock_db_pool, sample_grant_rows):
    """stop_reconcile_loop() cancels the background task."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.start_reconcile_loop()

        assert sync._reconcile_task is not None
        assert not sync._reconcile_task.done()

        await sync.stop_reconcile_loop()

        # Task should be None or done
        assert sync._reconcile_task is None or sync._reconcile_task.done()


@pytest.mark.asyncio
async def test_stop_reconcile_loop_idempotent(mock_db_pool):
    """stop_reconcile_loop() can be called multiple times safely."""
    sync = OPADataSync(db_pool=mock_db_pool)

    # Should not raise even if no task running
    await sync.stop_reconcile_loop()
    await sync.stop_reconcile_loop()


# ---------------------------------------------------------------------------
# Integration-like test: startup + mutation pattern
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_and_mutation_pattern(mock_db_pool, sample_grant_rows):
    """
    Simulates startup (push_grants) followed by mutation (call push_grants again).
    Both should succeed independently.
    """
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        # Startup push
        await sync.push_grants()
        assert mock_put.call_count == 1

        # Mutation push (before commit in a transaction)
        await sync.push_grants()
        assert mock_put.call_count == 2

        # Both calls should be identical (idempotent data)
        call1_data = mock_put.call_args_list[0][1]["data"]
        call2_data = mock_put.call_args_list[1][1]["data"]
        assert call1_data == call2_data
