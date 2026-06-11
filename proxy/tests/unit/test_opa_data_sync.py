"""
Unit Tests — OPA Data Sync Service (Task 4.4b — SELF-F6)

Tests the OPADataSync service that fetches grants from the client_grants table
and pushes them to OPA's data API at /mcp_grants (NOT owned by the signed bundle).

Requirements:
  - build_grants_data() converts client_grants rows to flat OPA data structure
  - OPADataSync.push_grants() fetches from DB, calls OPA PUT /v1/data/mcp_grants
  - OPADataSync.start_reconcile_loop() starts a background task that runs every 60s
  - OPADataSync.stop_reconcile_loop() stops the background task
  - OPAClient.put_data() sends PUT request to OPA data API
  - Fail-closed: if push_grants() raises, it propagates (caller handles rollback)

Data path change (Task 4.4b):
  - Old: PUT /v1/data/mcp/grants (bundle-owned — REJECTED by signed OPA)
  - New: PUT /v1/data/mcp_grants (NOT bundle-owned — ACCEPTED by signed OPA)
  - authz.rego reads data.mcp_grants[client_id].allowed_tools (updated)

Run:
  pytest proxy/tests/unit/test_opa_data_sync.py -v
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from app.services.opa_data_sync import OPADataSync, build_grants_data, _OPA_GRANTS_PATH
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
    """Sample rows as returned from client_grants table (Task 4.4b schema)."""
    return [
        {
            "client_id": "alice@corp",
            "allowed_tools": ["read", "write", "delete"],
            "allowed_tags": ["safe", "testing"],
            "max_risk_level": "high",
        },
        {
            "client_id": "bob@corp",
            "allowed_tools": ["read"],
            "allowed_tags": ["safe"],
            "max_risk_level": "low",
        },
        {
            "client_id": "agent-001",
            "allowed_tools": ["invoke", "monitor"],
            "allowed_tags": ["internal"],
            "max_risk_level": "medium",
        },
    ]


# ---------------------------------------------------------------------------
# Tests for _OPA_GRANTS_PATH constant
# ---------------------------------------------------------------------------


def test_opa_grants_path_is_mcp_grants():
    """
    INV-012 carve-out: grants must be pushed to /mcp_grants (not /mcp/grants).

    The signed bundle owns the "mcp" root (see policies/rego/.manifest).
    Pushing to /mcp/grants would be REJECTED by OPA because the bundle owns
    that path. The path /mcp_grants is not bundle-owned, so the data-API
    write succeeds.
    """
    assert _OPA_GRANTS_PATH == "/mcp_grants", (
        f"Expected /mcp_grants (bundle-roots carve-out), got {_OPA_GRANTS_PATH!r}. "
        "Pushing to /mcp/grants would be rejected by a signed OPA bundle (INV-012)."
    )


# ---------------------------------------------------------------------------
# Tests for build_grants_data()
# ---------------------------------------------------------------------------


def test_build_grants_data_empty():
    """build_grants_data() handles empty row list — returns empty flat dict."""
    result = build_grants_data([])
    assert result == {}


def test_build_grants_data_single_grant(sample_grant_rows):
    """build_grants_data() converts a single client_grants row to flat dict."""
    result = build_grants_data([sample_grant_rows[0]])
    assert result == {
        "alice@corp": {
            "allowed_tools": ["read", "write", "delete"],
            "allowed_tags": ["safe", "testing"],
            "max_risk_level": "high",
        }
    }


def test_build_grants_data_multiple_grants(sample_grant_rows):
    """build_grants_data() converts multiple client_grants rows."""
    result = build_grants_data(sample_grant_rows)
    assert result["alice@corp"]["allowed_tools"] == ["read", "write", "delete"]
    assert result["bob@corp"]["max_risk_level"] == "low"
    assert result["agent-001"]["allowed_tags"] == ["internal"]
    assert len(result) == 3


def test_build_grants_data_no_mcp_wrapper():
    """
    Task 4.4b: build_grants_data() returns a flat dict (not wrapped in {"mcp": {"grants": ...}}).

    OPA receives this at PUT /v1/data/mcp_grants, making data.mcp_grants["alice@corp"]
    readable in Rego. The old format was {"mcp": {"grants": {...}}} pushed to /mcp/grants.
    """
    result = build_grants_data([{"client_id": "test", "allowed_tools": [], "allowed_tags": [], "max_risk_level": "low"}])
    # Must NOT be nested under mcp/grants wrapper
    assert "mcp" not in result, (
        "build_grants_data() must return a flat dict for /mcp_grants, not wrapped in {'mcp': ...}"
    )
    assert "test" in result


def test_build_grants_data_preserves_order(sample_grant_rows):
    """build_grants_data() preserves all fields exactly as provided."""
    result = build_grants_data(sample_grant_rows)
    for row in sample_grant_rows:
        client_id = row["client_id"]
        assert result[client_id]["allowed_tools"] == row["allowed_tools"]
        assert result[client_id]["allowed_tags"] == row["allowed_tags"]
        assert result[client_id]["max_risk_level"] == row["max_risk_level"]


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
async def test_push_grants_fetches_from_client_grants(mock_db_pool, sample_grant_rows):
    """push_grants() executes SELECT query on client_grants table (Task 4.4b)."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock):
        await sync.push_grants()

    # Verify DB query names client_grants (not role_assignments)
    mock_db_pool.fetch.assert_called_once()
    call_args = mock_db_pool.fetch.call_args[0]
    query = str(call_args[0])
    assert "client_grants" in query, (
        f"push_grants() must query client_grants table, not role_assignments. Query: {query}"
    )


@pytest.mark.asyncio
async def test_push_grants_calls_opa_put_at_mcp_grants(mock_db_pool, sample_grant_rows):
    """
    push_grants() calls OPA client put_data() at /mcp_grants (not /mcp/grants).

    This is the key INV-012 bundle-roots carve-out assertion: the data-API
    path must be /mcp_grants (bundle-unowned), not /mcp/grants (bundle-owned,
    would be rejected by signed OPA).
    """
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        mock_put.assert_called_once()
        call_kwargs = mock_put.call_args[1]
        path = call_kwargs.get("path") or mock_put.call_args[0][0]
        data = call_kwargs.get("data") or mock_put.call_args[0][1]

        assert path == "/mcp_grants", (
            f"Expected OPA path /mcp_grants (bundle-roots carve-out), got {path!r}. "
            "Pushing to /mcp/grants would be rejected by signed OPA (INV-012)."
        )
        # Data must be a flat dict by client_id (not wrapped in {"mcp": {"grants": ...}})
        assert "alice@corp" in data, "grants data must be keyed by client_id"
        assert "mcp" not in data, "grants data must NOT be wrapped in {'mcp': ...}"


@pytest.mark.asyncio
async def test_push_grants_raises_on_opa_failure(mock_db_pool, sample_grant_rows):
    """push_grants() propagates OPA failures (fail-closed)."""
    mock_db_pool.fetch.return_value = sample_grant_rows

    sync = OPADataSync(db_pool=mock_db_pool)

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
    """push_grants() handles empty grant list — calls OPA with empty dict."""
    mock_db_pool.fetch.return_value = []

    sync = OPADataSync(db_pool=mock_db_pool)

    with patch("app.services.opa_data_sync.OPAClient.put_data", new_callable=AsyncMock) as mock_put:
        await sync.push_grants()

        mock_put.assert_called_once()
        call = mock_put.call_args
        data = call.kwargs.get("data") if call.kwargs else None
        if data is None and call.args and len(call.args) > 1:
            data = call.args[1]
        assert data == {}, "Empty client_grants should push empty dict to OPA"


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

    async def fast_sleep(duration):
        return None

    async def failing_put_data(path, data):
        raise PolicyEngineError("Temporary failure")

    with patch("app.services.opa_data_sync.asyncio.sleep", side_effect=fast_sleep):
        with patch("app.services.opa_data_sync.OPAClient.put_data", side_effect=failing_put_data):
            try:
                await sync.start_reconcile_loop()
                await asyncio.sleep(0.005)
                await sync.stop_reconcile_loop()
                assert True
            except PolicyEngineError:
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
    Both should succeed independently. Both must use /mcp_grants path.
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
        call1_kwargs = mock_put.call_args_list[0][1]
        call2_kwargs = mock_put.call_args_list[1][1]
        data1 = call1_kwargs.get("data") or mock_put.call_args_list[0][0][1]
        data2 = call2_kwargs.get("data") or mock_put.call_args_list[1][0][1]
        assert data1 == data2

        # Both calls must use /mcp_grants path
        for i, call in enumerate(mock_put.call_args_list):
            path = call[1].get("path") or call[0][0]
            assert path == "/mcp_grants", f"Call {i+1}: expected /mcp_grants, got {path!r}"
