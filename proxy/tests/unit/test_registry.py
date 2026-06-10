"""
Unit Tests — Registry Class (DB-Driven ServerConfig with 30s Refresh)

Tests the Registry class that reads ServerConfig from the database instead of
mcps.yaml. Includes 30-second auto-refresh loop to pick up approved servers
without restarting.

Requirements:
  - Mocked asyncpg.Pool (no real database needed for unit tests)
  - Dataclass ServerConfig with fields: server_id, service_name, upstream_url,
    injection_mode, status, credential_id (optional)
  - Registry.refresh() loads approved servers WHERE status='approved'
  - Registry.get_config(service_name) returns ServerConfig or None
  - Registry.start_refresh_loop() and stop_refresh_loop() manage background task
  - Auto-refresh every 30 seconds (configurable)

Run:
  pytest proxy/tests/unit/test_registry.py -v
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest

# Import the Registry class and ServerConfig dataclass
from app.credential_broker.registry import Registry, ServerConfig


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_db_pool() -> AsyncMock:
    """Mock asyncpg.Pool for database operations."""
    pool = AsyncMock()
    return pool


@pytest.fixture
def sample_servers() -> list[dict[str, Any]]:
    """Sample server records as they would be returned from the database."""
    return [
        {
            "server_id": UUID("00000000-0000-0000-0000-000000000001"),
            "service_name": "github-server",
            "upstream_url": "http://localhost:9001",
            "injection_mode": "oauth_user_token",
            "status": "approved",
            "credential_id": UUID("11111111-1111-1111-1111-111111111111"),
        },
        {
            "server_id": UUID("00000000-0000-0000-0000-000000000002"),
            "service_name": "slack-server",
            "upstream_url": "http://localhost:9002",
            "injection_mode": "service",
            "status": "approved",
            "credential_id": UUID("22222222-2222-2222-2222-222222222222"),
        },
        {
            "server_id": UUID("00000000-0000-0000-0000-000000000003"),
            "service_name": "pending-server",
            "upstream_url": "http://localhost:9003",
            "injection_mode": "none",
            "status": "pending",
            "credential_id": None,
        },
        {
            "server_id": UUID("00000000-0000-0000-0000-000000000004"),
            "service_name": "revoked-server",
            "upstream_url": "http://localhost:9004",
            "injection_mode": "user",
            "status": "revoked",
            "credential_id": None,
        },
    ]


# ---------------------------------------------------------------------------
# Test 1: Registry.refresh() loads approved servers from database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_reads_db(mock_db_pool: AsyncMock, sample_servers: list) -> None:
    """
    Registry.refresh() loads servers from server_registry WHERE status='approved'.

    Expected behavior:
    - Query executed with WHERE status='approved'
    - Only approved servers are loaded into _servers dict
    - Pending and revoked servers are ignored
    - ServerConfig objects are created for each approved server
    """
    # Arrange: Mock the database to return approved servers only
    approved_servers = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers

    # Act: Create registry and refresh
    registry = Registry(db_pool=mock_db_pool)
    await registry.refresh()

    # Assert: Database was queried with correct SQL
    mock_db_pool.fetch.assert_called_once()
    call_args = mock_db_pool.fetch.call_args
    assert call_args is not None
    sql = call_args[0][0].lower() if call_args[0] else ""
    # Check SQL contains expected keywords (note: "approved" is passed as parameter $1)
    assert "server_registry" in sql
    assert "status = $1" in sql.lower()  # Parameter placeholder instead of literal
    assert "deleted_at" in sql

    # Assert: Registry loaded both approved servers
    assert len(registry._servers) == 2
    assert "github-server" in registry._servers
    assert "slack-server" in registry._servers

    # Assert: Pending and revoked servers are NOT loaded
    assert "pending-server" not in registry._servers
    assert "revoked-server" not in registry._servers

    # Assert: ServerConfig objects are valid
    github_cfg = registry._servers["github-server"]
    assert isinstance(github_cfg, ServerConfig)
    assert github_cfg.server_id == "00000000-0000-0000-0000-000000000001"
    assert github_cfg.service_name == "github-server"
    assert github_cfg.upstream_url == "http://localhost:9001"
    assert github_cfg.injection_mode == "oauth_user_token"
    assert github_cfg.status == "approved"
    assert github_cfg.credential_id == "11111111-1111-1111-1111-111111111111"


# ---------------------------------------------------------------------------
# Test 2: Registry.get_config() returns matching ServerConfig
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_get_config_returns_matching_server(
    mock_db_pool: AsyncMock, sample_servers: list
) -> None:
    """
    registry.get_config('service-name') returns ServerConfig for matching row.

    Expected behavior:
    - get_config(service_name) looks up by service_name (key in _servers)
    - Returns ServerConfig if found
    - Returns None if not found
    """
    # Arrange: Load some servers
    approved_servers = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers

    registry = Registry(db_pool=mock_db_pool)
    await registry.refresh()

    # Act & Assert: Get existing server
    github_cfg = registry.get_config("github-server")
    assert github_cfg is not None
    assert github_cfg.service_name == "github-server"
    assert github_cfg.upstream_url == "http://localhost:9001"

    # Act & Assert: Get non-existent server
    missing_cfg = registry.get_config("nonexistent-server")
    assert missing_cfg is None


# ---------------------------------------------------------------------------
# Test 3: Registry auto-refreshes on schedule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_refreshes_on_schedule(
    mock_db_pool: AsyncMock, sample_servers: list
) -> None:
    """
    Registry auto-refreshes every N seconds; new servers picked up after refresh.

    Expected behavior:
    - start_refresh_loop() launches a background task
    - Background task calls refresh() every N seconds
    - New servers added to the database are picked up on next refresh
    - stop_refresh_loop() cancels the background task
    """
    # Arrange: Create registry with short 0.2s refresh interval for testing
    registry = Registry(db_pool=mock_db_pool, refresh_interval_secs=0.2)

    # Initially return only github-server
    approved_servers_v1 = [s for s in sample_servers if s["status"] == "approved"]
    approved_servers_v1 = approved_servers_v1[:1]  # Just github-server
    mock_db_pool.fetch.return_value = approved_servers_v1

    # Act: Start the refresh loop
    await registry.start_refresh_loop()

    # Verify initial load
    await asyncio.sleep(0.1)  # Let the first refresh happen
    assert len(registry._servers) == 1
    assert "github-server" in registry._servers

    # Change the mock to return both approved servers on next refresh
    approved_servers_v2 = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers_v2

    # Wait for the refresh interval + buffer
    await asyncio.sleep(0.3)

    # Assert: New server was picked up
    assert len(registry._servers) == 2
    assert "github-server" in registry._servers
    assert "slack-server" in registry._servers

    # Act: Stop the refresh loop
    await registry.stop_refresh_loop()
    await asyncio.sleep(0.1)  # Give it a moment to stop

    # Assert: Task was cancelled
    assert registry._refresh_task is None or registry._refresh_task.cancelled()


# ---------------------------------------------------------------------------
# Test 4: Registry ignores non-approved servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_ignores_non_approved_servers(
    mock_db_pool: AsyncMock, sample_servers: list
) -> None:
    """
    Only status='approved' servers are loaded; pending/revoked/suspended ignored.

    Expected behavior:
    - refresh() queries database with WHERE status='approved'
    - The database query is correct, filtering at the source
    - Registry only stores what the database returns (approved servers)
    """
    # Arrange: Mock the database to return only approved servers
    # (This is what the actual database would do with WHERE status='approved')
    approved_servers = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers

    registry = Registry(db_pool=mock_db_pool)

    # Act: Refresh — the SQL WHERE clause ensures only approved servers are fetched
    await registry.refresh()

    # Assert: Only the servers the database returned are present
    assert len(registry._servers) == 2

    # Assert: Only approved servers are present
    for service_name, cfg in registry._servers.items():
        assert cfg.status == "approved", f"Server {service_name} has status {cfg.status}"

    # Assert: Non-approved servers are absent
    assert "pending-server" not in registry._servers
    assert "revoked-server" not in registry._servers


# ---------------------------------------------------------------------------
# Test 5: Registry handles database errors gracefully
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_handles_db_error_gracefully(mock_db_pool: AsyncMock) -> None:
    """
    Registry handles database errors without crashing.

    Expected behavior:
    - If database raises an exception during refresh, it is logged
    - Registry continues to serve the last known _servers state
    - No exception is propagated to the caller
    """
    # Arrange: Mock database to raise an exception
    mock_db_pool.fetch.side_effect = Exception("Database connection failed")

    registry = Registry(db_pool=mock_db_pool)

    # Act: Call refresh — should handle the error
    with patch("app.credential_broker.registry.logger") as mock_logger:
        try:
            await registry.refresh()
        except Exception:
            pytest.fail("Registry.refresh() should not raise exceptions")

        # Assert: Error was logged
        mock_logger.error.assert_called_once()


# ---------------------------------------------------------------------------
# Test 6: Registry converts UUID fields to strings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_converts_uuid_to_strings(
    mock_db_pool: AsyncMock, sample_servers: list
) -> None:
    """
    Registry converts UUID objects to strings in ServerConfig.

    Expected behavior:
    - server_id (UUID) is converted to string
    - credential_id (Optional[UUID]) is converted to string or None
    - service_name remains a string
    """
    # Arrange
    approved_servers = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers

    # Act
    registry = Registry(db_pool=mock_db_pool)
    await registry.refresh()

    # Assert: UUIDs are strings
    github_cfg = registry._servers["github-server"]
    assert isinstance(github_cfg.server_id, str)
    assert isinstance(github_cfg.credential_id, str)
    assert github_cfg.server_id == "00000000-0000-0000-0000-000000000001"
    assert github_cfg.credential_id == "11111111-1111-1111-1111-111111111111"

    slack_cfg = registry._servers["slack-server"]
    assert isinstance(slack_cfg.credential_id, str)
    assert slack_cfg.credential_id == "22222222-2222-2222-2222-222222222222"


# ---------------------------------------------------------------------------
# Test 7: Registry starts with empty servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_starts_empty(mock_db_pool: AsyncMock) -> None:
    """
    Registry initializes with empty _servers dict before first refresh.

    Expected behavior:
    - Constructor does NOT call refresh automatically
    - get_config returns None for all names until refresh is called
    - _servers dict is empty at initialization
    """
    # Arrange & Act
    registry = Registry(db_pool=mock_db_pool)

    # Assert: No servers loaded yet
    assert len(registry._servers) == 0
    assert registry.get_config("any-server") is None


# ---------------------------------------------------------------------------
# Test 8: Registry refresh updates existing servers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_refresh_updates_servers(
    mock_db_pool: AsyncMock, sample_servers: list
) -> None:
    """
    Registry.refresh() replaces the entire _servers dict on each call.

    Expected behavior:
    - First refresh loads servers A and B
    - Second refresh with only server A removes server B
    - The dict is replaced, not merged
    """
    # Arrange: Set up registry with two servers
    approved_servers_v1 = [s for s in sample_servers if s["status"] == "approved"]
    mock_db_pool.fetch.return_value = approved_servers_v1

    registry = Registry(db_pool=mock_db_pool)
    await registry.refresh()

    assert len(registry._servers) == 2
    assert "github-server" in registry._servers
    assert "slack-server" in registry._servers

    # Act: Change the mock to return only one server
    approved_servers_v2 = approved_servers_v1[:1]
    mock_db_pool.fetch.return_value = approved_servers_v2

    await registry.refresh()

    # Assert: Only the remaining server is present (no merge)
    assert len(registry._servers) == 1
    assert "github-server" in registry._servers
    assert "slack-server" not in registry._servers


# ---------------------------------------------------------------------------
# Test 9: refresh_interval_secs parameter works
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_registry_custom_refresh_interval(mock_db_pool: AsyncMock) -> None:
    """
    Registry respects the refresh_interval_secs parameter.

    Expected behavior:
    - Default refresh_interval_secs is 30
    - Custom value is used if provided
    - The interval is respected by the background loop
    """
    # Arrange & Act: Create registry with custom interval
    registry = Registry(db_pool=mock_db_pool, refresh_interval_secs=5)

    # Assert
    assert registry.refresh_interval_secs == 5


# ---------------------------------------------------------------------------
# Test 10: get_config returns None for empty registry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_config_empty_registry(mock_db_pool: AsyncMock) -> None:
    """
    get_config returns None when registry has no servers loaded.

    Expected behavior:
    - Even after refresh() with empty results, get_config returns None
    - No exceptions are raised
    """
    # Arrange
    mock_db_pool.fetch.return_value = []

    registry = Registry(db_pool=mock_db_pool)
    await registry.refresh()

    # Act & Assert
    result = registry.get_config("any-server")
    assert result is None
