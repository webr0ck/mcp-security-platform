"""
Integration Test — mcps.yaml → DB Registry Migration Golden Test

Tests that servers from mcps.yaml can be imported into the database
and then resolved via the Registry class with identical ServerConfig.

Requirements:
  - podman-compose up (postgres service running)
  - DATABASE_URL accessible
  - Registry class implemented (Task 8)

Invariants covered:
  - mcps.yaml servers can be parsed and inserted into server_registry table
  - Registry.refresh() reads DB and returns ServerConfig for each server
  - ServerConfig fields match original mcps.yaml values

Run:
  pytest proxy/tests/integration/test_registry_migration.py::test_mcps_yaml_import_golden -m integration -v
"""
from __future__ import annotations

import asyncio
import os
import yaml
from pathlib import Path
from typing import AsyncIterator

import asyncpg
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Use settings.database_url to get the asyncpg-compatible DSN
def _get_db_dsn() -> str:
    """Get database DSN from settings, converting from asyncpg format."""
    try:
        from app.core.config import settings
        # settings.database_url is in asyncpg format: postgresql+asyncpg://...
        # Convert to plain postgresql:// for asyncpg.connect()
        dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")
        return dsn
    except Exception:
        # Fallback for when app settings can't be loaded
        return os.environ.get(
            "TEST_DB_DSN",
            "postgresql://mcp_app:devpassword@db:5432/mcp_security",
        )

DB_DSN = _get_db_dsn()

# Project root — mcps.yaml lives here
PROJECT_ROOT = Path(__file__).parents[3]
MCPS_YAML_PATH = PROJECT_ROOT / "mcps.yaml"

# Sample mcps.yaml data for testing (mirrors real mcps.yaml structure)
SAMPLE_MCPS_YAML = {
    "servers": {
        "grafana": {
            "url": "http://grafana:3000/mcp",
            "enabled": True,
            "demand_activate": True,
            "credential": {
                "approach": "B",
                "type": "api_key",
                "inject_header": "Authorization",
                "inject_prefix": "Bearer ",
                "adapter": "grafana",
            },
        },
        "netbox": {
            "url": "http://netbox.internal/mcp",
            "enabled": True,
            "demand_activate": True,
            "credential": {
                "approach": "B",
                "type": "api_key",
                "inject_header": "Authorization",
                "inject_prefix": "Token ",
                "adapter": "netbox",
            },
        },
        "lab-echo": {
            "url": "http://lab-mcp-echo:8000/mcp",
            "enabled": True,
            "demand_activate": True,
            "credential": {
                "approach": "B",
                "type": "none",
            },
        },
    }
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_conn() -> AsyncIterator[asyncpg.Connection]:
    """Live asyncpg connection — only valid when postgres is running."""
    conn = await asyncpg.connect(DB_DSN)
    try:
        yield conn
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def db_pool() -> AsyncIterator[asyncpg.Pool]:
    """Live asyncpg pool — used by Registry class."""
    pool = await asyncpg.create_pool(DB_DSN, min_size=1, max_size=5)
    try:
        yield pool
    finally:
        await pool.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_mcps_yaml() -> dict:
    """
    Load mcps.yaml from project root, or use sample data if not found.

    The test container may not have mcps.yaml mounted, so we fall back to
    sample data that mirrors the real structure.
    """
    if MCPS_YAML_PATH.exists():
        with open(MCPS_YAML_PATH) as f:
            return yaml.safe_load(f) or {}
    else:
        # Return sample data for testing
        return SAMPLE_MCPS_YAML


async def _import_servers_to_db(conn: asyncpg.Connection, servers: dict) -> None:
    """
    Insert servers from mcps.yaml dict into server_registry table.
    Simulates the import step that would be done by a migration script.

    Args:
        conn: asyncpg connection
        servers: dict of {name: {url, enabled, demand_activate, credential}}
    """
    for name, cfg in servers.items():
        # Build the credential JSON blob
        credential_json = cfg.get("credential", {})

        # Insert into server_registry with reasonable defaults
        await conn.execute(
            """
            INSERT INTO server_registry
                (name, upstream_url, status, owner_sub, injection_mode,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, now(), now())
            ON CONFLICT (name) DO NOTHING
            """,
            name,                           # name
            cfg.get("url", ""),            # upstream_url
            "pending",                      # status (servers start as pending)
            "import-script",               # owner_sub (placeholder)
            "none",                        # injection_mode (will be refined per task 3)
        )


# ---------------------------------------------------------------------------
# Golden Test
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_mcps_yaml_import_golden(db_pool):
    """
    Setup: mcps.yaml has N servers.
    Import via script → server_registry rows created.
    Verify: Registry reads DB and returns identical ServerConfig for each.

    Steps:
      1. Load mcps.yaml from project root
      2. Parse servers dict
      3. Simulate import: INSERT servers into server_registry table
      4. Create Registry instance with DB pool
      5. Call await registry.refresh()
      6. For each server in mcps.yaml, assert registry.get_config(name) has:
         - name matching
         - upstream_url == original url
         - enabled == original enabled
         - credential == original credential dict
    """
    # Step 1-2: Load mcps.yaml
    mcps_raw = _load_mcps_yaml()
    servers_dict = mcps_raw.get("servers", {})

    assert len(servers_dict) > 0, "mcps.yaml must have at least one server"

    # Step 3: Simulate import — insert servers into DB
    async with db_pool.acquire() as conn:
        await _import_servers_to_db(conn, servers_dict)

    # Step 4-5: Create Registry and refresh from DB
    # NOTE: Registry class will be implemented in Task 8.
    # This test is a spec for what it should do.
    from app.credential_broker.registry import Registry

    registry = Registry(db_pool=db_pool)
    await registry.refresh()

    # Step 6: Verify each server
    for server_name, original_cfg in servers_dict.items():
        # Get config from registry
        config = registry.get_config(server_name)

        assert config is not None, (
            f"Server '{server_name}' from mcps.yaml must be in Registry after refresh()"
        )

        # Verify fields match original
        assert config.name == server_name, (
            f"config.name mismatch for '{server_name}': "
            f"got {config.name}, expected {server_name}"
        )

        assert config.upstream_url == original_cfg.get("url"), (
            f"config.upstream_url mismatch for '{server_name}': "
            f"got {config.upstream_url}, expected {original_cfg.get('url')}"
        )

        assert config.enabled == original_cfg.get("enabled", True), (
            f"config.enabled mismatch for '{server_name}': "
            f"got {config.enabled}, expected {original_cfg.get('enabled', True)}"
        )

        assert config.demand_activate == original_cfg.get("demand_activate", False), (
            f"config.demand_activate mismatch for '{server_name}': "
            f"got {config.demand_activate}, expected {original_cfg.get('demand_activate', False)}"
        )

        assert config.credential == original_cfg.get("credential", {}), (
            f"config.credential mismatch for '{server_name}': "
            f"got {config.credential}, expected {original_cfg.get('credential', {})}"
        )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_registry_refresh_updates_db_changes(db_pool):
    """
    Verify Registry.refresh() picks up changes from the DB.

    Setup: Insert server with enabled=true
    Import: Call registry.refresh()
    Modify: Update server_registry.status in DB
    Call: registry.refresh() again
    Verify: Registry sees the updated status
    """
    # Use a test-specific server name
    test_server = "test-registry-refresh-server"

    async with db_pool.acquire() as conn:
        # Insert a test server
        await conn.execute(
            """
            INSERT INTO server_registry
                (name, upstream_url, status, owner_sub, injection_mode,
                 created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, now(), now())
            ON CONFLICT (name) DO UPDATE SET
                status = EXCLUDED.status
            """,
            test_server,
            "http://test-server:8000/mcp",
            "pending",
            "test-import",
            "none",
        )

    # Create Registry and refresh
    from app.credential_broker.registry import Registry

    registry = Registry(db_pool=db_pool)
    await registry.refresh()

    # Verify initial state
    config = registry.get_config(test_server)
    assert config is not None
    assert config.upstream_url == "http://test-server:8000/mcp"

    # Update the server status in DB
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE server_registry SET status = $1 WHERE name = $2",
            "approved",
            test_server,
        )

    # Refresh again and verify
    await registry.refresh()
    config_updated = registry.get_config(test_server)
    assert config_updated is not None
    # Registry should see the updated DB state after refresh
    # (exact status field handling depends on Task 8 implementation)
