"""
MCP Security Platform — Registry (DB-Driven ServerConfig)

Loads approved MCP servers from the database (server_registry table) instead of
mcps.yaml. Includes a 30-second auto-refresh loop to pick up newly approved
servers without restarting the proxy.

Architecture:
  - Registry.__init__(db_pool, refresh_interval_secs=30)
    - Initializes _servers dict empty (does not auto-refresh)
    - Stores db_pool and refresh_interval_secs for later use

  - Registry.refresh()
    - Queries server_registry WHERE status='approved'
    - Builds ServerConfig objects from each row
    - Replaces _servers dict (not merged)

  - Registry.get_config(service_name)
    - Returns ServerConfig by service_name or None
    - O(1) lookup from _servers dict

  - Registry.start_refresh_loop()
    - Launches background asyncio.Task that calls refresh() every N seconds
    - Runs until stopped

  - Registry.stop_refresh_loop()
    - Cancels the background task
    - Waits for cancellation to complete

The database schema (V014__server_registry.sql) defines the table:
  - server_id: UUID PK
  - service_name: VARCHAR(128)
  - upstream_url: TEXT
  - injection_mode: injection_mode_enum
  - status: VARCHAR(32) CHECK IN ('pending', 'approved', 'suspended')
  - credential_id: Optional[UUID]
  - ... (approval metadata, etc.)

This complements Task 7 (server registration) which creates pending servers.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

import asyncpg

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """
    Represents an approved MCP server configuration loaded from server_registry.

    Attributes:
        server_id: UUID of the server (primary key in database)
        service_name: Human-readable name (used as lookup key)
        upstream_url: HTTP(S) URL of the MCP server
        injection_mode: Type of credential injection ('oauth_user_token', 'service', 'user', 'none', etc.)
        status: Server status ('pending', 'approved', 'suspended')
        credential_id: Optional UUID linking to credential_store record
    """

    server_id: str  # str representation of UUID
    service_name: str
    upstream_url: str
    injection_mode: str
    status: str
    credential_id: Optional[str] = None  # str representation of UUID or None


class Registry:
    """
    DB-driven registry for approved MCP servers.

    Loads server_registry table periodically (every 30 seconds by default).
    Only approved servers are loaded; pending and suspended servers are ignored.

    Usage:
        registry = Registry(db_pool=pool, refresh_interval_secs=30)
        await registry.start_refresh_loop()
        cfg = registry.get_config("github-server")
        # ... use cfg.upstream_url, cfg.injection_mode, etc.
        await registry.stop_refresh_loop()

    The background refresh loop is optional. You can also call refresh()
    manually when needed (e.g., in tests, or after receiving a webhook).
    """

    def __init__(self, db_pool: asyncpg.Pool, refresh_interval_secs: int = 30) -> None:
        """
        Initialize the registry.

        Args:
            db_pool: asyncpg connection pool for database access
            refresh_interval_secs: How often to refresh from DB (default 30)

        Side effects: None. The constructor does NOT call refresh().
        """
        self.db_pool = db_pool
        self.refresh_interval_secs = refresh_interval_secs
        self._servers: dict[str, ServerConfig] = {}
        self._refresh_task: Optional[asyncio.Task[None]] = None

    async def refresh(self) -> None:
        """
        Load all approved servers from server_registry.

        Queries:
            SELECT server_id, service_name, upstream_url, injection_mode,
                   status, credential_id
            FROM server_registry
            WHERE status = 'approved' AND deleted_at IS NULL

        Side effects:
            - Replaces self._servers dict entirely (not merged)
            - Logs at info level if successful
            - Logs at error level if a database exception occurs

        Raises:
            - No exceptions are propagated. All errors are logged.
        """
        try:
            # Query all approved servers from the database
            rows = await self.db_pool.fetch(
                """
                SELECT server_id, service_name, upstream_url, injection_mode,
                       status, default_credential_id AS credential_id
                FROM server_registry
                WHERE status = $1 AND deleted_at IS NULL
                ORDER BY service_name
                """,
                "approved",
            )

            # Build ServerConfig objects and index by service_name
            new_servers: dict[str, ServerConfig] = {}
            for row in rows:
                cfg = ServerConfig(
                    server_id=str(row["server_id"]),
                    service_name=row["service_name"],
                    upstream_url=row["upstream_url"],
                    injection_mode=row["injection_mode"],
                    status=row["status"],
                    credential_id=str(row["credential_id"]) if row["credential_id"] else None,
                )
                new_servers[row["service_name"]] = cfg

            # Replace the servers dict (atomic swap)
            self._servers = new_servers
            logger.info("registry_refresh_succeeded", extra={"server_count": len(self._servers)})

        except Exception as exc:
            logger.error("registry_refresh_failed", extra={"error": str(exc)})

    def get_config(self, service_name: str) -> Optional[ServerConfig]:
        """
        Retrieve a server's config by service_name.

        Args:
            service_name: The service_name to look up

        Returns:
            ServerConfig if found, None otherwise.

        Time complexity: O(1)
        """
        return self._servers.get(service_name)

    async def start_refresh_loop(self) -> None:
        """
        Start the background refresh loop.

        Launches an asyncio.Task that calls refresh() every N seconds.
        The loop runs until stop_refresh_loop() is called.

        Side effects:
            - Stores the task in self._refresh_task
            - Calls refresh() at least once before returning
            - Calls refresh() again every refresh_interval_secs seconds

        Idempotent: Calling start_refresh_loop() multiple times is safe
        (only one loop runs at a time).
        """
        if self._refresh_task is not None and not self._refresh_task.done():
            # Loop already running
            return

        # Define the refresh loop coroutine
        async def _refresh_loop() -> None:
            """Background task: refresh every N seconds."""
            while True:
                try:
                    await self.refresh()
                    await asyncio.sleep(self.refresh_interval_secs)
                except asyncio.CancelledError:
                    break
                except Exception:
                    # Already logged by refresh()
                    await asyncio.sleep(self.refresh_interval_secs)

        # Launch the background task
        self._refresh_task = asyncio.create_task(_refresh_loop())

    async def stop_refresh_loop(self) -> None:
        """
        Stop the background refresh loop.

        Side effects:
            - Cancels self._refresh_task
            - Waits for the task to complete
            - Sets self._refresh_task to None

        Idempotent: Safe to call even if the loop is not running.
        """
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = None
            return

        # Cancel the task and wait for it to finish
        self._refresh_task.cancel()
        try:
            await self._refresh_task
        except asyncio.CancelledError:
            pass
        finally:
            self._refresh_task = None
