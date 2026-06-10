"""
MCP Security Platform — Asyncpg Connection Pool

Provides a low-level asyncpg connection pool for use cases where SQLAlchemy's
async engine is not suitable (e.g., Registry, credential_storage).

This is a singleton pool that is initialized during FastAPI lifespan and
is available for use by background tasks, services, and other components.

Usage:
    from app.core.asyncpg_pool import asyncpg_pool

    # During app startup (handled by lifespan):
    await asyncpg_pool.initialize()

    # Use the pool:
    cfg = registry.get_config("service-name")

    # During app shutdown (handled by lifespan):
    await asyncpg_pool.close()
"""
from __future__ import annotations

import logging
from typing import Optional

import asyncpg

logger = logging.getLogger(__name__)


class AsyncpgPool:
    """Singleton wrapper for asyncpg connection pool."""

    def __init__(self) -> None:
        """Initialize the wrapper (does not create the pool yet)."""
        self._pool: Optional[asyncpg.Pool] = None

    async def initialize(self, dsn: str | None = None) -> None:
        """
        Create the asyncpg connection pool.

        Args:
            dsn: Database connection string. If not provided, uses settings.database_url.

        Side effects:
            - Creates an asyncpg.Pool with min_size=2, max_size=20
            - Stores the pool in self._pool
            - Logs at info level on success
            - Logs at error level if creation fails
        """
        if self._pool is not None:
            logger.warning("asyncpg_pool already initialized; ignoring re-initialization")
            return

        from app.core.config import settings

        # Use provided DSN or settings database_url (convert from asyncpg format)
        if dsn is None:
            dsn = settings.database_url.replace("postgresql+asyncpg://", "postgresql://")

        try:
            self._pool = await asyncpg.create_pool(
                dsn,
                min_size=2,
                max_size=20,
                command_timeout=30,
                connection_class=asyncpg.Connection,
            )
            logger.info("Asyncpg pool initialized", extra={"dsn": dsn})
        except Exception as exc:
            logger.error("Failed to initialize asyncpg pool", extra={"error": str(exc)})
            self._pool = None
            raise

    async def close(self) -> None:
        """
        Close the asyncpg connection pool.

        Side effects:
            - Closes all connections in the pool
            - Sets self._pool to None
            - Logs at info level
        """
        if self._pool is None:
            return

        try:
            await self._pool.close()
            self._pool = None
            logger.info("Asyncpg pool closed")
        except Exception as exc:
            logger.error("Error closing asyncpg pool", extra={"error": str(exc)})

    def get(self) -> asyncpg.Pool:
        """
        Get the asyncpg pool.

        Returns:
            The asyncpg.Pool instance.

        Raises:
            RuntimeError: If the pool is not initialized.
        """
        if self._pool is None:
            raise RuntimeError(
                "Asyncpg pool not initialized. Call asyncpg_pool.initialize() first."
            )
        return self._pool


# Singleton instance
asyncpg_pool = AsyncpgPool()
