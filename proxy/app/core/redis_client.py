"""
MCP Security Platform — Redis Client

Provides an async Redis connection pool for:
- Rate limit counters (REDIS_RATE_LIMIT_DB)
- API key lookup cache (REDIS_DB)
- Session state and anomaly score caching

Uses redis-py async client. Connection pool is initialized at application startup
and closed on shutdown (managed via lifespan in main.py).
"""
from __future__ import annotations

import redis.asyncio as aioredis

from app.core.config import settings


class RedisPool:
    """Wrapper around redis.asyncio connection pools."""

    def __init__(self) -> None:
        self._client: aioredis.Redis | None = None
        self._rate_limit_client: aioredis.Redis | None = None

    async def initialize(self) -> None:
        """Initialize connection pools. Called at application startup."""
        self._client = aioredis.Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        rate_limit_url = (
            f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}"
            f":{settings.REDIS_PORT}/{settings.REDIS_RATE_LIMIT_DB}"
        )
        self._rate_limit_client = aioredis.Redis.from_url(
            rate_limit_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
        )

    async def close(self) -> None:
        """Close all connection pools. Called at application shutdown."""
        if self._client:
            await self._client.aclose()
        if self._rate_limit_client:
            await self._rate_limit_client.aclose()

    @property
    def client(self) -> aioredis.Redis:
        if self._client is None:
            raise RuntimeError("Redis pool not initialized. Call initialize() first.")
        return self._client

    @property
    def rate_limit_client(self) -> aioredis.Redis:
        if self._rate_limit_client is None:
            raise RuntimeError("Redis rate-limit pool not initialized.")
        return self._rate_limit_client

    async def ping(self) -> bool:
        """Check Redis connectivity. Used by health endpoints."""
        try:
            return await self.client.ping()  # type: ignore[return-value]
        except Exception:
            return False


# Module-level singleton; initialized in app lifespan
redis_pool = RedisPool()
