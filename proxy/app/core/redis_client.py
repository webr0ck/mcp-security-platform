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


import time as _time

_ANOMALY_WINDOW_SECONDS = 300  # 5-minute sliding window


async def push_anomaly_invocation(client_id: str, tool_name: str) -> list[str]:
    """
    Push a tool invocation event into a per-client sliding window in Redis.
    Returns the list of tool names invoked in the last ANOMALY_WINDOW_SECONDS.
    Used by the anomaly detector to compute invocation frequency scores.
    """
    redis = redis_pool.client
    key = f"anomaly:window:{client_id}"
    now = _time.time()
    cutoff = now - _ANOMALY_WINDOW_SECONDS

    pipe = redis.pipeline()
    pipe.zadd(key, {f"{tool_name}:{now}": now})
    pipe.zremrangebyscore(key, "-inf", cutoff)
    pipe.zrange(key, 0, -1)
    pipe.expire(key, _ANOMALY_WINDOW_SECONDS * 2)
    results = await pipe.execute()

    # results[2] is the current window members (tool_name:timestamp strings)
    members: list[str] = results[2] if results[2] else []
    return [m.split(":")[0] for m in members]
