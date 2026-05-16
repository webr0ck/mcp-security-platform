from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

_KEY_PREFIX = "broker"
_TTL_SECONDS = 28800  # 8 hours — matches BROKER_SESSION_TTL_SECONDS


class SessionStore:
    """
    Redis-backed store for active session tokens (Approach B in-session state).
    Key: broker:{session_id}:{service}
    Value: JSON with token value, token_id, expires_at, approach, service.
    TTL = session TTL to auto-expire on idle.
    """

    def __init__(self, redis: aioredis.Redis, ttl: int = _TTL_SECONDS) -> None:
        self._redis = redis
        self._ttl = ttl

    def _key(self, session_id: str, service: str) -> str:
        return f"{_KEY_PREFIX}:{session_id}:{service}"

    async def save(
        self,
        session_id: str,
        service: str,
        token: str,
        token_id: str,
        expires_at: datetime,
        approach: str,
    ) -> None:
        key = self._key(session_id, service)
        payload = json.dumps({
            "value": token,
            "token_id": token_id,
            "expires_at": expires_at.isoformat(),
            "service": service,
            "approach": approach,
        })
        await self._redis.set(key, payload, ex=self._ttl)

    async def get(self, session_id: str, service: str) -> dict | None:
        raw = await self._redis.get(self._key(session_id, service))
        if raw is None:
            return None
        return json.loads(raw)

    async def delete(self, session_id: str, service: str) -> None:
        await self._redis.delete(self._key(session_id, service))
