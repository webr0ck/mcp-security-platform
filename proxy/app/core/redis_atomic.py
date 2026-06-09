"""
redis_atomic.py — Atomic Redis helpers for the MCP Security Platform.

C5 (R-5 AppSec condition): CSRF-token validation at POST /auth/enroll/{svc}/consent
MUST use an atomic GET+DEL to prevent double-submit (two Entra redirects on one consent).

The existing oauth.py callback uses `pipe.get + pipe.delete` which is NOT atomic.
This module provides `get_and_delete` using `redis.getdel()` (Redis ≥6.2) for a
true atomic consume.

Fallback: if the connected Redis does not support GETDEL (unlikely in any modern
deployment), we fall back to a Lua GET/DEL script which is also atomic.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Lua script: atomically GET the value then DEL the key.
# Returns the value (string) or false if the key does not exist.
_LUA_GETDEL = """
local v = redis.call('GET', KEYS[1])
if v ~= false then
    redis.call('DEL', KEYS[1])
end
return v
"""


async def get_and_delete(redis, key: str) -> str | None:
    """
    Atomically retrieve and delete a key in one round-trip (C5).

    Attempts redis.getdel() (Redis ≥6.2, redis-py ≥4.1) first.
    Falls back to a Lua EVAL GET+DEL script for older deployments.

    Returns the string value if the key existed, None otherwise.

    MUST be used for CSRF token consumption to prevent double-submit attacks:
    a non-atomic GET-then-DEL allows a race where two concurrent requests
    both GET the value before either DELetes it, granting two Entra redirects
    from a single user consent.
    """
    try:
        # redis-py exposes getdel() as a coroutine on async Redis clients
        result = await redis.getdel(key)
        return result  # None if key did not exist
    except AttributeError:
        # Older redis-py or unexpected client — fall back to Lua
        logger.warning(
            "redis_atomic: getdel() not available; falling back to Lua GET+DEL. "
            "Upgrade redis-py ≥4.1 for native GETDEL support."
        )
        result = await redis.eval(_LUA_GETDEL, 1, key)
        # Lua returns the value or nil (False/None in redis-py)
        return result if result else None
    except Exception as exc:
        # Surface unexpected errors — do NOT silently swallow (fail-closed)
        logger.error(
            "redis_atomic: get_and_delete failed",
            extra={"key": key, "error": str(exc)},
        )
        raise
