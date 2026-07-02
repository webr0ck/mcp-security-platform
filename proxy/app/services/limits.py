"""Per-client request-limit overrides: rate limit + anomaly sensitivity.

Reads the client_limits table through a Redis-only write-through cache (no
per-process memo, so DEL-on-edit reaches every worker). Every getter FAILS
CLOSED: on any error it returns the strict default (never higher / unlimited /
'off')."""
from __future__ import annotations

import json
import logging

from app.core.asyncpg_pool import asyncpg_pool
from app.core.redis_client import redis_pool, get_anomaly_window_with_timestamps
from app.services.anomaly import _score_window

logger = logging.getLogger(__name__)

SENSITIVITY_CUTOFF = {"normal": 0.85, "lenient": 0.95, "off": 2.0}
_DEFAULT_CUTOFF = 0.85
_CACHE_TTL = 60
_CACHE_PREFIX = "limits:cfg:"
_MISS = "\x00none"


def cutoff_for_sensitivity(sensitivity: str) -> float:
    return SENSITIVITY_CUTOFF.get(sensitivity, _DEFAULT_CUTOFF)


async def _read_limits_row(client_id: str) -> dict | None:
    rc = redis_pool.client
    ckey = f"{_CACHE_PREFIX}{client_id}"
    cached = await rc.get(ckey)
    if cached is not None:
        if cached == _MISS:
            return None
        return json.loads(cached)
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("db pool unavailable")
    row = await pool.fetchrow(
        "SELECT rate_limit, anomaly_sensitivity FROM client_limits WHERE client_id = $1",
        client_id,
    )
    if row is None:
        await rc.set(ckey, _MISS, ex=_CACHE_TTL)
        return None
    row_dict = {"rate_limit": row["rate_limit"], "anomaly_sensitivity": row["anomaly_sensitivity"]}
    await rc.set(ckey, json.dumps(row_dict), ex=_CACHE_TTL)
    return row_dict


async def invalidate(client_id: str) -> None:
    try:
        await redis_pool.client.delete(f"{_CACHE_PREFIX}{client_id}")
    except Exception as exc:
        logger.warning("limits cache invalidate failed for %s: %s", client_id, exc)


async def get_rate_limit(client_id: str, role_default: int) -> int:
    try:
        row = await _read_limits_row(client_id)
        if row and row.get("rate_limit") is not None:
            return int(row["rate_limit"])
        return role_default
    except Exception as exc:
        logger.error("get_rate_limit failed for %s, using role_default=%s: %s",
                     client_id, role_default, exc)
        return role_default


async def get_anomaly_cutoff(client_id: str) -> float:
    try:
        row = await _read_limits_row(client_id)
        if row:
            return cutoff_for_sensitivity(row.get("anomaly_sensitivity", "normal"))
        return _DEFAULT_CUTOFF
    except Exception as exc:
        logger.error("get_anomaly_cutoff failed for %s, using 0.85: %s", client_id, exc)
        return _DEFAULT_CUTOFF


async def score_window(client_id: str) -> float:
    window = await get_anomaly_window_with_timestamps(client_id)
    names = [e["tool_name"] for e in window]
    score, _pattern, _desc = _score_window(names)
    return score
