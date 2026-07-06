"""
scanner-worker DB access — connects ONLY as scanner_worker_app.

Deliberately its own tiny asyncpg pool, not proxy's app.core.asyncpg_pool:
this process must never share a DSN, secret, or code path with the proxy's
DB-admin connection.
"""
from __future__ import annotations

import logging
import os

import asyncpg

logger = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None


def _dsn() -> str:
    # SCANNER_WORKER_DATABASE_URL takes precedence (full DSN); otherwise build
    # from discrete parts so compose can inject just a password.
    dsn = os.environ.get("SCANNER_WORKER_DATABASE_URL")
    if dsn:
        return dsn
    host = os.environ.get("DB_HOST", "db")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "mcp_security")
    user = os.environ.get("SCANNER_WORKER_DB_USER", "scanner_worker_app")
    password = os.environ["SCANNER_WORKER_DB_PASSWORD"]  # required, no default — fail loud
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4, command_timeout=30)
        logger.info("scanner-worker DB pool initialized (role=scanner_worker_app)")
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
