"""
build-worker DB access — connects ONLY as build_worker_app.

Deliberately its own tiny asyncpg pool, mirroring scanner_worker/db.py: this
process must never share a DSN, secret, or code path with the proxy's
DB-admin connection (CR-01 / WP-B3 execution/adjudication split, same
rationale as CR-14's scanner-worker isolation).
"""
from __future__ import annotations

import logging
import os

import asyncpg

logger = logging.getLogger(__name__)

_pool: asyncpg.Pool | None = None


def _dsn() -> str:
    # BUILD_WORKER_DATABASE_URL takes precedence (full DSN); otherwise build
    # from discrete parts so compose can inject just a password.
    dsn = os.environ.get("BUILD_WORKER_DATABASE_URL")
    if dsn:
        return dsn
    host = os.environ.get("DB_HOST", "db")
    port = os.environ.get("DB_PORT", "5432")
    name = os.environ.get("DB_NAME", "mcp_security")
    user = os.environ.get("BUILD_WORKER_DB_USER", "build_worker_app")
    password = os.environ["BUILD_WORKER_DB_PASSWORD"]  # required, no default — fail loud
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4, command_timeout=30)
        logger.info("build-worker DB pool initialized (role=build_worker_app)")
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
