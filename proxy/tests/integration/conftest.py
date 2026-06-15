"""
Integration-test fixtures.

Root-cause fix for the "Future attached to a different loop" / "Event loop is
closed" failures across the integration suite.

pytest-asyncio (asyncio_mode=auto, v0.24) gives each async test its own
function-scoped event loop. But `app.core.database.engine` is a module-level
singleton whose asyncpg connection pool (pool_pre_ping=True) caches connections,
and `app.core.asyncpg_pool` is a process-wide singleton too. A connection opened
on test A's loop is then checked out (and pre-ping'd) on test B's loop ->
RuntimeError: "got Future attached to a different loop"; at teardown the original
loop is already closed -> "Event loop is closed".

Disposing both pools after every integration test guarantees each test opens
fresh connections on its own loop. dispose()/close() run on the current
(about-to-close) loop — the same loop those connections were opened on — so the
teardown itself is loop-consistent. This is scoped to tests/integration only;
the unit suite mocks the database and must not pay this cost.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
async def _isolate_db_pools_per_loop():
    """Tear down pooled DB connections after each integration test so none leak
    into the next test's event loop."""
    yield
    try:
        from app.core.database import engine

        await engine.dispose()
    except Exception:
        # Engine may not have been touched by this test; disposal is best-effort.
        pass
    try:
        from app.core.asyncpg_pool import asyncpg_pool

        await asyncpg_pool.close()
    except Exception:
        # Pool may never have been initialized (ASGITransport skips lifespan).
        pass
