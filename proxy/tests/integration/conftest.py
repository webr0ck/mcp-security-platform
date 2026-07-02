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

Lab credentials: when running from the Mac host (outside the podman network),
load real credentials from .env.lab so the app can authenticate to mcp-db and
mcp-redis.  The root conftest.py applies fake values via setdefault(), so we
override here with the lab values.  Inside a container, DB_HOST=db is already
set in the environment and will take precedence because os.environ assignments
here only run when the existing value is the fake default.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load lab credentials for the in-process app when running from the Mac host
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).parent.parent.parent.parent
_ENV_LAB = _REPO_ROOT / ".env.lab"

if _ENV_LAB.exists():
    _lab_vars: dict[str, str] = {}
    for _line in _ENV_LAB.read_text().splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _, _v = _line.partition("=")
        _lab_vars[_k.strip()] = _v.strip()

    # Only override vars that the root conftest set to fake values (i.e. those
    # whose current value equals the fake default).  If the real env already has
    # them set (e.g. running inside a container), skip.
    _FAKE_DEFAULTS = {
        "DB_PASSWORD": "test",
        "REDIS_PASSWORD": "test",
        "PROXY_SECRET_KEY": "test",
        "API_KEY_HMAC_KEY": "test",
        "SBOM_SIGNING_KEY": "test",
        "AUDIT_LOG_HMAC_KEY": "test",
        "WEBHOOK_SIGNING_KEY": "test",
        "MINIO_ROOT_USER": "test",
        "MINIO_ROOT_PASSWORD": "test",
    }
    for _k, _fake in _FAKE_DEFAULTS.items():
        if os.environ.get(_k) == _fake and _k in _lab_vars:
            os.environ[_k] = _lab_vars[_k]

    # DB_HOST is already set to "localhost" by root conftest (Mac-host mapping).
    # No changes needed for DB_HOST or REDIS_PORT (already handled above).

    # After updating os.environ, the Settings @lru_cache must be cleared so that
    # the next access to `settings` creates a fresh instance with the real
    # credentials — otherwise the cached instance (created by root conftest when
    # it imported settings to read GATEWAY_SHARED_SECRET) still holds "test".
    try:
        from app.core.config import get_settings  # noqa: PLC0415
        get_settings.cache_clear()
    except Exception:
        pass  # module not yet imported; nothing to clear


import asyncio as _asyncio
import asyncpg as _asyncpg
import json as _json

def _lab_dsn() -> str:
    """Build a direct asyncpg DSN for seed/cleanup fixtures."""
    from app.core.config import get_settings
    s = get_settings()
    return f"postgresql://{s.DB_USER}:{s.DB_PASSWORD}@{s.DB_HOST}:{s.DB_PORT}/{s.DB_NAME}"


# Test clients required by integration tests hitting localhost:8000.
# Seeded at session start, cleaned up at session end to avoid polluting the lab DB.
_TEST_ROLE_SEEDS = [
    ("test-agent-client", "agent"),
    ("test-admin-client", "admin"),
    ("test-auditor-client", "auditor"),
    ("test-server-owner", "server_owner"),
]

# Test tools required by integration tests (tool_registry rows with fixed UUIDs).
_TEST_TOOL_SEEDS = [
    # (tool_id, name, status, injection_mode, risk_level)
    ("00000000-0000-0000-0000-000000000010", "active-low-risk-tool", "active", "none", "low"),
    ("00000000-0000-0000-0000-000000000020", "quarantined-tool", "quarantined", "none", "low"),
    ("00000000-0000-0000-0000-000000000030", "deprecated-tool", "deprecated", "none", "low"),
    ("00000000-0000-0000-0000-000000000031", "basic-auth-unsupported-tool", "active", "service", "low"),
]


async def _run_seed(dsn: str, insert: bool) -> None:
    try:
        conn = await _asyncpg.connect(dsn)
    except Exception:
        return  # can't connect; tests hitting localhost:8000 will still use seeded data from prior runs
    try:
        for client_id, role in _TEST_ROLE_SEEDS:
            if insert:
                await conn.execute(
                    "INSERT INTO role_assignments (client_id, role, granted_by) "
                    "VALUES ($1, $2, 'integration-test-seed') "
                    "ON CONFLICT (client_id, role) DO NOTHING",
                    client_id, role,
                )
            else:
                await conn.execute(
                    "DELETE FROM role_assignments WHERE client_id=$1 AND role=$2 "
                    "AND granted_by='integration-test-seed'",
                    client_id, role,
                )
        for tool_id, name, status, injection_mode, risk_level in _TEST_TOOL_SEEDS:
            if insert:
                await conn.execute(
                    "INSERT INTO tool_registry "
                    "  (tool_id, name, version, description, schema, upstream_url, "
                    "   registered_by, status, injection_mode, risk_level) "
                    "VALUES ($1, $2, '1.0.0', 'Integration test seed', '{}'::jsonb, "
                    "   'http://unused.invalid/mcp', 'integration-test-seed', $3, $4, $5) "
                    "ON CONFLICT (tool_id) DO NOTHING",
                    tool_id, name, status, injection_mode, risk_level,
                )
            else:
                pass  # Cannot DELETE: FK→audit_events has ON DELETE SET NULL which the immutability guard blocks.
                      # Tools have fixed UUIDs; leaving them in place is safe (ON CONFLICT DO NOTHING on insert).
        # Flush the proxy's Redis role cache for all seeded test clients so the
        # running proxy picks up the new role_assignments immediately (not after TTL).
        try:
            import redis as _redis_lib
            from app.core.config import get_settings as _gs
            _s = _gs()
            r = _redis_lib.Redis(
                host="localhost",
                port=6379,
                password=_s.REDIS_PASSWORD,
                decode_responses=True,
            )
            for cid, _ in _TEST_ROLE_SEEDS:
                r.delete(f"roles:{cid}")
            r.close()
        except Exception:
            pass

        # Update test-agent-client's allowed_tools to include all seeded test tools
        # and push the updated grants to OPA (since OPA caches grants at startup).
        if insert:
            test_tool_names = list({
                "active-low-risk-tool",
                *[n for _, n, _, _, _ in _TEST_TOOL_SEEDS],
            })
            await conn.execute(
                "UPDATE client_grants SET allowed_tools = $1::jsonb "
                "WHERE client_id = 'test-agent-client'",
                _json.dumps(test_tool_names),
            )
            # Push updated grants to OPA so the running proxy sees the change.
            try:
                import urllib.request as _req
                import urllib.error as _uerr
                opa_url = "http://localhost:8181/v1/data/mcp_grants/test-agent-client"
                data = _json.dumps({
                    "allowed_tools": test_tool_names,
                    "allowed_tags": [],
                    "max_risk_level": "high",
                }).encode()
                request = _req.Request(opa_url, data=data, method="PUT",
                                        headers={"Content-Type": "application/json"})
                _req.urlopen(request, timeout=5)
            except Exception:
                pass  # OPA push failure is non-fatal for test setup
        else:
            await conn.execute(
                "UPDATE client_grants SET allowed_tools = '[\"active-low-risk-tool\"]'::jsonb "
                "WHERE client_id = 'test-agent-client'",
            )
            try:
                import urllib.request as _req
                opa_url = "http://localhost:8181/v1/data/mcp_grants/test-agent-client"
                data = _json.dumps({
                    "allowed_tools": ["active-low-risk-tool"],
                    "allowed_tags": [],
                    "max_risk_level": "low",
                }).encode()
                request = _req.Request(opa_url, data=data, method="PUT",
                                        headers={"Content-Type": "application/json"})
                _req.urlopen(request, timeout=5)
            except Exception:
                pass
    except Exception:
        pass  # seed errors are non-fatal; tests may fail individually if rows are missing
    finally:
        await conn.close()


@pytest.fixture(scope="session", autouse=True)
def _seed_test_role_assignments():
    """Insert minimal role_assignments for test clients (sync, session-scoped)."""
    dsn = _lab_dsn()
    _asyncio.run(_run_seed(dsn, insert=True))
    yield
    _asyncio.run(_run_seed(dsn, insert=False))


@pytest.fixture(autouse=True)
async def _isolate_db_pools_per_loop():
    """Tear down pooled DB/Redis connections after each integration test so none leak
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
    try:
        from app.core.redis_client import redis_pool

        await redis_pool.close()
    except Exception:
        # Redis pool may never have been initialized; close is best-effort.
        pass
