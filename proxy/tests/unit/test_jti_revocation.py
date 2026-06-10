"""
Unit Tests — JTI Revocation deny-on-error (F-C)

Security invariant: JTI revocation must never fail open.
- Redis hit → revoked (fast path)
- Redis miss → DB check (fallback)
- DB says revoked_at IS NOT NULL → revoked
- DB says row not found → deny (token never legitimately issued)
- Redis error → deny (fail-closed)
- DB error → deny (fail-closed)
- Both Redis and DB error → deny (fail-closed)

See: proxy/app/middleware/auth.py::_is_session_jti_revoked
     proxy/app/routers/oidc_browser.py::oidc_logout (writes Redis marker)
"""
from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers: error factories for monkeypatching
# ---------------------------------------------------------------------------

class _FakeDBAPIError(Exception):
    """Simulates a SQLAlchemy / asyncpg DBAPI error."""


class _FakeRedisConnError(Exception):
    """Simulates a redis.exceptions.ConnectionError."""


async def _raise_dbapi_error(*args, **kwargs):  # noqa: ARG001
    raise _FakeDBAPIError("DB connection refused")


async def _raise_conn_error(*args, **kwargs):  # noqa: ARG001
    raise _FakeRedisConnError("Redis connection refused")


async def _redis_miss(*args, **kwargs):  # noqa: ARG001
    """Simulates Redis key not present (MISS)."""
    return None


async def _db_row_not_revoked(*args, **kwargs):  # noqa: ARG001
    """Simulates a DB row where revoked_at IS NULL (active session)."""
    return SimpleNamespace(revoked_at=None)


async def _db_row_revoked(*args, **kwargs):  # noqa: ARG001
    """Simulates a DB row where revoked_at is set (revoked session)."""
    from datetime import datetime, timezone
    return SimpleNamespace(revoked_at=datetime.now(timezone.utc))


async def _db_row_none(*args, **kwargs):  # noqa: ARG001
    """Simulates no DB row (JTI was never issued)."""
    return None


# ---------------------------------------------------------------------------
# Import shim — load _is_session_jti_revoked without the full app lifespan
# ---------------------------------------------------------------------------

def _get_fn():
    """
    Return the _is_session_jti_revoked function.
    Import is deferred so monkeypatching happens before the first call.
    """
    from app.middleware.auth import _is_session_jti_revoked
    return _is_session_jti_revoked


# ---------------------------------------------------------------------------
# Core deny-on-error tests (key security property)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_db_error_during_jti_check_denies(monkeypatch):
    """
    If the DB raises an error and Redis also errors, the check MUST deny (return True).
    Previously the code did `return False` in the except block — this is the regression test.
    """
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _raise_dbapi_error)
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _raise_conn_error)
    fn = _get_fn()
    result = await fn("some-jti")
    assert result is True, "Expected DENY (True) when both Redis and DB error"


@pytest.mark.asyncio
async def test_redis_error_falls_through_to_db_error_denies(monkeypatch):
    """Redis error falls through to DB; DB also errors → deny."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _raise_conn_error)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _raise_dbapi_error)
    fn = _get_fn()
    result = await fn("error-jti")
    assert result is True, "Expected DENY when redis errors and db also errors"


@pytest.mark.asyncio
async def test_redis_error_falls_through_to_db_hit_active(monkeypatch):
    """Redis errors → fall through to DB; DB returns active row → NOT revoked (False)."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _raise_conn_error)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_row_not_revoked)
    fn = _get_fn()
    result = await fn("active-jti")
    assert result is False, "Expected ALLOW (False) when Redis errors but DB says session is active"


@pytest.mark.asyncio
async def test_redis_error_falls_through_to_db_hit_revoked(monkeypatch):
    """Redis errors → fall through to DB; DB returns revoked row → DENY (True)."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _raise_conn_error)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_row_revoked)
    fn = _get_fn()
    result = await fn("revoked-jti")
    assert result is True, "Expected DENY (True) when DB says session is revoked"


# ---------------------------------------------------------------------------
# Redis fast-path tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_redis_hit_short_circuits_db(monkeypatch):
    """
    Redis key `revoked_jti:{jti}` exists → immediately return DENY without touching DB.
    """
    async def _redis_hit(jti: str):
        return "1"  # key exists

    db_called = []

    async def _db_should_not_be_called(jti: str):
        db_called.append(jti)
        return SimpleNamespace(revoked_at=None)

    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _redis_hit)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_should_not_be_called)
    fn = _get_fn()
    result = await fn("abc")
    assert result is True, "Redis hit must return DENY immediately"
    assert db_called == [], "DB must NOT be called when Redis cache hit"


@pytest.mark.asyncio
async def test_redis_miss_falls_through_to_db_active(monkeypatch):
    """Redis miss (key absent) → fall through to DB; DB says active → allow."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _redis_miss)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_row_not_revoked)
    fn = _get_fn()
    result = await fn("active-jti")
    assert result is False, "Expected ALLOW (False) when Redis misses and DB says active"


# ---------------------------------------------------------------------------
# DB-only path tests (unknown JTI = deny)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_jti_not_in_db_denies(monkeypatch):
    """
    JTI not present in oidc_sessions table at all → deny (possible forged token).
    This is the existing 'never issued' invariant.
    """
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _redis_miss)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_row_none)
    fn = _get_fn()
    result = await fn("unknown-jti")
    assert result is True, "Expected DENY (True) for JTI not found in oidc_sessions"


@pytest.mark.asyncio
async def test_valid_active_session_allows(monkeypatch):
    """Happy path: Redis miss, DB returns active row → allow."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _redis_miss)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _db_row_not_revoked)
    fn = _get_fn()
    result = await fn("valid-jti")
    assert result is False, "Expected ALLOW (False) for valid active session"


@pytest.mark.asyncio
async def test_db_only_error_denies(monkeypatch):
    """Redis miss, DB errors → deny (fail-closed)."""
    monkeypatch.setattr("app.middleware.auth._redis_jti_lookup", _redis_miss)
    monkeypatch.setattr("app.middleware.auth._db_jti_lookup", _raise_dbapi_error)
    fn = _get_fn()
    result = await fn("some-jti")
    assert result is True, "Expected DENY (True) when Redis misses and DB errors"


# ---------------------------------------------------------------------------
# Integration test: login → revoke → postgres down → request → 401
# (requires running services: postgres + redis + proxy)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_revoked_session_denied_when_postgres_down():
    """
    End-to-end integration test:
      1. Authenticate and obtain a session JWT.
      2. Revoke the session via POST /api/v1/auth/oidc/logout.
      3. Stop postgres container.
      4. Re-attempt a request with the revoked JWT.
      5. Assert HTTP 401 (was HTTP 200 under the fail-open bug).

    This test requires:
      - Running compose stack (postgres, redis, proxy)
      - Ability to stop the postgres container mid-test
      - INTEGRATION_TEST=1 env var to gate execution

    The key invariant: after revocation, Redis holds `revoked_jti:{jti}` = "1",
    so even if postgres goes down, the Redis fast-path denies the revoked JTI.
    """
    import os
    import subprocess
    import time

    import httpx

    if not os.environ.get("INTEGRATION_TEST"):
        pytest.skip("Set INTEGRATION_TEST=1 to run this test")

    proxy_url = os.environ.get("PROXY_URL", "http://localhost:8000")
    test_user = os.environ.get("TEST_OIDC_USER", "testuser")
    test_pass = os.environ.get("TEST_OIDC_PASS", "testpass")

    async with httpx.AsyncClient(base_url=proxy_url, follow_redirects=False) as client:
        # Step 1: PKCE login — get session JWT (abbreviated; in real test use full OIDC flow)
        # For integration, we use a pre-obtained session JWT via test helper.
        session_jwt = os.environ.get("TEST_SESSION_JWT")
        if not session_jwt:
            pytest.skip("Set TEST_SESSION_JWT to a valid session JWT for integration test")

        # Verify the token works before revocation
        pre_resp = await client.get(
            "/api/v1/auth/oidc/session",
            headers={"Authorization": f"Bearer {session_jwt}"},
        )
        assert pre_resp.status_code == 200, f"Pre-revoke session check failed: {pre_resp.text}"

        # Step 2: Revoke the session
        logout_resp = await client.post(
            "/api/v1/auth/oidc/logout",
            headers={"Authorization": f"Bearer {session_jwt}"},
        )
        assert logout_resp.status_code == 200, f"Logout failed: {logout_resp.text}"

        # Step 3: Stop postgres (requires docker/podman socket access)
        pg_container = os.environ.get("POSTGRES_CONTAINER", "mcp-security-platform-postgres-1")
        try:
            subprocess.run(["podman", "stop", pg_container], check=True, timeout=15)
        except Exception as e:
            pytest.skip(f"Cannot stop postgres container {pg_container}: {e}")

        try:
            # Brief wait for stop to propagate
            time.sleep(1)

            # Step 4: Attempt request with revoked JWT (postgres is down)
            post_resp = await client.get(
                "/api/v1/auth/oidc/session",
                headers={"Authorization": f"Bearer {session_jwt}"},
            )
            # Step 5: Assert 401 — Redis fast-path should deny even without postgres
            assert post_resp.status_code == 401, (
                f"Expected 401 for revoked session (postgres down), got {post_resp.status_code}. "
                f"Body: {post_resp.text}. This indicates fail-open regression on Redis+DB outage."
            )
        finally:
            # Restore postgres
            subprocess.run(["podman", "start", pg_container], check=False, timeout=15)
