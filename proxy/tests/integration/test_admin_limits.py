"""Integration tests for admin_limits router (Task 5).

These tests exercise the router functions directly with monkeypatched DB pool
and Redis clients. No running PostgreSQL, Redis, or OPA instance is required —
the repo's live integration tests (test_invoke.py, etc.) require docker compose
and are skipped in CI; this test is designed to run standalone with
  cd proxy && ENVIRONMENT=development python3 -m pytest tests/integration/test_admin_limits.py -v

Coverage:
  (a) _require_admin raises 403 when client_roles lacks admin
  (b) put_limit upserts + calls invalidate + emits audit
  (c) reset_limit with target='both' deletes both Redis keys
  (d) reset_limit over the cap (>10) returns 429
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(roles: list[str], client_id: str = "admin-actor") -> SimpleNamespace:
    """Build a minimal fake FastAPI Request object."""
    state = SimpleNamespace(client_roles=roles, client_id=client_id)
    return SimpleNamespace(state=state)


# ---------------------------------------------------------------------------
# (a) _require_admin raises 403 for non-admin roles
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_require_admin_raises_403_for_non_admin():
    from fastapi import HTTPException
    from app.routers.admin_limits import _require_admin

    for bad_role in (["agent"], ["auditor"], ["readonly"], []):
        req = _make_request(bad_role)
        with pytest.raises(HTTPException) as exc_info:
            _require_admin(req)
        assert exc_info.value.status_code == 403


@pytest.mark.asyncio
async def test_require_admin_passes_for_admin_roles():
    from app.routers.admin_limits import _require_admin

    for good_role in (["admin"], ["platform_admin"], ["admin", "auditor"]):
        req = _make_request(good_role)
        _require_admin(req)  # must not raise


# ---------------------------------------------------------------------------
# (b) put_limit upserts + calls invalidate + emits audit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_put_limit_upserts_and_emits_audit():
    from app.routers.admin_limits import put_limit, LimitUpdate

    req = _make_request(["admin"], client_id="admin-actor")

    # Fake asyncpg pool
    fake_prev_row = None  # no existing row — insert path
    mock_pool = MagicMock()
    mock_pool.fetchrow = AsyncMock(return_value=fake_prev_row)
    mock_pool.execute = AsyncMock(return_value="INSERT 0 1")

    with (
        patch("app.routers.admin_limits._db", AsyncMock(return_value=mock_pool)),
        patch("app.routers.admin_limits.limits_svc.invalidate", AsyncMock()) as mock_invalidate,
        patch("app.routers.admin_limits.emit_admin_config_event", AsyncMock()) as mock_emit,
        patch("app.routers.admin_limits.get_settings", return_value=MagicMock(DEFAULT_RATE_LIMIT=100)),
    ):
        body = LimitUpdate(rate_limit=50, anomaly_sensitivity="lenient")
        result = await put_limit("test-client", body, req)

    assert result == {"ok": True, "client_id": "test-client"}
    # Pool execute was called (the UPSERT)
    mock_pool.execute.assert_awaited_once()
    # Cache invalidated
    mock_invalidate.assert_awaited_once_with("test-client")
    # Audit emitted (at minimum the set_limits event)
    assert mock_emit.await_count >= 1
    first_call_args = mock_emit.call_args_list[0]
    assert first_call_args.args[0] == "admin-actor"
    assert first_call_args.args[1] == "set_limits"
    assert first_call_args.args[2] == "test-client"


@pytest.mark.asyncio
async def test_put_limit_anomaly_off_emits_extra_audit():
    """Setting sensitivity='off' must emit a second 'anomaly_disabled' audit event."""
    from app.routers.admin_limits import put_limit, LimitUpdate

    req = _make_request(["admin"], client_id="admin-actor")
    mock_pool = MagicMock()
    mock_pool.fetchrow = AsyncMock(return_value=None)
    mock_pool.execute = AsyncMock(return_value="INSERT 0 1")

    with (
        patch("app.routers.admin_limits._db", AsyncMock(return_value=mock_pool)),
        patch("app.routers.admin_limits.limits_svc.invalidate", AsyncMock()),
        patch("app.routers.admin_limits.emit_admin_config_event", AsyncMock()) as mock_emit,
        patch("app.routers.admin_limits.get_settings", return_value=MagicMock(DEFAULT_RATE_LIMIT=100)),
    ):
        body = LimitUpdate(rate_limit=None, anomaly_sensitivity="off")
        await put_limit("dangerous-client", body, req)

    # Must have emitted at least 2 events: set_limits + anomaly_disabled
    assert mock_emit.await_count >= 2
    actions = [c.args[1] for c in mock_emit.call_args_list]
    assert "set_limits" in actions
    assert "anomaly_disabled" in actions
    # anomaly_disabled must be outcome="allow" — SIEM differentiates on tool_name,
    # not outcome; using "deny" would pollute deny-rate dashboards (L5 polish).
    disabled_call = next(c for c in mock_emit.call_args_list if c.args[1] == "anomaly_disabled")
    assert disabled_call.kwargs.get("outcome") == "allow" or (
        len(disabled_call.args) > 4 and disabled_call.args[4] == "allow"
    )


# ---------------------------------------------------------------------------
# (c) reset_limit with target='both' deletes both Redis keys
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_limit_both_deletes_both_redis_keys():
    from app.routers.admin_limits import reset_limit, ResetBody

    req = _make_request(["admin"], client_id="admin-actor")

    mock_rl_client = AsyncMock()
    mock_rl_client.incr = AsyncMock(return_value=1)   # first reset, well under cap
    mock_rl_client.expire = AsyncMock()
    mock_rl_client.delete = AsyncMock()

    mock_anomaly_client = AsyncMock()
    mock_anomaly_client.delete = AsyncMock()

    mock_redis_pool = MagicMock()
    mock_redis_pool.rate_limit_client = mock_rl_client
    mock_redis_pool.client = mock_anomaly_client

    with (
        patch("app.routers.admin_limits.redis_pool", mock_redis_pool),
        patch("app.routers.admin_limits.emit_admin_config_event", AsyncMock()),
    ):
        body = ResetBody(target="both")
        result = await reset_limit("target-client", body, req)

    assert result["ok"] is True
    assert "rate" in result["cleared"]
    assert "anomaly" in result["cleared"]

    # rate key deleted
    mock_rl_client.delete.assert_awaited_once_with("rl:mcp:target-client")
    # anomaly window key deleted
    mock_anomaly_client.delete.assert_awaited_once_with("anomaly:window:target-client")


@pytest.mark.asyncio
async def test_reset_limit_rate_only_does_not_touch_anomaly():
    from app.routers.admin_limits import reset_limit, ResetBody

    req = _make_request(["platform_admin"])

    mock_rl_client = AsyncMock()
    mock_rl_client.incr = AsyncMock(return_value=1)
    mock_rl_client.expire = AsyncMock()
    mock_rl_client.delete = AsyncMock()

    mock_anomaly_client = AsyncMock()
    mock_anomaly_client.delete = AsyncMock()

    mock_redis_pool = MagicMock()
    mock_redis_pool.rate_limit_client = mock_rl_client
    mock_redis_pool.client = mock_anomaly_client

    with (
        patch("app.routers.admin_limits.redis_pool", mock_redis_pool),
        patch("app.routers.admin_limits.emit_admin_config_event", AsyncMock()),
    ):
        result = await reset_limit("target-client", ResetBody(target="rate"), req)

    assert result["cleared"] == ["rate"]
    mock_rl_client.delete.assert_awaited_once_with("rl:mcp:target-client")
    mock_anomaly_client.delete.assert_not_awaited()


# ---------------------------------------------------------------------------
# (d) reset over the cap returns 429
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_reset_limit_over_cap_returns_429():
    from fastapi import HTTPException
    from app.routers.admin_limits import reset_limit, ResetBody, _RESET_RL

    req = _make_request(["admin"])

    mock_rl_client = AsyncMock()
    # Simulate counter already at cap + 1
    mock_rl_client.incr = AsyncMock(return_value=_RESET_RL + 1)
    mock_rl_client.expire = AsyncMock()
    mock_rl_client.delete = AsyncMock()

    mock_redis_pool = MagicMock()
    mock_redis_pool.rate_limit_client = mock_rl_client

    with (
        patch("app.routers.admin_limits.redis_pool", mock_redis_pool),
        patch("app.routers.admin_limits.emit_admin_config_event", AsyncMock()) as mock_emit,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await reset_limit("spammy-client", ResetBody(target="both"), req)

    assert exc_info.value.status_code == 429
    # No actual Redis delete should have happened
    mock_rl_client.delete.assert_not_awaited()
    # A deny audit event must have been emitted for the rate-limited attempt
    assert mock_emit.await_count >= 1
    deny_calls = [c for c in mock_emit.call_args_list if "deny" in str(c)]
    assert len(deny_calls) >= 1


# ---------------------------------------------------------------------------
# (e) get_limit returns blocked_by correctly and tolerates score_window errors
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_limit_blocked_by_rate():
    from app.routers.admin_limits import get_limit

    req = _make_request(["admin"])

    # no override row
    mock_pool = MagicMock()
    mock_pool.fetchrow = AsyncMock(return_value=None)

    settings_mock = MagicMock()
    settings_mock.DEFAULT_RATE_LIMIT = 60

    with (
        patch("app.routers.admin_limits._db", AsyncMock(return_value=mock_pool)),
        patch("app.routers.admin_limits._rate_count", AsyncMock(return_value=200)),
        patch("app.routers.admin_limits.limits_svc.score_window", AsyncMock(return_value=0.1)),
        patch("app.routers.admin_limits.get_settings", return_value=settings_mock),
        patch("app.routers.admin_limits.get_rate_limit_for_roles", return_value=60),
    ):
        result = await get_limit("busy-client", req)

    assert result["blocked_by"] == "rate"
    assert result["rate"]["count"] == 200
    assert result["rate"]["limit"] == 60


@pytest.mark.asyncio
async def test_get_limit_score_window_error_falls_back_to_zero():
    """score_window exceptions must not 500 the admin detail view."""
    from app.routers.admin_limits import get_limit

    req = _make_request(["admin"])
    mock_pool = MagicMock()
    mock_pool.fetchrow = AsyncMock(return_value=None)

    with (
        patch("app.routers.admin_limits._db", AsyncMock(return_value=mock_pool)),
        patch("app.routers.admin_limits._rate_count", AsyncMock(return_value=5)),
        patch("app.routers.admin_limits.limits_svc.score_window", AsyncMock(side_effect=RuntimeError("redis down"))),
        patch("app.routers.admin_limits.get_settings", return_value=MagicMock(DEFAULT_RATE_LIMIT=100)),
        patch("app.routers.admin_limits.get_rate_limit_for_roles", return_value=100),
    ):
        result = await get_limit("flaky-client", req)

    # score defaulted to 0.0 — not blocked by anomaly
    assert result["anomaly"]["score"] == 0.0
    assert result["blocked_by"] == "none"
