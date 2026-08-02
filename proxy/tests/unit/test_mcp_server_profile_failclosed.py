"""
Unit tests — N2 fix: Profile lookup fail-closed in mcp_server.py (INV-015).

Covers the two router-level helpers added/rewritten for N2:
  _lookup_profile_source     (cache key: mcp_profile:v2:id:{client_id}:{tool})
    (the named source uses mcp_profile:v2:uuid:{profile_uuid}:{tool})

And the tools/list dispatch path that must return JSON-RPC error + HTTP 503 when
ProfileLookupError propagates out of _registered_tools_for_client.

Test matrix
-----------
  Test 1: _lookup_profile_source — DB raises, Redis raises ConnectionError
          → ProfileLookupError raised (NOT a passthrough / None return)
  Test 2: _lookup_profile_source — DB raises, Redis returns None (cache miss)
          → ProfileLookupError raised
  Test 3: _lookup_profile_source — DB raises, Redis returns a cached JSON value
          → cached value returned (no exception, no 503)
  Test 4: tools/list handler — _registered_tools_for_client raises ProfileLookupError
          → _dispatch raises _ProfileLookupUnavailable → mcp_post returns HTTP 503
            with JSON-RPC error body

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_mcp_server_profile_failclosed.py -v
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_db_exc() -> Exception:
    """Simulate a SQLAlchemy DB connection failure."""
    return Exception("could not connect to server: Connection refused")


# ---------------------------------------------------------------------------
# Test 1: DB raises, Redis raises ConnectionError → ProfileLookupError
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_lookup_profile_row_db_raises_redis_raises():
    """
    INV-015: when the DB raises AND Redis raises a RedisError (e.g. ECONNREFUSED),
    _lookup_profile_source must raise ProfileLookupError.

    A Redis exception is NOT a cache miss — it must never fall through.
    """
    from app.services.invocation import _lookup_profile_source
    from app.services.invocation import ProfileLookupError

    # DB raises
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(side_effect=_make_db_exc())

    # Redis client raises ConnectionError on .get()
    mock_redis_client = AsyncMock()
    mock_redis_client.get = AsyncMock(side_effect=RedisConnectionError("ECONNREFUSED"))
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis_client

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session), \
         patch("app.core.redis_client.redis_pool", mock_redis_pool):
        with pytest.raises(ProfileLookupError):
            await _lookup_profile_source(
                table="mcp_profiles",
                key_column="profile_id",
                key_value="user-123",
                tool_name="some-mcp-tool",
                cache_key="mcp_profile:v2:id:user-123:some-mcp-tool",
                log_ctx={},
            )


# ---------------------------------------------------------------------------
# Test 2: DB raises, Redis returns None (cache miss) → ProfileLookupError
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_lookup_profile_row_db_raises_redis_miss():
    """
    INV-015: when the DB raises AND Redis returns None (genuine cache miss),
    _lookup_profile_source must raise ProfileLookupError.
    """
    from app.services.invocation import _lookup_profile_source
    from app.services.invocation import ProfileLookupError

    # DB raises
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(side_effect=_make_db_exc())

    # Redis returns None (no cached entry)
    mock_redis_client = AsyncMock()
    mock_redis_client.get = AsyncMock(return_value=None)
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis_client

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session), \
         patch("app.core.redis_client.redis_pool", mock_redis_pool):
        with pytest.raises(ProfileLookupError):
            await _lookup_profile_source(
                table="mcp_profiles",
                key_column="profile_id",
                key_value="user-123",
                tool_name="some-mcp-tool",
                cache_key="mcp_profile:v2:id:user-123:some-mcp-tool",
                log_ctx={},
            )


# ---------------------------------------------------------------------------
# Test 3: DB raises, Redis returns cached value → cached value returned
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_lookup_profile_row_db_raises_redis_hit():
    """
    INV-015: when the DB raises but Redis has a cached profile row,
    _lookup_profile_source must return the cached value without raising.

    This is the last-known-state path — availability via cache on transient DB blip.
    """
    from app.services.invocation import _lookup_profile_source

    cached_row = {"enabled": True}

    # DB raises
    mock_session = AsyncMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.execute = AsyncMock(side_effect=_make_db_exc())

    # Redis returns a JSON-encoded cached row
    mock_redis_client = AsyncMock()
    mock_redis_client.get = AsyncMock(return_value=json.dumps(cached_row))
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis_client

    with patch("app.core.database.AsyncSessionLocal", return_value=mock_session), \
         patch("app.core.redis_client.redis_pool", mock_redis_pool):
        result = await _lookup_profile_source(
                table="mcp_profiles",
                key_column="profile_id",
                key_value="user-123",
                tool_name="some-mcp-tool",
                cache_key="mcp_profile:v2:id:user-123:some-mcp-tool",
                log_ctx={},
            )

    assert result == cached_row, (
        f"Expected cached row {cached_row!r}, got {result!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: tools/list — ProfileLookupError propagates → HTTP 503 JSON-RPC error
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_tools_list_profile_lookup_error_returns_503():
    """
    INV-015: when _registered_tools_for_client raises ProfileLookupError,
    the tools/list handler must NOT return a 200. It must raise
    _ProfileLookupUnavailable, which mcp_post converts to HTTP 503 with a
    valid JSON-RPC error body containing code -32603.
    """
    from fastapi import Request
    from starlette.datastructures import State
    from app.services.invocation import ProfileLookupError
    from app.routers.mcp_server import _dispatch, _ProfileLookupUnavailable

    # Build a minimal fake Request with required state
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": [],
        "query_string": b"",
    }
    fake_request = Request(scope=scope)
    fake_request._state = State()
    fake_request.state.client_id = "test-client"
    fake_request.state.client_roles = ["agent"]
    fake_request.state.principal_id = "test-client"
    fake_request.state.principal_type = "user"
    fake_request.state.profile_uuid = None
    fake_request.state.request_id = "req-test-profile-503"

    tools_list_body = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/list",
        "params": {},
    }

    with patch(
        "app.routers.mcp_server._registered_tools_for_client",
        new=AsyncMock(side_effect=ProfileLookupError("DB down, no cache")),
    ):
        with pytest.raises(_ProfileLookupUnavailable) as exc_info:
            await _dispatch(tools_list_body, fake_request)

    rpc_error = exc_info.value.rpc_error
    assert rpc_error.get("jsonrpc") == "2.0", "Response must be JSON-RPC 2.0"
    assert rpc_error.get("id") == 42, "Response must echo the request id"
    assert "error" in rpc_error, "Response must have an 'error' key"
    assert rpc_error["error"]["code"] == -32603, (
        f"Expected error code -32603, got {rpc_error['error']['code']!r}"
    )
    assert "unavailable" in rpc_error["error"]["message"].lower(), (
        f"Error message should mention 'unavailable': {rpc_error['error']['message']!r}"
    )
