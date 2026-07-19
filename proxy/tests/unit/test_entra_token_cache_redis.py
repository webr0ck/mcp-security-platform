"""
Unit tests — Entra client_credentials token cache via Redis (Task 3.6, AUTH-F14 / AUTH-R7)

Covers:
  - Cache HIT: a cached token is returned without calling Entra token endpoint
  - Cache MISS / expired: falls through to a fresh token fetch from Entra
  - Redis DOWN during read: falls through to fresh fetch (never fail-closed on cache miss)
  - Redis DOWN during write: token is still returned (write failure is non-fatal)
  - Fresh token is written to Redis after a successful fetch
  - TTL is set to expires_in - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS

All tests mock httpx and Redis. The credential_store retrieval is also mocked.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    _ENTRA_TOKEN_CACHE_MARGIN_SECONDS,
    _inject_entra_client_credentials,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

_CRED_DICT = {
    "tenant_id": "tenant-abc",
    "client_id": "app-client-xyz",
    "client_secret": "s3cr3t",
}

_REDIS_KEY = f"entra:cc:{_CRED_DICT['tenant_id']}:{_CRED_DICT['client_id']}"

_TOOL_RECORD = {
    "tool_id": "tool-entra-1",
    "service_name": "m365",
    "credential_id": "cred-entra-001",
    "inject_header": "Authorization",
    "inject_prefix": "Bearer",
}


def _mock_broker_and_retrieve(cred_dict: dict = _CRED_DICT):
    """
    Context manager stack that:
      1. Sets broker_instance to a non-None sentinel.
      2. Mocks retrieve_credential to return cred_dict.
    """
    broker_sentinel = MagicMock()
    broker_sentinel.vault_client = MagicMock()
    broker_sentinel.db_pool = MagicMock()

    return (
        patch("app.services.invocation.broker_instance", broker_sentinel),
        patch(
            "app.services.credential_storage.retrieve_credential",
            new_callable=AsyncMock,
            return_value=cred_dict,
        ),
    )


def _make_redis_mock(cached_value: str | None = None):
    """Return an async Redis mock with get/setex wired."""
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=cached_value)
    redis_mock.setex = AsyncMock(return_value=True)
    return redis_mock


def _make_redis_pool_mock(redis_mock):
    pool = MagicMock()
    pool.client = redis_mock
    return pool


def _make_httpx_response(access_token: str = "fresh-entra-token", expires_in: int = 3600):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"access_token": access_token, "expires_in": expires_in})
    return resp


# ---------------------------------------------------------------------------
# Cache HIT
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_cache_hit_skips_entra_request():
    """
    When Redis returns a cached token, _inject_entra_client_credentials must return it
    WITHOUT calling the Entra token endpoint.
    """
    cached_json = json.dumps({"access_token": "cached-entra-token"})
    redis_mock = _make_redis_mock(cached_value=cached_json)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient") as mock_httpx:

        result = await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    assert result == {"Authorization": "Bearer cached-entra-token", "X-Entra-Auth-Mode": "app-only"}
    # Must NOT have called the Entra token endpoint
    mock_httpx.assert_not_called()


# ---------------------------------------------------------------------------
# Cache MISS → fresh fetch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_cache_miss_triggers_fresh_fetch():
    """
    When Redis returns None (cache miss), a fresh token must be fetched from Entra
    and then written back to Redis.
    """
    redis_mock = _make_redis_mock(cached_value=None)  # cache miss

    mock_resp = _make_httpx_response(access_token="fresh-token-001", expires_in=3600)
    mock_http_client = AsyncMock()
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)
    mock_http_client.post = AsyncMock(return_value=mock_resp)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient", return_value=mock_http_client):

        result = await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    assert result == {"Authorization": "Bearer fresh-token-001", "X-Entra-Auth-Mode": "app-only"}
    # Token must be written to Redis with correct TTL
    expected_ttl = max(1, 3600 - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS)
    redis_mock.setex.assert_awaited_once_with(
        _REDIS_KEY,
        expected_ttl,
        json.dumps({"access_token": "fresh-token-001"}),
    )


# ---------------------------------------------------------------------------
# Redis DOWN during read → falls through to fresh fetch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_read_failure_falls_through_to_fresh_fetch():
    """
    When Redis is unavailable (raises on GET), the dispatcher must fall through
    to a fresh token fetch — never fail-closed on a cache read failure.
    """
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(side_effect=ConnectionError("Redis down"))
    redis_mock.setex = AsyncMock(return_value=True)

    mock_resp = _make_httpx_response(access_token="fresh-redis-down-token", expires_in=3600)
    mock_http_client = AsyncMock()
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)
    mock_http_client.post = AsyncMock(return_value=mock_resp)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient", return_value=mock_http_client):

        result = await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    # Auth still works — we get a token even with Redis down
    assert result == {"Authorization": "Bearer fresh-redis-down-token", "X-Entra-Auth-Mode": "app-only"}
    # GET was attempted
    redis_mock.get.assert_awaited_once()


# ---------------------------------------------------------------------------
# Redis DOWN during write → token still returned
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_write_failure_does_not_prevent_token_return():
    """
    When Redis raises on SETEX (write failure), the dispatcher must still return
    the freshly-fetched token — write failures are non-fatal.
    """
    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)         # cache miss
    redis_mock.setex = AsyncMock(side_effect=ConnectionError("Redis write failed"))

    mock_resp = _make_httpx_response(access_token="fresh-write-fail-token", expires_in=3600)
    mock_http_client = AsyncMock()
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)
    mock_http_client.post = AsyncMock(return_value=mock_resp)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient", return_value=mock_http_client):

        result = await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    assert result == {"Authorization": "Bearer fresh-write-fail-token", "X-Entra-Auth-Mode": "app-only"}


# ---------------------------------------------------------------------------
# TTL calculation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_ttl_uses_expires_in_minus_margin():
    """
    The Redis TTL must be set to expires_in - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS.
    Verify the correct TTL is passed to setex.
    """
    expires_in = 7200  # 2-hour token

    redis_mock = _make_redis_mock(cached_value=None)

    mock_resp = _make_httpx_response(access_token="ttl-test-token", expires_in=expires_in)
    mock_http_client = AsyncMock()
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)
    mock_http_client.post = AsyncMock(return_value=mock_resp)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient", return_value=mock_http_client):

        await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    expected_ttl = max(1, expires_in - _ENTRA_TOKEN_CACHE_MARGIN_SECONDS)
    _call = redis_mock.setex.call_args
    assert _call.args[1] == expected_ttl or _call[0][1] == expected_ttl, (
        f"Expected Redis TTL={expected_ttl}, got setex call: {_call}"
    )


# ---------------------------------------------------------------------------
# Redis key format
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_redis_cache_key_format():
    """
    The Redis cache key must be 'entra:cc:{tenant_id}:{client_id}'.
    Verifies the key passed to get (and setex) matches the expected pattern.
    """
    redis_mock = _make_redis_mock(cached_value=None)

    mock_resp = _make_httpx_response(access_token="key-format-token", expires_in=3600)
    mock_http_client = AsyncMock()
    mock_http_client.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client.__aexit__ = AsyncMock(return_value=None)
    mock_http_client.post = AsyncMock(return_value=mock_resp)

    broker_patch, retrieve_patch = _mock_broker_and_retrieve()
    with broker_patch, retrieve_patch, \
         patch("app.core.redis_client.redis_pool", _make_redis_pool_mock(redis_mock)), \
         patch("httpx.AsyncClient", return_value=mock_http_client):

        await _inject_entra_client_credentials(
            tool_record=_TOOL_RECORD,
            inject_header="Authorization",
            inject_prefix="Bearer",
        )

    expected_key = f"entra:cc:{_CRED_DICT['tenant_id']}:{_CRED_DICT['client_id']}"
    redis_mock.get.assert_awaited_once_with(expected_key)
    setex_call = redis_mock.setex.call_args
    assert setex_call.args[0] == expected_key or setex_call[0][0] == expected_key
