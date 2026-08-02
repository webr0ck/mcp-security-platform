"""
JWKS fetch: error backoff, single-flight, and bounded staleness.

_fetch_jwks sits on the hot path of EVERY OIDC-authenticated request. Before this,
a failed fetch did not update `fetched_at`, so an IdP outage made each inbound request
re-attempt discovery + fetch (up to 3 HTTP calls at 5s each) against the already-failing
issuer — the proxy amplified the outage instead of absorbing it. Stale keys were also
served forever, so keys the issuer had rotated away stayed trusted indefinitely.

These tests count actual fetch attempts and assert the fail-closed edge, so a regression
that removes the backoff or the staleness bound goes red rather than merely slow.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.middleware import auth

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _clean_cache():
    auth._jwks_cache.clear()
    yield
    auth._jwks_cache.clear()


def _failing_client(counter: list[int]):
    """An httpx.AsyncClient stand-in whose GET always fails, counting attempts."""
    class _C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k):
            counter.append(1)
            raise RuntimeError("issuer down")
    return _C


@pytest.mark.asyncio
async def test_failed_fetch_backs_off_instead_of_retrying_every_request():
    calls: list[int] = []
    with patch.object(auth, "_discover_jwks_uri", AsyncMock(return_value="http://idp/keys")), \
         patch("httpx.AsyncClient", _failing_client(calls)):
        for _ in range(20):
            assert await auth._fetch_jwks() == []

    # Exactly one attempt: the first. The other 19 must be served by the backoff.
    assert len(calls) == 1, (
        f"{len(calls)} JWKS fetches for 20 requests — the error backoff is not holding, "
        "so an IdP outage is amplified by every inbound request"
    )
    assert auth._jwks_cache.get("retry_after", 0) > 0


@pytest.mark.asyncio
async def test_concurrent_misses_trigger_a_single_fetch():
    calls: list[int] = []

    class _SlowOK:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k):
            calls.append(1)
            await asyncio.sleep(0.05)          # hold the lock so the others pile up
            r = AsyncMock()
            r.raise_for_status = lambda: None
            r.json = lambda: {"keys": [{"kid": "k1"}]}
            return r

    with patch.object(auth, "_discover_jwks_uri", AsyncMock(return_value="http://idp/keys")), \
         patch("httpx.AsyncClient", _SlowOK):
        results = await asyncio.gather(*[auth._fetch_jwks() for _ in range(10)])

    assert len(calls) == 1, f"{len(calls)} concurrent fetches — single-flight lock is not working"
    assert all(r == [{"kid": "k1"}] for r in results), "losers of the race got no keys"


@pytest.mark.asyncio
async def test_stale_keys_are_served_briefly_then_fail_closed():
    auth._jwks_cache.update({"keys": [{"kid": "old"}], "fetched_at": 0.0, "jwks_uri": "http://idp/keys"})

    # Just inside the staleness bound: keep serving last-known-good.
    assert auth._stale_jwks_or_empty(auth._JWKS_MAX_STALE - 1) == [{"kid": "old"}]

    # Past it: refuse. Returning keys here would keep trusting a possibly-rotated signing
    # key forever, which is the whole reason the bound exists.
    assert auth._stale_jwks_or_empty(auth._JWKS_MAX_STALE + 1) == [], (
        "JWKS older than the staleness bound was still served — a rotated-away signing "
        "key would stay trusted for as long as the issuer is unreachable"
    )


@pytest.mark.asyncio
async def test_recovery_clears_the_backoff():
    calls: list[int] = []
    with patch.object(auth, "_discover_jwks_uri", AsyncMock(return_value="http://idp/keys")), \
         patch("httpx.AsyncClient", _failing_client(calls)):
        await auth._fetch_jwks()
    assert "retry_after" in auth._jwks_cache

    class _OK:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k):
            r = AsyncMock()
            r.raise_for_status = lambda: None
            r.json = lambda: {"keys": [{"kid": "new"}]}
            return r

    auth._jwks_cache.pop("retry_after")          # simulate the backoff window elapsing
    with patch("httpx.AsyncClient", _OK):
        assert await auth._fetch_jwks() == [{"kid": "new"}]
    assert "retry_after" not in auth._jwks_cache, "backoff survived a successful fetch"
