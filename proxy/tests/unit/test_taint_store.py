"""Unit tests for the fail-closed taint store (PRD-0001 M2 / RFC-0001 §8.1, INV-015).

The taint store is the OPPOSITE of the mcp_session cache: it fails CLOSED. A read
error or an unavailable store means "treat the session as tainted" (deny high sinks),
never "clean". A write failure must raise so the caller fails the in-flight request
closed (write-before-forward). It uses a distinct `mcp_taint:` namespace so it can
never be confused with the fail-open `mcp_session:` cache.

These tests inject a fake async Redis client to exercise OUR error handling, not Redis.
"""

import pytest

from app.services.taint_store import (
    TaintStoreError,
    is_tainted,
    mark_tainted,
    taint_key,
)


class _FakeRedis:
    def __init__(self, value=None, raise_on_get=False, raise_on_setex=False):
        self._value = value
        self._raise_on_get = raise_on_get
        self._raise_on_setex = raise_on_setex
        self.setex_calls = []

    async def get(self, key):
        if self._raise_on_get:
            raise ConnectionError("redis down")
        return self._value

    async def setex(self, key, ttl, value):
        if self._raise_on_setex:
            raise ConnectionError("redis down")
        self.setex_calls.append((key, ttl, value))


# --- namespace isolation ---

def test_taint_key_uses_distinct_namespace():
    key = taint_key("human:kc:alice")
    assert key.startswith("mcp_taint:")
    assert "mcp_session:" not in key


# --- is_tainted: fail-closed reads ---

async def test_is_tainted_failclosed_when_client_none():
    assert await is_tainted(None, "human:kc:alice") is True


async def test_is_tainted_failclosed_when_principal_none():
    # No principal -> cannot key a clean session -> tainted (H-2).
    assert await is_tainted(_FakeRedis(value=None), None) is True


async def test_mark_tainted_raises_when_principal_none():
    with pytest.raises(TaintStoreError):
        await mark_tainted(_FakeRedis(), None)


async def test_is_tainted_failclosed_on_read_error():
    client = _FakeRedis(raise_on_get=True)
    assert await is_tainted(client, "human:kc:alice") is True


async def test_is_tainted_true_when_bit_present():
    client = _FakeRedis(value=b"1")
    assert await is_tainted(client, "human:kc:alice") is True


async def test_is_tainted_false_when_absent_and_healthy():
    client = _FakeRedis(value=None)
    assert await is_tainted(client, "human:kc:alice") is False


# --- mark_tainted: write-before-forward, raise on failure ---

async def test_mark_tainted_raises_when_client_none():
    with pytest.raises(TaintStoreError):
        await mark_tainted(None, "human:kc:alice")


async def test_mark_tainted_raises_on_write_error():
    client = _FakeRedis(raise_on_setex=True)
    with pytest.raises(TaintStoreError):
        await mark_tainted(client, "human:kc:alice")


async def test_mark_tainted_writes_taint_bit():
    client = _FakeRedis()
    await mark_tainted(client, "human:kc:alice")
    assert len(client.setex_calls) == 1
    key, ttl, value = client.setex_calls[0]
    assert key == taint_key("human:kc:alice")
    assert ttl > 0


# --- LOGIC-005 fix: taint key is stable across auth methods ---

def test_taint_key_same_client_id_is_stable():
    """Same client_id always produces the same taint key (deterministic)."""
    from app.services.taint_store import taint_key
    assert taint_key("alice@corp") == taint_key("alice@corp")


def test_taint_key_differs_across_identities():
    """Different logical identities must produce different taint keys."""
    from app.services.taint_store import taint_key
    assert taint_key("alice@corp") != taint_key("bob@corp")


def test_taint_key_does_not_encode_auth_method():
    """The old principal_id namespace (human:oidc-issuer:alice vs human:apikey:alice)
    produced different keys for the same human. The new key (client_id directly)
    must be identical for both auth paths for the same logical identity.
    """
    from app.services.taint_store import taint_key
    # Both OIDC and API-key auth for alice@corp yield the same client_id="alice@corp"
    # so they must share one taint key. Verify the function is stable for that value.
    key = taint_key("alice@corp")
    assert key.startswith("mcp_taint:")
    # Historically principal_id would have been "human:oidc-issuer:alice@corp"
    # or "human:apikey:alice@corp" — those would have hashed differently.
    # Now both callers pass client_id="alice@corp" and get the same key.
    assert taint_key("human:oidc-issuer:alice@corp") != key  # old path would have differed
    assert taint_key("human:apikey:alice@corp") != key       # old path would have differed
