"""
Regression tests for the credential-broker OAuth router after the
CB-001 / CB-003 / CB-004 / CB-011 hardening.

Invariants under test:
  * enroll is an authenticated endpoint (no identity -> 401)        [CB-001]
  * enroll mints an unguessable server-side nonce + PKCE challenge   [CB-003/011]
  * callback identity comes from the stored nonce, NEVER a header    [CB-001]
  * an unknown/replayed state is rejected                            [CB-003]
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport


class _FakeRedis:
    def __init__(self, store: dict | None = None) -> None:
        self.store = store if store is not None else {}
        self.setex = AsyncMock(side_effect=self._setex)

    async def _setex(self, key, ttl, val):
        self.store[key] = val

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self) -> None:
                self._key = None

            def get(self, key):
                self._key = key
                return self

            def delete(self, key):
                return self

            async def execute(self):
                return [outer.store.get(self._key), 1]

        return _Pipe()


class _FakeAdapter:
    def build_auth_url(self, state: str, code_challenge: str | None = None) -> str:
        return f"https://idp.example/auth?state={state}&code_challenge={code_challenge}"

    async def exchange_code(self, code: str, code_verifier: str | None = None):
        assert code_verifier, "PKCE code_verifier must be passed to exchange_code"
        return ("access-tok", "refresh-tok", 3600)


def _client():
    from app.main import app
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


@pytest.mark.unit
async def test_enroll_without_identity_is_401():
    """CB-001: /auth/enroll is protected; no cert/key/JWT -> 401, no redirect."""
    async with _client() as c:
        resp = await c.get("/auth/enroll/m365", follow_redirects=False)
    assert resp.status_code == 401


@pytest.mark.unit
async def test_enroll_mints_nonce_and_pkce():
    """CB-003/011: enroll stores a server-side nonce and sends an S256 challenge."""
    fake_redis = _FakeRedis()
    redis_pool = MagicMock()
    redis_pool.client = fake_redis
    with patch("app.core.redis_client.redis_pool", redis_pool), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/m365",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )
    assert resp.status_code == 302
    loc = resp.headers["location"]
    assert "code_challenge=" in loc and "code_challenge=None" not in loc
    # exactly one pending-flow record was written, keyed by the nonce == state
    assert len(fake_redis.store) == 1
    stored_key = next(iter(fake_redis.store))
    nonce = stored_key.split("oauth_flow:")[-1]
    assert f"state={nonce}" in loc
    flow = json.loads(fake_redis.store[stored_key])
    assert flow["client_id"] == "alice@corp" and flow["service"] == "m365"
    assert len(nonce) >= 32  # unguessable


@pytest.mark.unit
async def test_callback_identity_is_stored_not_header():
    """
    CB-001 core: a spoofed X-Client-Cert-CN on the callback must be ignored;
    the credential is encrypted+stored under the identity bound at enroll.
    """
    nonce = "server-minted-nonce-value-1234567890"
    fake_redis = _FakeRedis(store={
        f"oauth_flow:{nonce}": json.dumps(
            {"client_id": "legit-user@corp", "service": "m365", "cv": "verifier-xyz"}
        )
    })
    redis_pool = MagicMock()
    redis_pool.client = fake_redis

    captured = {}

    class _FakeDB:
        async def execute(self, _stmt, params):
            captured.update(params)

        async def commit(self):
            pass

    async def _fake_get_db():
        yield _FakeDB()

    kms = MagicMock()
    kms.get_master_secret = AsyncMock(return_value=b"\x00" * 32)

    with patch("app.core.redis_client.redis_pool", redis_pool), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
         patch("app.credential_broker.kms.VaultKMSClient", return_value=kms), \
         patch("app.routers.oauth._emit_credential_audit", new=AsyncMock()), \
         patch("app.core.database.get_db", _fake_get_db):
        async with _client() as c:
            resp = await c.get(
                f"/auth/callback/m365?code=abc&state={nonce}",
                headers={"X-Client-Cert-CN": "attacker@evil"},  # spoof attempt
                follow_redirects=False,
            )
    assert resp.status_code == 200
    assert captured["sub"] == "legit-user@corp"  # NOT attacker@evil
    assert captured["svc"] == "m365"


@pytest.mark.unit
async def test_callback_unknown_state_rejected():
    """CB-003: a callback whose state is not in the server-side store -> 400."""
    fake_redis = _FakeRedis()  # empty
    redis_pool = MagicMock()
    redis_pool.client = fake_redis
    with patch("app.core.redis_client.redis_pool", redis_pool), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
        async with _client() as c:
            resp = await c.get(
                "/auth/callback/m365?code=abc&state=forged-or-expired",
                follow_redirects=False,
            )
    assert resp.status_code == 400


@pytest.mark.unit
async def test_enroll_unknown_service_returns_404():
    async with _client() as c:
        resp = await c.get(
            "/auth/enroll/nonexistent",
            headers={"X-Client-Cert-CN": "alice@corp"},
            follow_redirects=False,
        )
    assert resp.status_code == 404
