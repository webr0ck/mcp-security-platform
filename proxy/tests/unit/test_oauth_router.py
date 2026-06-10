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
async def test_enroll_renders_consent_page():
    """
    R-5 / D1 / D2: GET /auth/enroll/{svc} now renders a consent page (200 HTML).
    It does NOT immediately 302 to Entra — PKCE state is minted only after POST /consent.

    Previously tested as 'test_enroll_mints_nonce_and_pkce' (CB-003/011), which
    expected a 302. Updated to match the consent-gate design (ADR-003 D1/D2).
    """
    fake_redis = _FakeRedis()
    redis_pool_mock = MagicMock()
    redis_pool_mock.client = fake_redis
    with patch("app.core.redis_client.redis_pool", redis_pool_mock), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/m365",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )
    # D1: must return HTML consent page, NOT a 302 redirect to Entra
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    # D2: a pending enroll_consent: record is written (keyed by CSRF token)
    consent_keys = [k for k in fake_redis.store if k.startswith("enroll_consent:")]
    assert len(consent_keys) == 1, (
        f"D2: exactly one enroll_consent: record; found {consent_keys}"
    )
    record = json.loads(fake_redis.store[consent_keys[0]])
    assert record["client_id"] == "alice@corp"
    assert record["service"] == "m365"
    # D2: NO oauth_flow: (PKCE state) written at GET time — only after POST /consent
    pkce_keys = [k for k in fake_redis.store if k.startswith("oauth_flow:")]
    assert not pkce_keys, f"D2: oauth_flow: must not be written at GET time; found {pkce_keys}"


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


# ---------------------------------------------------------------------------
# Task 12: server-scoped enrollment tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_enroll_falls_back_to_hardcoded_adapter_when_registry_unavailable():
    """
    Task 12: When registry_instance is None (e.g., startup failure),
    fallback to hardcoded adapters (m365, bitbucket, dex).
    """
    fake_redis = _FakeRedis()
    redis_pool_mock = MagicMock()
    redis_pool_mock.client = fake_redis

    with patch("app.services.invocation.registry_instance", None), \
         patch("app.core.redis_client.redis_pool", redis_pool_mock), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/m365",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )

    # Should fall back to hardcoded adapter and render consent page
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")


@pytest.mark.unit
async def test_enroll_registry_config_not_found_falls_back_to_hardcoded():
    """
    Task 12: When service is not in registry, fall back to hardcoded adapters.
    """
    fake_redis = _FakeRedis()
    redis_pool_mock = MagicMock()
    redis_pool_mock.client = fake_redis

    # Mock registry to return None for this service
    mock_registry = MagicMock()
    mock_registry.get_config = MagicMock(return_value=None)

    with patch("app.services.invocation.registry_instance", mock_registry), \
         patch("app.core.redis_client.redis_pool", redis_pool_mock), \
         patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/m365",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )

    # Should fall back to hardcoded adapter and render consent page
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
