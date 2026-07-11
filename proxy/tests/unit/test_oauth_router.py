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

from app.credential_broker.registry import ServerConfig


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


def _fake_db_engine(server_registry_row: tuple | None, credential_store_row: tuple | None = None):
    """Fake app.core.database.engine whose .connect().execute(...).fetchone()
    returns `server_registry_row` for the (approved_upstream_idp_config,
    approved_oauth_scopes, upstream_idp_type) lookup and `credential_store_row`
    for the stored-scopes diff lookup — oauth.py::enroll issues both as
    separate queries against the same engine."""
    async def _execute(stmt, *_a, **_kw):
        result = MagicMock()
        if "FROM server_registry" in str(stmt):
            result.fetchone = MagicMock(return_value=server_registry_row)
        else:
            result.fetchone = MagicMock(return_value=credential_store_row)
        return result

    conn = MagicMock()
    conn.execute = AsyncMock(side_effect=_execute)

    class _ConnCM:
        async def __aenter__(self):
            return conn

        async def __aexit__(self, *a):
            return False

    engine_mock = MagicMock()
    engine_mock.connect = MagicMock(return_value=_ConnCM())
    return engine_mock


@pytest.mark.unit
async def test_enroll_fails_closed_when_oauth_config_not_yet_approved():
    """
    WP-A6 Finding 2: a server with a submitted (upstream_idp_type set) but
    not-yet-reviewer-approved OAuth config must 409, never silently fall back
    to rendering a consent page from the unapproved requested config.
    """
    fake_redis = _FakeRedis()
    redis_pool_mock = MagicMock()
    redis_pool_mock.client = fake_redis

    mock_registry = MagicMock()
    mock_registry.get_config = MagicMock(
        return_value=ServerConfig(
            server_id="11111111-1111-1111-1111-111111111111",
            service_name="acme", upstream_url="https://acme.example",
            injection_mode="external_oauth_user_token", status="approved",
        )
    )
    # approved_upstream_idp_config NULL, but upstream_idp_type IS set —
    # a request was submitted, just never approved.
    engine_mock = _fake_db_engine((None, None, "external_oauth"))

    with patch("app.services.invocation.registry_instance", mock_registry), \
         patch("app.core.redis_client.redis_pool", redis_pool_mock), \
         patch("app.core.database.engine", engine_mock):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/acme",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )

    assert resp.status_code == 409
    assert "approved" in resp.json()["detail"].lower()


@pytest.mark.unit
async def test_enroll_uses_approved_scopes_not_requested():
    """
    WP-A6 Finding 2: when approved_oauth_scopes differs from what the
    submitter originally requested in upstream_idp_config, the consent page
    must render the approved set, not the requested one.
    """
    fake_redis = _FakeRedis()
    redis_pool_mock = MagicMock()
    redis_pool_mock.client = fake_redis

    mock_registry = MagicMock()
    mock_registry.get_config = MagicMock(
        return_value=ServerConfig(
            server_id="22222222-2222-2222-2222-222222222222",
            service_name="acme2", upstream_url="https://acme2.example",
            injection_mode="external_oauth_user_token", status="approved",
        )
    )
    approved_config = {
        "issuer": "https://idp.example", "client_id": "abc123",
        "scopes": ["read", "write", "admin"],  # requested — must NOT be shown
    }
    engine_mock = _fake_db_engine((approved_config, ["read"], "external_oauth"))

    with patch("app.services.invocation.registry_instance", mock_registry), \
         patch("app.core.redis_client.redis_pool", redis_pool_mock), \
         patch("app.core.database.engine", engine_mock):
        async with _client() as c:
            resp = await c.get(
                "/auth/enroll/acme2",
                headers={"X-Client-Cert-CN": "alice@corp"},
                follow_redirects=False,
            )

    assert resp.status_code == 200
    assert "write" not in resp.text
    assert "admin" not in resp.text
    assert "read" in resp.text


@pytest.mark.unit
async def test_post_enrollment_discovery_persists_service_context(monkeypatch):
    """WP-A6 Finding 3: after a successful OAuth callback, a server backed by
    a profile with a service_adapter gets its ServiceAdapter's
    build_runtime_context() result persisted to server_registry.service_context."""
    from app.routers import oauth as oauth_router

    captured_update = {}

    class _FakeConn:
        async def execute(self, stmt, params=None):
            result = MagicMock()
            result.fetchone = MagicMock(return_value=(
                "11111111-1111-1111-1111-111111111111",
                {"issuer": "https://idp.example", "client_id": "abc", "api_base_url": "https://api.acme.example"},
                None,  # service_adapter slug -> resolves to GenericServiceAdapter
                "external_oauth_client_credentials",  # app-level injection_mode — eligible for discovery
            ))
            return result

    class _FakeConnCM:
        async def __aenter__(self):
            return _FakeConn()

        async def __aexit__(self, *a):
            return False

    class _FakeDB:
        async def execute(self, stmt, params=None):
            captured_update.update(params or {})

        async def commit(self):
            pass

    class _FakeDBCM:
        async def __aenter__(self):
            return _FakeDB()

        async def __aexit__(self, *a):
            return False

    engine_mock = MagicMock()
    engine_mock.connect = MagicMock(return_value=_FakeConnCM())

    with patch("app.core.database.engine", engine_mock), \
         patch("app.core.database.AsyncSessionLocal", lambda: _FakeDBCM()):
        await oauth_router._run_post_enrollment_discovery(service="acme", access_token="tok-123")

    assert captured_update["sid"] == "11111111-1111-1111-1111-111111111111"
    ctx = json.loads(captured_update["ctx"])
    assert ctx["adapter"] == "generic"
    assert ctx["api_base_url"] == "https://api.acme.example"


@pytest.mark.unit
async def test_post_enrollment_discovery_skips_per_user_injection_mode():
    """C-02 (2026-07-11 audit): server_registry.service_context is a single,
    server-wide column with no principal dimension. Per-user injection modes
    must never write it, or the last user to enroll silently overwrites the
    resource context for every other user and the deployed container."""
    from app.routers import oauth as oauth_router

    captured_update = {}

    class _FakeConn:
        async def execute(self, stmt, params=None):
            result = MagicMock()
            result.fetchone = MagicMock(return_value=(
                "11111111-1111-1111-1111-111111111111",
                {"api_base_url": "https://api.acme.example"},
                None,
                "external_oauth_user_token",  # per-user mode — must be skipped
            ))
            return result

    class _FakeConnCM:
        async def __aenter__(self):
            return _FakeConn()

        async def __aexit__(self, *a):
            return False

    class _FakeDB:
        async def execute(self, stmt, params=None):
            captured_update.update(params or {})

        async def commit(self):
            pass

    class _FakeDBCM:
        async def __aenter__(self):
            return _FakeDB()

        async def __aexit__(self, *a):
            return False

    engine_mock = MagicMock()
    engine_mock.connect = MagicMock(return_value=_FakeConnCM())

    with patch("app.core.database.engine", engine_mock), \
         patch("app.core.database.AsyncSessionLocal", lambda: _FakeDBCM()):
        await oauth_router._run_post_enrollment_discovery(service="acme", access_token="tok-123")

    assert captured_update == {}  # no UPDATE ever executed


@pytest.mark.unit
async def test_post_enrollment_discovery_never_reads_submitter_controlled_config():
    """C-01 (2026-07-11 audit): must select approved_upstream_idp_config, never
    the submitter-controlled upstream_idp_config — and must fail closed
    (skip discovery) rather than discover against unapproved config."""
    from app.routers import oauth as oauth_router

    captured_sql = {}
    captured_update = {}

    class _FakeConn:
        async def execute(self, stmt, params=None):
            captured_sql["text"] = str(stmt)
            result = MagicMock()
            # approved_upstream_idp_config is NULL — not yet approved
            result.fetchone = MagicMock(return_value=(
                "11111111-1111-1111-1111-111111111111",
                None,
                None,
                "external_oauth_client_credentials",
            ))
            return result

    class _FakeConnCM:
        async def __aenter__(self):
            return _FakeConn()

        async def __aexit__(self, *a):
            return False

    class _FakeDB:
        async def execute(self, stmt, params=None):
            captured_update.update(params or {})

        async def commit(self):
            pass

    class _FakeDBCM:
        async def __aenter__(self):
            return _FakeDB()

        async def __aexit__(self, *a):
            return False

    engine_mock = MagicMock()
    engine_mock.connect = MagicMock(return_value=_FakeConnCM())

    with patch("app.core.database.engine", engine_mock), \
         patch("app.core.database.AsyncSessionLocal", lambda: _FakeDBCM()):
        await oauth_router._run_post_enrollment_discovery(service="acme", access_token="tok-123")

    assert "sr.approved_upstream_idp_config" in captured_sql["text"]
    assert "sr.upstream_idp_config" not in captured_sql["text"]  # never the submitter-controlled column
    assert captured_update == {}  # NULL approved config -> never discovers, never writes


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
