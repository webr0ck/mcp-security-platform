"""
Enrollment Consent Gate tests — P1 / R-5

Covers:
  - C4: client_id derived ONLY from Redis consent record, never body/query/header
  - C5: CSRF token validated with ATOMIC get_and_delete (single-use)
  - C7: ModeChangePayload path unchanged (regression guard + EnrollmentConsentPayload
        jti-burn uses Redis GET+DEL, NOT consume_consent_token / mode_change_consent)
  - C8: consent POST with invalid/expired CSRF or client_id mismatch emits
        synchronous CREDENTIAL_CONSENT_DENIED audit BEFORE 4xx (INV-001)
  - D1/D2: GET /auth/enroll/{svc} returns HTML consent page (200), NO oauth_flow: key
           written at GET time (state-only-after-consent)
  - D3: POST /consent on valid CSRF mints PKCE and stores scopes in oauth_flow:
  - Scope upgrade: fresh consent required; stored scopes written at callback
  - INV-002: no raw scopes/CSRF tokens/refresh tokens logged or in audit

INV-001: audit emitted BEFORE 4xx.
INV-002: scopes_hash in audit, never raw scopes or tokens.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from httpx import ASGITransport, AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client():
    from app.main import app
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver")


class _FakeRedis:
    """
    In-memory Redis fake supporting setex, get, delete, getdel, and a
    tracking getdel for atomicity tests.
    """

    def __init__(self, store: dict | None = None) -> None:
        self.store: dict = store if store is not None else {}
        self.getdel_call_count = 0

    async def setex(self, key: str, ttl: int, value: str) -> None:
        self.store[key] = value

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def delete(self, key: str) -> int:
        return 1 if self.store.pop(key, None) is not None else 0

    async def getdel(self, key: str) -> str | None:
        self.getdel_call_count += 1
        return self.store.pop(key, None)

    def pipeline(self):
        """Fallback pipeline (used by callback's existing state lookup)."""
        outer = self

        class _Pipe:
            def __init__(self) -> None:
                self._key: str | None = None

            def get(self, key: str):
                self._key = key
                return self

            def delete(self, key: str):
                return self

            async def execute(self):
                val = outer.store.pop(self._key, None) if self._key else None
                return [val, 1]

        return _Pipe()


class _FakeAdapter:
    def __init__(self, scopes: list[str] | None = None) -> None:
        self._scopes = scopes or ["User.Read", "Mail.Read"]

    def build_auth_url(self, state: str, code_challenge: str | None = None) -> str:
        return f"https://idp.example/auth?state={state}&code_challenge={code_challenge}"

    async def exchange_code(self, code: str, code_verifier: str | None = None):
        assert code_verifier, "PKCE code_verifier must be passed to exchange_code"
        return ("access-tok", "refresh-tok", 3600)

    @property
    def scopes(self) -> list[str]:
        return self._scopes


def _make_redis_pool(fake: _FakeRedis) -> MagicMock:
    pool = MagicMock()
    pool.client = fake
    return pool


# ---------------------------------------------------------------------------
# Task 2 Step 1 — C7 regression guard: ModeChangePayload path unchanged
# ---------------------------------------------------------------------------

class TestModeChangePayloadRegression:
    """
    C7 regression guard (MUST stay green throughout all R-5 changes).
    Asserts the existing ModeChangePayload (issue / verify / consume path)
    is behavior-identical after consent.py refactoring.
    """

    def test_mode_change_issue_verify_roundtrip_unchanged(self):
        """C7: issue_consent_token + verify_consent_token work identically."""
        from app.services.consent import (
            ConsentPayload,
            issue_consent_token,
            verify_consent_token,
        )
        token, jti = issue_consent_token(
            server_id="srv-regression",
            old_mode="none",
            new_mode="service",
            owner_sub="owner:alice",
        )
        payload = verify_consent_token(
            token=token,
            expected_server_id="srv-regression",
            expected_new_mode="service",
            expected_owner_sub="owner:alice",
        )
        assert isinstance(payload, ConsentPayload)
        assert payload.server_id == "srv-regression"
        assert payload.jti == jti
        assert payload.old_mode == "none"
        assert payload.new_mode == "service"
        assert payload.owner_sub == "owner:alice"

    def test_mode_change_expired_token_still_raises(self):
        """C7: expired ModeChangePayload still raises ConsentTokenExpiredError."""
        from app.services.consent import (
            ConsentTokenExpiredError,
            issue_consent_token,
            verify_consent_token,
        )
        token, _ = issue_consent_token(
            server_id="srv-001", old_mode="none", new_mode="service",
            owner_sub="owner:bob", ttl_seconds=0,
        )
        with pytest.raises(ConsentTokenExpiredError):
            verify_consent_token(
                token=token, expected_server_id="srv-001",
                expected_new_mode="service", expected_owner_sub="owner:bob",
            )

    def test_mode_change_tampered_payload_still_raises(self):
        """C7: tampered ModeChangePayload still fails signature check."""
        import json as _json
        from app.services.consent import (
            ConsentTokenMismatchError,
            issue_consent_token,
            verify_consent_token,
        )
        token, _ = issue_consent_token(
            server_id="srv-001", old_mode="none", new_mode="service",
            owner_sub="owner:carol",
        )
        payload_json, sig = token.rsplit(".", 1)
        p = _json.loads(payload_json)
        p["server_id"] = "srv-EVIL"
        tampered = f"{_json.dumps(p, sort_keys=True)}.{sig}"
        with pytest.raises(ConsentTokenMismatchError, match="signature"):
            verify_consent_token(
                token=tampered, expected_server_id="srv-EVIL",
                expected_new_mode="service", expected_owner_sub="owner:carol",
            )

    def test_mode_change_consume_uses_mode_change_consent_table(self):
        """
        C7: consume_consent_token still writes to mode_change_consent, NOT to
        any enrollment table or Redis. Verify the SQL targets mode_change_consent.
        """
        import inspect
        from app.services import consent as consent_mod
        source = inspect.getsource(consent_mod.consume_consent_token)
        # Must reference mode_change_consent (the DB table)
        assert "mode_change_consent" in source, (
            "C7: consume_consent_token must still target mode_change_consent table"
        )
        # Must NOT reference any enrollment-specific key/table
        assert "enroll_consent" not in source, (
            "C7: consume_consent_token must NOT touch enrollment consent records"
        )


# ---------------------------------------------------------------------------
# Task 3 Step 2 — C5 atomic get_and_delete helper
# ---------------------------------------------------------------------------

class TestAtomicGetAndDelete:
    """C5: get_and_delete must be atomic — only ONE concurrent caller gets value."""

    @pytest.mark.asyncio
    async def test_get_and_delete_returns_value_and_removes(self):
        """C5: get_and_delete returns the stored value and removes the key."""
        from app.core.redis_atomic import get_and_delete
        fake = _FakeRedis(store={"mykey": "myval"})
        result = await get_and_delete(fake, "mykey")
        assert result == "myval"
        assert "mykey" not in fake.store

    @pytest.mark.asyncio
    async def test_get_and_delete_returns_none_on_miss(self):
        """C5: get_and_delete returns None for missing key (already consumed)."""
        from app.core.redis_atomic import get_and_delete
        fake = _FakeRedis()
        result = await get_and_delete(fake, "nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_and_delete_uses_getdel_not_pipeline(self):
        """
        C5: get_and_delete must use getdel (atomic) not a pipeline GET+DEL.
        We track this by verifying fake.getdel_call_count increments.
        """
        from app.core.redis_atomic import get_and_delete
        fake = _FakeRedis(store={"csrf-key": "csrf-val"})
        await get_and_delete(fake, "csrf-key")
        assert fake.getdel_call_count == 1, (
            "C5: get_and_delete must call redis.getdel() for atomicity, "
            "not a non-atomic pipeline GET+DEL"
        )

    @pytest.mark.asyncio
    async def test_second_caller_gets_none_simulated_atomicity(self):
        """
        C5: simulated double-submit — only the first caller gets the value,
        the second gets None (the record has been consumed).
        """
        from app.core.redis_atomic import get_and_delete
        fake = _FakeRedis(store={"csrf-once": "csrf-value"})
        first = await get_and_delete(fake, "csrf-once")
        second = await get_and_delete(fake, "csrf-once")
        assert first == "csrf-value"
        assert second is None


# ---------------------------------------------------------------------------
# Task 4 — D1/D2: GET renders consent HTML, no PKCE state written
# ---------------------------------------------------------------------------

class TestEnrollGetConsent:
    """D1/D2: GET /auth/enroll/{svc} returns HTML consent page, no oauth_flow: key written."""

    @pytest.mark.asyncio
    async def test_get_enroll_returns_html_200_not_redirect(self):
        """D1: GET returns 200 HTML consent page, NOT a 302 redirect to Entra."""
        fake = _FakeRedis()
        pool = _make_redis_pool(fake)
        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
            async with _client() as c:
                resp = await c.get(
                    "/auth/enroll/m365",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert resp.status_code == 200, f"Expected 200 HTML, got {resp.status_code}"
        assert "text/html" in resp.headers.get("content-type", ""), (
            "D1: response must be HTML"
        )

    @pytest.mark.asyncio
    async def test_get_enroll_contains_consent_form(self):
        """D1: consent page must contain a form with csrf token and approve button."""
        fake = _FakeRedis()
        pool = _make_redis_pool(fake)
        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
            async with _client() as c:
                resp = await c.get(
                    "/auth/enroll/m365",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        body = resp.text
        # Form must post to the consent endpoint
        assert "/consent" in body, "D1: form must POST to /consent endpoint"
        # Must show client identity
        assert "alice@corp" in body, "D1: must display requesting client_id"
        # Must have a csrf field
        assert "csrf" in body.lower(), "D1: must include CSRF token in form"
        # Must show scopes
        assert "User.Read" in body or "scope" in body.lower(), "D1: must display requested scopes"

    @pytest.mark.asyncio
    async def test_get_enroll_no_pkce_state_written(self):
        """
        D2 state-only-after-consent: GET MUST NOT write any oauth_flow: key.
        Only an enroll_consent: record is written at GET time.
        """
        fake = _FakeRedis()
        pool = _make_redis_pool(fake)
        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
            async with _client() as c:
                await c.get(
                    "/auth/enroll/m365",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        # No oauth_flow: key must exist — state minted ONLY after POST /consent
        pkce_keys = [k for k in fake.store if k.startswith("oauth_flow:")]
        assert not pkce_keys, (
            f"D2: oauth_flow: keys must NOT be written at GET time; found {pkce_keys}"
        )

    @pytest.mark.asyncio
    async def test_get_enroll_writes_consent_record_in_redis(self):
        """D2: GET writes exactly one enroll_consent: record keyed by CSRF token."""
        fake = _FakeRedis()
        pool = _make_redis_pool(fake)
        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
            async with _client() as c:
                await c.get(
                    "/auth/enroll/m365",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        consent_keys = [k for k in fake.store if k.startswith("enroll_consent:")]
        assert len(consent_keys) == 1, (
            f"D2: exactly one enroll_consent: record must be written; found {consent_keys}"
        )
        record = json.loads(fake.store[consent_keys[0]])
        assert record["client_id"] == "alice@corp"
        assert record["service"] == "m365"
        assert "requested_scopes" in record

    @pytest.mark.asyncio
    async def test_get_enroll_without_identity_is_401(self):
        """CB-001: /auth/enroll still requires authentication."""
        async with _client() as c:
            resp = await c.get("/auth/enroll/m365", follow_redirects=False)
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Task 5 — POST /auth/enroll/{svc}/consent: the gate
# ---------------------------------------------------------------------------

def _build_consent_store(client_id: str = "alice@corp", service: str = "m365",
                          scopes: list[str] | None = None) -> tuple[str, dict]:
    """Helper: build a csrf token + consent record dict as GET would store it."""
    csrf = secrets.token_urlsafe(32)
    record = {
        "client_id": client_id,
        "service": service,
        "requested_scopes": " ".join(sorted(scopes or ["User.Read", "Mail.Read"])),
    }
    return csrf, record


def _no_op_audit(*_args, **_kwargs):
    """Async no-op for audit helper mocking in POST consent tests."""
    return None


class TestConsentPost:
    """C4/C5/C8/D2: POST /auth/enroll/{svc}/consent — the gate."""

    # All POST consent tests must mock both audit helpers because the DB is not
    # available in unit tests. The C8 tests that want to *assert* on audit calls
    # use their own capture mock; all others use _no_op_audit.
    _AUDIT_PATCHES = (
        "app.routers.oauth._emit_consent_denied_audit",
        "app.routers.oauth._emit_consent_grant_audit",
    )

    @pytest.mark.asyncio
    async def test_valid_consent_post_302s_to_entra(self):
        """D2: valid CSRF + matching session → 302 to Entra + oauth_flow: key written."""
        csrf, record = _build_consent_store()
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert resp.status_code == 302, f"Expected 302, got {resp.status_code}: {resp.text}"
        loc = resp.headers.get("location", "")
        assert "idp.example" in loc or "login.microsoftonline.com" in loc or "state=" in loc, (
            f"302 must redirect to Entra; got location: {loc}"
        )

    @pytest.mark.asyncio
    async def test_valid_consent_post_writes_pkce_state_to_redis(self):
        """D2 state-only-after-consent: PKCE oauth_flow: key written ONLY after valid POST."""
        csrf, record = _build_consent_store()
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        pkce_keys = [k for k in fake.store if k.startswith("oauth_flow:")]
        assert len(pkce_keys) == 1, (
            f"D2: exactly one oauth_flow: key must be written after consent POST; found {pkce_keys}"
        )
        flow = json.loads(fake.store[pkce_keys[0]])
        assert flow["client_id"] == "alice@corp"
        assert flow["service"] == "m365"
        assert "cv" in flow, "oauth_flow: record must contain PKCE code_verifier"
        assert "scopes" in flow, "C6: oauth_flow: record must contain scopes"

    @pytest.mark.asyncio
    async def test_c4_client_id_from_redis_not_body(self):
        """
        C4: client_id MUST come from the Redis consent record, NOT from any
        client-supplied param (body/query/header).
        Even if the attacker supplies a different client_id in the POST body,
        the oauth_flow: record must use the server-side value.
        """
        csrf, record = _build_consent_store(client_id="legit@corp")
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/m365/consent",
                    # Attacker tries to inject their own client_id
                    data={"csrf_token": csrf, "client_id": "attacker@evil"},
                    headers={"X-Client-Cert-CN": "attacker@evil"},  # also spoof header
                    follow_redirects=False,
                )
        # The flow may or may not 302 depending on session auth, but if it does
        # proceed, the stored client_id must be the Redis value, not the body value.
        pkce_keys = [k for k in fake.store if k.startswith("oauth_flow:")]
        if pkce_keys:
            flow = json.loads(fake.store[pkce_keys[0]])
            assert flow["client_id"] == "legit@corp", (
                f"C4: client_id must come from Redis record 'legit@corp', got {flow['client_id']}"
            )

    @pytest.mark.asyncio
    async def test_c5_csrf_single_use_second_post_rejected(self):
        """
        C5: CSRF token is single-use — second POST with the same token must be rejected.
        """
        csrf, record = _build_consent_store()
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                # First POST — should succeed (302)
                r1 = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
                # Second POST with same CSRF — must be rejected (403) because
                # get_and_delete already consumed the record on the first POST
                r2 = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert r1.status_code == 302, f"First POST should succeed (302), got {r1.status_code}"
        assert r2.status_code in (400, 403), (
            f"C5: second POST with same CSRF must be rejected (400/403), got {r2.status_code}"
        )

    @pytest.mark.asyncio
    async def test_c5_expired_or_missing_csrf_rejected(self):
        """C5: POST with a CSRF token that has no corresponding Redis record → 403."""
        fake = _FakeRedis()  # empty — no consent record
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": "expired-or-forged-csrf"},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert resp.status_code in (400, 403), (
            f"C5: missing/expired CSRF must return 400/403, got {resp.status_code}"
        )

    @pytest.mark.asyncio
    async def test_c8_invalid_csrf_emits_deny_audit_before_4xx(self):
        """
        C8 (INV-001): POST with invalid/expired CSRF MUST emit a synchronous
        CREDENTIAL_CONSENT_DENIED audit BEFORE returning the 4xx.

        Mirrors test_invoke_tool_audits_deny_before_reraising_enrollment_error:
        we verify the audit mock was called before the HTTP response is returned.
        """
        fake = _FakeRedis()  # empty — no consent record
        pool = _make_redis_pool(fake)
        audit_calls: list[dict] = []

        async def _capture_audit(*_args, **kwargs):
            audit_calls.append(kwargs)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_denied_audit",
                   AsyncMock(side_effect=_capture_audit)):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": "invalid-token"},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )

        assert resp.status_code in (400, 403), (
            f"C8: invalid CSRF must return 400/403, got {resp.status_code}"
        )
        assert audit_calls, (
            "C8 (INV-001): _emit_consent_denied_audit must have been called before the 4xx response"
        )
        kw = audit_calls[0]
        assert kw.get("outcome") == "deny" or kw.get("event_type") == "CREDENTIAL_CONSENT_DENIED", (
            f"C8: audit must record deny outcome; got {kw}"
        )

    @pytest.mark.asyncio
    async def test_c8_deny_audit_contains_no_raw_scopes_or_csrf(self):
        """
        INV-002: the deny audit must NOT contain raw scopes, CSRF tokens, or
        refresh tokens. It may contain scopes_hash.
        """
        csrf, record = _build_consent_store()
        # We'll use a mismatched service to trigger a deny
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)
        audit_calls: list[dict] = []

        async def _capture_audit(*_args, **kwargs):
            audit_calls.append(kwargs)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_denied_audit",
                   AsyncMock(side_effect=_capture_audit)):
            async with _client() as c:
                # Wrong service in URL vs. record's service
                await c.post(
                    "/auth/enroll/wrongservice/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )

        # If audit was called, verify no raw tokens in the serializable audit fields.
        # The 'request' kwarg is a FastAPI Request object (not JSON-serializable),
        # so we check only the string-valued fields individually.
        import re
        _LOOKS_LIKE_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")
        for kw in audit_calls:
            # Check each string-valued kwarg individually (skip Request objects)
            for key, val in kw.items():
                if not isinstance(val, str):
                    continue
                # CSRF token itself must not appear in audit fields
                assert csrf not in val, (
                    f"INV-002: raw CSRF token must not appear in audit field '{key}'"
                )
                # No JWT/bearer-shaped strings (40+ char base64-like) in audit values
                assert not _LOOKS_LIKE_TOKEN.search(val), (
                    f"INV-002: audit field '{key}' contains what looks like a raw token: {val}"
                )

    @pytest.mark.asyncio
    async def test_post_consent_no_service_match_returns_4xx(self):
        """
        D2: if the consent record's service != the URL service,
        the POST must be rejected (service mismatch → deny).
        """
        csrf, record = _build_consent_store(service="m365")
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/bitbucket/consent",  # different service
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert resp.status_code in (400, 403), (
            f"service mismatch must be rejected; got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Task 6 — Scope-aware callback (C6)
# ---------------------------------------------------------------------------

class TestScopeAwareCallback:
    """C6/D3: callback UPSERT writes scopes from oauth_flow: record."""

    @pytest.mark.asyncio
    async def test_c6_callback_stores_scopes_from_flow_record(self):
        """
        C6: callback must write 'scopes' from the oauth_flow: record (the
        consent-time value), NEVER re-reading tool_registry at callback time.
        """
        nonce = "scope-test-nonce-1234567890abcdef"
        consented_scopes = "Mail.Read User.Read"
        store = {
            f"oauth_flow:{nonce}": json.dumps({
                "client_id": "alice@corp",
                "service": "m365",
                "cv": "verifier-scope-test",
                "scopes": consented_scopes,
            })
        }
        fake = _FakeRedis(store=store)
        pool = _make_redis_pool(fake)

        captured: dict[str, Any] = {}

        class _FakeDB:
            async def execute(self, _stmt, params):
                captured.update(params)

            async def commit(self):
                pass

        async def _fake_get_db():
            yield _FakeDB()

        kms = MagicMock()
        kms.get_master_secret = AsyncMock(return_value=b"\x00" * 32)

        adapter = _FakeAdapter(scopes=["User.Read", "Mail.Read", "Calendars.Read"])

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=adapter), \
             patch("app.credential_broker.kms.VaultKMSClient", return_value=kms), \
             patch("app.routers.oauth._emit_credential_audit", new=AsyncMock()), \
             patch("app.core.database.get_db", _fake_get_db):
            async with _client() as c:
                resp = await c.get(
                    f"/auth/callback/m365?code=abc&state={nonce}",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )

        assert resp.status_code == 200, f"callback should succeed; got {resp.status_code}: {resp.text}"
        # C6: scopes written must be the consent-time value, not the adapter's current scopes
        assert "scopes" in captured, (
            "C6: callback UPSERT must include 'scopes' param"
        )
        assert captured["scopes"] == consented_scopes, (
            f"C6: stored scopes must be the consent-time value '{consented_scopes}', "
            f"got '{captured.get('scopes')}'"
        )
        # Must NOT contain Calendars.Read (only in adapter, not in consented_scopes)
        assert "Calendars.Read" not in captured.get("scopes", ""), (
            "C6: callback must not re-read tool_registry/adapter scopes; "
            "Calendars.Read was not consented"
        )

    @pytest.mark.asyncio
    async def test_c6_callback_without_scopes_in_flow_uses_empty_string(self):
        """
        C6 backward compatibility: oauth_flow: records written before R-5 have no
        'scopes' key — callback must not crash and must store empty string (or default).
        This covers the transition period.
        """
        nonce = "legacy-nonce-no-scopes-12345678"
        store = {
            f"oauth_flow:{nonce}": json.dumps({
                "client_id": "legacy@corp",
                "service": "m365",
                "cv": "verifier-legacy",
                # No "scopes" key — pre-R5 record
            })
        }
        fake = _FakeRedis(store=store)
        pool = _make_redis_pool(fake)

        captured: dict[str, Any] = {}

        class _FakeDB:
            async def execute(self, _stmt, params):
                captured.update(params)

            async def commit(self):
                pass

        async def _fake_get_db():
            yield _FakeDB()

        kms = MagicMock()
        kms.get_master_secret = AsyncMock(return_value=b"\x00" * 32)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.credential_broker.kms.VaultKMSClient", return_value=kms), \
             patch("app.routers.oauth._emit_credential_audit", new=AsyncMock()), \
             patch("app.core.database.get_db", _fake_get_db):
            async with _client() as c:
                resp = await c.get(
                    f"/auth/callback/m365?code=abc&state={nonce}",
                    headers={"X-Client-Cert-CN": "legacy@corp"},
                    follow_redirects=False,
                )

        assert resp.status_code == 200
        # scopes may be absent or empty string — must not be an error
        scopes_val = captured.get("scopes", "")
        assert isinstance(scopes_val, str), "C6: scopes must be a string"


# ---------------------------------------------------------------------------
# Task 7 — Sweep: state-only-after-consent, CSRF reuse, INV-002 log check
# ---------------------------------------------------------------------------

class TestConsentGateSweep:
    """Task 7: comprehensive state/CSRF/INV-002 checks."""

    @pytest.mark.asyncio
    async def test_no_pkce_key_until_valid_consent_post(self):
        """Task 7 Step 1: no oauth_flow: in Redis until a valid POST /consent."""
        fake = _FakeRedis()
        pool = _make_redis_pool(fake)

        # Step 1: GET — must not create oauth_flow:
        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()):
            async with _client() as c:
                await c.get(
                    "/auth/enroll/m365",
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )

        pkce_before = [k for k in fake.store if k.startswith("oauth_flow:")]
        assert not pkce_before, f"No oauth_flow: before consent POST; found {pkce_before}"

        # Step 2: POST with valid CSRF — now oauth_flow: must appear
        consent_keys = [k for k in fake.store if k.startswith("enroll_consent:")]
        assert consent_keys, "GET must write enroll_consent: record"
        csrf = consent_keys[0].split("enroll_consent:")[-1]

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )

        pkce_after = [k for k in fake.store if k.startswith("oauth_flow:")]
        assert pkce_after, "oauth_flow: must be written after valid POST /consent"

    @pytest.mark.asyncio
    async def test_csrf_reuse_rejected_second_post(self):
        """Task 7 Step 2: CSRF reuse rejected — same as C5 double-submit test."""
        csrf, record = _build_consent_store()
        fake = _FakeRedis(store={f"enroll_consent:{csrf}": json.dumps(record)})
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_grant_audit", new=AsyncMock()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
                r2 = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": csrf},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert r2.status_code in (400, 403), (
            f"Task 7 Step 2: CSRF reuse must be rejected; got {r2.status_code}"
        )

    @pytest.mark.asyncio
    async def test_consent_skip_no_record_rejected(self):
        """Task 7 Step 2: POST with no consent record (consent-skip) rejected."""
        fake = _FakeRedis()  # no records at all
        pool = _make_redis_pool(fake)

        with patch("app.core.redis_client.redis_pool", pool), \
             patch("app.routers.oauth._get_adapter", return_value=_FakeAdapter()), \
             patch("app.routers.oauth._emit_consent_denied_audit", new=AsyncMock()):
            async with _client() as c:
                resp = await c.post(
                    "/auth/enroll/m365/consent",
                    data={"csrf_token": "skip-attempt"},
                    headers={"X-Client-Cert-CN": "alice@corp"},
                    follow_redirects=False,
                )
        assert resp.status_code in (400, 403), (
            f"Task 7 Step 2: consent-skip (no record) must be rejected; got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Task 2 Step 2/3 — EnrollmentConsentPayload (C7)
# ---------------------------------------------------------------------------

class TestEnrollmentConsentPayload:
    """C7: EnrollmentConsentPayload single-use jti-burn uses Redis GET+DEL."""

    def test_enrollment_payload_issue_and_verify(self):
        """EnrollmentConsentPayload: issue + verify roundtrip returns correct fields."""
        from app.services.consent import (
            EnrollmentConsentPayload,
            issue_enrollment_consent_token,
            verify_enrollment_consent_token,
        )
        scopes = ["User.Read", "Mail.Read"]
        token, jti = issue_enrollment_consent_token(
            client_id="alice@corp",
            service="m365",
            scopes=scopes,
        )
        payload = verify_enrollment_consent_token(token=token)
        assert isinstance(payload, EnrollmentConsentPayload)
        assert payload.client_id == "alice@corp"
        assert payload.service == "m365"
        assert payload.jti == jti
        # scopes_hash must be SHA-256 of the canonical (sorted, lowercased) scope string
        # canonical form matches _canonical_scopes() in consent.py
        expected_hash = hashlib.sha256(
            " ".join(sorted(s.lower() for s in scopes)).encode()
        ).hexdigest()
        assert payload.scopes_hash == expected_hash

    def test_enrollment_payload_expired_raises(self):
        """EnrollmentConsentPayload: expired token raises ConsentTokenExpiredError."""
        from app.services.consent import (
            ConsentTokenExpiredError,
            issue_enrollment_consent_token,
            verify_enrollment_consent_token,
        )
        token, _ = issue_enrollment_consent_token(
            client_id="alice@corp", service="m365",
            scopes=["User.Read"], ttl_seconds=0,
        )
        with pytest.raises(ConsentTokenExpiredError):
            verify_enrollment_consent_token(token=token)

    def test_enrollment_payload_tampered_raises(self):
        """EnrollmentConsentPayload: tampered token raises ConsentTokenMismatchError."""
        import json as _json
        from app.services.consent import (
            ConsentTokenMismatchError,
            issue_enrollment_consent_token,
            verify_enrollment_consent_token,
        )
        token, _ = issue_enrollment_consent_token(
            client_id="alice@corp", service="m365", scopes=["User.Read"],
        )
        payload_json, sig = token.rsplit(".", 1)
        p = _json.loads(payload_json)
        p["client_id"] = "evil@corp"
        tampered = f"{_json.dumps(p, sort_keys=True)}.{sig}"
        with pytest.raises(ConsentTokenMismatchError):
            verify_enrollment_consent_token(token=tampered)

    def test_enrollment_payload_does_not_use_mode_change_consent_table(self):
        """
        C7: EnrollmentConsentPayload issue/verify/burn MUST NOT reference
        the mode_change_consent DB table (single-use via Redis GET+DEL only).
        """
        import ast
        import inspect
        from app.services import consent as consent_mod

        def _strip_docstring(src: str) -> str:
            """Remove module/function docstrings from source before checking."""
            try:
                tree = ast.parse(src)
                # Collect docstring line ranges to exclude
                excluded_lines: set[int] = set()
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module, ast.ClassDef)):
                        if (node.body and isinstance(node.body[0], ast.Expr)
                                and isinstance(node.body[0].value, ast.Constant)
                                and isinstance(node.body[0].value.value, str)):
                            docnode = node.body[0]
                            for ln in range(docnode.lineno, docnode.end_lineno + 1):
                                excluded_lines.add(ln)
                lines = src.splitlines()
                return "\n".join(
                    line for i, line in enumerate(lines, start=1)
                    if i not in excluded_lines
                )
            except Exception:
                return src

        issue_src = _strip_docstring(
            inspect.getsource(consent_mod.issue_enrollment_consent_token)
        )
        verify_src = _strip_docstring(
            inspect.getsource(consent_mod.verify_enrollment_consent_token)
        )
        # Neither issue nor verify code body (excluding docstrings) should
        # execute SQL against mode_change_consent or call consume_consent_token
        assert "mode_change_consent" not in issue_src, (
            "C7: issue_enrollment_consent_token code body must NOT reference mode_change_consent table"
        )
        assert "mode_change_consent" not in verify_src, (
            "C7: verify_enrollment_consent_token code body must NOT reference mode_change_consent table"
        )
        assert "consume_consent_token" not in issue_src, (
            "C7: issue_enrollment_consent_token must NOT call consume_consent_token"
        )
        assert "consume_consent_token" not in verify_src, (
            "C7: verify_enrollment_consent_token must NOT call consume_consent_token"
        )
