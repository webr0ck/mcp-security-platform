"""
Unit tests for proxy/app/services/consent.py — owner-consent tokens.

Phase 2.3 additions:
  - verify_approve_consent_token: expired, wrong-server, wrong-owner, tamper, valid
  - mint_consent_token route: roles, server-not-found, already-approved, persist called
  - approve_server route: expired token, wrong server, replay, happy path
  - RBAC matrix: server_owner allowed, agent/user not allowed
"""
from __future__ import annotations

import json
import time
import hmac as _hmac
import secrets as _secrets
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.consent import (
    ConsentPayload,
    ConsentTokenError,
    ConsentTokenExpiredError,
    ConsentTokenMismatchError,
    issue_consent_token,
    verify_consent_token,
)


def test_issue_and_verify_roundtrip():
    """Issuing and immediately verifying a token should return a ConsentPayload."""
    token, jti = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload = verify_consent_token(
        token=token,
        expected_server_id="srv-001",
        expected_new_mode="service",
        expected_owner_sub="user:sub123",
    )
    assert isinstance(payload, ConsentPayload)
    assert payload.server_id == "srv-001"
    assert payload.new_mode == "service"
    assert payload.jti == jti


def test_expired_token_raises():
    """A token issued with ttl_seconds=0 should be expired immediately."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
        ttl_seconds=0,
    )
    # Even without sleeping, exp = iat+0 will be <= now at verify time
    with pytest.raises(ConsentTokenExpiredError):
        verify_consent_token(
            token=token,
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_wrong_server_id_raises_mismatch():
    """Verifying with the wrong server_id must raise ConsentTokenMismatchError."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    with pytest.raises(ConsentTokenMismatchError, match="server_id"):
        verify_consent_token(
            token=token,
            expected_server_id="srv-WRONG",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_wrong_new_mode_raises_mismatch():
    """Verifying with the wrong new_mode must raise ConsentTokenMismatchError."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    with pytest.raises(ConsentTokenMismatchError, match="new_mode"):
        verify_consent_token(
            token=token,
            expected_server_id="srv-001",
            expected_new_mode="user",
            expected_owner_sub="user:sub123",
        )


def test_tampered_payload_raises_mismatch():
    """Modifying the payload portion (before the dot) should fail signature check."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload_json, sig = token.rsplit(".", 1)
    # Change server_id in the payload
    payload = json.loads(payload_json)
    payload["server_id"] = "srv-EVIL"
    tampered_payload = json.dumps(payload, sort_keys=True)
    tampered_token = f"{tampered_payload}.{sig}"
    with pytest.raises(ConsentTokenMismatchError, match="signature"):
        verify_consent_token(
            token=tampered_token,
            expected_server_id="srv-EVIL",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_tampered_signature_raises_mismatch():
    """A correct payload with a forged signature should fail."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload_json, _ = token.rsplit(".", 1)
    forged_token = f"{payload_json}.{'a' * 64}"
    with pytest.raises(ConsentTokenMismatchError, match="signature"):
        verify_consent_token(
            token=forged_token,
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_malformed_token_raises():
    """A garbage string should raise ConsentTokenError (no dot separator)."""
    with pytest.raises(ConsentTokenError):
        verify_consent_token(
            token="this-is-not-a-valid-token",
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_payload_hash_in_issued_token():
    """The token should contain a parseable JSON payload (not an opaque blob)."""
    token, jti = issue_consent_token(
        server_id="srv-007",
        old_mode="none",
        new_mode="user",
        owner_sub="human:keycloak:alice",
    )
    payload_json, sig = token.rsplit(".", 1)
    payload = json.loads(payload_json)
    assert payload["server_id"] == "srv-007"
    assert payload["jti"] == jti
    assert "exp" in payload
    assert "iat" in payload


# =============================================================================
# Phase 2.3: verify+consume wiring tests
# =============================================================================

_SERVER_ID = "aaaaaaaa-0000-0000-0000-000000000001"
_SERVER_ID_B = "bbbbbbbb-0000-0000-0000-000000000002"
_OWNER_SUB = "owner-user-001"
_APPROVER_ID = "admin-001"
_FAKE_SECRET = "test-proxy-secret-key-for-tests-only"


def _make_request(
    roles: list[str] | None = None,
    client_id: str = _OWNER_SUB,
) -> MagicMock:
    req = MagicMock()
    req.state = SimpleNamespace(
        client_roles=roles if roles is not None else [],
        client_id=client_id,
        request_id="req-test-001",
    )
    return req


def _build_approve_token(
    server_id: str = _SERVER_ID,
    owner_sub: str = _OWNER_SUB,
    secret: str = _FAKE_SECRET,
    ttl_seconds: int = 900,
) -> tuple[str, str]:
    """Build a valid HMAC-signed approve consent token without hitting the DB."""
    jti = _secrets.token_hex(16)
    now = int(time.time())
    payload: dict = {
        "server_id": server_id,
        "old_mode": "__approve_pending__",
        "new_mode": "__approve_approved__",
        "owner_sub": owner_sub,
        "jti": jti,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    sig = _hmac.new(secret.encode(), payload_json.encode(), "sha256").hexdigest()
    return f"{payload_json}.{sig}", jti


def _build_expired_approve_token(
    server_id: str = _SERVER_ID,
    owner_sub: str = _OWNER_SUB,
    secret: str = _FAKE_SECRET,
) -> tuple[str, str]:
    jti = _secrets.token_hex(16)
    now = int(time.time())
    payload: dict = {
        "server_id": server_id,
        "old_mode": "__approve_pending__",
        "new_mode": "__approve_approved__",
        "owner_sub": owner_sub,
        "jti": jti,
        "iat": now - 2000,
        "exp": now - 1,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    sig = _hmac.new(secret.encode(), payload_json.encode(), "sha256").hexdigest()
    return f"{payload_json}.{sig}", jti


def _make_mock_db(fetchone_return=None, rowcount: int = 1):
    mock_result = MagicMock()
    mock_result.fetchone.return_value = fetchone_return
    mock_result.rowcount = rowcount

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_result)
    mock_db.commit = AsyncMock()
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=False)
    return mock_db


# ---------------------------------------------------------------------------
# verify_approve_consent_token — pure primitive, no DB
# ---------------------------------------------------------------------------

class TestVerifyApproveConsentToken:

    @pytest.mark.unit
    def test_expired_token_raises(self):
        from app.services.consent import verify_approve_consent_token
        token, _ = _build_expired_approve_token()
        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            with pytest.raises(ConsentTokenExpiredError):
                verify_approve_consent_token(
                    token=token,
                    expected_server_id=_SERVER_ID,
                    expected_owner_sub=_OWNER_SUB,
                )

    @pytest.mark.unit
    def test_wrong_server_raises_mismatch(self):
        """Token for server A must not verify against server B."""
        from app.services.consent import verify_approve_consent_token
        token, _ = _build_approve_token(server_id=_SERVER_ID)
        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            with pytest.raises(ConsentTokenMismatchError):
                verify_approve_consent_token(
                    token=token,
                    expected_server_id=_SERVER_ID_B,
                    expected_owner_sub=_OWNER_SUB,
                )

    @pytest.mark.unit
    def test_wrong_owner_raises_mismatch(self):
        from app.services.consent import verify_approve_consent_token
        token, _ = _build_approve_token(owner_sub="original-owner")
        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            with pytest.raises(ConsentTokenMismatchError):
                verify_approve_consent_token(
                    token=token,
                    expected_server_id=_SERVER_ID,
                    expected_owner_sub="different-owner",
                )

    @pytest.mark.unit
    def test_tampered_signature_raises_mismatch(self):
        from app.services.consent import verify_approve_consent_token
        token, _ = _build_approve_token()
        tampered = token[:-4] + "XXXX"
        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            with pytest.raises(ConsentTokenMismatchError):
                verify_approve_consent_token(
                    token=tampered,
                    expected_server_id=_SERVER_ID,
                    expected_owner_sub=_OWNER_SUB,
                )

    @pytest.mark.unit
    def test_valid_token_returns_payload(self):
        from app.services.consent import verify_approve_consent_token
        token, jti = _build_approve_token()
        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            payload = verify_approve_consent_token(
                token=token,
                expected_server_id=_SERVER_ID,
                expected_owner_sub=_OWNER_SUB,
            )
        assert isinstance(payload, ConsentPayload)
        assert payload.jti == jti
        assert payload.server_id == _SERVER_ID
        assert payload.owner_sub == _OWNER_SUB


# ---------------------------------------------------------------------------
# mint_consent_token route (POST /api/v1/servers/{id}/consent)
# ---------------------------------------------------------------------------

class TestMintConsentTokenRoute:

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_owner_can_mint(self):
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["server_owner"], client_id=_OWNER_SUB)
        body = ConsentRequest(action="approve")
        mock_db = _make_mock_db(fetchone_return=MagicMock(status="pending"))

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.server_registry.persist_consent_token", new_callable=AsyncMock) as mock_persist, \
             patch("app.routers.server_registry.issue_approve_consent_token",
                   return_value=("fake-token-str", "fake-jti")):
            response = await mint_consent_token(_SERVER_ID, body, req)

        assert response.status_code == 201
        data = json.loads(response.body)
        assert data["consent_token"] == "fake-token-str"
        assert data["jti"] == "fake-jti"
        mock_persist.assert_awaited_once()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_platform_admin_can_mint(self):
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["platform_admin"], client_id="admin-user")
        body = ConsentRequest(action="approve")
        mock_db = _make_mock_db(fetchone_return=MagicMock(status="pending"))

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.server_registry.persist_consent_token", new_callable=AsyncMock), \
             patch("app.routers.server_registry.issue_approve_consent_token",
                   return_value=("tok", "jti-x")):
            response = await mint_consent_token(_SERVER_ID, body, req)

        assert response.status_code == 201

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_agent_cannot_mint(self):
        from fastapi import HTTPException
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["agent"])
        body = ConsentRequest(action="approve")

        with pytest.raises(HTTPException) as exc_info:
            await mint_consent_token(_SERVER_ID, body, req)
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_user_cannot_mint(self):
        from fastapi import HTTPException
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["user"])
        body = ConsentRequest(action="approve")

        with pytest.raises(HTTPException) as exc_info:
            await mint_consent_token(_SERVER_ID, body, req)
        assert exc_info.value.status_code == 403

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_not_found_raises_404(self):
        from fastapi import HTTPException
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["server_owner"])
        body = ConsentRequest(action="approve")
        mock_db = _make_mock_db(fetchone_return=None)

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db):
            with pytest.raises(HTTPException) as exc_info:
                await mint_consent_token(_SERVER_ID, body, req)
        assert exc_info.value.status_code == 404

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_already_approved_raises_409(self):
        from fastapi import HTTPException
        from app.routers.server_registry import mint_consent_token, ConsentRequest

        req = _make_request(roles=["server_owner"])
        body = ConsentRequest(action="approve")
        mock_db = _make_mock_db(fetchone_return=MagicMock(status="approved"))

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db):
            with pytest.raises(HTTPException) as exc_info:
                await mint_consent_token(_SERVER_ID, body, req)
        assert exc_info.value.status_code == 409

    @pytest.mark.unit
    def test_consent_request_rejects_unknown_action(self):
        from pydantic import ValidationError
        from app.routers.server_registry import ConsentRequest
        with pytest.raises(ValidationError):
            ConsentRequest(action="change_mode")

    @pytest.mark.unit
    def test_approve_body_requires_consent_token(self):
        from pydantic import ValidationError
        from app.routers.server_registry import ApproveBody
        with pytest.raises(ValidationError):
            ApproveBody()


# ---------------------------------------------------------------------------
# approve_server route — consent enforcement
# ---------------------------------------------------------------------------

class TestApproveServerConsent:

    def _make_approve_body(self, token: str = "valid-token"):
        from app.routers.server_registry import ApproveBody
        return ApproveBody(consent_token=token)

    def _server_row(self, url: str = "https://safe-server.internal", owner: str = _OWNER_SUB, adapter_name = None):
        row = MagicMock()
        row.__getitem__ = lambda self, i: [url, owner, adapter_name][i]
        return row

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_expired_consent_token_rejected(self):
        """Expired token → 409 owner_consent_required."""
        from fastapi import HTTPException
        from app.routers.server_registry import approve_server

        req = _make_request(roles=["platform_admin"], client_id=_APPROVER_ID)
        body = self._make_approve_body("expired-token")

        mock_db = _make_mock_db(fetchone_return=self._server_row())

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.server_registry.validate_server_url"), \
             patch("app.routers.server_registry.verify_approve_consent_token",
                   side_effect=ConsentTokenExpiredError("expired")):
            with pytest.raises(HTTPException) as exc_info:
                await approve_server(_SERVER_ID, body, req)

        assert exc_info.value.status_code == 409
        assert "owner_consent_required" in exc_info.value.detail

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_consent_token_wrong_server_rejected(self):
        """Token bound to wrong server → 409."""
        from fastapi import HTTPException
        from app.routers.server_registry import approve_server

        req = _make_request(roles=["platform_admin"], client_id=_APPROVER_ID)
        body = self._make_approve_body("misbound-token")

        mock_db = _make_mock_db(fetchone_return=self._server_row())

        with patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.server_registry.validate_server_url"), \
             patch("app.routers.server_registry.verify_approve_consent_token",
                   side_effect=ConsentTokenMismatchError("server_id mismatch")):
            with pytest.raises(HTTPException) as exc_info:
                await approve_server(_SERVER_ID, body, req)

        assert exc_info.value.status_code == 409
        assert "owner_consent_required" in exc_info.value.detail

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_consent_token_replay_rejected(self):
        """
        Replay attack: consume_consent_token returns False on second call.
        The handler MUST reject with 409 — never allow-through.

        This test drives the approve_server handler twice (once succeeds, once replay).
        """
        from fastapi import HTTPException
        from app.routers.server_registry import approve_server

        req = _make_request(roles=["platform_admin"], client_id=_APPROVER_ID)
        token_str, jti = _build_approve_token()
        body = self._make_approve_body(token_str)

        valid_payload = ConsentPayload(
            server_id=_SERVER_ID,
            old_mode="__approve_pending__",
            new_mode="__approve_approved__",
            owner_sub=_OWNER_SUB,
            jti=jti,
            iat=int(time.time()),
            exp=int(time.time()) + 900,
        )

        def _make_two_execute_db(second_rowcount: int = 0):
            """
            First execute: URL/owner fetch row.
            Second execute: UPDATE returning (used for rowcount check post-consume).
            """
            url_result = MagicMock()
            url_result.fetchone.return_value = self._server_row()

            update_result = MagicMock()
            update_result.rowcount = second_rowcount

            call_count = 0

            async def _execute(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                return url_result if call_count == 1 else update_result

            mock_db = AsyncMock()
            mock_db.execute = _execute
            mock_db.commit = AsyncMock()
            mock_db.__aenter__ = AsyncMock(return_value=mock_db)
            mock_db.__aexit__ = AsyncMock(return_value=False)
            return mock_db

        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET):
            # First call: consume returns True → approval succeeds
            with patch("app.routers.server_registry.AsyncSessionLocal",
                       return_value=_make_two_execute_db(second_rowcount=1)), \
                 patch("app.routers.server_registry.validate_server_url"), \
                 patch("app.routers.server_registry.consume_consent_token",
                       new_callable=AsyncMock, return_value=True):
                response = await approve_server(_SERVER_ID, body, req)
            assert response.status_code == 200

            # Second call (replay): consume returns False → 409
            with patch("app.routers.server_registry.AsyncSessionLocal",
                       return_value=_make_two_execute_db(second_rowcount=0)), \
                 patch("app.routers.server_registry.validate_server_url"), \
                 patch("app.routers.server_registry.consume_consent_token",
                       new_callable=AsyncMock, return_value=False):
                with pytest.raises(HTTPException) as exc_info:
                    await approve_server(_SERVER_ID, body, req)

        assert exc_info.value.status_code == 409
        assert "owner_consent_required" in exc_info.value.detail or "already used" in exc_info.value.detail

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_happy_path_approve_records_consent_jti(self):
        """
        Happy path: valid token, consume returns True → 200 with approved_by + consent_jti.
        """
        from app.routers.server_registry import approve_server

        req = _make_request(roles=["platform_admin"], client_id=_APPROVER_ID)
        token_str, jti = _build_approve_token()
        body = self._make_approve_body(token_str)

        url_result = MagicMock()
        url_result.fetchone.return_value = self._server_row()
        update_result = MagicMock()
        update_result.rowcount = 1

        call_count = 0

        async def _execute(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return url_result if call_count == 1 else update_result

        mock_db = AsyncMock()
        mock_db.execute = _execute
        mock_db.commit = AsyncMock()
        mock_db.__aenter__ = AsyncMock(return_value=mock_db)
        mock_db.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.consent._get_signing_key", return_value=_FAKE_SECRET), \
             patch("app.routers.server_registry.AsyncSessionLocal", return_value=mock_db), \
             patch("app.routers.server_registry.validate_server_url"), \
             patch("app.routers.server_registry.consume_consent_token",
                   new_callable=AsyncMock, return_value=True):
            response = await approve_server(_SERVER_ID, body, req)

        assert response.status_code == 200
        data = json.loads(response.body)
        assert data["status"] == "approved"
        assert data["approved_by"] == _APPROVER_ID
        assert data["consent_jti"] == jti

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_non_admin_rejected(self):
        """server_owner cannot call the approve endpoint (platform_admin only)."""
        from fastapi import HTTPException
        from app.routers.server_registry import approve_server

        req = _make_request(roles=["server_owner"], client_id=_OWNER_SUB)
        body = self._make_approve_body("some-token")

        with pytest.raises(HTTPException) as exc_info:
            await approve_server(_SERVER_ID, body, req)
        assert exc_info.value.status_code == 403


# ---------------------------------------------------------------------------
# RBAC matrix — consent route role coverage
# ---------------------------------------------------------------------------

class TestConsentRouteRBAC:

    @pytest.mark.unit
    def test_server_owner_allowed_to_mint(self):
        from app.middleware.rbac import _resolve_allowed_roles
        roles = _resolve_allowed_roles("POST", f"/api/v1/servers/{_SERVER_ID}/consent")
        assert roles is not None
        assert "server_owner" in roles

    @pytest.mark.unit
    def test_platform_admin_allowed_to_mint(self):
        from app.middleware.rbac import _resolve_allowed_roles
        roles = _resolve_allowed_roles("POST", f"/api/v1/servers/{_SERVER_ID}/consent")
        assert roles is not None
        assert "platform_admin" in roles

    @pytest.mark.unit
    def test_agent_not_allowed_to_mint(self):
        from app.middleware.rbac import _resolve_allowed_roles
        roles = _resolve_allowed_roles("POST", f"/api/v1/servers/{_SERVER_ID}/consent")
        assert roles is not None
        assert "agent" not in roles

    @pytest.mark.unit
    def test_user_not_allowed_to_mint(self):
        from app.middleware.rbac import _resolve_allowed_roles
        roles = _resolve_allowed_roles("POST", f"/api/v1/servers/{_SERVER_ID}/consent")
        assert roles is not None
        assert "user" not in roles
