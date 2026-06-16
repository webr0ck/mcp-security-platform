"""
Task 0.1 — Encrypt KC tokens on the token-refresh path (AUTH-F3, HIGH)

Tests verifying that token_refresh:
  1. Stores encrypted (not plaintext) access + refresh tokens on UPDATE.
  2. Encryption/DB failure raises (returns 503), not swallows with logger.warning.
  3. expires_at is set from the new token lifetime, not NULL.
  4. Round-trip: a second refresh can decrypt what the first wrote.
  5. try-decrypt-else-revoke: a plaintext-token session is revoked on first touch.
"""
from __future__ import annotations

import asyncio
import base64
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

# 32-byte random master secret (hex) — matches the lab seeder pattern.
_MASTER_HEX = os.urandom(32).hex()
_MASTER_BYTES = bytes.fromhex(_MASTER_HEX)
_SUBJECT = "test-user@example.com"
_SESSION_ID = uuid.uuid4()
_SESSION_JTI = str(uuid.uuid4())


def _make_valid_jwt_claims(jti: str = _SESSION_JTI) -> dict[str, Any]:
    return {
        "sub": _SUBJECT,
        "client_id": _SUBJECT,
        "roles": ["agent"],
        "jti": jti,
        "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
    }


def _encrypt_token(plaintext: str, subject: str = _SUBJECT) -> str:
    """Encrypt a token the same way the callback does (for seeding rows)."""
    from app.credential_broker.approaches.approach_a import encrypt as _enc
    return base64.b64encode(
        _enc(plaintext, subject, _MASTER_BYTES, service="oidc_session")
    ).decode("ascii")


def _decrypt_token(b64_blob: str, subject: str = _SUBJECT) -> str:
    """Decrypt what the refresh path should write."""
    from app.credential_broker.approaches.approach_a import decrypt as _dec
    return _dec(
        base64.b64decode(b64_blob), subject, _MASTER_BYTES, service="oidc_session"
    )


# ---------------------------------------------------------------------------
# Helpers — build DB row and KC response mocks
# ---------------------------------------------------------------------------

def _make_db_row(
    kc_refresh_token: str,
    subject: str = _SUBJECT,
    session_id: uuid.UUID = _SESSION_ID,
) -> MagicMock:
    row = MagicMock()
    row.kc_refresh_token = kc_refresh_token
    row.subject = subject
    row.client_id_resolved = subject
    row.session_id = session_id
    return row


def _make_kc_token_response(
    access_token: str = "new_access_tok",
    refresh_token: str = "new_refresh_tok",
    expires_in: int = 300,
) -> dict[str, Any]:
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": expires_in,
    }


# ---------------------------------------------------------------------------
# Step 1 (failing before fix): refresh stores ENCRYPTED tokens in UPDATE
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_refresh_persists_encrypted_tokens():
    """
    After token_refresh, the kc_access_token and kc_refresh_token stored in the
    DB UPDATE must NOT equal the plaintext values and must decrypt back to them.

    This test FAILS before the fix (plaintext currently stored).
    """
    # Seed the DB row with an encrypted refresh token (simulating the callback path).
    encrypted_rt = _encrypt_token("old_refresh_tok")
    db_row = _make_db_row(kc_refresh_token=encrypted_rt)

    new_at = "brand_new_access_token_xyz"
    new_rt = "brand_new_refresh_token_abc"

    captured_params: dict[str, Any] = {}

    async def _fake_execute(sql_text, params=None):
        if params and "at" in params and "rt" in params:
            captured_params.update(params)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = db_row
        return mock_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.oidc_browser._decode_session_jwt",
              return_value=_make_valid_jwt_claims()),
        patch("app.routers.oidc_browser._issue_session_jwt",
              return_value="new_session_jwt"),
        patch("app.routers.oidc_browser._discover",
              new=AsyncMock(return_value={"token_endpoint": "http://kc/token"})),
        patch("app.credential_broker.kms.load_master_secret_standalone",
              new=AsyncMock(return_value=_MASTER_BYTES)),
        patch("app.core.database.AsyncSessionLocal",
              return_value=fake_db),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_kc_token_response(new_at, new_rt)
        mock_resp.raise_for_status = MagicMock()
        mock_httpx.return_value.__aenter__ = AsyncMock(return_value=mock_httpx.return_value)
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_httpx.return_value.post = AsyncMock(return_value=mock_resp)

        from starlette.testclient import TestClient
        from fastapi import FastAPI, Cookie, Request
        # Build a minimal ASGI scope to call token_refresh directly
        from app.routers.oidc_browser import token_refresh
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/oidc/token/refresh",
            "headers": [(b"authorization", f"Bearer valid_jwt".encode())],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        response = await token_refresh(request, mcp_session="valid_jwt")

    # Assert: tokens were captured in the UPDATE
    assert "at" in captured_params, "UPDATE did not include 'at' param"
    assert "rt" in captured_params, "UPDATE did not include 'rt' param"

    stored_at = captured_params["at"]
    stored_rt = captured_params["rt"]

    # Must NOT equal the plaintext
    assert stored_at != new_at, (
        f"kc_access_token stored as PLAINTEXT ('{stored_at}'). "
        "encrypt-before-persist not implemented on the refresh path."
    )
    assert stored_rt != new_rt, (
        f"kc_refresh_token stored as PLAINTEXT ('{stored_rt}'). "
        "encrypt-before-persist not implemented on the refresh path."
    )

    # Must decrypt back to the originals
    assert _decrypt_token(stored_at) == new_at, "Decrypted access token mismatch"
    assert _decrypt_token(stored_rt) == new_rt, "Decrypted refresh token mismatch"


# ---------------------------------------------------------------------------
# Step 4a: DB/encryption failure on refresh must raise 503, not swallow
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_refresh_db_failure_returns_503():
    """
    If the UPDATE fails, the path must return 503 (caller retains old session),
    not silently swallow the error with logger.warning.

    FAILS before the fix (current code: logger.warning + continues to return 200).
    """
    encrypted_rt = _encrypt_token("old_refresh_tok")
    db_row = _make_db_row(kc_refresh_token=encrypted_rt)

    call_count = 0

    async def _fake_execute_raise_on_update(sql_text, params=None):
        nonlocal call_count
        call_count += 1
        if params and "at" in params:
            # This is the UPDATE — simulate failure
            raise RuntimeError("DB write error")
        mock_result = MagicMock()
        mock_result.fetchone.return_value = db_row
        return mock_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute_raise_on_update
    fake_db.commit = AsyncMock()
    fake_db.rollback = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.oidc_browser._decode_session_jwt",
              return_value=_make_valid_jwt_claims()),
        patch("app.routers.oidc_browser._issue_session_jwt",
              return_value="new_session_jwt"),
        patch("app.routers.oidc_browser._discover",
              new=AsyncMock(return_value={"token_endpoint": "http://kc/token"})),
        patch("app.credential_broker.kms.load_master_secret_standalone",
              new=AsyncMock(return_value=_MASTER_BYTES)),
        patch("app.core.database.AsyncSessionLocal",
              return_value=fake_db),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_kc_token_response()
        mock_resp.raise_for_status = MagicMock()
        mock_httpx.return_value.__aenter__ = AsyncMock(return_value=mock_httpx.return_value)
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_httpx.return_value.post = AsyncMock(return_value=mock_resp)

        from app.routers.oidc_browser import token_refresh
        from starlette.requests import Request as StarletteRequest
        from fastapi import HTTPException

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/oidc/token/refresh",
            "headers": [(b"authorization", b"Bearer valid_jwt")],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        # The fixed implementation raises HTTPException(503) on DB failure.
        # Calling the handler directly bypasses FastAPI's exception-to-response
        # conversion, so we catch the HTTPException and check its status code.
        got_status: int | None = None
        try:
            response = await token_refresh(request, mcp_session="valid_jwt")
            got_status = response.status_code
        except HTTPException as http_exc:
            got_status = http_exc.status_code

    assert got_status == 503, (
        f"Expected 503 on DB failure, got {got_status}. "
        "Current code swallows the error and returns 200."
    )


# ---------------------------------------------------------------------------
# Step 4b: expires_at must be set from token lifetime, not NULL
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_refresh_sets_expires_at_from_token_lifetime():
    """
    The UPDATE must set expires_at to NOW() + expires_in, not NULL.
    expires_at = NULL after refresh removes session expiry — a security regression.

    FAILS before the fix (current code: expires_at = NULL).
    """
    encrypted_rt = _encrypt_token("old_refresh_tok")
    db_row = _make_db_row(kc_refresh_token=encrypted_rt)

    captured_params: dict[str, Any] = {}

    async def _fake_execute(sql_text, params=None):
        if params and "at" in params:
            captured_params.update(params)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = db_row
        return mock_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.oidc_browser._decode_session_jwt",
              return_value=_make_valid_jwt_claims()),
        patch("app.routers.oidc_browser._issue_session_jwt",
              return_value="new_session_jwt"),
        patch("app.routers.oidc_browser._discover",
              new=AsyncMock(return_value={"token_endpoint": "http://kc/token"})),
        patch("app.credential_broker.kms.load_master_secret_standalone",
              new=AsyncMock(return_value=_MASTER_BYTES)),
        patch("app.core.database.AsyncSessionLocal",
              return_value=fake_db),
        patch("httpx.AsyncClient") as mock_httpx,
    ):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _make_kc_token_response(expires_in=600)
        mock_resp.raise_for_status = MagicMock()
        mock_httpx.return_value.__aenter__ = AsyncMock(return_value=mock_httpx.return_value)
        mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_httpx.return_value.post = AsyncMock(return_value=mock_resp)

        from app.routers.oidc_browser import token_refresh
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/oidc/token/refresh",
            "headers": [(b"authorization", b"Bearer valid_jwt")],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        await token_refresh(request, mcp_session="valid_jwt")

    expires_at = captured_params.get("exp")
    assert expires_at is not None, (
        "expires_at not set in UPDATE params ('exp' key missing). "
        "Current code sets expires_at = NULL."
    )
    # Should be a datetime roughly now + 600s (allow ±60s tolerance)
    now = datetime.now(timezone.utc)
    if isinstance(expires_at, datetime):
        delta = (expires_at - now).total_seconds()
        assert 540 <= delta <= 660, (
            f"expires_at {expires_at} is not ~600s from now (delta={delta:.0f}s)"
        )


# ---------------------------------------------------------------------------
# Step 5: Round-trip — second refresh decrypts what first refresh wrote
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_refresh_round_trip_two_refreshes():
    """
    Refresh twice in sequence. The second refresh must successfully decrypt
    the tokens written by the first (proving the cycle doesn't break).
    """
    # Initial state: row seeded with encrypted tokens from the callback.
    initial_rt = "initial_refresh_tok"
    encrypted_initial_rt = _encrypt_token(initial_rt)
    session_id = uuid.uuid4()

    # We'll track what gets written so the second refresh reads it.
    stored_at_blob: list[str] = [_encrypt_token("initial_access_tok")]
    stored_rt_blob: list[str] = [encrypted_initial_rt]

    def _make_current_row():
        row = _make_db_row(
            kc_refresh_token=stored_rt_blob[0],
            session_id=session_id,
        )
        return row

    async def _fake_execute(sql_text, params=None):
        if params and "at" in params and "rt" in params:
            # Record what was written
            stored_at_blob[0] = params["at"]
            stored_rt_blob[0] = params["rt"]
        mock_result = MagicMock()
        mock_result.fetchone.return_value = _make_current_row()
        return mock_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    async def run_refresh(at_val: str, rt_val: str) -> None:
        with (
            patch("app.routers.oidc_browser._decode_session_jwt",
                  return_value=_make_valid_jwt_claims()),
            patch("app.routers.oidc_browser._issue_session_jwt",
                  return_value="new_session_jwt"),
            patch("app.routers.oidc_browser._discover",
                  new=AsyncMock(return_value={"token_endpoint": "http://kc/token"})),
            patch("app.credential_broker.kms.load_master_secret_standalone",
                  new=AsyncMock(return_value=_MASTER_BYTES)),
            patch("app.core.database.AsyncSessionLocal",
                  return_value=fake_db),
            patch("httpx.AsyncClient") as mock_httpx,
        ):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = _make_kc_token_response(at_val, rt_val)
            mock_resp.raise_for_status = MagicMock()
            mock_httpx.return_value.__aenter__ = AsyncMock(
                return_value=mock_httpx.return_value)
            mock_httpx.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_httpx.return_value.post = AsyncMock(return_value=mock_resp)

            from app.routers.oidc_browser import token_refresh
            from starlette.requests import Request as StarletteRequest
            scope = {
                "type": "http", "method": "POST",
                "path": "/api/v1/auth/oidc/token/refresh",
                "headers": [(b"authorization", b"Bearer valid_jwt")],
                "query_string": b"", "client": ("127.0.0.1", 1234),
                "server": ("testserver", 80),
            }
            request = StarletteRequest(scope)
            resp = await token_refresh(request, mcp_session="valid_jwt")
            assert resp.status_code == 200, (
                f"Refresh returned {resp.status_code} — expected 200"
            )

    # First refresh
    await run_refresh("access_tok_round2", "refresh_tok_round2")

    # After first refresh, stored blobs should be encrypted
    assert stored_rt_blob[0] != "refresh_tok_round2", (
        "After first refresh, kc_refresh_token is still plaintext — encrypt not applied."
    )

    # Second refresh — must succeed (decrypt the first refresh's output)
    await run_refresh("access_tok_round3", "refresh_tok_round3")

    # Verify final stored values decrypt correctly
    assert _decrypt_token(stored_at_blob[0]) == "access_tok_round3"
    assert _decrypt_token(stored_rt_blob[0]) == "refresh_tok_round3"


# ---------------------------------------------------------------------------
# Step 6: try-decrypt-else-revoke — plaintext session is revoked on first touch
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_plaintext_token_session_is_revoked_on_refresh():
    """
    A session row that has a plaintext (pre-fix) kc_refresh_token must trigger
    try-decrypt-else-revoke: AES-GCM decryption fails → session is revoked
    (revoked_at = NOW()) → caller gets 401 forcing re-login.

    FAILS before the fix (current code: returns 500 on decrypt failure, no revocation).
    """
    plaintext_rt = "plaintext_refresh_tok_not_encrypted"
    db_row = _make_db_row(kc_refresh_token=plaintext_rt)

    revoke_params: dict[str, Any] = {}

    async def _fake_execute(sql_text, params=None):
        # Capture the revocation UPDATE
        if params and "revoked_at" in (params or {}):
            revoke_params.update(params)
        mock_result = MagicMock()
        mock_result.fetchone.return_value = db_row
        return mock_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    with (
        patch("app.routers.oidc_browser._decode_session_jwt",
              return_value=_make_valid_jwt_claims()),
        patch("app.credential_broker.kms.load_master_secret_standalone",
              new=AsyncMock(return_value=_MASTER_BYTES)),
        patch("app.core.database.AsyncSessionLocal",
              return_value=fake_db),
    ):
        from app.routers.oidc_browser import token_refresh
        from starlette.requests import Request as StarletteRequest
        scope = {
            "type": "http", "method": "POST",
            "path": "/api/v1/auth/oidc/token/refresh",
            "headers": [(b"authorization", b"Bearer valid_jwt")],
            "query_string": b"", "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        response = await token_refresh(request, mcp_session="valid_jwt")

    # Must return 401 (session revoked, force re-login)
    assert response.status_code == 401, (
        f"Expected 401 (session revoked) for plaintext token, got {response.status_code}. "
        "try-decrypt-else-revoke not implemented."
    )
    # Must have issued a revocation UPDATE
    assert revoke_params, (
        "No revocation UPDATE issued for plaintext-token session. "
        "try-decrypt-else-revoke not implemented."
    )
    assert "revoked_at" in revoke_params, (
        "Revocation UPDATE missing 'revoked_at' field."
    )


# ---------------------------------------------------------------------------
# N6: Session revocation missing Redis compensating write
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_logout_db_failure_triggers_redis_compensating_write():
    """
    N6 (MEDIUM): When the DB revocation write fails during logout, the Redis
    compensating marker must still be written (SETEX revoked_jti:{jti} …).

    The logout handler already writes Redis unconditionally (after the try/except
    DB block), so this test confirms that the Redis write is NOT conditional on
    DB success — i.e. setex is called even when the DB raises.
    """
    import math
    jti = str(uuid.uuid4())
    exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    claims = {"sub": _SUBJECT, "jti": jti, "exp": exp}

    # DB always raises
    fake_db = AsyncMock()
    fake_db.execute = AsyncMock(side_effect=RuntimeError("DB down"))
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.client = mock_redis

    with (
        patch("app.routers.oidc_browser._decode_session_jwt", return_value=claims),
        patch("app.core.database.AsyncSessionLocal", return_value=fake_db),
        patch("app.core.redis_client.redis_pool", mock_pool),
    ):
        from app.routers.oidc_browser import oidc_logout
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/oidc/logout",
            "headers": [(b"authorization", f"Bearer valid_jwt".encode())],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        response = await oidc_logout(request, mcp_session="valid_jwt")

    # Response must still succeed (logout is best-effort on DB failure)
    assert response.status_code == 200

    # Redis setex must have been called with the correct key
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    redis_key = call_args[0][0] if call_args[0] else call_args.kwargs.get("name", "")
    assert redis_key == f"revoked_jti:{jti}", (
        f"Expected Redis key 'revoked_jti:{jti}', got '{redis_key}'. "
        "Redis compensating write not called on logout DB failure."
    )


@pytest.mark.unit
@pytest.mark.asyncio
async def test_decrypt_else_revoke_db_failure_triggers_redis_compensating_write():
    """
    N6 (MEDIUM): When the DB revocation write fails during decrypt-else-revoke
    (token_refresh path), a Redis compensating marker must be written to close
    the TOCTOU window: SETEX revoked_jti:{jti} must be called.
    """
    jti = str(uuid.uuid4())
    exp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    claims = {"sub": _SUBJECT, "jti": jti, "exp": exp}

    # Row with a plaintext (unencrypted) refresh token — triggers decrypt-else-revoke
    plaintext_rt = "not_encrypted_refresh_token"
    db_row = _make_db_row(kc_refresh_token=plaintext_rt)

    # First execute returns the row (SELECT); second execute raises (revoke UPDATE fails)
    select_result = MagicMock()
    select_result.fetchone.return_value = db_row

    call_count = 0

    async def _fake_execute(sql_text, params=None):
        nonlocal call_count
        call_count += 1
        if params and "revoked_at" in (params or {}):
            raise RuntimeError("DB revocation write failed")
        return select_result

    fake_db = AsyncMock()
    fake_db.execute = _fake_execute
    fake_db.commit = AsyncMock()
    fake_db.__aenter__ = AsyncMock(return_value=fake_db)
    fake_db.__aexit__ = AsyncMock(return_value=False)

    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock()

    mock_pool = MagicMock()
    mock_pool.client = mock_redis

    with (
        patch("app.routers.oidc_browser._decode_session_jwt", return_value=claims),
        patch("app.credential_broker.kms.load_master_secret_standalone",
              new=AsyncMock(return_value=_MASTER_BYTES)),
        patch("app.core.database.AsyncSessionLocal", return_value=fake_db),
        patch("app.core.redis_client.redis_pool", mock_pool),
    ):
        from app.routers.oidc_browser import token_refresh
        from starlette.requests import Request as StarletteRequest

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/auth/oidc/token/refresh",
            "headers": [(b"authorization", b"Bearer valid_jwt")],
            "query_string": b"",
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
        request = StarletteRequest(scope)
        response = await token_refresh(request, mcp_session="valid_jwt")

    # Response must be 401 (session revoked, force re-login)
    assert response.status_code == 401

    # Redis setex must have been called with the correct key
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args
    redis_key = call_args[0][0] if call_args[0] else call_args.kwargs.get("name", "")
    assert redis_key == f"revoked_jti:{jti}", (
        f"Expected Redis key 'revoked_jti:{jti}', got '{redis_key}'. "
        "Redis compensating write missing from decrypt-else-revoke DB failure path (N6)."
    )
