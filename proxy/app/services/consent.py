"""
Owner-consent token — cryptographically-bound, single-use, signed payload.

Governs: server_registry mode changes (custody_mode, injection_mode, upstream_url)
that require owner consent per the spec (D3 flow).

Token: signed JWT-like dict with:
  {server_id, old_mode, new_mode, old_cred_ref, new_cred_ref, owner_sub, jti, iat, exp}

Single-use: jti burned in mode_change_consent.consumed_at on first consume.
An admin PATCH that changes mode/cred without a valid, matching, unconsumed consent → 409.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, fields as dataclass_fields


class ConsentTokenError(Exception):
    """Base for all consent-token errors."""


class ConsentTokenExpiredError(ConsentTokenError):
    pass


class ConsentTokenAlreadyConsumedError(ConsentTokenError):
    pass


class ConsentTokenMismatchError(ConsentTokenError):
    pass


@dataclass(frozen=True)
class ConsentPayload:
    server_id: str
    old_mode: str
    new_mode: str
    owner_sub: str
    jti: str
    iat: int
    exp: int
    old_cred_ref: str | None = None
    new_cred_ref: str | None = None


def _get_signing_key() -> str:
    """Return the application signing key (PROXY_SECRET_KEY)."""
    from app.core.config import settings
    return settings.PROXY_SECRET_KEY


def issue_consent_token(
    server_id: str,
    old_mode: str,
    new_mode: str,
    owner_sub: str,
    old_cred_ref: str | None = None,
    new_cred_ref: str | None = None,
    ttl_seconds: int = 600,  # 10 minutes max per spec
) -> tuple[str, str]:
    """
    Issue a signed consent token.
    Returns (token_str, jti) where token_str is the bearer value and jti is for DB storage.

    Signs with HMAC-SHA256 over the canonical JSON payload using PROXY_SECRET_KEY.
    """
    jti = secrets.token_hex(16)
    now = int(time.time())
    payload: dict = {
        "server_id": server_id,
        "old_mode": old_mode,
        "new_mode": new_mode,
        "owner_sub": owner_sub,
        "jti": jti,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if old_cred_ref:
        payload["old_cred_ref"] = old_cred_ref
    if new_cred_ref:
        payload["new_cred_ref"] = new_cred_ref

    payload_json = json.dumps(payload, sort_keys=True)
    sig = hmac.new(_get_signing_key().encode(), payload_json.encode(), "sha256").hexdigest()
    token = f"{payload_json}.{sig}"
    return token, jti


def verify_consent_token(
    token: str,
    expected_server_id: str,
    expected_new_mode: str,
    expected_owner_sub: str,
) -> ConsentPayload:
    """
    Verify and decode a consent token.
    Raises ConsentTokenError subclass on any failure.
    Does NOT mark the token as consumed — call consume_consent_token() after.
    """
    try:
        payload_json, sig = token.rsplit(".", 1)
    except ValueError:
        raise ConsentTokenError("Malformed consent token")

    expected_sig = hmac.new(_get_signing_key().encode(), payload_json.encode(), "sha256").hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ConsentTokenMismatchError("Consent token signature invalid")

    payload = json.loads(payload_json)
    now = int(time.time())
    if payload.get("exp", 0) <= now:
        raise ConsentTokenExpiredError("Consent token has expired")
    if payload.get("server_id") != expected_server_id:
        raise ConsentTokenMismatchError("Token server_id mismatch")
    if payload.get("new_mode") != expected_new_mode:
        raise ConsentTokenMismatchError("Token new_mode mismatch")
    if payload.get("owner_sub") != expected_owner_sub:
        raise ConsentTokenMismatchError("Token owner_sub mismatch")

    # Build ConsentPayload from known fields only
    field_names = {f.name for f in dataclass_fields(ConsentPayload)}
    kwargs = {k: payload.get(k) for k in field_names}
    return ConsentPayload(**kwargs)


async def consume_consent_token(jti: str) -> bool:
    """
    Mark a consent token as consumed. Returns True if consumed, False if already consumed.
    Idempotent: calling twice returns False on second call.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from datetime import datetime, timezone

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("""
                UPDATE mode_change_consent
                SET consumed_at = :now
                WHERE jti = :jti AND consumed_at IS NULL
            """),
            {"jti": jti, "now": datetime.now(timezone.utc)},
        )
        await db.commit()
        return result.rowcount > 0
