"""
Consent token service for server approval and mode-change operations.

The approve path in routers/server_registry.py calls:
  1. verify_approve_consent_token() — HMAC signature + expiry + server binding check
  2. consume_consent_token() — marks jti used in mode_change_consent (row-level PG lock prevents replay)
  3. Only then: approval db.commit()

Known gap (accepted): consume and approval run in separate DB sessions. A failure between
consume commit and approval commit leaves the token consumed but the server unapproved.
Owner must re-mint a consent token. This is fail-closed (not fail-open).

Governs: server_registry mode changes (custody_mode, injection_mode, upstream_url)
that require owner consent per the spec (D3 flow).

Token: signed JWT-like dict with:
  {server_id, old_mode, new_mode, old_cred_ref, new_cred_ref, owner_sub, jti, iat, exp}

Single-use: jti burned in mode_change_consent.consumed_at on first consume.
An admin PATCH that changes mode/cred without a valid, matching, unconsumed consent → 409.

--- R-5 EXTENSION (2026-06-09) ---

Added EnrollmentConsentPayload for OAuth enrollment consent gate (ADR-003).

PAYLOAD SEPARATION (C7):
  ModeChangePayload  — server_registry mode transitions; single-use jti burned
                       in mode_change_consent DB table via consume_consent_token().
  EnrollmentConsentPayload — OAuth enrollment consent; single-use jti burned in
                       Redis via get_and_delete() (NOT consume_consent_token / the
                       mode_change_consent table — which would silently no-op or
                       contaminate that table).

The signed EnrollmentConsentPayload is the DURABLE AUDIT ATTESTATION only.
In-flow single-use enforcement is handled by the Redis enroll_consent: key
consumed atomically at POST /auth/enroll/{svc}/consent (C5).
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
    expected_old_mode: str | None = None,
    expected_old_cred_ref: str | None = None,
    expected_new_cred_ref: str | None = None,
) -> ConsentPayload:
    """
    Verify and decode a consent token.
    Raises ConsentTokenError subclass on any failure.
    Does NOT mark the token as consumed — call consume_consent_token() after.

    The optional expected_old_mode, expected_old_cred_ref, and
    expected_new_cred_ref parameters bind the token to a specific transition.
    Without these checks a token issued for one mode/credential transition
    could be replayed for a different transition on the same server.
    Callers that do not pass these parameters retain existing behaviour.
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
    if expected_old_mode is not None and payload.get("old_mode") != expected_old_mode:
        raise ConsentTokenMismatchError("Token old_mode mismatch")
    if expected_old_cred_ref is not None and payload.get("old_cred_ref") != expected_old_cred_ref:
        raise ConsentTokenMismatchError("Token old_cred_ref mismatch")
    if expected_new_cred_ref is not None and payload.get("new_cred_ref") != expected_new_cred_ref:
        raise ConsentTokenMismatchError("Token new_cred_ref mismatch")

    # Build ConsentPayload from known fields only
    field_names = {f.name for f in dataclass_fields(ConsentPayload)}
    kwargs = {k: payload.get(k) for k in field_names}
    return ConsentPayload(**kwargs)


# =============================================================================
# R-5: EnrollmentConsentPayload — OAuth enrollment durable audit attestation
# =============================================================================

@dataclass(frozen=True)
class EnrollmentConsentPayload:
    """
    Durable signed attestation for an OAuth enrollment consent (R-5, ADR-003 D4).

    Fields:
      client_id    — MCP client that requested enrollment (from server-side session)
      service      — OAuth service (e.g. "m365")
      scopes_hash  — SHA-256 hex of the canonical (sorted, space-separated) scopes
                     (INV-002: never raw scopes in a signed/stored token)
      jti          — unique token id (single-use guard; burned in Redis via get_and_delete)
      iat          — issued-at Unix timestamp
      exp          — expiry Unix timestamp

    Single-use enforcement: the in-flow CSRF/single-use check is done by the Redis
    enroll_consent: key consumed atomically at POST /consent (C5). This payload is
    the durable audit record only — NOT burned in mode_change_consent (C7).
    """
    client_id: str
    service: str
    scopes_hash: str
    jti: str
    iat: int
    exp: int


def _canonical_scopes(scopes: list[str]) -> str:
    """Return a canonical (sorted, lowercased, space-separated) scope string."""
    return " ".join(sorted(s.lower() for s in scopes if s))


def _scopes_hash(scopes: list[str]) -> str:
    """Return SHA-256 hex of the canonical scope string (INV-002)."""
    return hashlib.sha256(_canonical_scopes(scopes).encode()).hexdigest()


def issue_enrollment_consent_token(
    client_id: str,
    service: str,
    scopes: list[str],
    ttl_seconds: int = 300,  # 5 minutes — matches enroll_consent: Redis TTL
) -> tuple[str, str]:
    """
    Issue a signed EnrollmentConsentPayload token.

    Returns (token_str, jti).

    Signs with HMAC-SHA256 over canonical JSON using PROXY_SECRET_KEY.
    Stores scopes_hash (not raw scopes) per INV-002.

    C7: single-use enforcement is Redis-side (enroll_consent: key consumed via
    get_and_delete at POST /consent). This token is the durable audit record only.
    See module docstring for the payload separation design.
    """
    jti = secrets.token_hex(16)
    now = int(time.time())
    payload: dict = {
        "type": "enrollment_consent",
        "client_id": client_id,
        "service": service,
        "scopes_hash": _scopes_hash(scopes),
        "jti": jti,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload_json = json.dumps(payload, sort_keys=True)
    sig = hmac.new(_get_signing_key().encode(), payload_json.encode(), "sha256").hexdigest()
    return f"{payload_json}.{sig}", jti


def verify_enrollment_consent_token(token: str) -> EnrollmentConsentPayload:
    """
    Verify and decode an EnrollmentConsentPayload token.
    Raises ConsentTokenError subclass on any failure.

    C7: does NOT burn a jti in any DB table. In-flow single-use enforcement is
    handled by the caller via Redis get_and_delete on the enroll_consent: key.
    See module docstring for the payload separation design.
    """
    try:
        payload_json, sig = token.rsplit(".", 1)
    except ValueError:
        raise ConsentTokenError("Malformed enrollment consent token")

    expected_sig = hmac.new(
        _get_signing_key().encode(), payload_json.encode(), "sha256"
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise ConsentTokenMismatchError("Enrollment consent token signature invalid")

    payload = json.loads(payload_json)
    now = int(time.time())
    if payload.get("exp", 0) <= now:
        raise ConsentTokenExpiredError("Enrollment consent token has expired")
    if payload.get("type") != "enrollment_consent":
        raise ConsentTokenMismatchError("Token type mismatch: expected enrollment_consent")

    return EnrollmentConsentPayload(
        client_id=payload["client_id"],
        service=payload["service"],
        scopes_hash=payload["scopes_hash"],
        jti=payload["jti"],
        iat=payload["iat"],
        exp=payload["exp"],
    )


async def persist_consent_token(
    jti: str,
    server_id: str,
    old_mode: str,
    new_mode: str,
    owner_sub: str,
    payload_hash: str,
    expires_at: "datetime",
    old_cred_ref: str | None = None,
    new_cred_ref: str | None = None,
) -> None:
    """
    Persist a consent token record to mode_change_consent.

    Must be called after issue_consent_token() or issue_approve_consent_token()
    to enable replay-prevention via consume_consent_token().
    Without persisting, consume_consent_token() will silently no-op (rowcount=0)
    and replay is possible for the full TTL window.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await db.execute(
            text("""
                INSERT INTO mode_change_consent
                    (jti, server_id, old_mode, new_mode, old_cred_ref, new_cred_ref,
                     owner_sub, payload_hash, expires_at)
                VALUES
                    (:jti, :server_id, :old_mode, :new_mode, :old_cred_ref, :new_cred_ref,
                     :owner_sub, :payload_hash, :expires_at)
                ON CONFLICT (jti) DO NOTHING
            """),
            {
                "jti": jti,
                "server_id": server_id,
                "old_mode": old_mode,
                "new_mode": new_mode,
                "old_cred_ref": old_cred_ref,
                "new_cred_ref": new_cred_ref,
                "owner_sub": owner_sub,
                "payload_hash": payload_hash,
                "expires_at": expires_at,
            },
        )
        await db.commit()


async def consume_consent_token(jti: str) -> bool:
    """
    Mark a consent token as consumed. Returns True if consumed, False if already consumed.
    Idempotent: calling twice returns False on second call.

    IMPORTANT: Returns False if the jti was never persisted (not found). Callers must
    treat False as replay/invalid and raise a 409, never silently allow-through.
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


# =============================================================================
# Approve-action consent tokens — server approval dual-control (D3)
# =============================================================================

# Sentinel values used in mode_change_consent for approval-action tokens.
# These are not valid injection_mode_enum values, so they cannot collide with
# real mode-transition tokens stored in the same table.
_APPROVE_OLD_MODE = "__approve_pending__"
_APPROVE_NEW_MODE = "__approve_approved__"


def issue_approve_consent_token(
    server_id: str,
    owner_sub: str,
    ttl_seconds: int = 900,  # 15 minutes per spec
) -> tuple[str, str]:
    """
    Issue a signed consent token for the 'approve' action (pending→approved).

    Returns (token_str, jti).

    Callers MUST also call persist_consent_token() with the returned jti
    to enable replay-prevention. Verify+consume at approval time with
    verify_approve_consent_token() + consume_consent_token().
    """
    return issue_consent_token(
        server_id=server_id,
        old_mode=_APPROVE_OLD_MODE,
        new_mode=_APPROVE_NEW_MODE,
        owner_sub=owner_sub,
        ttl_seconds=ttl_seconds,
    )


def verify_approve_consent_token(
    token: str,
    expected_server_id: str,
    expected_owner_sub: str,
) -> "ConsentPayload":
    """
    Verify a consent token issued for the 'approve' action.

    Raises ConsentTokenError subclass on any failure.
    Does NOT consume the token — call consume_consent_token(payload.jti) after.
    """
    return verify_consent_token(
        token=token,
        expected_server_id=expected_server_id,
        expected_new_mode=_APPROVE_NEW_MODE,
        expected_owner_sub=expected_owner_sub,
        expected_old_mode=_APPROVE_OLD_MODE,
    )
