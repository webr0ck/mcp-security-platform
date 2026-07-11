"""
MCP Security Platform — OIDC Browser Login Flow

Implements the browser-based Keycloak login flow with PKCE (S256):

  GET  /api/v1/auth/oidc/login     — redirect to Keycloak with PKCE challenge
  GET  /api/v1/auth/oidc/callback  — handle KC callback, issue internal session JWT
  POST /api/v1/auth/oidc/logout    — revoke session JWT + KC session
  GET  /api/v1/auth/oidc/session   — return current session info (who am I?)

The internal session JWT (HS256, short-lived) is stored in:
  - A HttpOnly session cookie (browser flow)
  - Returned as JSON body (API clients that call /login directly)

The Keycloak access/refresh tokens stay server-side (oidc_sessions table + Redis).
Callers never see raw KC tokens.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth/oidc", tags=["OIDC Browser"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _issuer_url_internal() -> str:
    """Keycloak URL reachable from container network."""
    return (
        settings.OIDC_INTERNAL_ISSUER_URL
        or settings.OIDC_INTERNAL_URL
        or settings.OIDC_ISSUER_URL
    )


def _issuer_url_external() -> str:
    """Keycloak URL for browser redirects (LAB_HOST-based)."""
    return settings.OIDC_ISSUER_URL


async def _discover() -> dict[str, Any]:
    """Fetch Keycloak OIDC discovery document (cached in Redis 5 min)."""
    cache_key = "oidc:discovery"
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached = await redis.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    url = f"{_issuer_url_internal()}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            doc = resp.json()
    except Exception as exc:
        logger.error("OIDC discovery failed from %s: %s", url, exc)
        return {}

    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        await redis.setex(cache_key, 300, json.dumps(doc))
    except Exception:
        pass

    return doc


def _derive_callback_url(request: Request) -> str:
    """
    Build the OIDC redirect_uri for the current request.

    Priority:
    1. ``PROXY_BASE_URL`` — always wins when non-empty (production default).
    2. When ``OIDC_TRUST_FORWARDED_HOST=True`` and ``PROXY_BASE_URL`` is empty:
       use ``X-Forwarded-Proto`` + ``X-Forwarded-Host`` (set by the gateway),
       or fall back to the request's ``Host`` header and scheme.

    This makes the redirect_uri match whichever address the browser used
    (LAN IP, Tailscale IP, hostname), so Keycloak's callback lands correctly
    regardless of access path — without hardcoding a single base URL.

    Security: only enable ``OIDC_TRUST_FORWARDED_HOST`` when either:
    - the proxy sits behind a trusted reverse proxy that overwrites Host, OR
    - Keycloak's valid redirect URI list is scoped to trusted hosts.
    When ``PROXY_ALLOWED_HOSTS`` is set, the derived host is validated against
    that allow-list to prevent Host-header injection attacks.
    """
    if settings.PROXY_BASE_URL:
        return f"{settings.PROXY_BASE_URL}/api/v1/auth/oidc/callback"

    if settings.OIDC_TRUST_FORWARDED_HOST:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")

        # Reject malformed host values that could inject characters into the URL.
        # Only allow hostname chars, dots, hyphens, and a single optional :port.
        if not re.match(r'^[A-Za-z0-9.\-]+(:\d{1,5})?$', host):
            raise HTTPException(status_code=400, detail="Invalid Host header")

        # Validate against the explicit allow-list when one is configured.
        if settings.PROXY_ALLOWED_HOSTS:
            allowed = {h.strip() for h in settings.PROXY_ALLOWED_HOSTS.split(",") if h.strip()}
            if host not in allowed:
                raise HTTPException(status_code=400, detail="Untrusted Host header")

        return f"{proto}://{host}/api/v1/auth/oidc/callback"

    # Fallback: PROXY_BASE_URL is empty and trust is off — use configured value.
    return f"{settings.PROXY_BASE_URL}/api/v1/auth/oidc/callback"


def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier + code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _issue_session_jwt(
    subject: str,
    client_id: str,
    roles: list[str],
    jti: str,
    profile_uuid: str | None = None,
) -> str:
    """Issue an internal HS256 session JWT (never contains raw KC tokens).

    Task 4.3: adds optional ``profile`` claim containing the named profile UUID
    string when a profile is bound to this session.  Absent claim = no profile
    (backward compatible — auth middleware treats missing claim as None).
    """
    import jwt as jose_jwt  # PyJWT

    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": subject,
        "client_id": client_id,
        "roles": roles,
        "iss": settings.PROXY_BASE_URL,
        "aud": "mcp-proxy-session",
        "jti": jti,
        "iat": now,
        "exp": now + settings.SESSION_JWT_EXPIRE_SECONDS,
        "auth_method": "oidc_browser",
    }
    if profile_uuid:
        payload["profile"] = profile_uuid
    return jose_jwt.encode(payload, settings.PROXY_SECRET_KEY, algorithm="HS256")


def _decode_session_jwt(token: str) -> dict[str, Any] | None:
    """Decode and verify internal session JWT. Returns None on failure."""
    import jwt as jose_jwt
    from jwt.exceptions import InvalidTokenError as JWTError

    try:
        return jose_jwt.decode(
            token,
            settings.PROXY_SECRET_KEY,
            algorithms=["HS256"],
            audience="mcp-proxy-session",
        )
    except JWTError:
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/login")
async def oidc_login(
    request: Request,
    redirect_after: str = Query(default="/", alias="redirect"),
    profile: str | None = Query(default=None),
):
    """
    Initiate Keycloak browser login with PKCE S256.
    Redirects the browser to Keycloak. On success, Keycloak calls /callback.
    """
    if not settings.OIDC_ENABLED:
        return JSONResponse(
            status_code=501,
            content={"error": "oidc_not_enabled", "message": "OIDC is not configured on this proxy."},
        )

    discovery = await _discover()
    auth_endpoint = discovery.get("authorization_endpoint")
    if not auth_endpoint:
        return JSONResponse(status_code=503, content={"error": "oidc_discovery_failed"})

    # Replace internal URL with external URL for browser redirect
    auth_endpoint = auth_endpoint.replace(_issuer_url_internal(), _issuer_url_external())

    rand_part = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    # Embed post-login redirect destination in state so the callback knows where to send the user.
    # Format: <random>.<base64url(redirect_path)>[.<base64url(profile_name)>]
    # KC round-trips state back unchanged.
    _safe_redirect = redirect_after if redirect_after.startswith("/") else "/"
    state = rand_part + "." + base64.urlsafe_b64encode(_safe_redirect.encode()).rstrip(b"=").decode()
    # Task 4.3: embed profile name in state so callback can resolve it without a DB round-trip.
    # Validate profile name: alphanumeric + hyphens/underscores only, max 64 chars.
    _safe_profile: str | None = None
    if profile:
        import re as _re
        if _re.match(r'^[A-Za-z0-9_-]{1,64}$', profile):
            _safe_profile = profile
        else:
            logger.warning("Invalid profile name ignored at login: %r", profile)
    if _safe_profile:
        state += "." + base64.urlsafe_b64encode(_safe_profile.encode()).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    verifier, challenge = _pkce_pair()

    callback_url = _derive_callback_url(request)

    # Persist PKCE state in DB
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    INSERT INTO oidc_sessions
                        (state, pkce_code_verifier, pkce_code_challenge_method, nonce, redirect_uri)
                    VALUES
                        (:state, :verifier, 'S256', :nonce, :redirect_uri)
                """),
                {
                    "state": state,
                    "verifier": verifier,
                    "nonce": nonce,
                    "redirect_uri": callback_url,
                },
            )
            await session.commit()
    except Exception as exc:
        logger.error("Failed to persist OIDC session state: %s", exc)
        return JSONResponse(status_code=500, content={"error": "session_persist_failed"})

    params = {
        "response_type": "code",
        "client_id": settings.OIDC_CLIENT_ID,
        "redirect_uri": callback_url,
        "scope": "openid profile email roles offline_access",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    from urllib.parse import urlencode
    redirect_url = f"{auth_endpoint}?{urlencode(params)}"
    return RedirectResponse(redirect_url)


@router.get("/callback")
async def oidc_callback(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
    error: str | None = Query(default=None),
    error_description: str | None = Query(default=None),
):
    """
    Handle Keycloak redirect callback.
    Exchanges authorization code for tokens, stores KC tokens server-side,
    issues an internal session JWT, and sets it as a cookie.
    """
    if error:
        return JSONResponse(
            status_code=400,
            content={"error": error, "error_description": error_description},
        )

    # Look up PKCE state
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("SELECT * FROM oidc_sessions WHERE state = :state AND expires_at IS NULL LIMIT 1"),
                {"state": state},
            )
            row = result.fetchone()
    except Exception as exc:
        logger.error("Failed to fetch OIDC session state: %s", exc)
        return JSONResponse(status_code=500, content={"error": "db_error"})

    if row is None:
        # Browser back-button UX (not a security issue): Chromium keeps this
        # callback URL — with its one-time code/state — as a distinct,
        # back-reachable history entry even though the login flow already
        # completed via a normal 302 chain (reproduced directly; not
        # collapsed out of history the way a single-origin redirect chain
        # usually is). Pressing Back after a successful login replays this
        # exact URL, which correctly fails the anti-replay check below —
        # but showing a raw JSON error is a bad, confusing experience for
        # what is actually a no-op (the user is already logged in). If a
        # still-valid session cookie is present, this is that case: bounce
        # to the portal instead of erroring. Anti-replay itself is untouched
        # — a genuinely invalid/expired/forged state with NO valid session
        # still hits the branch below.
        session_token = request.cookies.get(settings.SESSION_COOKIE_NAME, "")
        if session_token:
            try:
                import jwt as jose_jwt
                jose_jwt.decode(
                    session_token,
                    settings.PROXY_SECRET_KEY,
                    algorithms=["HS256"],
                    audience="mcp-proxy-session",
                )
                return RedirectResponse(url="/portal", status_code=302)
            except Exception:
                pass  # fall through to the normal error below
        return JSONResponse(status_code=400, content={"error": "invalid_state", "message": "State not found or already used."})

    verifier = row.pkce_code_verifier
    stored_nonce = row.nonce
    session_id = str(row.session_id)
    callback_uri = row.redirect_uri
    # Proxy-layer PKCE method enforcement: reject sessions that did not use S256.
    # Prevents downgrade even if Keycloak's pkce_code_challenge_method is misconfigured.
    stored_method = getattr(row, "pkce_code_challenge_method", "S256")
    if stored_method != "S256":
        logger.error(
            "PKCE method %r is not S256 for session %s — rejecting callback",
            stored_method,
            session_id,
        )
        return JSONResponse(
            status_code=400,
            content={"error": "pkce_method_not_s256", "message": "Only S256 PKCE is accepted."},
        )

    # Extract post-login redirect from state (<random>.<base64url(path)>[.<base64url(profile)>])
    _post_login_redirect = "/portal"
    _requested_profile_name: str | None = None
    if "." in state:
        try:
            _parts = state.split(".")
            # Part 1: random.  Part 2: base64url(redirect).  Part 3 (optional): base64url(profile).
            if len(_parts) >= 2:
                _encoded = _parts[1]
                _padding = "=" * (-len(_encoded) % 4)
                _decoded = base64.urlsafe_b64decode(_encoded + _padding).decode()
                if _decoded.startswith("/"):
                    _post_login_redirect = _decoded
            if len(_parts) >= 3:
                _p_encoded = _parts[2]
                _p_padding = "=" * (-len(_p_encoded) % 4)
                _p_decoded = base64.urlsafe_b64decode(_p_encoded + _p_padding).decode()
                if _p_decoded:
                    _requested_profile_name = _p_decoded
        except Exception:
            pass

    # Task 4.3: resolve named profile UUID from profile name (if requested)
    _profile_uuid: str | None = None
    if _requested_profile_name:
        try:
            from sqlalchemy import text as _satext
            from app.core.database import AsyncSessionLocal as _ASLS
            async with _ASLS() as _pdb:
                _prow = await _pdb.execute(
                    _satext(
                        "SELECT id FROM profiles WHERE name = :name AND is_active = TRUE LIMIT 1"
                    ),
                    {"name": _requested_profile_name},
                )
                _prof = _prow.fetchone()
                if _prof:
                    _profile_uuid = str(_prof[0])
                else:
                    logger.warning(
                        "Requested profile %r not found or inactive — ignoring profile binding",
                        _requested_profile_name,
                    )
        except Exception as _pexc:
            # INV-015: profile lookup fail-closed.  A DB error during login
            # must NOT silently continue with profile_uuid=None — that would
            # allow a session to be issued without the profile binding that the
            # caller explicitly requested, potentially bypassing tool restrictions.
            logger.error(
                "Failed to resolve profile %r during login callback: %s — returning 503",
                _requested_profile_name,
                _pexc,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "profile_lookup_failed",
                    "message": "Profile lookup unavailable — service degraded. Please retry.",
                },
            )

    # Exchange code for tokens at Keycloak (use internal URL)
    discovery = await _discover()
    token_endpoint = discovery.get("token_endpoint", "")
    if not token_endpoint:
        return JSONResponse(status_code=503, content={"error": "oidc_discovery_failed"})

    # Discovery always advertises the external (browser-facing) issuer URL, even
    # though _discover() itself fetched the document over the internal network.
    # Replace external with internal here so this server-to-server call goes
    # directly to Keycloak over the container network instead of hairpinning
    # back out through nginx's external TLS listener (whose cert the proxy
    # container does not trust) — mirrors the internal->external rewrite for
    # auth_endpoint above.
    token_endpoint = token_endpoint.replace(_issuer_url_external(), _issuer_url_internal())

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": callback_uri,
                    "code_verifier": verifier,
                },
            )
            resp.raise_for_status()
            token_data = resp.json()
    except Exception as exc:
        logger.exception("Token exchange failed: %s", exc)
        return JSONResponse(status_code=502, content={"error": "token_exchange_failed", "detail": "Authentication failed. Check server logs for details."})

    access_token = token_data.get("access_token", "")
    refresh_token = token_data.get("refresh_token", "")
    id_token = token_data.get("id_token", "")
    expires_in = token_data.get("expires_in", settings.SESSION_JWT_EXPIRE_SECONDS)

    # Decode ID token claims — verify signature using JWKS (Bug 3 fix).
    # Falls back to unverified decode only when JWKS is unavailable (fail-open).
    try:
        import jwt as jose_jwt
        from jwt.algorithms import RSAAlgorithm
        from jwt.exceptions import InvalidTokenError as JWTError
        import json as _json
        from app.middleware.auth import _fetch_jwks

        try:
            jwks = await _fetch_jwks()
            if jwks:
                # Pick the key matching the token's kid header
                raw_token = id_token or access_token
                header = jose_jwt.get_unverified_header(raw_token)
                kid = header.get("kid")
                matching_keys = [k for k in jwks if k.get("kid") == kid] if kid else jwks
                if not matching_keys:
                    matching_keys = jwks
                verify_exc_last: Exception | None = None
                id_token_claims: dict = {}
                for jwk_key in matching_keys:
                    try:
                        pub = RSAAlgorithm.from_jwk(_json.dumps(jwk_key))
                        decode_opts: dict = {}
                        if not settings.OIDC_AUDIENCE:
                            decode_opts["verify_aud"] = False
                        id_token_claims = jose_jwt.decode(
                            raw_token,
                            pub,
                            algorithms=["RS256"],
                            audience=settings.OIDC_AUDIENCE or None,
                            issuer=settings.OIDC_ISSUER_URL or None,  # AUTH-001: validate iss claim
                            options=decode_opts,
                        )
                        break
                    except JWTError as ve:
                        verify_exc_last = ve
                        continue
                if not id_token_claims:
                    raise ValueError(verify_exc_last or "No matching JWKS key")
            else:
                raise ValueError("JWKS unavailable — no keys returned")
        except Exception as verify_exc:
            # AUTH-002: fail closed — never skip signature verification.
            # A 503 here is safer than issuing a session backed by unverified claims.
            logger.error(
                "ID token signature verification failed (%s); JWKS unavailable or "
                "token invalid — returning 503 to caller (fail-closed).",
                verify_exc,
            )
            return JSONResponse(
                status_code=503,
                content={
                    "error": "oidc_jwks_unavailable",
                    "message": "Identity provider keys are temporarily unavailable. Please retry.",
                },
            )
    except Exception:
        id_token_claims = {}

    # Validate nonce binding to prevent token injection / replay attacks.
    # Even without full signature verification, this binds the token to the
    # specific login session initiated by /login.
    token_nonce = id_token_claims.get("nonce")
    # Fail-closed: a missing stored_nonce is treated as a reject, not a skip.
    # A NULL/empty nonce means the session row is corrupt or was tampered with.
    if not stored_nonce:
        logger.error(
            "OIDC nonce absent for session %s — possible DB corruption; rejecting callback",
            session_id,
        )
        raise HTTPException(400, "OIDC nonce absent — cannot validate token binding")
    if token_nonce != stored_nonce:
        logger.warning(
            "OIDC nonce mismatch for session %s: stored=%s token=%s",
            session_id,
            stored_nonce,
            token_nonce,
        )
        raise HTTPException(400, "OIDC nonce mismatch — possible token injection")

    from app.middleware.auth import verified_oidc_identity

    claims = id_token_claims
    subject = claims.get("sub", "unknown")
    email = claims.get("email", "")
    # SECURITY (P1-1): only trust email as identity when IdP-verified; else fall
    # back to the immutable sub. Shared with the bearer path in middleware.auth.
    email_verified = claims.get("email_verified", False) is True
    roles = claims.get("roles", []) or []
    if isinstance(roles, str):
        roles = [roles]

    # Map KC roles to proxy roles
    _ROLE_MAP = {
        "admin": "admin", "agent": "agent", "auditor": "auditor", "readonly": "readonly",
        "security_reviewer": "security_reviewer",
    }
    proxy_roles = [_ROLE_MAP[r] for r in roles if r in _ROLE_MAP]
    client_id = verified_oidc_identity(subject, email, email_verified)

    jti = str(uuid.uuid4())
    session_jwt = _issue_session_jwt(
        subject=subject,
        client_id=client_id,
        roles=proxy_roles,
        jti=jti,
        profile_uuid=_profile_uuid,
    )

    expires_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = datetime.fromtimestamp(time.time() + settings.SESSION_JWT_EXPIRE_SECONDS, tz=timezone.utc)

    # AUTH-007: encrypt KC tokens at rest before persisting.
    # Reuses the platform's AES-256-GCM helper (approach_a) with the same
    # master secret used by the credential broker. The subject is used as
    # user_sub for key derivation; service="oidc_session" for AAD separation.
    try:
        from app.credential_broker.approaches.approach_a import encrypt as _enc
        from app.credential_broker.kms import load_master_secret_standalone
        _master = await load_master_secret_standalone()
        # encrypt() returns bytes; columns are TEXT, so base64-encode for storage.
        _enc_access = base64.b64encode(
            _enc(access_token, subject, _master, service="oidc_session")
        ).decode("ascii")
        _enc_refresh = base64.b64encode(
            _enc(refresh_token, subject, _master, service="oidc_session")
        ).decode("ascii")
    except Exception as enc_exc:
        logger.error("Failed to encrypt KC tokens for session %s: %s", session_id, enc_exc)
        raise HTTPException(status_code=500, detail="Session encryption failed.") from enc_exc

    # Update session record with identity + tokens + optional profile binding (Task 4.3)
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    UPDATE oidc_sessions SET
                        subject = :sub,
                        client_id_resolved = :client_id,
                        kc_access_token = :at,
                        kc_refresh_token = :rt,
                        session_jwt_jti = :jti,
                        expires_at = :exp,
                        ip_address = :ip,
                        user_agent = :ua,
                        profile_uuid = :profile_uuid
                    WHERE session_id = :sid
                """),
                {
                    "sub": subject,
                    "client_id": client_id,
                    "at": _enc_access,
                    "rt": _enc_refresh,
                    "jti": jti,
                    "exp": expires_at,
                    "ip": request.client.host if request.client else None,
                    "ua": request.headers.get("user-agent", "")[:512],
                    "profile_uuid": _profile_uuid,
                    "sid": session_id,
                },
            )
            await session.commit()
    except Exception as exc:
        logger.error("Failed to update OIDC session record: %s", exc)
        # SECURITY: If the DB write fails, the JTI is not registered in oidc_sessions.
        # Subsequent auth checks will deny this JWT (unknown JTI = forged token policy).
        # Return a 503 rather than issuing a JWT the user can never use.
        raise HTTPException(
            status_code=503,
            detail="Session registration failed — please try logging in again.",
        ) from exc

    # Sync KC-held roles into role_assignments (append-only, INV-011/V050 — no
    # UPDATE/DELETE available). Only insert a fresh 'keycloak' grant event when
    # the latest event for this (client_id, role) isn't already an active
    # keycloak-sourced grant — otherwise every login would insert a duplicate
    # row forever. This also means: if an admin revokes a KC-sourced role via
    # the RBAC panel but Keycloak still grants it, the next login re-activates
    # it (documented in the panel UI, not a bug — KC remains the identity
    # source of truth for KC-mapped roles).
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            for role in proxy_roles:
                await session.execute(
                    text("""
                        INSERT INTO role_assignments (client_id, role, granted_by)
                        SELECT :cid, :role, 'keycloak'
                        WHERE NOT EXISTS (
                            SELECT 1 FROM role_assignments
                            WHERE client_id = :cid AND role = :role
                            ORDER BY created_at DESC LIMIT 1
                        ) OR (
                            SELECT revoked = false AND granted_by = 'keycloak'
                            FROM role_assignments
                            WHERE client_id = :cid AND role = :role
                            ORDER BY created_at DESC LIMIT 1
                        ) = false
                    """),
                    {"cid": client_id, "role": role},
                )
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to sync KC roles to role_assignments: %s", exc)

    # Redirect the browser to the post-login destination (or /portal by default).
    # The session JWT travels as an httpOnly cookie — no token in the URL.
    response = RedirectResponse(url=_post_login_redirect, status_code=302)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_jwt,
        max_age=settings.SESSION_JWT_EXPIRE_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        domain=settings.SESSION_COOKIE_DOMAIN if settings.SESSION_COOKIE_DOMAIN != "localhost" else None,
    )
    return response


@router.post("/logout")
async def oidc_logout(
    request: Request,
    mcp_session: str | None = Cookie(default=None, alias="mcp_session"),
):
    """Revoke the internal session JWT and KC session."""
    token = mcp_session
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()

    if token:
        claims = _decode_session_jwt(token)
        if claims:
            jti = claims.get("jti")
            subject = claims.get("sub")
            # Revoke in DB
            try:
                from sqlalchemy import text
                from app.core.database import AsyncSessionLocal
                from datetime import datetime, timezone
                async with AsyncSessionLocal() as session:
                    await session.execute(
                        text("UPDATE oidc_sessions SET revoked_at = :now WHERE session_jwt_jti = :jti"),
                        {"now": datetime.now(timezone.utc), "jti": jti},
                    )
                    await session.commit()
            except Exception as exc:
                logger.warning("Failed to revoke OIDC session in DB: %s", exc)

            # Write Redis fast-path revocation marker (revoked_jti:{jti}).
            # TTL is bounded to the JWT's remaining validity so the key is
            # self-expiring: after the JWT would have expired anyway the key
            # is no longer needed.  This means even if postgres is down after
            # logout, the Redis fast-path in _is_session_jti_revoked will
            # immediately deny the revoked token (F-C fix).
            if jti:
                try:
                    import math
                    from app.core.redis_client import redis_pool
                    exp = claims.get("exp", 0)
                    remaining_ttl = max(math.ceil(exp - time.time()), 1)
                    redis = redis_pool.client
                    await redis.setex(f"revoked_jti:{jti}", remaining_ttl, "1")
                    logger.debug(
                        "JTI revocation: Redis marker written",
                        extra={"jti_prefix": jti[:8] if len(jti) >= 8 else jti, "ttl": remaining_ttl},
                    )
                except Exception as exc:
                    # Best-effort: log but do not block logout.
                    # The DB revocation is already committed; Redis is a fast-path
                    # optimisation.  A Redis failure here is logged so ops can
                    # investigate degraded fast-path availability.
                    logger.warning("Failed to write Redis JTI revocation marker: %s", exc)

    response = JSONResponse(content={"message": "Logged out."})
    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    return response


@router.get("/session")
async def oidc_session_info(
    request: Request,
    mcp_session: str | None = Cookie(default=None, alias="mcp_session"),
):
    """Return current session identity (who am I?)."""
    token = mcp_session
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()

    if not token:
        return JSONResponse(status_code=401, content={"error": "no_session"})

    claims = _decode_session_jwt(token)
    if not claims:
        return JSONResponse(status_code=401, content={"error": "invalid_session"})

    # Enforce JTI revocation — consistent with auth middleware on all other paths.
    jti = claims.get("jti")
    if jti and await _is_session_jti_revoked(jti):
        return JSONResponse(status_code=401, content={"error": "session_revoked"})

    return JSONResponse(content={
        "subject": claims.get("sub"),
        "client_id": claims.get("client_id"),
        "roles": claims.get("roles", []),
        "auth_method": claims.get("auth_method"),
        "expires_at": claims.get("exp"),
    })


@router.post("/token/refresh")
async def token_refresh(
    request: Request,
    mcp_session: str | None = Cookie(default=None, alias="mcp_session"),
):
    """
    Refresh the internal session JWT using the stored KC refresh token.

    MCP clients call this when their session JWT is near expiry.
    Accepts the current session JWT via cookie OR Authorization: Bearer header.
    Returns a new session JWT (same roles, new expiry) and sets the cookie.

    Flow: decode current JWT → look up oidc_sessions row by jti →
          call KC token endpoint with stored refresh_token →
          issue new internal session JWT → update DB row.
    """
    token = mcp_session
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()

    if not token:
        return JSONResponse(status_code=401, content={"error": "no_session"})

    claims = _decode_session_jwt(token)
    if not claims:
        return JSONResponse(status_code=401, content={"error": "invalid_session"})

    jti = claims.get("jti")
    if not jti:
        return JSONResponse(status_code=401, content={"error": "no_jti"})

    # Look up the stored KC refresh token
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("""
                    SELECT kc_refresh_token, subject, client_id_resolved, session_id
                    FROM oidc_sessions
                    WHERE session_jwt_jti = :jti AND revoked_at IS NULL
                    LIMIT 1
                """),
                {"jti": uuid.UUID(jti)},
            )
            row = result.fetchone()
    except Exception as exc:
        logger.error("DB error in token/refresh: %s", exc)
        return JSONResponse(status_code=500, content={"error": "db_error"})

    if row is None:
        return JSONResponse(status_code=401, content={"error": "session_not_found"})

    # AUTH-007: decrypt the stored KC refresh token before using it.
    _raw_rt_blob = row.kc_refresh_token
    if not _raw_rt_blob:
        return JSONResponse(status_code=400, content={"error": "no_refresh_token_stored"})
    try:
        from app.credential_broker.approaches.approach_a import decrypt as _dec, encrypt as _enc
        from app.credential_broker.kms import load_master_secret_standalone
        _master_rt = await load_master_secret_standalone()
        # subject comes from the row; fall back to JWT claims if missing.
        _rt_subject = row.subject or claims.get("sub", "")
        kc_refresh_token = _dec(
            base64.b64decode(_raw_rt_blob), _rt_subject, _master_rt, service="oidc_session"
        )
    except Exception as dec_exc:
        # AUTH-007 / Task 0.1 Step 6: try-decrypt-else-revoke.
        # A row with a plaintext (pre-fix) token will fail AES-GCM decryption.
        # Revoke the session immediately and force re-login — never 500 on this path.
        logger.warning(
            "KC refresh token decryption failed for session %s (possible pre-fix plaintext row):"
            " %s — revoking session and forcing re-login.",
            row.session_id, dec_exc,
        )
        try:
            _revoke_ts = datetime.now(timezone.utc)
            async with AsyncSessionLocal() as _revoke_db:
                await _revoke_db.execute(
                    text(
                        "UPDATE oidc_sessions SET revoked_at = :revoked_at"
                        " WHERE session_id = :sid"
                    ),
                    {"revoked_at": _revoke_ts, "sid": row.session_id},
                )
                await _revoke_db.commit()
        except Exception as revoke_exc:
            logger.error(
                "Failed to revoke session %s after decryption failure: %s",
                row.session_id, revoke_exc,
            )
            # N6: Compensating Redis revocation — best-effort (prevents TOCTOU window
            # if DB revocation write failed silently after decrypt-else-revoke).
            try:
                import math as _math
                from app.core.redis_client import redis_pool as _redis_pool
                _jti = jti  # jti decoded from claims earlier in this function (line 712)
                _exp = claims.get("exp", 0)
                _ttl = max(_math.ceil(_exp - time.time()), 300) if _exp else 86400
                _redis = _redis_pool.client
                await _redis.setex(f"revoked_jti:{_jti}", _ttl, "1")
                logger.warning(
                    "Redis compensating revocation written for jti %s after DB failure",
                    _jti[:8] if _jti and len(_jti) >= 8 else _jti,
                )
            except Exception as _redis_err:
                logger.warning("Redis compensating revocation write failed: %s", _redis_err)
        return JSONResponse(
            status_code=401,
            content={"error": "session_revoked_relogin_required"},
        )

    # Exchange refresh token at KC (use internal URL — see R-1 fix in oidc_callback
    # above: discovery advertises the external issuer URL for token_endpoint too).
    discovery = await _discover()
    token_endpoint = discovery.get("token_endpoint", "")
    token_endpoint = token_endpoint.replace(_issuer_url_external(), _issuer_url_internal())
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "client_id": settings.OIDC_CLIENT_ID,
                    "client_secret": settings.OIDC_CLIENT_SECRET,
                    "refresh_token": kc_refresh_token,
                },
            )
            if resp.status_code == 400:
                return JSONResponse(status_code=401, content={"error": "refresh_token_expired"})
            resp.raise_for_status()
            token_data = resp.json()
    except Exception as exc:
        logger.error("KC refresh token exchange failed: %s", exc)
        return JSONResponse(status_code=502, content={"error": "refresh_failed"})

    new_access_token = token_data.get("access_token", "")
    new_refresh_token = token_data.get("refresh_token", kc_refresh_token)
    new_jti = str(uuid.uuid4())

    roles: list[str] = claims.get("roles", [])
    subject: str = row.subject or claims.get("sub", "")
    client_id: str = row.client_id_resolved or claims.get("client_id", "")

    new_jwt = _issue_session_jwt(subject, client_id, roles, new_jti)

    # AUTH-007 / Task 0.1 Step 3: encrypt new tokens before persisting —
    # identical pattern to the callback path (oidc_browser.py:438-451).
    # _enc and _master_rt are already in scope from the decrypt block above.
    try:
        _enc_new_at = base64.b64encode(
            _enc(new_access_token, _rt_subject, _master_rt, service="oidc_session")
        ).decode("ascii")
        _enc_new_rt = base64.b64encode(
            _enc(new_refresh_token, _rt_subject, _master_rt, service="oidc_session")
        ).decode("ascii")
    except Exception as enc_exc:
        logger.error(
            "Failed to encrypt new KC tokens for session %s: %s",
            row.session_id, enc_exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Session token encryption failed — please retry.",
        ) from enc_exc

    # Task 0.1 Step 4: set expires_at from the new token's lifetime instead of NULL.
    # Falls back to SESSION_JWT_EXPIRE_SECONDS when KC doesn't return expires_in.
    _kc_expires_in: int = token_data.get("expires_in", settings.SESSION_JWT_EXPIRE_SECONDS)
    _new_expires_at = datetime.fromtimestamp(
        time.time() + _kc_expires_in, tz=timezone.utc
    )

    # Update DB: rotate jti + refresh token, store new KC access token.
    # Task 0.1 Step 4: raise on failure (caller retains old session; 503).
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(
                text("""
                    UPDATE oidc_sessions SET
                        kc_access_token  = :at,
                        kc_refresh_token = :rt,
                        session_jwt_jti  = :new_jti,
                        expires_at       = :exp
                    WHERE session_id = :sid
                """),
                {
                    "at": _enc_new_at,
                    "rt": _enc_new_rt,
                    "new_jti": uuid.UUID(new_jti),
                    "exp": _new_expires_at,
                    "sid": row.session_id,
                },
            )
            await db.commit()
    except Exception as exc:
        logger.error(
            "Failed to update session after refresh for session %s: %s",
            row.session_id, exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Session refresh failed — please retry.",
        ) from exc

    response = JSONResponse(content={
        "session_token": new_jwt,
        "expires_in": settings.SESSION_JWT_EXPIRE_SECONDS,
        "token_type": "Bearer",
    })
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=new_jwt,
        max_age=settings.SESSION_JWT_EXPIRE_SECONDS,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite="lax",
        domain=settings.SESSION_COOKIE_DOMAIN if settings.SESSION_COOKIE_DOMAIN != "localhost" else None,
    )
    return response
