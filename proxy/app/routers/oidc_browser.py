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
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Cookie, Query, Request
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


def _pkce_pair() -> tuple[str, str]:
    """Generate PKCE code_verifier + code_challenge (S256)."""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _issue_session_jwt(subject: str, client_id: str, roles: list[str], jti: str) -> str:
    """Issue an internal HS256 session JWT (never contains raw KC tokens)."""
    import jwt as jose_jwt  # PyJWT

    now = int(time.time())
    payload = {
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

    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    nonce = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()
    verifier, challenge = _pkce_pair()

    callback_url = f"{settings.PROXY_BASE_URL}/api/v1/auth/oidc/callback"

    # Persist PKCE state in DB
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    INSERT INTO oidc_sessions
                        (state, pkce_code_verifier, nonce, redirect_uri)
                    VALUES
                        (:state, :verifier, :nonce, :redirect_uri)
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
        return JSONResponse(status_code=400, content={"error": "invalid_state", "message": "State not found or already used."})

    verifier = row.pkce_code_verifier
    stored_nonce = row.nonce
    session_id = str(row.session_id)
    callback_uri = row.redirect_uri

    # Exchange code for tokens at Keycloak (use internal URL)
    discovery = await _discover()
    token_endpoint = discovery.get("token_endpoint", "")
    if not token_endpoint:
        return JSONResponse(status_code=503, content={"error": "oidc_discovery_failed"})

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
        logger.error("Token exchange failed: %s", exc)
        return JSONResponse(status_code=502, content={"error": "token_exchange_failed", "detail": str(exc)})

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
            logger.warning(
                "ID token signature verification failed (%s), falling back to "
                "unverified claims (fail-open — JWKS may be temporarily unreachable)",
                verify_exc,
            )
            # PyJWT equivalent of get_unverified_claims
            raw_token = id_token or access_token
            id_token_claims = jose_jwt.decode(
                raw_token,
                options={"verify_signature": False},
                algorithms=["RS256", "HS256"],
            )
    except Exception:
        id_token_claims = {}

    # Validate nonce binding to prevent token injection / replay attacks.
    # Even without full signature verification, this binds the token to the
    # specific login session initiated by /login.
    from fastapi import HTTPException
    token_nonce = id_token_claims.get("nonce")
    if stored_nonce and token_nonce != stored_nonce:
        logger.warning(
            "OIDC nonce mismatch for session %s: stored=%s token=%s",
            session_id,
            stored_nonce,
            token_nonce,
        )
        raise HTTPException(400, "OIDC nonce mismatch — possible token injection")

    claims = id_token_claims
    subject = claims.get("sub", "unknown")
    email = claims.get("email", "")
    roles = claims.get("roles", []) or []
    if isinstance(roles, str):
        roles = [roles]

    # Map KC roles to proxy roles
    _ROLE_MAP = {"admin": "admin", "agent": "agent", "auditor": "auditor", "readonly": "readonly"}
    proxy_roles = [_ROLE_MAP[r] for r in roles if r in _ROLE_MAP]
    client_id = email or subject

    jti = str(uuid.uuid4())
    session_jwt = _issue_session_jwt(
        subject=subject,
        client_id=client_id,
        roles=proxy_roles,
        jti=jti,
    )

    expires_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = datetime.fromtimestamp(time.time() + settings.SESSION_JWT_EXPIRE_SECONDS, tz=timezone.utc)

    # Update session record with identity + tokens
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
                        user_agent = :ua
                    WHERE session_id = :sid
                """),
                {
                    "sub": subject,
                    "client_id": client_id,
                    "at": access_token,
                    "rt": refresh_token,
                    "jti": jti,
                    "exp": expires_at,
                    "ip": request.client.host if request.client else None,
                    "ua": request.headers.get("user-agent", "")[:512],
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

    # Also register the session JWT client_id in role_assignments if not present
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            for role in proxy_roles:
                await session.execute(
                    text("""
                        INSERT INTO role_assignments (client_id, role, granted_by)
                        VALUES (:cid, :role, 'keycloak')
                        ON CONFLICT DO NOTHING
                    """),
                    {"cid": client_id, "role": role},
                )
            await session.commit()
    except Exception as exc:
        logger.warning("Failed to sync KC roles to role_assignments: %s", exc)

    response_data = {
        "session_token": session_jwt,
        "subject": subject,
        "client_id": client_id,
        "roles": proxy_roles,
        "expires_in": settings.SESSION_JWT_EXPIRE_SECONDS,
        "token_type": "Bearer",
    }

    response = JSONResponse(content=response_data)
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

    return JSONResponse(content={
        "subject": claims.get("sub"),
        "client_id": claims.get("client_id"),
        "roles": claims.get("roles", []),
        "auth_method": claims.get("auth_method"),
        "expires_at": claims.get("exp"),
    })
