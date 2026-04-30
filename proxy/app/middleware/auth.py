"""
MCP Security Platform — Authentication Middleware

Resolves the caller identity for every request in priority order:
  1. mTLS client certificate CN (extracted from X-Client-Cert-CN header set by Nginx gateway)
  2. OIDC JWT Bearer token (if OIDC_ENABLED=true) — validates JWT, extracts sub claim as client_id
  3. API key Bearer token — hashes the token, looks up api_keys table via Redis cache

Public endpoints (health checks, OIDC callbacks) bypass authentication.

Identity is attached to request.state.client_id and request.state.auth_method.
Roles are loaded from role_assignments table and cached in Redis (key: roles:{client_id}).

See docs/ARCHITECTURE.md Section 5.4 for the API key auth flow.
See docs/RBAC.md Section 5 for enforcement points.
"""
from __future__ import annotations

import json
import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings
from app.core.security import hash_api_key

logger = logging.getLogger(__name__)

# Endpoints that do not require authentication
PUBLIC_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/ready",
    "/api/v1/auth/oidc/login",
    "/api/v1/auth/oidc/callback",
    "/api/v1/integrations/jira/webhook",  # authenticated by JIRA_WEBHOOK_SECRET, not RBAC
})

# Redis key TTL for role cache (5 minutes — short enough to pick up revocations quickly)
_ROLE_CACHE_TTL_SECONDS = 300


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Resolves caller identity and attaches it to request.state.
    Returns HTTP 401 if no valid identity can be resolved for protected endpoints.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: object) -> Response:  # type: ignore[override]
        """
        Resolve identity in mTLS → OIDC JWT → API key priority order.
        Load roles from cache or DB and attach to request.state.client_roles.
        """
        # Skip auth for public endpoints and OPTIONS preflight.
        if request.url.path in PUBLIC_PATHS or request.method == "OPTIONS":
            request.state.client_id = None
            request.state.auth_method = "none"
            request.state.client_roles = []
            return await call_next(request)  # type: ignore[misc]

        client_id: str | None = None
        auth_method: str = "none"

        # ----------------------------------------------------------------
        # Priority 1: mTLS client certificate CN (set by Nginx gateway)
        # ----------------------------------------------------------------
        cert_cn = request.headers.get("X-Client-Cert-CN", "").strip()
        if cert_cn:
            client_id = cert_cn
            auth_method = "mtls"
            logger.debug("Auth: mTLS cert CN=%s", cert_cn)

        # ----------------------------------------------------------------
        # Priority 2: Bearer token — OIDC JWT or API key
        # ----------------------------------------------------------------
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[len("Bearer "):].strip()
                if token:
                    # Try OIDC JWT first (if enabled), fall through to API key check.
                    if settings.OIDC_ENABLED:
                        oidc_client_id = await _validate_oidc_jwt(token)
                        if oidc_client_id:
                            client_id = oidc_client_id
                            auth_method = "oidc"

                    # If OIDC didn't resolve, try API key hash lookup.
                    if not client_id:
                        api_key_client_id = await _resolve_api_key(token)
                        if api_key_client_id:
                            client_id = api_key_client_id
                            auth_method = "api_key"

        if not client_id:
            return JSONResponse(
                status_code=401,
                content={
                    "error": {
                        "code": "UNAUTHENTICATED",
                        "message": (
                            "No valid identity could be resolved. "
                            "Provide mTLS client cert or Authorization: Bearer <token>."
                        ),
                        "request_id": getattr(request.state, "request_id", "unknown"),
                    }
                },
            )

        request.state.client_id = client_id
        request.state.auth_method = auth_method

        # ----------------------------------------------------------------
        # Load roles from Redis cache or PostgreSQL role_assignments
        # ----------------------------------------------------------------
        request.state.client_roles = await _load_roles(client_id)

        logger.debug(
            "Auth resolved",
            extra={
                "client_id": client_id,
                "auth_method": auth_method,
                "roles": request.state.client_roles,
                "request_id": getattr(request.state, "request_id", "unknown"),
            },
        )

        return await call_next(request)  # type: ignore[misc]


async def _validate_oidc_jwt(token: str) -> str | None:
    """
    Validate an OIDC JWT Bearer token.

    Fetches the JWKS from the configured OIDC issuer and validates the token's
    signature, expiry, and audience. Returns the 'sub' claim as client_id.

    Returns None on any validation failure (falls through to API key check).

    STUB: Full JWKS fetch and jose.jwt.decode not yet implemented.
    Returns None — falls through to API key check.
    # TODO: Implement with python-jose: fetch OIDC discovery doc, validate JWT
    #       against JWKS, extract settings.OIDC_ROLE_CLAIM_PATH for roles.
    """
    # STUB: replace with working impl when OIDC is enabled in production.
    return None


async def _resolve_api_key(token: str) -> str | None:
    """
    Resolve an API key Bearer token to a client_id.

    Pipeline (ARCHITECTURE.md §5.4):
      1. Hash the token with API_KEY_HMAC_KEY (HMAC-SHA-256).
      2. Check Redis cache key api_key:{hash} → client_id (TTL 300s).
      3. On cache miss: query api_keys table for matching key_hash and is_active=true.
      4. On DB hit: populate Redis cache and return client_id.
      5. On DB miss or revoked key: return None (→ 401).

    Returns:
        client_id string on success, None on failure.
    """
    key_hash = hash_api_key(token)
    redis_cache_key = f"api_key:{key_hash}"

    # Step 2: Redis cache check
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached = await redis.get(redis_cache_key)
        if cached:
            client_id = cached.decode() if isinstance(cached, bytes) else cached
            logger.debug("API key resolved from Redis cache", extra={"key_hash_prefix": key_hash[:8]})
            return client_id
    except Exception as exc:
        logger.warning("Redis cache miss for API key — falling through to DB", extra={"error": str(exc)})

    # Step 3: PostgreSQL lookup
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    """
                    SELECT client_id FROM api_keys
                    WHERE key_hash = :key_hash
                      AND is_active = true
                      AND (expires_at IS NULL OR expires_at > NOW())
                    LIMIT 1
                    """
                ),
                {"key_hash": key_hash},
            )
            row = result.fetchone()
    except Exception as exc:
        logger.error("DB error during API key lookup", extra={"error": str(exc)})
        return None

    if row is None:
        logger.info("API key not found or revoked", extra={"key_hash_prefix": key_hash[:8]})
        return None

    client_id: str = row.client_id

    # Step 4: Populate Redis cache (best-effort — don't block on failure)
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        await redis.setex(redis_cache_key, _ROLE_CACHE_TTL_SECONDS, client_id)
    except Exception as exc:
        logger.warning("Failed to cache API key in Redis", extra={"error": str(exc)})

    return client_id


async def _load_roles(client_id: str) -> list[str]:
    """
    Load roles for a client from Redis cache or PostgreSQL role_assignments.

    Cache key: roles:{client_id}, TTL 300s.
    Falls back to empty list on any error (callers treat missing roles as least privilege).

    Returns:
        List of role name strings (e.g. ["agent"], ["admin"]).
    """
    redis_cache_key = f"roles:{client_id}"

    # Redis cache check
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached = await redis.get(redis_cache_key)
        if cached:
            roles_str = cached.decode() if isinstance(cached, bytes) else cached
            return json.loads(roles_str)
    except Exception as exc:
        logger.warning("Redis roles cache miss — falling through to DB", extra={"client_id": client_id, "error": str(exc)})

    # PostgreSQL role_assignments lookup
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    """
                    SELECT role FROM role_assignments
                    WHERE client_id = :client_id
                      AND (expires_at IS NULL OR expires_at > NOW())
                    """
                ),
                {"client_id": client_id},
            )
            rows = result.fetchall()
            roles = [row.role for row in rows]
    except Exception as exc:
        logger.error("DB error loading roles", extra={"client_id": client_id, "error": str(exc)})
        return []

    # Populate Redis cache (best-effort)
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        await redis.setex(redis_cache_key, _ROLE_CACHE_TTL_SECONDS, json.dumps(roles))
    except Exception as exc:
        logger.warning("Failed to cache roles in Redis", extra={"error": str(exc)})

    return roles
