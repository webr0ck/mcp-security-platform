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
import re
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

import ipaddress

from app.core.config import settings
from app.core.security import hash_api_key


def _sanitize_cn(cn: str) -> str:
    """Strip control characters from mTLS CN to prevent log injection."""
    return re.sub(r"[\x00-\x1f\x7f]", "", cn).strip()[:128]


def _is_trusted_proxy(request: Request) -> bool:
    """Return True only when the request carries the gateway shared secret.

    RT-NEW-005: X-Client-Cert-CN must only be honoured when it arrives from
    Nginx/gateway, which proves its identity via X-Gateway-Secret.
    CIDR-based checks are insufficient because gvproxy port-forwarding makes
    direct host connections appear on the same subnet as Nginx.

    Design: Nginx sets `proxy_set_header X-Gateway-Secret <secret>` on every
    proxied request. Direct callers cannot know this secret and are rejected.
    If GATEWAY_SHARED_SECRET is empty (lab), mTLS CN auth is disabled entirely
    rather than trusting unverified headers. When the secret IS configured,
    a missing or mismatched header is denied (fail-closed, GW-001).
    """
    secret = settings.GATEWAY_SHARED_SECRET
    if not secret:
        # Lab mode: secret not configured — CN auth disabled. Safe: no grant is given.
        return False
    provided = request.headers.get("X-Gateway-Secret", "")
    if not provided:
        # Secret configured but header absent — deny (GW-001: fail closed)
        logger.warning(
            "X-Gateway-Secret not present but GATEWAY_SHARED_SECRET is set — "
            "denying CN auth (possible direct-connect bypass attempt)"
        )
        return False
    import hmac as _hmac
    return _hmac.compare_digest(provided, secret)

logger = logging.getLogger(__name__)


def verified_oidc_identity(sub: str, email: str, email_verified: bool) -> str:
    """Resolve the client_id for an OIDC caller, anti-spoof (P1-1).

    Email is used as the identity key only when the IdP asserts it verified.
    With ``verifyEmail=true`` on the realm, changing one's email resets
    ``email_verified`` to false until the new mailbox is proven — so a user
    cannot rename their email to a privileged identity (e.g. ``admin@corp``)
    and inherit its roles / entitlements / brokered credentials. An unverified
    or absent email falls back to the immutable ``sub`` (a non-privileged UUID),
    never the claimed email. Fail-closed by construction.
    """
    if email and email_verified:
        return email
    if email and not email_verified:
        logger.warning(
            "OIDC identity: email present but not verified for sub=%s; "
            "using sub as client_id (P1-1 anti-spoof)", sub
        )
    return sub


# Endpoints that do not require authentication
PUBLIC_PATHS: frozenset[str] = frozenset({
    "/",           # redirects to /portal
    "/health",
    "/health/ready",
    "/api/v1/auth/oidc/login",
    "/api/v1/auth/oidc/callback",
    "/api/v1/auth/oidc/token/refresh",    # self-authenticated via current JWT
    "/api/v1/integrations/jira/webhook",  # authenticated by JIRA_WEBHOOK_SECRET, not RBAC
    "/oauth/register",                    # RFC 7591 dynamic client registration — pre-auth
})

# CB-001: the OAuth IdP redirects the user's browser here with no client
# cert / API key, so the path must be public — but identity is NOT taken
# from a header. It is recovered from the single-use server-side nonce
# created at /auth/enroll/* (a PROTECTED path). /auth/enroll/* is
# intentionally NOT public and is authenticated by AuthMiddleware.
_PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/auth/callback/",
    "/.well-known/",
    "/static/",    # vendored JS/CSS assets — no auth required
    # NOTE: Reverse-proxy target prefixes (/netbox/, /grafana/, /keycloak/) are NOT
    # in this list. Those services manage their own auth, but the proxy layer must
    # still authenticate the caller before forwarding. Defence in depth.
)


def _is_public(path: str) -> bool:
    return path in PUBLIC_PATHS or path.startswith(_PUBLIC_PATH_PREFIXES)


def _build_principal_id(auth_method: str, client_id: str) -> tuple[str, str]:
    """
    Return (principal_id, principal_type) in the v3 typed namespace.

    human OIDC/session: ("human:{issuer_id}:{sub}", "human")
    agent mTLS cert:    ("agent:{ca_id}:{cn}", "agent")
    API key:            ("human:apikey:{client_id}", "human")
    """
    if auth_method == "mtls":
        return f"agent:{settings.MTLS_CA_ID}:{client_id}", "agent"
    if auth_method == "api_key":
        return f"human:apikey:{client_id}", "human"
    # oidc_session, oidc, or any other human auth method
    return f"human:{settings.OIDC_ISSUER_ID}:{client_id}", "human"


# Redis key TTL for role cache (60s — matches v3 spec ≤60s revocation SLA)
_ROLE_CACHE_TTL_SECONDS = 60


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
        if _is_public(request.url.path) or request.method == "OPTIONS":
            request.state.client_id = None
            request.state.auth_method = "none"
            request.state.client_roles = []
            request.state.principal_id = None
            request.state.principal_type = None
            request.state.profile_uuid = None
            request.state.is_service_account = False
            return await call_next(request)  # type: ignore[misc]

        client_id: str | None = None
        auth_method: str = "none"
        # P1-2: default False; only the OIDC bearer path flips this True for
        # Keycloak client_credentials (service-account) tokens.
        request.state.is_service_account = False

        # ----------------------------------------------------------------
        # Priority 1: mTLS client certificate CN (set by Nginx gateway)
        # RT-NEW-005 fix: only trust X-Client-Cert-CN from upstream proxy IPs.
        # Direct callers (port 8000) cannot spoof mTLS identity via this header.
        # ----------------------------------------------------------------
        cert_cn = _sanitize_cn(request.headers.get("X-Client-Cert-CN", ""))
        if cert_cn and _is_trusted_proxy(request):
            client_id = cert_cn
            auth_method = "mtls"
            logger.debug("Auth: mTLS cert CN=%s", cert_cn)
        elif cert_cn:
            logger.warning(
                "X-Client-Cert-CN header ignored: source IP %s is not a trusted proxy",
                request.client.host if request.client else "unknown",
            )

        # ----------------------------------------------------------------
        # Priority 2: Internal session JWT (from Keycloak browser login cookie)
        # ----------------------------------------------------------------
        if not client_id:
            session_token = request.cookies.get(settings.SESSION_COOKIE_NAME, "")
            if session_token:
                try:
                    import jwt as jose_jwt
                    from jwt.exceptions import InvalidTokenError as JWTError
                    claims = jose_jwt.decode(
                        session_token,
                        settings.PROXY_SECRET_KEY,
                        algorithms=["HS256"],
                        audience="mcp-proxy-session",
                    )
                    session_client_id = claims.get("client_id") or claims.get("sub")
                    if session_client_id:
                        jti = claims.get("jti")
                        # Require jti — a legitimately issued session JWT always has one.
                        # Missing jti means a crafted/forged token; treat as revoked/unknown.
                        if not jti or await _is_session_jti_revoked(jti):
                            return JSONResponse({"detail": "Session revoked or not issued by this proxy"}, status_code=401)
                        client_id = session_client_id
                        auth_method = "oidc_session"
                        request.state._jwt_roles = claims.get("roles", [])
                        request.state._kc_sub = claims.get("sub")
                        # Task 4.3: propagate named profile UUID from JWT claim.
                        # Absent claim → None (backward compatible: no profile = legacy path).
                        request.state._session_profile_uuid = claims.get("profile")
                except Exception:
                    pass

        # ----------------------------------------------------------------
        # Priority 3: Bearer token — OIDC JWT, internal session JWT, or API key
        # ----------------------------------------------------------------
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[len("Bearer "):].strip()
                if token:
                    # 3a. Try internal session JWT (issued by /auth/oidc/callback)
                    try:
                        import jwt as jose_jwt
                        from jwt.exceptions import InvalidTokenError as JWTError
                        claims = jose_jwt.decode(
                            token,
                            settings.PROXY_SECRET_KEY,
                            algorithms=["HS256"],
                            audience="mcp-proxy-session",
                        )
                        session_client_id = claims.get("client_id") or claims.get("sub")
                        if session_client_id:
                            jti = claims.get("jti")
                            # Require jti — legitimately issued session JWTs always carry one.
                            if not jti or await _is_session_jti_revoked(jti):
                                return JSONResponse({"detail": "Session revoked or not issued by this proxy"}, status_code=401)
                            client_id = session_client_id
                            auth_method = "oidc_session"
                            request.state._jwt_roles = claims.get("roles", [])
                            request.state._kc_sub = claims.get("sub")
                            # Task 4.3: propagate named profile UUID from JWT claim.
                            request.state._session_profile_uuid = claims.get("profile")
                    except Exception:
                        pass

                    # 3b. Try external OIDC JWT (Keycloak access token directly).
                    if not client_id and settings.OIDC_ENABLED:
                        oidc_client_id, jwt_roles, is_sa = await _validate_oidc_jwt(token)
                        if oidc_client_id:
                            client_id = oidc_client_id
                            auth_method = "oidc"
                            request.state._jwt_roles = jwt_roles
                            request.state.is_service_account = is_sa
                            # 6.3: the bearer IS a Keycloak access token here, so it
                            # can serve as the RFC 8693 subject_token for
                            # oauth_user_token on-behalf-of exchange. Stash it for the
                            # invoke path. NOT set for api_key/mtls/internal-session
                            # callers — their bearer is not a KC subject token.
                            # In-memory for the request only; never logged (INV-002).
                            request.state.user_kc_token = token

                    # 3c. API key hash lookup (no OIDC dependency).
                    if not client_id:
                        api_key_client_id = await _resolve_api_key(token)
                        if api_key_client_id:
                            client_id = api_key_client_id
                            auth_method = "api_key"

        if not client_id:
            # Browser requests (Accept: text/html) get a login redirect instead of JSON 401.
            accept = request.headers.get("accept", "")
            if "text/html" in accept and settings.OIDC_ENABLED:
                from urllib.parse import quote
                from starlette.responses import RedirectResponse as _Redirect
                redirect_to = quote(str(request.url.path), safe="")
                return _Redirect(
                    url=f"/api/v1/auth/oidc/login?redirect={redirect_to}",
                    status_code=302,
                )
            _base = settings.PROXY_BASE_URL.rstrip("/") if settings.PROXY_BASE_URL else str(request.base_url).rstrip("/")
            resource_metadata_url = _base + "/.well-known/oauth-protected-resource"
            return JSONResponse(
                status_code=401,
                content={
                    # RFC 6750 §3.1 — `error` must be a string (OAuth clients validate this)
                    "error": "unauthenticated",
                    "error_description": (
                        "No valid identity could be resolved. "
                        "Provide mTLS client cert or Authorization: Bearer <token>."
                    ),
                    "request_id": getattr(request.state, "request_id", "unknown"),
                },
                headers={
                    "WWW-Authenticate": f'Bearer realm="mcp-proxy", resource_metadata="{resource_metadata_url}"',
                },
            )

        request.state.client_id = client_id
        request.state.auth_method = auth_method
        # 6.3: default — only the direct-OIDC path (3b) sets a real KC subject token.
        if not hasattr(request.state, "user_kc_token"):
            request.state.user_kc_token = None
        principal_id, principal_type = _build_principal_id(auth_method, client_id)
        request.state.principal_id = principal_id
        request.state.principal_type = principal_type
        # Task 4.3: named profile UUID from session JWT claim (cookie path 2 or Bearer 3a).
        # None when no profile was bound at login (backward compatible: legacy mcp_profiles path).
        # mTLS and API-key callers never have a profile_uuid.
        request.state.profile_uuid = getattr(request.state, "_session_profile_uuid", None)

        # ----------------------------------------------------------------
        # Load roles: merge DB role_assignments with any roles in the JWT.
        # DB is always authoritative. Internal session JWTs (proxy-issued,
        # auth_method=oidc_session) are trusted in all environments and may
        # supplement DB roles. External OIDC JWTs (auth_method=oidc, roles
        # from the IdP) are mechanically blocked from augmenting DB roles in
        # non-development environments to prevent JWT role escalation attacks.
        # ----------------------------------------------------------------
        db_roles = await _load_roles(client_id)
        jwt_roles: list[str] = getattr(request.state, "_jwt_roles", [])
        # External OIDC JWT roles (from IdP) must not augment DB roles in production.
        # Internal session JWTs (proxy-issued, auth_method=oidc_session) are trusted in all envs.
        if auth_method == "oidc" and settings.ENVIRONMENT != "development":
            jwt_roles = []
        combined = list(dict.fromkeys(db_roles + [r for r in jwt_roles if r not in db_roles]))
        request.state.client_roles = combined

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


async def _redis_jti_lookup(jti: str) -> str | None:
    """
    Check whether a revoked-JTI marker exists in Redis.

    Returns the stored value (truthy string) if the key `revoked_jti:{jti}` is
    present, or None if the key is absent.

    Raises on any Redis connectivity or command error so the caller can decide
    how to handle it (fail-closed by default in _is_session_jti_revoked).

    Extracted as a separate function so tests can monkeypatch it cleanly.
    """
    from app.core.redis_client import redis_pool
    redis = redis_pool.client
    return await redis.get(f"revoked_jti:{jti}")


async def _db_jti_lookup(jti: str):
    """
    Look up a session JTI in the oidc_sessions table.

    Returns a SimpleNamespace-like row with a `revoked_at` attribute, or None
    if no row exists for the given JTI.

    Raises on any DB connectivity or query error so the caller can decide how
    to handle it (fail-closed by default in _is_session_jti_revoked).

    Extracted as a separate function so tests can monkeypatch it cleanly.
    """
    from types import SimpleNamespace
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import text as sa_text
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            sa_text(
                "SELECT revoked_at FROM oidc_sessions WHERE session_jwt_jti = :jti LIMIT 1"
            ),
            {"jti": jti},
        )
        record = row.fetchone()
        if record is None:
            return None
        return SimpleNamespace(revoked_at=record[0])


async def _is_session_jti_revoked(jti: str) -> bool:
    """
    Return True (DENY) if the given session JWT JTI is:
      - present in the Redis `revoked_jti:{jti}` fast-path cache (written at logout), OR
      - not found in the oidc_sessions table (never legitimately issued → forged), OR
      - found in oidc_sessions with revoked_at IS NOT NULL (explicitly revoked), OR
      - triggers ANY exception in either Redis or DB lookup (fail-closed).

    Return False (ALLOW) only when:
      - Redis cache misses (key absent), AND
      - oidc_sessions row exists with revoked_at IS NULL (active session).

    Security invariant (F-C): this function MUST NEVER return False on error.
    A total Redis+DB outage blocks all session-JWT authentication — this is the
    accepted availability cost in exchange for the security guarantee.

    Two-tier lookup:
      1. Redis fast-path: O(1) sub-millisecond; populated at logout.
         Error → fall through to DB (not silently deny, as DB may be healthy).
      2. DB authoritative fallback: source of truth for sessions not yet in Redis.
         Error → deny (fail-closed).

    Both-error path: if Redis errors AND DB errors → deny.
    """
    # -----------------------------------------------------------------------
    # Tier 1: Redis fast-path (revoked_jti:{jti} key written at logout time)
    # -----------------------------------------------------------------------
    redis_errored = False
    try:
        cached = await _redis_jti_lookup(jti)
        if cached is not None:
            # Key exists → token was explicitly revoked; deny immediately.
            logger.debug(
                "JTI revocation: Redis cache hit — denying revoked JTI",
                extra={"jti_prefix": jti[:8] if len(jti) >= 8 else jti},
            )
            return True  # DENY: Redis fast-path hit
        # Key absent — Redis is reachable but JTI not yet cached; fall through to DB.
    except Exception as exc:
        redis_errored = True
        logger.warning(
            "JTI revocation: Redis lookup failed — falling through to DB (fail-closed on DB error): %s",
            exc,
        )

    # -----------------------------------------------------------------------
    # Tier 2: DB authoritative fallback
    # -----------------------------------------------------------------------
    try:
        row = await _db_jti_lookup(jti)
        if row is None:
            # JTI was never registered — token was never legitimately issued.
            logger.warning(
                "JTI revocation: JTI not found in oidc_sessions — possible forged token; denying",
                extra={"jti_prefix": jti[:8] if len(jti) >= 8 else jti},
            )
            return True  # DENY: unknown JTI = forged / replay
        revoked = row.revoked_at is not None
        if revoked:
            logger.debug(
                "JTI revocation: DB row has revoked_at set — denying",
                extra={"jti_prefix": jti[:8] if len(jti) >= 8 else jti},
            )
        return revoked  # True if revoked, False if active
    except Exception as exc:
        # DB error: fail-closed regardless of whether Redis also errored.
        logger.warning(
            "JTI revocation: DB lookup failed — denying (fail-closed): %s",
            exc,
            extra={"redis_also_errored": redis_errored},
        )
        return True  # DENY: fail-closed


_jwks_cache: dict[str, Any] = {}   # {"keys": [...], "fetched_at": float, "jwks_uri": str}
_JWKS_TTL = 300.0


async def _discover_jwks_uri(base: str) -> str:
    """
    Resolve the JWKS URI via OIDC discovery.
    Tries RFC 8414 (/.well-known/oauth-authorization-server) then OIDC standard
    (/.well-known/openid-configuration). Falls back to Dex-style {base}/keys.
    """
    import httpx

    for path in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{base}{path}")
                if resp.status_code == 200:
                    uri = resp.json().get("jwks_uri", "")
                    if uri:
                        # Rewrite host to internal URL so JWKS fetch stays on container network
                        return uri
        except Exception:
            continue
    # Last resort: Dex default JWKS path relative to issuer base
    return f"{base}/keys"


def _get_jwks_base_url() -> str:
    """Return the internal JWKS discovery URL — prefers OIDC_INTERNAL_ISSUER_URL over OIDC_INTERNAL_URL."""
    internal_issuer = getattr(settings, "OIDC_INTERNAL_ISSUER_URL", "").strip()
    if internal_issuer:
        return internal_issuer.rstrip("/")
    internal_url = getattr(settings, "OIDC_INTERNAL_URL", "").strip()
    if internal_url:
        return internal_url.rstrip("/")
    return settings.OIDC_ISSUER_URL.rstrip("/")


async def _fetch_jwks() -> list[dict]:
    """Fetch and cache the JWKS from the configured OIDC issuer using discovery."""
    import time
    import httpx

    now = time.monotonic()
    if _jwks_cache and now - _jwks_cache.get("fetched_at", 0) < _JWKS_TTL:
        return _jwks_cache["keys"]

    # Use OIDC_INTERNAL_ISSUER_URL (Keycloak container URL) for JWKS fetches,
    # falling back to OIDC_INTERNAL_URL and finally OIDC_ISSUER_URL.
    # Bug fix: previously hardcoded OIDC_INTERNAL_URL which pointed at Dex,
    # causing all Keycloak tokens to be rejected during JWKS validation.
    base = _get_jwks_base_url()

    jwks_uri = _jwks_cache.get("jwks_uri") or await _discover_jwks_uri(base)

    # Ensure the JWKS URI uses the internal base (discovery may return the public URL)
    public_base = settings.OIDC_ISSUER_URL.rstrip("/")
    if public_base and public_base != base:
        jwks_uri = jwks_uri.replace(public_base, base)

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            data = resp.json()
            keys = data.get("keys", [])
            _jwks_cache["keys"] = keys
            _jwks_cache["fetched_at"] = now
            _jwks_cache["jwks_uri"] = jwks_uri
            return keys
    except Exception as exc:
        logger.warning("JWKS fetch failed from %s: %s", jwks_uri, exc)
        return _jwks_cache.get("keys", [])


async def _validate_oidc_jwt(token: str) -> tuple[str | None, list[str], bool]:
    """
    Validate an OIDC JWT Bearer token against the configured issuer's JWKS.
    Returns (client_id, roles_from_jwt, is_service_account) on success,
    (None, [], False) on failure. Roles from the JWT are a fallback when the DB
    has no assignments. ``is_service_account`` is True for Keycloak
    client_credentials tokens (preferred_username ``service-account-<clientId>``)
    — used to bar machine tokens from human-only self-service (P1-2).
    """
    try:
        import jwt as jose_jwt
        from jwt.algorithms import RSAAlgorithm
        from jwt.exceptions import InvalidTokenError as JWTError

        keys = await _fetch_jwks()
        if not keys:
            logger.warning("No JWKS keys available — cannot validate OIDC JWT")
            return None, [], False

        # Decode header to pick the right key by kid
        header = jose_jwt.get_unverified_header(token)
        kid = header.get("kid")
        matching = [k for k in keys if k.get("kid") == kid] if kid else keys
        if not matching:
            matching = keys  # fall back to trying all keys

        # Enforce audience when OIDC_AUDIENCE is set.
        # If unset in non-production, log a WARNING (production is
        # blocked at startup by the config validator).
        # OIDC_CLIENT_ID is the proxy's own client identity — it must NOT
        # be used as an audience constraint because dynamic clients
        # (e.g. Claude Code via RFC 7591) receive tokens with their own
        # dynamically-generated client_id in the aud claim.
        expected_aud = settings.OIDC_AUDIENCE.strip() or None
        if not expected_aud:
            logger.warning(
                "OIDC_AUDIENCE is not set — audience validation is DISABLED. "
                "Any valid JWT from the same Keycloak realm will authenticate. "
                "Set OIDC_AUDIENCE to the expected audience to close this gap."
            )

        last_exc: Exception | None = None
        import json as _json
        for jwk_key in matching:
            try:
                # PyJWT: construct public key from JWK dict
                pub = RSAAlgorithm.from_jwk(_json.dumps(jwk_key))
                decode_options: dict = {}
                if not expected_aud:
                    decode_options["verify_aud"] = False
                claims = jose_jwt.decode(
                    token,
                    pub,
                    algorithms=["RS256"],
                    audience=expected_aud,
                    issuer=settings.OIDC_ISSUER_URL or None,  # AUTH-001: validate iss (mirror oidc_browser)
                    options=decode_options,
                )
                sub: str = claims.get("sub", "")
                if not sub:
                    return None, [], False
                # Email is the identity key when present (matches role_assignments
                # and OPA grants like alice@corp) — but only when IdP-verified (P1-1).
                email: str = claims.get("email", "")
                email_verified = claims.get("email_verified", False) is True
                client_id_from_jwt = verified_oidc_identity(sub, email, email_verified)
                # P1-2: KC client_credentials (service-account) tokens carry
                # preferred_username="service-account-<clientId>". Flag them so the
                # entitlement layer can bar machine tokens from human-only actions
                # (self-service profile mutation) — a service account that could
                # self-expand its own profile is a privilege-escalation vector.
                preferred_username = str(claims.get("preferred_username", ""))
                is_service_account = preferred_username.startswith("service-account-")
                # Extract roles claim — supports top-level "roles" claim.
                # Also check realm_access.roles (Keycloak default location).
                jwt_roles: list[str] = claims.get("roles", [])
                if not jwt_roles:
                    realm_access = claims.get("realm_access", {})
                    jwt_roles = realm_access.get("roles", []) if isinstance(realm_access, dict) else []
                if isinstance(jwt_roles, str):
                    jwt_roles = [jwt_roles]
                logger.debug("OIDC JWT validated: sub=%s client_id=%s jwt_roles=%s sa=%s",
                             sub, client_id_from_jwt, jwt_roles, is_service_account)
                return client_id_from_jwt, jwt_roles, is_service_account
            except JWTError as exc:
                last_exc = exc
                continue

        logger.info("OIDC JWT validation failed: %s", last_exc)
        return None, [], False

    except Exception as exc:
        logger.warning("Unexpected error in OIDC JWT validation: %s", exc)
        return None, [], False


async def _resolve_api_key(token: str) -> str | None:
    """
    Resolve an API key Bearer token to a client_id.

    Pipeline (ARCHITECTURE.md §5.4):
      1. Hash the token with API_KEY_HMAC_KEY (HMAC-SHA-256).
      2. Check Redis cache key api_key:{hash} → client_id (TTL 300s).
      3. On cache miss: query api_keys table for matching key_hash and revoked_at IS NULL.
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
                      AND revoked_at IS NULL
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
