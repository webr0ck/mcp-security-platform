"""
MCP Security Platform — Keycloak Token Client

Thin async client for Keycloak token operations:
  - service_account_token(): client_credentials grant for service-account mode
  - exchange_token(): token exchange (RFC 8693) for oauth_user_token mode
  - jwks_uri(): JWKS discovery for JWT verification

All tokens are cached in Redis with a TTL derived from expires_in minus a
30-second safety margin. Cache key format:
  kc:sa:{client_id}          — service-account tokens
  kc:ex:{subject_token_hash} — exchanged user tokens
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_KC_TOKEN_CACHE_MARGIN_SECONDS = 30


def _issuer_url() -> str:
    """Return the internal Keycloak issuer URL for container-to-container calls."""
    return (
        settings.OIDC_INTERNAL_ISSUER_URL
        or settings.OIDC_INTERNAL_URL
        or settings.OIDC_ISSUER_URL
    )


def _token_endpoint() -> str:
    return f"{_issuer_url()}/protocol/openid-connect/token"


async def get_service_account_token(
    client_id: str,
    client_secret: str,
    scope: str = "openid",
) -> str | None:
    """
    Obtain a Keycloak service-account access token via client_credentials grant.
    Result is cached in Redis; returns None on failure.
    """
    cache_key = f"kc:sa:{client_id}"

    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            return data.get("access_token")
    except Exception as exc:
        logger.warning("Redis cache miss for KC service-account token: %s", exc)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _token_endpoint(),
                data={
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                },
            )
            resp.raise_for_status()
            token_data = resp.json()
    except Exception as exc:
        logger.error("Failed to obtain KC service-account token for %s: %s", client_id, exc)
        return None

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 300)
    ttl = max(1, expires_in - _KC_TOKEN_CACHE_MARGIN_SECONDS)

    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        await redis.setex(cache_key, ttl, json.dumps({"access_token": access_token}))
    except Exception as exc:
        logger.warning("Failed to cache KC service-account token: %s", exc)

    return access_token


async def exchange_token(
    subject_token: str,
    audience: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    requested_token_type: str = "urn:ietf:params:oauth:token-type:access_token",
    subject_token_type: str = "urn:ietf:params:oauth:token-type:access_token",
) -> str | None:
    """
    Exchange a Keycloak access token for a different audience (RFC 8693).
    Used for oauth_user_token injection mode — exchanges the user's session
    token for an upstream service token.
    Returns None if token exchange is disabled or fails.
    """
    if not settings.KC_TOKEN_EXCHANGE_ENABLED:
        logger.debug("KC token exchange disabled; skipping")
        return None

    _client_id = client_id or settings.OIDC_CLIENT_ID
    _client_secret = client_secret or settings.OIDC_CLIENT_SECRET
    _audience = audience or settings.KC_TOKEN_EXCHANGE_AUDIENCE

    subject_hash = hashlib.sha256(subject_token.encode()).hexdigest()[:16]
    cache_key = f"kc:ex:{subject_hash}:{_audience}"

    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cached = await redis.get(cache_key)
        if cached:
            data = json.loads(cached)
            if data.get("expires_at", 0) > time.time() + _KC_TOKEN_CACHE_MARGIN_SECONDS:
                return data.get("access_token")
    except Exception as exc:
        logger.warning("Redis cache miss for KC token exchange: %s", exc)

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                _token_endpoint(),
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": _client_id,
                    "client_secret": _client_secret,
                    "subject_token": subject_token,
                    "subject_token_type": subject_token_type,
                    "requested_token_type": requested_token_type,
                    "audience": _audience,
                },
            )
            resp.raise_for_status()
            token_data = resp.json()
    except Exception as exc:
        logger.error("KC token exchange failed (audience=%s): %s", _audience, exc)
        return None

    access_token = token_data.get("access_token")
    expires_in = token_data.get("expires_in", 300)
    expires_at = time.time() + expires_in

    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        ttl = max(1, expires_in - _KC_TOKEN_CACHE_MARGIN_SECONDS)
        await redis.setex(
            cache_key,
            ttl,
            json.dumps({"access_token": access_token, "expires_at": expires_at}),
        )
    except Exception as exc:
        logger.warning("Failed to cache KC exchanged token: %s", exc)

    return access_token


async def discover_jwks_uri() -> dict[str, Any]:
    """
    Fetch the JWKS from Keycloak's well-known endpoint.
    Used by the auth middleware for JWT verification.
    """
    oidc_config_url = f"{_issuer_url()}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            cfg_resp = await client.get(oidc_config_url)
            cfg_resp.raise_for_status()
            jwks_uri = cfg_resp.json()["jwks_uri"]
            jwks_resp = await client.get(jwks_uri)
            jwks_resp.raise_for_status()
            return jwks_resp.json()
    except Exception as exc:
        logger.error("Failed to fetch JWKS from %s: %s", oidc_config_url, exc)
        return {"keys": []}


async def get_public_key_for_token(token: str):
    """
    Fetch KC JWKS and return the RSA public key matching the token's kid header.
    Used by S-5 to verify exchanged tokens before trusting any claim.
    """
    from jwt.algorithms import RSAAlgorithm
    import json as _json
    import jwt as _jwt

    jwks = await discover_jwks_uri()
    keys = jwks.get("keys", [])

    header = _jwt.get_unverified_header(token)
    kid = header.get("kid")
    matching = [k for k in keys if k.get("kid") == kid] if kid else keys
    if not matching:
        raise ValueError(f"No JWKS key matching kid={kid!r}")
    return RSAAlgorithm.from_jwk(_json.dumps(matching[0]))
