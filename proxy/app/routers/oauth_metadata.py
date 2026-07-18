"""
MCP OAuth 2.1 discovery endpoints (MCP spec §4.2, RFC 8414).

Zero-credential client model: MCP clients (Claude Code, etc.) need only the
gateway URL — no API key, no pre-configured client ID. The flow is:

  1. Client hits POST /mcp with no credentials.
  2. Proxy returns 401 with:
       WWW-Authenticate: Bearer realm="mcp-proxy",
         resource_metadata="<base>/.well-known/oauth-protected-resource"
  3. Client fetches /.well-known/oauth-protected-resource → authorization_servers
  4. Client fetches /.well-known/oauth-authorization-server (proxied from Keycloak)
     → discovers auth/token/jwks endpoints + registration_endpoint
  5. Client POSTs to /oauth/register → receives static "claude-code" public client
     (no client_secret; Keycloak accepts public clients with PKCE).
  6. Client opens browser to Keycloak login page.
  7. User authenticates → client holds a short-lived session token.
  8. Client stores token in memory only — nothing persisted in ~/.mcp.json.

The only thing in ~/.mcp.json is the gateway URL:
  { "mcpServers": { "mcp-security-platform": { "type": "http",
      "url": "http://localhost:8000/mcp" } } }
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["oauth-discovery"])

# Schemes allowed for redirect_uris.
# http is permitted only for localhost loopback (RFC 8252 §8.3 / §7.3).
_ALLOWED_REDIRECT_SCHEMES = {"https", "http"}
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _validate_redirect_uri(uri: str) -> None:
    """
    Validate a redirect_uri scheme and hostname.

    Allowed:
      - https://<anything>
      - http://localhost, http://127.0.0.1, http://::1  (dev loopback only)

    Rejected with HTTP 422:
      - javascript:, data:, file:, ftp:, custom-scheme:, missing scheme
      - http:// with a non-loopback hostname
    """
    try:
        parsed = urlparse(uri)
    except Exception:
        raise HTTPException(status_code=422, detail=f"redirect_uri {uri!r} could not be parsed")

    if parsed.scheme not in _ALLOWED_REDIRECT_SCHEMES:
        raise HTTPException(
            status_code=422,
            detail=f"redirect_uri scheme {parsed.scheme!r} is not allowed; use https://",
        )
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
        raise HTTPException(
            status_code=422,
            detail=f"http redirect_uris are only allowed for localhost; got {parsed.hostname!r}",
        )


async def _check_register_rate_limit(client_ip: str, limit: int = 10, window: int = 60) -> bool:
    """
    Rate-limit POST /oauth/register by client IP.
    Returns True if the request is within quota, False if it should be rejected.
    Fails open (returns True) when Redis is unavailable.
    """
    try:
        from app.core.redis_client import redis_pool
        rl_client = redis_pool.rate_limit_client
        key = f"rl:oauth_register:{client_ip}"
        pipe = rl_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window)
        results = await pipe.execute()
        return results[0] <= limit
    except Exception:
        return False  # fail-closed: rate-limit must not bypass on infrastructure error

# "claude-code" is a pre-registered public Keycloak client (publicClient: true,
# no secret, PKCE S256 required, any localhost redirect URI allowed).
# Defined in lab/keycloak/realm-mcp.json.
_CLAUDE_CODE_CLIENT_ID = "claude-code"


def _public_issuer() -> str:
    return settings.OIDC_ISSUER_URL.rstrip("/")


def _internal_issuer() -> str:
    """Keycloak URL reachable inside the container network for server-to-server calls."""
    return (
        (settings.OIDC_INTERNAL_ISSUER_URL or settings.OIDC_INTERNAL_URL or settings.OIDC_ISSUER_URL)
        .rstrip("/")
    )


def _proxy_base(request: Request) -> str:
    return settings.PROXY_BASE_URL.rstrip("/") if settings.PROXY_BASE_URL else str(request.base_url).rstrip("/")


def _replace_str(value: Any, old: str, new: str) -> Any:
    """Recursively replace `old` with `new` in every string value, including
    nested dicts/lists (e.g. Keycloak's mtls_endpoint_aliases object)."""
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, dict):
        return {k: _replace_str(v, old, new) for k, v in value.items()}
    if isinstance(value, list):
        return [_replace_str(v, old, new) for v in value]
    return value


async def _fetch_idp_discovery() -> dict:
    """
    Fetch Keycloak's OIDC discovery document.
    Tries OIDC standard path first (Keycloak uses this), then RFC 8414.
    Rewrites container-internal URLs → public URLs so browser clients can follow them.
    """
    import httpx

    public = _public_issuer()
    internal = _internal_issuer()

    for path in ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"):
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{internal}{path}")
                if resp.status_code == 200:
                    data = resp.json()
                    if internal != public:
                        data = _replace_str(data, internal, public)
                    # KC dev-mode may return a different base URL than `internal`
                    # (e.g. "localhost:8082" when it inferred the frontend URL from
                    # an early browser request). Rewrite whatever KC actually returned
                    # as its issuer so all endpoints point at the public address.
                    actual_issuer = data.get("issuer", "").rstrip("/")
                    if actual_issuer and actual_issuer != public:
                        data = _replace_str(data, actual_issuer, public)
                    return data
        except Exception as exc:
            logger.debug("IdP discovery at %s%s unavailable: %s", internal, path, exc)

    return {}


async def _authorization_server_metadata(request: Request) -> dict:
    """
    RFC 8414 server metadata — proxies Keycloak's discovery document with the
    proxy's value-adds (registration bridge, PKCE S256, filtered scopes).

    ISSUER CONSISTENCY (RFC 9207 / doc 10): `issuer` is the realm issuer URL and
    MUST equal both the callback `iss` Keycloak emits and the `authorization_servers`
    entry in the protected-resource metadata. Strict clients (Codex >=0.143) fetch
    this document for the realm issuer via RFC 8414 path-insertion
    (`{origin}/.well-known/oauth-authorization-server/realms/<realm>`) — served by
    the path-insertion route below, which returns THIS same document.
    """
    public = _public_issuer()
    proxy = _proxy_base(request)

    data = await _fetch_idp_discovery()

    if not data:
        # Keycloak not yet up — return minimal fallback so the discovery chain
        # still works (client can retry; token endpoint will fail until KC starts).
        data = {
            "issuer": public,
            "authorization_endpoint": f"{public}/protocol/openid-connect/auth",
            "token_endpoint": f"{public}/protocol/openid-connect/token",
            "jwks_uri": f"{public}/protocol/openid-connect/certs",
            "end_session_endpoint": f"{public}/protocol/openid-connect/logout",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email", "roles"],
        }

    # RFC 9207/8414 issuer consistency: pin issuer to the realm URL (the value
    # Keycloak also puts in the callback `iss`). Never let it drift to the proxy
    # origin — a split issuer is what strict clients reject.
    data["issuer"] = public
    # Inject the proxy's registration bridge — always overrides the IdP's own
    # value so we control which client credentials are handed to MCP clients.
    data["registration_endpoint"] = f"{proxy}/oauth/register"
    # Ensure MCP clients know PKCE S256 is required (Keycloak enforces it on claude-code)
    data["code_challenge_methods_supported"] = ["S256"]
    # Override scopes_supported to only advertise the scopes enabled on the
    # claude-code public client. Keycloak's discovery lists every realm scope,
    # but MCP clients use scopes_supported to build the authorization request —
    # requesting an unenabled scope returns invalid_scope.
    data["scopes_supported"] = ["openid", "profile", "email", "roles", "offline_access"]

    # OAuth-discovery debuggability (doc 10): one greppable line carrying the
    # issuer identity the server advertises, so an operator can confirm from logs
    # that issuer == authorization_servers == (expected) callback iss without a
    # client. Search: "oauth.discovery".
    logger.info(
        "oauth.discovery as_metadata issuer=%s registration_endpoint=%s path=%s",
        data.get("issuer"), data["registration_endpoint"], request.url.path,
    )
    return data


@router.get("/.well-known/oauth-authorization-server")
async def oauth_server_metadata(request: Request):
    return await _authorization_server_metadata(request)


@router.get("/.well-known/oauth-authorization-server/{rest:path}")
async def oauth_server_metadata_path_insert(request: Request, rest: str):
    """RFC 8414 §3.1 path-insertion form for a path-containing issuer.

    For issuer `{origin}/realms/<realm>` the metadata URL is
    `{origin}/.well-known/oauth-authorization-server/realms/<realm>`. Strict
    RFC 9207 clients (Codex) use this once `authorization_servers` points at the
    realm issuer. Returns the SAME filtered document (issuer = realm URL) so the
    issuer stays consistent end-to-end."""
    return await _authorization_server_metadata(request)


@router.get("/.well-known/openid-configuration/{rest:path}")
async def openid_configuration_path_insert(request: Request, rest: str):
    """OIDC discovery path-insertion fallback ({origin}/.well-known/openid-configuration/realms/<realm>).
    Some clients try OIDC discovery for the issuer; serve the same consistent doc."""
    return await _authorization_server_metadata(request)


@router.post("/oauth/register")
async def dynamic_client_registration(request: Request):
    """
    RFC 7591 dynamic client registration bridge (zero-credential model).

    Every registration request receives the static "claude-code" Keycloak public
    client: publicClient=true, no client_secret, PKCE S256 required.
    Redirect URIs from the request body are echoed back but Keycloak accepts any
    localhost loopback redirect for public clients (RFC 8252 §7.3).

    Security controls:
    - Rate-limited to 10 registrations per IP per 60s (blocks enumeration/DDoS).
    - redirect_uris validated: only https:// and http://localhost allowed.
      javascript:, file://, data:, and other schemes are rejected (blocks open-redirect XSS).

    No secrets are issued. The client can authenticate only via browser + PKCE.
    """
    # Rate limiting — check before parsing body to avoid DoS via large payloads.
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    if not await _check_register_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many registration requests. Try again later.",
        )

    try:
        body = await request.json()
        redirect_uris = body.get("redirect_uris", [])
    except Exception:
        redirect_uris = []

    # Validate every redirect_uri before echoing it back.
    for uri in redirect_uris:
        _validate_redirect_uri(uri)

    public = _public_issuer()

    return JSONResponse(
        {
            "client_id": _CLAUDE_CODE_CLIENT_ID,
            # No client_secret: this is a public client (RFC 6749 §2.1).
            # Keycloak will refuse requests that include a client_secret for
            # a public client, so we must not return one here.
            "token_endpoint_auth_method": "none",
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "openid profile email roles offline_access",
            "code_challenge_methods_supported": ["S256"],
            # Advisory: tells the client where it came from
            "registration_client_uri": f"{public}/clients-registrations/openid-connect/{_CLAUDE_CODE_CLIENT_ID}",
        },
        status_code=201,
    )


def _protected_resource_metadata(request: Request, resource_path: str = "") -> dict:
    """
    RFC 9728 protected resource metadata.
    Points MCP clients at the Keycloak authorization server.
    The client needs only this URL (from the 401 WWW-Authenticate header) to
    discover the complete auth stack — no pre-configured credentials required.

    `resource_path` (e.g. "/mcp") makes "resource" the EXACT protected URL —
    some clients (Codex) reject metadata whose "resource" is just the origin
    when they're calling a specific path.
    """
    proxy = _proxy_base(request)
    issuer = _public_issuer()
    # RFC 9207/8414 issuer consistency (doc 10): authorization_servers MUST be the
    # realm issuer URL — the SAME value as this doc's `issuer`, the AS-metadata
    # `issuer`, and the callback `iss` Keycloak emits. Previously this pointed at
    # the proxy ORIGIN so the proxy could front filtered discovery; that split
    # (origin vs realm) is exactly what strict RFC 9207 clients (Codex >=0.143)
    # reject. We keep the filtering + registration bridge by serving that same
    # filtered AS metadata at the realm issuer's RFC 8414 path-insertion URL
    # (see oauth_server_metadata_path_insert) — so pointing here at the realm
    # issuer loses nothing and makes every issuer value identical.
    result = {
        "resource": proxy + resource_path,
        "authorization_servers": [issuer] if issuer else [proxy],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{proxy}/docs",
        "introspection_endpoint": f"{issuer}/protocol/openid-connect/token/introspect" if issuer else None,
        # RFC 9728 does not mandate "issuer", but current Codex (>=0.143, rmcp
        # PR896) fails without it. Same realm issuer identifier as above.
        "issuer": issuer if issuer else None,
    }
    logger.info(
        "oauth.discovery protected_resource resource=%s authorization_servers=%s issuer=%s",
        result["resource"], result["authorization_servers"], result["issuer"],
    )
    return result


@router.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request):
    return _protected_resource_metadata(request)


@router.get("/.well-known/oauth-protected-resource/{resource_path:path}")
async def oauth_protected_resource_scoped(request: Request, resource_path: str):
    """Resource-specific variant (RFC 9728 §3.1), e.g. /.well-known/oauth-protected-resource/mcp."""
    return _protected_resource_metadata(request, "/" + resource_path)
