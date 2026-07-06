# lab/mcp-servers/lab-tickets/server.py
"""
lab-tickets MCP resource server (PRD-0002 Case 4).

Validates the KC-issued exchanged Bearer token on every request:
  - RS256 JWKS verify from KC
  - aud == lab-tickets
  - azp == mcp-proxy  (KC 24 delegation evidence)

In production, sub would be used for per-user ticket isolation.
In this lab stub, tickets are stored in-memory per process.
"""
from __future__ import annotations

import os
import time
import uuid
from contextvars import ContextVar
from typing import Any

import httpx
import jwt
from mcp.server.fastmcp import FastMCP
from jwt.algorithms import RSAAlgorithm
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

KC_ISSUER = os.environ.get("KC_ISSUER", "http://lab-keycloak:8080/realms/mcp")
KC_JWKS_URI = f"{KC_ISSUER}/protocol/openid-connect/certs"
EXPECTED_AUDIENCE = "lab-tickets"
EXPECTED_AZP = "mcp-proxy"

_tickets: list[dict] = []
_jwt_claims: ContextVar[dict | None] = ContextVar("_jwt_claims", default=None)
_jwks_cache: dict[str, Any] = {}


async def _fetch_public_key(token: str):
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    if kid and kid in _jwks_cache:
        return _jwks_cache[kid]
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(KC_JWKS_URI)
        resp.raise_for_status()
    keys = resp.json().get("keys", [])
    for k in keys:
        _jwks_cache[k["kid"]] = RSAAlgorithm.from_jwk(k)
    if kid and kid in _jwks_cache:
        return _jwks_cache[kid]
    if keys:
        return RSAAlgorithm.from_jwk(keys[0])
    raise ValueError("No JWKS keys available from KC")


def _validate_token(token: str, public_key) -> dict:
    try:
        claims = jwt.decode(
            token, public_key, algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE, options={"verify_aud": True},
        )
    except jwt.PyJWTError as exc:
        raise ValueError(f"JWT validation failed: {exc}") from exc
    azp = claims.get("azp")
    if azp != EXPECTED_AZP:
        raise ValueError(f"azp {azp!r} != expected actor {EXPECTED_AZP!r}")
    return claims


class _AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        from starlette.responses import JSONResponse
        # ponytail: unauthenticated liveness path for the container healthcheck only
        if request.url.path == "/health":
            return JSONResponse({"status": "ok"})
        auth = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            return JSONResponse({"error": "Missing Bearer token"}, status_code=401)
        token = auth[7:].strip()
        try:
            public_key = await _fetch_public_key(token)
            claims = _validate_token(token, public_key)
        except Exception as exc:
            return JSONResponse({"error": f"Unauthorized: {exc}"}, status_code=401)
        token_ctx = _jwt_claims.set(claims)
        try:
            return await call_next(request)
        finally:
            _jwt_claims.reset(token_ctx)


# stateless_http=True is REQUIRED for the _AuthMiddleware ContextVar to work.
# In the default (stateful) streamable-http mode, tool handlers run inside a
# long-lived task group created at session-init time, so the ContextVar set by
# _AuthMiddleware on the per-request task does NOT propagate to the handler.
# In stateless mode each request is processed in its own task spawned from the
# request context, so the JWT claims injected by _AuthMiddleware reach the tool.
mcp = FastMCP(
    "lab-tickets",
    stateless_http=True,
)


@mcp.tool()
def list_tickets() -> list[dict]:
    """List all tickets visible to the current caller."""
    claims = _jwt_claims.get()
    caller = claims["sub"] if claims else "anonymous"
    return [t for t in _tickets if t.get("owner") == caller] or [
        {"id": "DEMO-001", "title": "Demo ticket", "status": "open", "owner": caller}
    ]


@mcp.tool()
def create_ticket(title: str, description: str = "") -> dict:
    """Create a new ticket. Returns the created ticket with its ID."""
    claims = _jwt_claims.get()
    caller = claims["sub"] if claims else "anonymous"
    ticket = {
        "id": f"TKT-{str(uuid.uuid4())[:8].upper()}",
        "title": title,
        "description": description,
        "owner": caller,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "open",
    }
    _tickets.append(ticket)
    return ticket


if __name__ == "__main__":
    import uvicorn
    # Disable DNS rebinding protection for lab (internal network only, no browser access)
    # LAB ONLY — never disable dns rebinding protection in production.
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_AuthMiddleware)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
