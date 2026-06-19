"""
NetBox MCP Server — per-user broker-injected token (Case 3, PRD-0002).

Auth scenario: user mode — the credential broker injects a per-user NetBox API
token via the `Authorization: Token <token>` header on every request.
Different callers get different tokens → attribution preserved in NetBox logs.

The injected token is read from the Authorization header via _AuthMiddleware,
NOT from env. Each user's token is stored encrypted in the credential broker.
"""
from __future__ import annotations

import contextvars
import os

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
NETBOX_URL = os.environ.get("NETBOX_URL", "http://lab-netbox:8080").rstrip("/")

# ContextVar populated by _AuthMiddleware from the broker-injected Authorization header.
_auth_header: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_auth_header", default=""
)


class _AuthMiddleware(BaseHTTPMiddleware):
    """Capture the broker-injected Authorization header into a ContextVar."""

    async def dispatch(self, request, call_next):
        auth = request.headers.get("authorization", "")
        tok = _auth_header.set(auth)
        try:
            return await call_next(request)
        finally:
            _auth_header.reset(tok)


# stateless_http=True is REQUIRED for the _AuthMiddleware ContextVar to work.
# In the default (stateful) streamable-http mode, tool handlers run inside a
# long-lived task group created at session-init time, so the ContextVar set by
# _AuthMiddleware on the per-request task does NOT propagate to the handler.
# In stateless mode each request is processed in its own task spawned from the
# request context, so the Authorization header the broker injects reaches the tool.
mcp = FastMCP("netbox-mcp", stateless_http=True)


def _netbox_headers() -> dict[str, str]:
    auth = _auth_header.get()
    if not auth:
        raise RuntimeError(
            "No Authorization header injected by broker (user mode requires per-user token)"
        )
    return {"Authorization": auth, "Content-Type": "application/json", "Accept": "application/json"}


@mcp.tool()
async def list_devices(limit: int = 10) -> dict:
    """List devices from NetBox DCIM."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{NETBOX_URL}/api/dcim/devices/",
            headers=_netbox_headers(),
            params={"limit": limit},
            timeout=10.0,
        )
        resp.raise_for_status()
        return {"devices": resp.json()}


@mcp.tool()
async def list_ip_addresses(limit: int = 10) -> dict:
    """List IP addresses from NetBox IPAM."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{NETBOX_URL}/api/ipam/ip-addresses/",
            headers=_netbox_headers(),
            params={"limit": limit},
            timeout=10.0,
        )
        resp.raise_for_status()
        return {"ip_addresses": resp.json()}


if __name__ == "__main__":
    # Disable DNS rebinding protection for lab (internal network only, no browser access)
    # LAB ONLY — never disable dns rebinding protection in production.
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_AuthMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
