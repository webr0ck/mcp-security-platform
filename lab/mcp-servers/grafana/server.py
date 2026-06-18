"""
Grafana MCP Server — broker-injected service account token (Case 2, PRD-0002).

Auth scenario: service mode — the credential broker injects a shared Grafana
service-account token via the `Authorization: Bearer <token>` header on every
request. The server forwards this token to the Grafana API. Attribution is
shared (all calls appear as the SA), not per-user.

The injected token is read from the Authorization header via _AuthMiddleware,
NOT from an env var — this is the broker-injectable pattern.
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
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://lab-grafana:3000").rstrip("/")

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
mcp = FastMCP("grafana-mcp", stateless_http=True)


def _grafana_headers() -> dict[str, str]:
    auth = _auth_header.get()
    if not auth:
        raise RuntimeError("No Authorization header injected by broker (service mode requires broker injection)")
    return {"Authorization": auth, "Content-Type": "application/json"}


@mcp.tool()
async def query_dashboards(search: str = "") -> dict:
    """Search Grafana dashboards. Returns dashboard list."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GRAFANA_URL}/api/search",
            headers=_grafana_headers(),
            params={"query": search, "type": "dash-db"},
            timeout=10.0,
        )
        resp.raise_for_status()
        return {"dashboards": resp.json()}


@mcp.tool()
async def get_datasources() -> dict:
    """List all Grafana datasources."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{GRAFANA_URL}/api/datasources",
            headers=_grafana_headers(),
            timeout=10.0,
        )
        resp.raise_for_status()
        return {"datasources": resp.json()}


if __name__ == "__main__":
    # Disable DNS rebinding protection for lab (internal network only, no browser access)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_AuthMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
