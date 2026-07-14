"""
Entra ID MCP Server — read-only directory lookup (users + groups).

Reuses the SAME Azure AD app registration as the m365 server (AZURE_TENANT_ID /
AZURE_CLIENT_ID), injection_mode=entra_client_credentials. Deliberately app-only,
always — list_users/list_groups are Graph endpoints that work fine with
application permissions (User.Read.All / Group.Read.All), unlike /me-style
endpoints which need a delegated per-user token.

IMPORTANT (found 2026-07-14, corrects an assumption copied from an older
comment in m365/server.py): for injection_mode=entra_client_credentials, the
credential broker's dispatcher (_inject_entra_client_credentials in
credential_broker/dispatcher.py) performs the ENTIRE client_credentials OAuth
exchange itself, server-side, using the vault-stored {tenant_id, client_id,
client_secret} — and injects a ready-to-use `Authorization: Bearer <token>`
header. It does NOT send a raw client secret via any X-Entra-Client-Secret
header (that mechanism does not exist in the current dispatcher). This server
therefore just reads the injected Authorization header directly — it never
performs its own token exchange.

Tools:
  list_users   — list directory users (id, displayName, mail, userPrincipalName)
  list_groups  — list directory groups (id, displayName, mail, description)
"""
from __future__ import annotations

import contextvars
import logging
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("entra-id-mcp")

GRAPH = (os.environ.get("M365_GRAPH_BASE") or "https://graph.microsoft.com/v1.0").rstrip("/")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

mcp = FastMCP("entra-id-mcp")

_injected_auth: contextvars.ContextVar[str] = contextvars.ContextVar("_injected_auth", default="")


def _http_request():
    try:
        from mcp.server.lowlevel.server import request_ctx
        req = getattr(request_ctx.get(), "request", None)
        if req is not None and hasattr(req, "headers"):
            return req
    except Exception:
        pass
    return None


def _injected_token() -> str:
    """The broker-injected, ready-to-use Graph access token (already 'Bearer <token>')."""
    req = _http_request()
    raw = req.headers.get("authorization", "") if req is not None else _injected_auth.get()
    if raw[:7].lower() == "bearer ":
        return raw[7:].strip()
    return ""


async def _get(path: str, params: dict | None = None) -> Any:
    token = _injected_token()
    if not token:
        raise PermissionError(
            "No Authorization token injected by the gateway. Ensure this tool is "
            "registered with injection_mode=entra_client_credentials and that "
            "approved_upstream_idp_config + a vault-stored {tenant_id, client_id, "
            "client_secret} credential exist for it."
        )
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{GRAPH}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        resp.raise_for_status()
        return resp.json()


@mcp.tool()
async def list_users(top: int = 25, filter: str = "") -> dict:
    """
    List directory users (app-only — User.Read.All application permission).
    top: max results (Graph caps at 999 per page; capped here at 100).
    filter: optional OData filter, e.g. "startswith(displayName,'A')".
    """
    params: dict[str, Any] = {
        "$top": max(1, min(top, 100)),
        "$select": "id,displayName,mail,userPrincipalName,jobTitle,department",
    }
    if filter:
        params["$filter"] = filter
    data = await _get("/users", params)
    return {
        "users": data.get("value", []),
        "count": len(data.get("value", [])),
    }


@mcp.tool()
async def list_groups(top: int = 25, filter: str = "") -> dict:
    """
    List directory groups (app-only — Group.Read.All application permission).
    top: max results (capped at 100).
    filter: optional OData filter, e.g. "startswith(displayName,'Security')".
    """
    params: dict[str, Any] = {
        "$top": max(1, min(top, 100)),
        "$select": "id,displayName,mail,description,securityEnabled,groupTypes",
    }
    if filter:
        params["$filter"] = filter
    data = await _get("/groups", params)
    return {
        "groups": data.get("value", []),
        "count": len(data.get("value", [])),
    }


class _InjectedAuthMiddleware:
    """
    Pure-ASGI (not Starlette BaseHTTPMiddleware) — same reasoning as m365/
    server.py: BaseHTTPMiddleware runs the inner app in a child task, so a
    contextvar set here would not be visible in the task that runs the JSON-RPC
    tool call. request_ctx alone was not sufficient in practice for this plain-
    FastMCP server (found 2026-07-14) — this middleware is the reliable path.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            for k, v in scope.get("headers", []):
                if k.lower() == b"authorization":
                    _injected_auth.set(v.decode("latin-1"))
                    break
        await self.app(scope, receive, send)


if __name__ == "__main__":
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings

    # Same DNS-rebinding-protection disable as m365/server.py — FastMCP's default
    # host allowlist (127.0.0.1/localhost only) rejects requests arriving via a
    # container hostname (lab-mcp-entra-id:8000), which is how the proxy reaches
    # every internal-network lab server (see lab-oauth-mcp-lessons.md, Issue 10).
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
    app = _InjectedAuthMiddleware(mcp.streamable_http_app())
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
