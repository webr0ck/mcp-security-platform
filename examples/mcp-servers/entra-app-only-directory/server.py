"""
Entra Directory MCP Server — read-only Microsoft Entra ID / Graph directory server.

App-only (client_credentials) only — directory reads (users/groups/app
registrations) are inherently tenant-admin-scoped, there is no meaningful
"delegated as this one user" mode for listing the whole directory, unlike
m365-mcp's mailbox/calendar tools.

Credential handling: injection_mode=entra_client_credentials does the ENTIRE
client_credentials token exchange on the proxy side (see
credential_broker/dispatcher.py::_inject_entra_client_credentials) and forwards
a ready-to-use Graph access token as a normal `Authorization: Bearer <token>`
header — this server never sees a client secret and never talks to
login.microsoftonline.com itself. (The X-Entra-Client-Secret /
server-does-its-own-token-exchange pattern that lab/mcp-servers/m365/server.py
also supports is a different, legacy fallback path used only when no token was
pre-injected — not what entra_client_credentials actually dispatches today;
confirmed by reading the dispatcher, not assumed.)

Required Graph application permissions on the app registration (admin consent):
  User.Read.All          — list_users / get_user
  Group.Read.All         — list_groups / get_group
  Application.Read.All   — list_app_registrations / get_app_registration

Tools:
  list_users              — page of directory users
  get_user                 — single user by id or userPrincipalName
  list_groups              — page of directory groups
  get_group                 — single group by id, with member count
  list_app_registrations    — page of app registrations (not enterprise apps)
  get_app_registration       — single app registration by id or appId
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("entra-directory-mcp")

GRAPH = os.environ.get("M365_GRAPH_BASE", "https://graph.microsoft.com/v1.0").rstrip("/")
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# stateless_http=True is REQUIRED so the per-request injected Authorization
# header reaches the tool handlers via request_ctx. In the default stateful
# streamable-http mode, tools run in a long-lived session-init task group and
# the per-request context never propagates — same fix as
# lab/mcp-servers/self-service/server.py.
mcp = FastMCP("entra-directory-mcp", stateless_http=True)


def _http_request():
    """Best-effort access to the current Starlette HTTP request.

    Reads via mcp.server.lowlevel.server.request_ctx, which is set in the SAME
    task that runs the tool — unlike an ASGI middleware's contextvar, which is
    set in a different task and does not propagate to the tool function. Exact
    pattern proven in lab/mcp-servers/m365/server.py::_http_request().
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
        req = getattr(request_ctx.get(), "request", None)
        if req is not None and hasattr(req, "headers"):
            return req
    except Exception:
        pass
    return None


async def _get_app_token() -> str:
    """Return the broker-injected Graph access token verbatim.

    The dispatcher already did the client_credentials exchange and forwards
    the result as `Authorization: Bearer <token>` — this server just reads it.
    """
    req = _http_request()
    raw = req.headers.get("authorization", "") if req is not None else ""
    if not raw or raw[:7].lower() != "bearer ":
        raise ValueError(
            "entra-directory MCP server received no Authorization header — the "
            "credential broker should have injected a Graph access token here. "
            "Ensure the tool is registered with injection_mode=entra_client_credentials."
        )
    return raw[7:].strip()


async def _get(path: str, params: dict | None = None) -> Any:
    token = await _get_app_token()
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{GRAPH}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params=params or {},
        )
        if resp.status_code == 403:
            raise PermissionError(
                f"Graph denied {path}: the app registration is missing the required "
                f"application permission (with admin consent) for this endpoint."
            )
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def list_users(top: int = 25) -> dict:
    """List directory users (id, displayName, userPrincipalName, jobTitle).
    Requires User.Read.All."""
    data = await _get("/users", {"$top": min(top, 100), "$select": "id,displayName,userPrincipalName,jobTitle,mail"})
    return {
        "count": len(data.get("value", [])),
        "users": data.get("value", []),
        "next_link_present": bool(data.get("@odata.nextLink")),
    }


@mcp.tool()
async def get_user(user_id: str) -> dict:
    """Get a single user by id (GUID) or userPrincipalName. Requires User.Read.All."""
    return await _get(f"/users/{user_id}")


@mcp.tool()
async def list_groups(top: int = 25) -> dict:
    """List directory groups (id, displayName, description, mail).
    Requires Group.Read.All."""
    data = await _get("/groups", {"$top": min(top, 100), "$select": "id,displayName,description,mail,groupTypes"})
    return {
        "count": len(data.get("value", [])),
        "groups": data.get("value", []),
        "next_link_present": bool(data.get("@odata.nextLink")),
    }


@mcp.tool()
async def get_group(group_id: str) -> dict:
    """Get a single group by id, including its member count. Requires Group.Read.All."""
    group = await _get(f"/groups/{group_id}")
    members = await _get(f"/groups/{group_id}/members", {"$top": 1, "$count": "true"})
    return {**group, "member_count_sample": len(members.get("value", []))}


@mcp.tool()
async def list_app_registrations(top: int = 25) -> dict:
    """List app registrations (id, appId, displayName, signInAudience) — NOT
    enterprise app / service principal objects, the registration objects
    themselves. Requires Application.Read.All."""
    data = await _get(
        "/applications",
        {"$top": min(top, 100), "$select": "id,appId,displayName,signInAudience,createdDateTime"},
    )
    return {
        "count": len(data.get("value", [])),
        "applications": data.get("value", []),
        "next_link_present": bool(data.get("@odata.nextLink")),
    }


@mcp.tool()
async def get_app_registration(app_id: str) -> dict:
    """Get a single app registration by object id or appId (client id).
    Requires Application.Read.All."""
    try:
        return await _get(f"/applications/{app_id}")
    except httpx.HTTPStatusError:
        # app_id looked like a client ID (appId), not the object id — retry via filter.
        data = await _get("/applications", {"$filter": f"appId eq '{app_id}'"})
        results = data.get("value", [])
        if not results:
            raise
        return results[0]


if __name__ == "__main__":
    import uvicorn
    from mcp.server.transport_security import TransportSecuritySettings

    # FastMCP's TrustedHostMiddleware rejects container hostnames by default —
    # disable DNS-rebinding protection, matching lab/mcp-servers/m365/server.py.
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
    app = mcp.streamable_http_app()
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
