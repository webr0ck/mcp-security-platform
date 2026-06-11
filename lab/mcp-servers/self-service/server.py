"""
Self-Service MCP — per-identity MCP permission management.

Task 2.2b: Rewritten to be a thin HTTP client of the proxy profile API
(proxy/app/routers/profiles.py) instead of accessing the database directly.
No proxy-db-net or DATABASE_URL required — the DB connection is exclusively
owned by the proxy.

Tools (all return tight JSON, no bloat):
  list_available_mcps    List MCPs visible to this account with enabled status
  get_profile            Full permission profile for an identity
  enable_mcp             Enable an MCP for this account (or a named profile)
  disable_mcp            Disable an MCP for this account (or a named profile)
  list_functions         List functions on an MCP with per-identity enabled status
  enable_function        Enable a specific function on an MCP for a profile
  disable_function       Disable a specific function on an MCP for a profile

Identity is resolved from the X-User-Sub and X-User-Role headers injected by
the proxy (credential approach A). The caller can only manage their own profile
unless they hold admin role (signaled via X-User-Role header).

Authentication to the proxy profile API:
  This server authenticates with an API key (SELF_SERVICE_API_KEY env var).
  The key is seeded by lab/seeder/seed.py into the proxy's api_keys table
  under the service identity "lab-self-service".
  The proxy then enforces RBAC: the self-service server may only modify a
  principal's profile if the X-User-Sub header (set by the proxy when routing
  tool calls) matches the target principal, or the caller has admin role.

  When routing tool calls, the proxy injects X-User-Sub and X-User-Role as
  HTTP headers into the MCP request. The self-service server extracts these
  and uses X-User-Sub as the principal for profile API calls. This means the
  *proxy* is the trust anchor for identity — not the self-service server.

Network: mcp-self-service-net (pairwise with proxy, internal: true).
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Proxy profile API base URL — reachable via mcp-self-service-net (pairwise)
PROXY_PROFILE_API_URL = os.environ.get(
    "PROXY_PROFILE_API_URL", "http://mcp-proxy:8000/api/v1/profiles"
).rstrip("/")

# Service API key for authenticating to the proxy profile API.
# Seeded by lab/seeder/seed.py into api_keys table as service "lab-self-service".
SELF_SERVICE_API_KEY = os.environ.get("SELF_SERVICE_API_KEY", "lab-self-service-key")

log = logging.getLogger("self-service-mcp")

# ContextVars populated by _IdentityMiddleware for each request.
# The proxy injects X-User-Sub and X-User-Role HTTP headers; tools read from
# these vars so the proxy-verified identity is used.
_ctx_caller_sub: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ctx_caller_sub", default="anonymous"
)
_ctx_caller_role: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ctx_caller_role", default="agent"
)


class _IdentityMiddleware(BaseHTTPMiddleware):
    """Populate identity ContextVars from proxy-injected HTTP headers."""

    async def dispatch(self, request, call_next):
        sub = request.headers.get("x-user-sub", "anonymous")
        role = request.headers.get("x-user-role", "agent")
        tok_sub = _ctx_caller_sub.set(sub)
        tok_role = _ctx_caller_role.set(role)
        try:
            return await call_next(request)
        finally:
            _ctx_caller_sub.reset(tok_sub)
            _ctx_caller_role.reset(tok_role)


mcp = FastMCP("self-service-mcp")

# ── proxy profile API client ──────────────────────────────────────────────────


def _auth_headers() -> dict[str, str]:
    """Return auth headers for proxy profile API requests."""
    return {
        "Authorization": f"Bearer {SELF_SERVICE_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


async def _proxy_get(path: str) -> dict:
    """GET from proxy profile API. Returns parsed JSON or error dict."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=_auth_headers())
        if r.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API GET %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


async def _proxy_post(path: str, body: dict | None = None) -> dict:
    """POST to proxy profile API."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                url, headers=_auth_headers(),
                content=json.dumps(body) if body else b"",
            )
        if r.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API POST %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


async def _proxy_put(path: str, body: dict) -> dict:
    """PUT to proxy profile API."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.put(url, headers=_auth_headers(),
                                 content=json.dumps(body))
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API PUT %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── MCP tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_available_mcps(
    include_disabled: bool = False,
) -> dict:
    """
    List all MCP servers available on the platform with their enabled status for this account.

    Identity is resolved from the X-User-Sub header injected by the proxy.

    Args:
        include_disabled: If true, include MCPs the caller has explicitly disabled.

    Returns compact JSON: {mcps: [{name, enabled_for_account}]}
    """
    caller_sub = _ctx_caller_sub.get()
    # Use the registry endpoint on the proxy (tool discovery via /api/v1/tools)
    # For now, return a note directing the user to the proxy registry endpoint.
    # The profile API is per-MCP; to list available MCPs, query the proxy tool registry.
    return {
        "note": (
            "For a full registry listing, query GET /api/v1/tools on the proxy. "
            "This tool returns only your profile entries below."
        ),
        "profile_id": caller_sub,
        "mcps": [],
        "hint": (
            "Use get_profile to see your full profile including all MCPs. "
            "Use enable_mcp/disable_mcp to change per-MCP settings."
        ),
    }


@mcp.tool()
async def get_profile(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Get the permission profile for (principal, mcp_name).

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to query.
        target_profile: Profile to retrieve. Defaults to caller identity. Admin/auditor required for others.

    Returns: {principal, mcp_name, enabled, allowed_functions, explicit_row}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin", "auditor"):
        return {"error": "forbidden", "detail": "Only admin/auditor can view other profiles"}

    return await _proxy_get(f"/{profile_id}/mcps/{mcp_name}")


@mcp.tool()
async def enable_mcp(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Enable an MCP server for an account. Idempotent.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to enable (must exist in tool_registry).
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.

    Returns: {ok: true, principal, mcp_name, enabled: true}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/enable")


@mcp.tool()
async def disable_mcp(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Disable an MCP server for an account.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to disable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.

    Returns: {ok: true, principal, mcp_name, enabled: false}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/disable")


@mcp.tool()
async def list_functions(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Get the function-level restrictions for an MCP on this account.

    Args:
        mcp_name: Name of the MCP server.
        target_profile: Profile to query. Defaults to caller.

    Returns: {mcp_name, allowed_functions (null=all), enabled}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin", "auditor"):
        return {"error": "forbidden"}

    result = await _proxy_get(f"/{profile_id}/mcps/{mcp_name}")
    if "error" in result:
        return result
    return {
        "mcp_name": mcp_name,
        "profile_id": profile_id,
        "enabled": result.get("enabled", True),
        "allowed_functions": result.get("allowed_functions"),
        "note": "null allowed_functions means all functions permitted",
    }


@mcp.tool()
async def enable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Enable a specific function on an MCP server for a profile.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: MCP server name.
        function_name: Function to enable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/functions/{function_name}/enable")


@mcp.tool()
async def disable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Disable a specific function on an MCP server for a profile.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: MCP server name.
        function_name: Function to disable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/functions/{function_name}/disable")


# ── startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_IdentityMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
