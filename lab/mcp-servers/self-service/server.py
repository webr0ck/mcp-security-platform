"""
Self-Service MCP — per-identity MCP permission management.

Tools (all return tight JSON, no bloat):
  list_available_mcps    List MCPs visible to this account with enabled status
  get_profile            Full permission profile for an identity
  enable_mcp             Enable an MCP for this account (or a named profile)
  disable_mcp            Disable an MCP for this account (or a named profile)
  list_functions         List functions on an MCP with per-identity enabled status
  enable_function        Enable a specific function on an MCP for a profile
  disable_function       Disable a specific function on an MCP for a profile

Identity is resolved from the X-User-Sub header injected by the proxy
(credential approach A). The caller can only manage their own profile unless
they hold admin role (signaled via X-User-Role header).

All mutations write to mcp_profiles + mcp_profile_events (audit trail).
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import asyncpg
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))
DB_DSN = os.environ.get(
    "DATABASE_URL",
    "postgresql://mcp_app:{pw}@mcp-db:5432/mcp_security".format(
        pw=os.environ.get("DB_PASSWORD", "devpassword")
    ),
)

log = logging.getLogger("self-service-mcp")

# ContextVars populated by _IdentityMiddleware for each request.
# The proxy injects X-User-Sub and X-User-Role HTTP headers; tools read from these
# vars so the proxy-verified identity is used regardless of what the client puts
# in the MCP arguments (prevents caller_sub spoofing).
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

# ── DB pool ───────────────────────────────────────────────────────────────────

_pool: asyncpg.Pool | None = None


async def _get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=10, command_timeout=10)
    return _pool


# ── helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _emit_event(
    profile_id: str,
    mcp_name: str,
    event_type: str,
    old_state: dict | None,
    new_state: dict | None,
    changed_by: str,
) -> None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO mcp_profile_events
                (profile_id, mcp_name, event_type, old_state, new_state, changed_by)
            VALUES ($1, $2, $3, $4::jsonb, $5::jsonb, $6)
            """,
            profile_id, mcp_name, event_type,
            json.dumps(old_state) if old_state is not None else None,
            json.dumps(new_state) if new_state is not None else None,
            changed_by,
        )


async def _get_profile_row(profile_id: str, mcp_name: str) -> dict | None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT enabled, allowed_functions FROM mcp_profiles WHERE profile_id=$1 AND mcp_name=$2",
            profile_id, mcp_name,
        )
    if row is None:
        return None
    return {"enabled": row["enabled"], "allowed_functions": row["allowed_functions"]}


async def _upsert_profile_row(
    profile_id: str,
    mcp_name: str,
    enabled: bool,
    allowed_functions: list | None,
    changed_by: str,
) -> None:
    pool = await _get_pool()
    af_json = json.dumps(allowed_functions) if allowed_functions is not None else None
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO mcp_profiles (profile_id, mcp_name, enabled, allowed_functions, updated_by, updated_at)
            VALUES ($1, $2, $3, $4::jsonb, $5, now())
            ON CONFLICT (profile_id, mcp_name) DO UPDATE SET
                enabled           = EXCLUDED.enabled,
                allowed_functions = EXCLUDED.allowed_functions,
                updated_by        = EXCLUDED.updated_by,
                updated_at        = now()
            """,
            profile_id, mcp_name, enabled, af_json, changed_by,
        )


async def _list_registry_mcps() -> list[dict]:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT name, description, status, upstream_url
            FROM tool_registry
            WHERE deleted_at IS NULL
            ORDER BY name
            """
        )
    return [dict(r) for r in rows]


async def _discover_mcp_functions(mcp_name: str, upstream_url: str) -> list[str]:
    """Call the upstream MCP's tools/list to enumerate its functions."""
    try:
        import httpx
        # Do NOT override Host header — FastMCP's TrustedHostMiddleware rejects cross-container
        # host overrides. Let httpx set the natural Host from the URL.
        base_hdrs = {"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"}
        async with httpx.AsyncClient(timeout=5) as client:
            init = await client.post(
                upstream_url,
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "self-service", "version": "1.0"}}},
                headers=base_hdrs,
            )
            session_id = init.headers.get("mcp-session-id", "")
            hdrs = {**base_hdrs}
            if session_id:
                hdrs["MCP-Session-Id"] = session_id

            resp = await client.post(
                upstream_url,
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers=hdrs,
            )
            body = resp.text
            for line in body.splitlines():
                if line.startswith("data:"):
                    data = json.loads(line[5:].strip())
                    tools = data.get("result", {}).get("tools", [])
                    return [t["name"] for t in tools]
    except Exception as exc:
        log.warning("Could not discover functions for %s: %s", mcp_name, exc)
    return []


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

    Returns compact JSON: {mcps: [{name, description, status, enabled_for_account}]}
    """
    caller_sub = _ctx_caller_sub.get()
    registry = await _list_registry_mcps()
    pool = await _get_pool()

    async with pool.acquire() as conn:
        profile_rows = await conn.fetch(
            "SELECT mcp_name, enabled FROM mcp_profiles WHERE profile_id=$1",
            caller_sub,
        )
    profile_map = {r["mcp_name"]: r["enabled"] for r in profile_rows}

    result = []
    for mcp_row in registry:
        name = mcp_row["name"]
        # Default: enabled (no explicit profile row = all enabled)
        enabled = profile_map.get(name, True)
        if not include_disabled and not enabled:
            continue
        result.append({
            "name": name,
            "description": (mcp_row["description"] or "")[:120],
            "status": mcp_row["status"],
            "enabled_for_account": enabled,
        })

    return {"mcps": result, "total": len(result), "profile_id": caller_sub}


@mcp.tool()
async def get_profile(
    target_profile: Optional[str] = None,
) -> dict:
    """
    Get the complete permission profile for an identity.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        target_profile: Profile to retrieve. Defaults to caller identity. Admin/auditor required for others.

    Returns: {profile_id, mcps: [{name, enabled, allowed_functions}]}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin", "auditor"):
        return {"error": "forbidden", "detail": "Only admin/auditor can view other profiles"}

    registry = await _list_registry_mcps()
    pool = await _get_pool()

    async with pool.acquire() as conn:
        profile_rows = await conn.fetch(
            "SELECT mcp_name, enabled, allowed_functions FROM mcp_profiles WHERE profile_id=$1",
            profile_id,
        )
    profile_map = {
        r["mcp_name"]: {"enabled": r["enabled"], "allowed_functions": r["allowed_functions"]}
        for r in profile_rows
    }

    mcps = []
    for mcp_row in registry:
        name = mcp_row["name"]
        row = profile_map.get(name)
        enabled = row["enabled"] if row else True
        af = row["allowed_functions"] if row else None
        # allowed_functions: None = all, list = restricted set
        mcps.append({
            "name": name,
            "enabled": enabled,
            "allowed_functions": af,  # null = all functions allowed
            "note": "null allowed_functions means all functions permitted",
        })

    return {
        "profile_id": profile_id,
        "mcps": mcps,
        "total_mcps": len(mcps),
        "retrieved_at": _now_iso(),
    }


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

    Returns: {ok: true, profile_id, mcp_name, enabled: true}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    # Verify MCP exists
    pool = await _get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM tool_registry WHERE name=$1 AND deleted_at IS NULL", mcp_name
        )
    if not exists:
        return {"error": "not_found", "mcp_name": mcp_name,
                "detail": "MCP not found in registry"}

    old = await _get_profile_row(profile_id, mcp_name)
    await _upsert_profile_row(
        profile_id, mcp_name, enabled=True,
        allowed_functions=old["allowed_functions"] if old else None,
        changed_by=caller_sub,
    )
    await _emit_event(
        profile_id, mcp_name, "MCP_ENABLED",
        old_state=old,
        new_state={"enabled": True},
        changed_by=caller_sub,
    )
    return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name, "enabled": True}


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

    Returns: {ok: true, profile_id, mcp_name, enabled: false}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    pool = await _get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM tool_registry WHERE name=$1 AND deleted_at IS NULL", mcp_name
        )
    if not exists:
        return {"error": "not_found", "mcp_name": mcp_name}

    old = await _get_profile_row(profile_id, mcp_name)
    await _upsert_profile_row(
        profile_id, mcp_name, enabled=False,
        allowed_functions=old["allowed_functions"] if old else None,
        changed_by=caller_sub,
    )
    await _emit_event(
        profile_id, mcp_name, "MCP_DISABLED",
        old_state=old,
        new_state={"enabled": False},
        changed_by=caller_sub,
    )
    return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name, "enabled": False}


@mcp.tool()
async def list_functions(
    mcp_name: str,
) -> dict:
    """
    List all functions exposed by an MCP server, with enabled status for this account.

    Discovers functions by querying the upstream MCP server directly.
    Identity is resolved from the X-User-Sub header injected by the proxy.
    Falls back to an empty list if the upstream is unreachable.

    Args:
        mcp_name: Name of the MCP server.

    Returns: {mcp_name, functions: [{name, enabled}], allowed_functions_policy}
    """
    caller_sub = _ctx_caller_sub.get()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT upstream_url FROM tool_registry WHERE name=$1 AND deleted_at IS NULL",
            mcp_name,
        )
    if not row:
        return {"error": "not_found", "mcp_name": mcp_name}

    upstream_url = row["upstream_url"]
    functions = await _discover_mcp_functions(mcp_name, upstream_url)

    profile_row = await _get_profile_row(caller_sub, mcp_name)
    allowed_functions: list | None = profile_row["allowed_functions"] if profile_row else None

    result = []
    for fn in functions:
        if allowed_functions is None:
            enabled = True  # all functions permitted
        else:
            enabled = fn in allowed_functions
        result.append({"name": fn, "enabled": enabled})

    return {
        "mcp_name": mcp_name,
        "functions": result,
        "total": len(result),
        "allowed_functions_policy": allowed_functions,  # null = unrestricted
    }


@mcp.tool()
async def enable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Enable a specific function on an MCP server for a profile.

    If the profile currently has no restriction (allowed_functions=null), calling
    this is a no-op (all functions already permitted). To restrict to a specific
    set, first call disable_function for each unwanted function.

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

    old = await _get_profile_row(profile_id, mcp_name)
    current_af: list | None = old["allowed_functions"] if old else None

    if current_af is None:
        # Already unrestricted — function is already enabled
        return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name,
                "function_name": function_name, "enabled": True,
                "note": "Profile is unrestricted — all functions already allowed"}

    if function_name in current_af:
        return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name,
                "function_name": function_name, "enabled": True, "note": "Already enabled"}

    new_af = sorted(set(current_af) | {function_name})
    await _upsert_profile_row(
        profile_id, mcp_name,
        enabled=old["enabled"] if old else True,
        allowed_functions=new_af,
        changed_by=caller_sub,
    )
    await _emit_event(
        profile_id, mcp_name, "FUNCTION_ENABLED",
        old_state={"allowed_functions": current_af},
        new_state={"allowed_functions": new_af},
        changed_by=caller_sub,
    )
    return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name,
            "function_name": function_name, "enabled": True, "allowed_functions": new_af}


@mcp.tool()
async def disable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Disable a specific function on an MCP server for a profile.

    If the profile is currently unrestricted (allowed_functions=null), this
    discovers all available functions and builds a restricted list excluding
    the one being disabled.

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

    pool = await _get_pool()
    async with pool.acquire() as conn:
        upstream_row = await conn.fetchrow(
            "SELECT upstream_url FROM tool_registry WHERE name=$1 AND deleted_at IS NULL",
            mcp_name,
        )
    if not upstream_row:
        return {"error": "not_found", "mcp_name": mcp_name}

    old = await _get_profile_row(profile_id, mcp_name)
    current_af: list | None = old["allowed_functions"] if old else None

    if current_af is None:
        # Unrestricted — discover all functions, then remove the one being disabled
        all_functions = await _discover_mcp_functions(mcp_name, upstream_row["upstream_url"])
        if not all_functions:
            return {"error": "discovery_failed", "mcp_name": mcp_name,
                    "detail": "Could not discover functions from upstream MCP — cannot build restriction list"}
        new_af = sorted(f for f in all_functions if f != function_name)
    else:
        new_af = sorted(f for f in current_af if f != function_name)

    await _upsert_profile_row(
        profile_id, mcp_name,
        enabled=old["enabled"] if old else True,
        allowed_functions=new_af,
        changed_by=caller_sub,
    )
    await _emit_event(
        profile_id, mcp_name, "FUNCTION_DISABLED",
        old_state={"allowed_functions": current_af},
        new_state={"allowed_functions": new_af},
        changed_by=caller_sub,
    )
    return {"ok": True, "profile_id": profile_id, "mcp_name": mcp_name,
            "function_name": function_name, "enabled": False, "allowed_functions": new_af}


# ── startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_IdentityMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
