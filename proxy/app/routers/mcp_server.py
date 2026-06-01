"""
MCP Streamable-HTTP Transport  (MCP spec 2025-03-26)


Handles JSON-RPC 2.0 messages from MCP clients (Claude Code, etc.) at POST /mcp.

Implemented methods
-------------------
initialize          — server capabilities + identity echo
notifications/initialized  — client ready notification (no response)
ping                — keep-alive
tools/list          — role-filtered catalogue of demo tools
tools/call          — execute a demo tool and return result

Role visibility
---------------
  admin    → all tools
  analyst  → security_* tools + platform_info
  viewer   → platform_info only
  (unauthenticated requests are blocked by AuthMiddleware before reaching here)

The /mcp path is public at the nginx level (no mTLS) but AuthMiddleware
enforces Bearer token auth so every request has request.state.client_id.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MCP"])

SERVER_INFO = {
    "name": "mcp-security-platform",
    "version": "1.0.0",
}

# ---------------------------------------------------------------------------
# Tool catalogue — each entry declares which roles may call it
# ---------------------------------------------------------------------------
_TOOLS: list[dict[str, Any]] = [
    {
        "name": "platform_info",
        "description": "Return MCP Security Platform version, environment, and authenticated identity.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "_roles": {"admin", "analyst", "viewer"},
    },
    {
        "name": "security_pulse_summary",
        "description": "Return the latest security pulse digest (CVEs, advisories, anomaly count).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "all"],
                    "description": "Filter by severity. Default: all.",
                }
            },
            "required": [],
        },
        "_roles": {"admin", "analyst"},
    },
    {
        "name": "list_registered_tools",
        "description": "List MCP tools registered in the platform tool registry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["approved", "quarantined", "pending", "all"],
                    "description": "Filter by audit status. Default: all.",
                }
            },
            "required": [],
        },
        "_roles": {"admin", "analyst"},
    },
    {
        "name": "invoke_tool",
        "description": "Invoke a registered MCP tool from the platform tool registry. Goes through OPA policy check, anomaly detection, credential injection, and audit logging.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Registered tool name (e.g. 'm365-graph', 'grafana-query', 'netbox-query')."},
                "method": {"type": "string", "description": "MCP method to call on the tool server (e.g. 'tools/list', 'tools/call')."},
                "arguments": {"type": "object", "description": "Arguments to pass to the tool."},
            },
            "required": ["tool_name"],
        },
        "_roles": {"admin", "platform_admin"},
    },
]


def _visible_tools(roles: list[str]) -> list[dict]:
    """Return tools visible to the given role set, stripping the internal _roles key."""
    role_set = set(roles)
    out = []
    for t in _TOOLS:
        if t["_roles"] & role_set:
            public = {k: v for k, v in t.items() if k != "_roles"}
            out.append(public)
    return out


def _can_call(tool_name: str, roles: list[str]) -> bool:
    role_set = set(roles)
    for t in _TOOLS:
        if t["name"] == tool_name:
            return bool(t["_roles"] & role_set)
    return False


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

def _handle_platform_info(args: dict, request: Request) -> dict:
    from app.core.config import settings
    return {
        "type": "text",
        "text": json.dumps({
            "platform": "MCP Security Platform",
            "version": settings.PLATFORM_VERSION,
            "environment": settings.ENVIRONMENT,
            "authenticated_as": request.state.client_id,
            "auth_method": getattr(request.state, "auth_method", "unknown"),
            "roles": getattr(request.state, "client_roles", []),
        }, indent=2),
    }


def _handle_security_pulse_summary(args: dict, request: Request) -> dict:
    severity = args.get("severity", "all")
    data = {
        "severity_filter": severity,
        "critical_cves": ["CVE-2025-1234 (CVSS 9.8, RCE in libssl)", "CVE-2025-5678 (CVSS 9.1, auth bypass)"],
        "high_cves": ["CVE-2025-9012 (CVSS 7.5, SQLi)"],
        "anomalies_last_24h": 3,
        "tools_quarantined": 1,
        "last_updated": "2026-05-25T06:00:00Z",
        "note": "Demo data — connect real advisories via /security-pulse skill",
    }
    if severity == "critical":
        data.pop("high_cves")
    elif severity == "high":
        data.pop("critical_cves")
    return {"type": "text", "text": json.dumps(data, indent=2)}


def _handle_list_registered_tools(args: dict, request: Request) -> dict:
    status_filter = args.get("status", "all")
    demo_tools = [
        {"name": "grafana-reader", "version": "1.0.0", "status": "approved", "risk_score": 12},
        {"name": "netbox-lookup", "version": "2.1.0", "status": "approved", "risk_score": 8},
        {"name": "file-writer", "version": "0.9.0", "status": "quarantined", "risk_score": 87,
         "quarantine_reason": "Detected write access outside /tmp"},
        {"name": "code-executor", "version": "1.2.0", "status": "pending", "risk_score": None},
    ]
    if status_filter != "all":
        demo_tools = [t for t in demo_tools if t["status"] == status_filter]
    return {
        "type": "text",
        "text": json.dumps({"tools": demo_tools, "total": len(demo_tools)}, indent=2),
    }



async def _handle_invoke_tool_real(args: dict, request: Request) -> dict:
    """
    Route a tool invocation through the full security pipeline:
    quarantine check → OPA policy → anomaly → credential injection → upstream MCP server → audit log.
    """
    from uuid import uuid4
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.services import invocation as inv_svc

    tool_name = args.get("tool_name", "").strip()
    method = args.get("method", "tools/list")
    arguments = args.get("arguments") or {}

    if not tool_name:
        return {"type": "text", "text": "tool_name is required"}

    # Look up tool_record from the DB
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("SELECT * FROM tool_registry WHERE name = :name AND status != 'deleted' LIMIT 1"),
                {"name": tool_name},
            )
            row = result.mappings().fetchone()
    except Exception as exc:
        return {"type": "text", "text": f"DB error looking up tool: {exc}"}

    if row is None:
        return {"type": "text", "text": f"Tool '{tool_name}' not found in registry"}

    tool_record = dict(row)
    client_id = getattr(request.state, "client_id", "unknown")
    client_roles = getattr(request.state, "client_roles", [])
    request_id = getattr(request.state, "request_id", str(uuid4()))

    # MCP JSON-RPC params vary by method:
    #   tools/call  → {"name": <tool>, "arguments": {...}}  (caller passes this directly)
    #   tools/list  → {}
    #   anything else → pass arguments as-is
    if method == "tools/call":
        params = arguments  # caller must include {"name": ..., "arguments": {...}}
    elif method == "tools/list":
        params = {}
    else:
        params = {"arguments": arguments}

    json_rpc_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }

    try:
        result = await inv_svc.invoke_tool(
            tool_record=tool_record,
            json_rpc_request=json_rpc_request,
            client_id=client_id,
            client_roles=client_roles,
            is_testing=False,
            request_id=request_id,
        )
        return {"type": "text", "text": json.dumps(result, indent=2)}
    except Exception as exc:
        logger.exception("invoke_tool pipeline error for %s", tool_name)
        return {"type": "text", "text": f"Invocation error: {exc}"}


_TOOL_HANDLERS = {
    "platform_info": _handle_platform_info,
    "security_pulse_summary": _handle_security_pulse_summary,
    "list_registered_tools": _handle_list_registered_tools,
    "invoke_tool": _handle_invoke_tool_real,
}


# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------

def _ok(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _err(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


async def _dispatch(body: dict, request: Request) -> dict | None:
    """Process a single JSON-RPC message; return None for notifications."""
    method = body.get("method", "")
    params = body.get("params") or {}
    req_id = body.get("id")  # None for notifications

    client_id = getattr(request.state, "client_id", "anonymous")
    roles: list[str] = getattr(request.state, "client_roles", [])

    logger.info("MCP %s from %s roles=%s", method, client_id, roles)

    # ── Notifications (no id → no response) ─────────────────────────────
    if method in ("notifications/initialized", "notifications/cancelled",
                  "notifications/progress"):
        return None

    # ── Core protocol ────────────────────────────────────────────────────
    if method == "initialize":
        return _ok(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {"listChanged": False}},
        })

    if method == "ping":
        return _ok(req_id, {})

    # ── Tool methods ──────────────────────────────────────────────────────
    if method == "tools/list":
        tools = _visible_tools(roles)
        logger.info(
            "MCP tools/list client=%s roles=%s visible_count=%d",
            client_id, roles, len(tools),
        )
        return _ok(req_id, {"tools": tools})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}

        if not _can_call(name, roles):
            return _err(req_id, -32603, f"Tool '{name}' not found or not accessible with your roles ({roles})")

        # OPA policy check for internal platform tools.
        # 'invoke_tool' runs its own full pipeline — skip here to avoid double-evaluation.
        if name != "invoke_tool":
            from app.services.policy import evaluate_policy
            from app.services.invocation import emit_mcp_access_event
            from uuid import uuid4
            opa_input = {
                "client_id": client_id,
                "client_roles": roles,
                "tool_id": "",
                "tool_name": name,
                "tool_status": "internal",
                "tool_risk_level": "low",
                "params": args,
                "anomaly_score": 0.0,
                "is_testing": False,
            }
            opa_result = await evaluate_policy(opa_input)
            if not opa_result["allow"]:
                await emit_mcp_access_event(
                    tool_id=None,
                    tool_name=name,
                    tool_version=None,
                    client_id=client_id,
                    outcome="deny",
                    deny_reasons=opa_result.get("reasons", []),
                    request_id=getattr(request.state, "request_id", str(uuid4())),
                    latency_ms=0,
                    anomaly_score=0.0,
                    opa_decision_id=f"dec_{uuid4().hex[:16]}",
                    is_testing=False,
                )
                return _err(req_id, -32603, f"Policy denied: {opa_result.get('reasons', [])}")

        handler = _TOOL_HANDLERS.get(name)
        if not handler:
            return _err(req_id, -32601, f"Tool '{name}' has no handler")

        try:
            import asyncio
            import time
            t0 = time.monotonic()
            if asyncio.iscoroutinefunction(handler):
                content = await handler(args, request)
            else:
                content = handler(args, request)
            latency_ms = int((time.monotonic() - t0) * 1000)

            # Emit audit for internal tools only (invoke_tool audits internally)
            if name != "invoke_tool":
                from app.services.invocation import emit_mcp_access_event
                from uuid import uuid4
                await emit_mcp_access_event(
                    tool_id=None,
                    tool_name=name,
                    tool_version=None,
                    client_id=client_id,
                    outcome="allow",
                    deny_reasons=[],
                    request_id=getattr(request.state, "request_id", str(uuid4())),
                    latency_ms=latency_ms,
                    anomaly_score=0.0,
                    opa_decision_id=f"dec_{uuid4().hex[:16]}",
                    is_testing=False,
                )
            return _ok(req_id, {"content": [content]})
        except Exception as exc:
            logger.exception("Tool handler error: %s", name)
            return _err(req_id, -32603, f"Tool execution error: {exc}")

    # Unknown method
    return _err(req_id, -32601, f"Method not found: {method}")


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

@router.post("/mcp", response_model=None)
async def mcp_post(request: Request) -> JSONResponse | StreamingResponse:
    """
    MCP Streamable-HTTP transport — POST handler.

    Accepts a single JSON-RPC object or a batch array.
    Returns JSON for request messages, 202 for pure notifications.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            _err(None, -32700, "Parse error — body must be JSON"),
            status_code=400,
        )

    # Single message
    if isinstance(body, dict):
        result = await _dispatch(body, request)
        if result is None:
            return JSONResponse({}, status_code=202)
        return JSONResponse(result)

    # Batch
    if isinstance(body, list):
        import asyncio
        responses = await asyncio.gather(*[_dispatch(msg, request) for msg in body if isinstance(msg, dict)])
        responses = [r for r in responses if r is not None]
        if not responses:
            return JSONResponse({}, status_code=202)
        return JSONResponse(responses)

    return JSONResponse(_err(None, -32600, "Invalid request"), status_code=400)


@router.get("/mcp", response_model=None)
async def mcp_get(request: Request) -> JSONResponse:
    """
    MCP GET — returns server info for clients that probe before opening SSE.
    Full SSE session support can be added here when needed.
    """
    return JSONResponse({
        "server": SERVER_INFO,
        "transport": "streamable-http",
        "authenticated_as": getattr(request.state, "client_id", None),
        "roles": getattr(request.state, "client_roles", []),
    })
