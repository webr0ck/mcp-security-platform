"""
MCP Streamable-HTTP Transport  (MCP spec 2025-03-26)


Handles JSON-RPC 2.0 messages from MCP clients (Claude Code, etc.) at POST /mcp.

Implemented methods
-------------------
initialize          — server capabilities + identity echo
notifications/initialized  — client ready notification (no response)
ping                — keep-alive
tools/list          — platform meta-tools + all grant-filtered registry tools
tools/call          — platform tools handled inline; registry tools routed through
                       OPA policy → credential injection → audit pipeline

Role visibility (platform meta-tools)
--------------------------------------
  admin    → all platform tools
  analyst  → security_* tools + platform_info
  viewer   → platform_info only

Registry tools
--------------
  All active tools from tool_registry are included in tools/list filtered by the
  caller's OPA grants (advisory; OPA re-enforces on every tools/call).
  A direct tools/call for any registered tool name bypasses the invoke_tool wrapper
  and routes straight through the security pipeline — transparent to the MCP client.

The /mcp path is public at the nginx level (no mTLS) but AuthMiddleware
enforces Bearer token auth so every request has request.state.client_id.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MCP"])

# ---------------------------------------------------------------------------
# Resource guards
# ---------------------------------------------------------------------------

_MAX_BATCH_SIZE = 20  # MCP spec doesn't define a limit; 20 is generous for real clients

_INVOKE_SEMAPHORE = asyncio.Semaphore(int(os.environ.get("MCP_INVOKE_CONCURRENCY", "10")))  # max concurrent invoke_tool calls

# MCP-006: when the rate-limit backend (Redis) is unavailable, fail CLOSED by
# default (deny) rather than silently disabling rate limiting. This is an
# explicit, documented availability/security tradeoff — set RATE_LIMIT_FAIL_OPEN=true
# to restore the old fail-open behaviour if availability must win in a given env.
_RATE_LIMIT_FAIL_OPEN = os.environ.get("RATE_LIMIT_FAIL_OPEN", "false").lower() == "true"


async def _check_rate_limit(client_id: str, limit: int = 300, window_seconds: int = 60) -> bool:
    """Returns True if request allowed, False if rate limited."""
    from app.core.redis_client import redis_pool
    try:
        rl_client = redis_pool.rate_limit_client
    except RuntimeError:
        return _RATE_LIMIT_FAIL_OPEN  # MCP-006: fail closed by default
    try:
        key = f"rl:mcp:{client_id}"
        pipe = rl_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        return results[0] <= limit
    except Exception:
        return _RATE_LIMIT_FAIL_OPEN  # MCP-006: fail closed by default


async def _check_rate_limit_by_key(key: str, limit: int, window_seconds: int = 60) -> bool:
    """Generic rate limiter keyed by an arbitrary string. Returns True if allowed."""
    from app.core.redis_client import redis_pool
    try:
        rl_client = redis_pool.rate_limit_client
    except RuntimeError:
        return _RATE_LIMIT_FAIL_OPEN  # MCP-006: fail closed by default
    try:
        pipe = rl_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        return results[0] <= limit
    except Exception:
        return _RATE_LIMIT_FAIL_OPEN  # MCP-006: fail closed by default

SERVER_INFO = {
    "name": "mcp-security-platform",
    "version": "1.0.0",
}

# ---------------------------------------------------------------------------
# Tool catalogue — each entry declares which roles may call it
# ---------------------------------------------------------------------------
_OAUTH_SERVICES: list[str] = ["m365", "bitbucket", "dex"]


async def _get_enrollment_status(client_id: str, base_url: str) -> list[dict]:
    """
    For each approach-A OAuth service, check whether client_id has a stored
    credential in credential_store. Returns a list of status dicts.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    base = base_url.rstrip("/")
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT service FROM credential_store WHERE user_sub = :sub "
                    "AND service = ANY(:services)"
                ),
                {"sub": client_id, "services": _OAUTH_SERVICES},
            )
            enrolled = {row[0] for row in result.fetchall()}
    except Exception as exc:
        logger.warning("enrollment_status DB check failed: %s", exc)
        enrolled = set()

    return [
        {
            "service": svc,
            "enrolled": svc in enrolled,
            "enrollment_url": f"{base}/auth/enroll/{svc}" if svc not in enrolled else None,
        }
        for svc in _OAUTH_SERVICES
    ]


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
        "name": "enrollment_status",
        "description": "List OAuth enrollment state for all delegated-auth services (m365, bitbucket, dex). Returns enrolled=true/false and an enrollment_url for any service that still needs browser authentication.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "_roles": {"admin", "analyst", "viewer"},
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
        "_roles": {"admin", "platform_admin", "agent"},
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


def _load_grants_data() -> tuple[dict, dict]:
    """Return (grants, tools_metadata) from data.json. Mirrors OPA bundle layout."""
    candidates = [
        "/app/policies/data.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../policies/rego/data.json"),
    ]
    for grants_path in candidates:
        if os.path.exists(grants_path):
            try:
                with open(grants_path) as f:
                    d = json.load(f).get("mcp", {})
                    return d.get("grants", {}), d.get("tools", {})
            except Exception:
                pass
    return {}, {}


async def _registered_tools_for_client(client_id: str, roles: list[str]) -> list[dict]:
    """Return active registry tools visible to this client.

    Mirrors OPA client_has_invoke_permission logic:
      - admin/platform_admin → all active tools
      - others → tools in allowed_tools OR having a tag in allowed_tags
    This is advisory; OPA re-enforces on every tools/call.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    grants, tools_meta = _load_grants_data()
    role_set = set(roles)
    is_admin = bool(role_set & {"admin", "platform_admin"})

    if not is_admin:
        grant = grants.get(client_id, {})
        allowed_tools: set[str] = set(grant.get("allowed_tools", []))
        allowed_tags: set[str] = set(grant.get("allowed_tags", []))
        if not allowed_tools and not allowed_tags:
            return []

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT name, description, schema, tags FROM tool_registry "
                    "WHERE status = 'active' AND deleted_at IS NULL ORDER BY name"
                )
            )
            rows = result.mappings().fetchall()
    except Exception as exc:
        logger.error("DB error fetching tool catalogue: %s", exc)
        return []

    platform_names = {t["name"] for t in _TOOLS}
    tools = []
    for row in rows:
        if row["name"] in platform_names:
            continue
        if not is_admin:
            # Mirror OPA tag-grant rule exactly:
            # OPA uses data.mcp.tools[tool_name].tags (data.json), NOT DB tags.
            meta_tags = set(tools_meta.get(row["name"], {}).get("tags", []))
            if row["name"] not in allowed_tools and not (meta_tags & allowed_tags):
                continue
        schema = row["schema"] or {}
        if isinstance(schema, str):
            try:
                schema = json.loads(schema)
            except Exception:
                schema = {}
        tools.append({
            "name": row["name"],
            "description": row["description"] or f"Registered MCP tool: {row['name']}",
            "inputSchema": schema,
        })
    return tools


async def _route_to_registry(name: str, args: dict, request: Request, req_id: Any) -> dict:
    """Route a direct tools/call for a registry tool through the full security pipeline."""
    from uuid import uuid4
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.services import invocation as inv_svc

    client_id = getattr(request.state, "client_id", "unknown")
    client_roles = getattr(request.state, "client_roles", [])
    request_id = getattr(request.state, "request_id", str(uuid4()))

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT * FROM tool_registry WHERE name = :name "
                    "AND status NOT IN ('deprecated', 'quarantined') "
                    "AND deleted_at IS NULL LIMIT 1"
                ),
                {"name": name},
            )
            row = result.mappings().fetchone()
    except Exception as exc:
        return _err(req_id, -32603, f"DB error looking up tool '{name}': {exc}")

    if row is None:
        return _err(req_id, -32601, f"Tool '{name}' not found in registry or not callable")

    tool_record = dict(row)
    json_rpc_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }

    try:
        async with _INVOKE_SEMAPHORE:
            upstream = await inv_svc.invoke_tool(
                tool_record=tool_record,
                json_rpc_request=json_rpc_request,
                client_id=client_id,
                client_roles=client_roles,
                is_testing=False,
                request_id=request_id,
                # Case-3 (3b): downstream-IDP token rides a dedicated header so the
                # gateway's own Authorization (Keycloak) stays free for its authz.
                inbound_auth=request.headers.get("x-downstream-authorization"),
                # 6.2: typed principal for the discovery==invoke entitlement gate.
                principal_id=getattr(request.state, "principal_id", None),
                principal_type=getattr(request.state, "principal_type", None),
            )
    except Exception as exc:
        from app.credential_broker.dispatcher import CredentialEnrollmentRequiredError
        from app.services.entitlement import NotEntitledError
        if isinstance(exc, NotEntitledError):
            # 6.2 discovery==invoke: caller is not entitled to this tool's server.
            # Return a deny without leaking the server_id / reason internals.
            logger.info("MCP invoke denied (not entitled) tool=%s client=%s reason=%s",
                        name, client_id, exc.reason)
            return _err(req_id, -32003, "Access denied: not entitled to this tool's server")
        if isinstance(exc, CredentialEnrollmentRequiredError):
            return _err(
                req_id,
                -32010,
                f"OAuth enrollment required for '{exc.service}'",
                data={
                    "service": exc.service,
                    "enrollment_url": exc.enrollment_url,
                    "action": "open_browser",
                    "instructions": (
                        f"Open {exc.enrollment_url} in your browser while authenticated "
                        "to the proxy. After completing consent, retry this tool call."
                    ),
                },
            )
        logger.exception("Registry tool invocation error for %s", name)
        return _err(req_id, -32603, f"Tool invocation failed: {exc}")

    if "error" in upstream:
        err = upstream["error"]
        # Preserve `data` — it carries the downstream auth challenge
        # (www_authenticate / resource metadata) for Case-3 passthrough.
        return _err(req_id, err.get("code", -32603), err.get("message", "Upstream error"),
                    data=err.get("data"))

    content = upstream.get("result", {}).get("content", [])
    if not content:
        content = [{"type": "text", "text": json.dumps(upstream.get("result", {}))}]
    return _ok(req_id, {"content": content})


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


async def _handle_enrollment_status(args: dict, request: Request) -> dict:
    from app.core.config import get_settings
    client_id = getattr(request.state, "client_id", "unknown")
    base_url = get_settings().PROXY_BASE_URL
    statuses = await _get_enrollment_status(client_id, base_url)
    pending = [s for s in statuses if not s["enrolled"]]
    return {
        "type": "text",
        "text": json.dumps({
            "services": statuses,
            "pending_count": len(pending),
            "instructions": (
                "Open each enrollment_url in your browser while authenticated to the proxy. "
                "After completing the Microsoft/OAuth consent flow, retry the tool call."
            ) if pending else "All OAuth services are enrolled.",
        }, indent=2),
    }


async def _handle_list_registered_tools(args: dict, request: Request) -> dict:
    status_filter = args.get("status", "all")
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    try:
        async with AsyncSessionLocal() as session:
            if status_filter == "all":
                result = await session.execute(
                    text("SELECT name, version, status, risk_score, upstream_url FROM tool_registry WHERE deleted_at IS NULL ORDER BY name")
                )
            else:
                result = await session.execute(
                    text("SELECT name, version, status, risk_score, upstream_url FROM tool_registry WHERE deleted_at IS NULL AND status = :s ORDER BY name"),
                    {"s": status_filter},
                )
            rows = result.mappings().fetchall()
    except Exception as exc:
        return {"type": "text", "text": f"DB error fetching tool registry: {exc}"}
    tools = [dict(r) for r in rows]
    return {
        "type": "text",
        "text": json.dumps({"tools": tools, "total": len(tools)}, indent=2),
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
                text("SELECT * FROM tool_registry WHERE name = :name AND status NOT IN ('deprecated', 'quarantined') AND deleted_at IS NULL LIMIT 1"),
                {"name": tool_name},
            )
            row = result.mappings().fetchone()
    except Exception as exc:
        logger.error("DB error looking up tool %s: %s", tool_name, exc)
        return {"type": "text", "text": "Tool lookup failed (internal error). Check server logs."}

    if row is None:
        return {"type": "text", "text": f"Tool '{tool_name}' not found in registry"}

    tool_record = dict(row)

    # 6.2 — discovery==invoke entitlement is now enforced inside
    # inv_svc.invoke_tool() (services/invocation.py → enforce_tool_entitlement),
    # the single chokepoint shared by REST + both /mcp paths. V023 added
    # tool_registry.server_id; SELECT * above carries it into tool_record. When
    # it is set, the caller must be entitled to that server — no role exception.

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
        async with _INVOKE_SEMAPHORE:
            result = await inv_svc.invoke_tool(
                tool_record=tool_record,
                json_rpc_request=json_rpc_request,
                client_id=client_id,
                client_roles=client_roles,
                is_testing=False,
                request_id=request_id,
                inbound_auth=request.headers.get("x-downstream-authorization"),
                # 6.2: typed principal for the discovery==invoke entitlement gate.
                principal_id=getattr(request.state, "principal_id", None),
                principal_type=getattr(request.state, "principal_type", None),
            )
        return {"type": "text", "text": json.dumps(result, indent=2)}
    except Exception as exc:
        from app.services.entitlement import NotEntitledError
        if isinstance(exc, NotEntitledError):
            # 6.2 discovery==invoke: not entitled to this tool's server. Clean
            # deny, no info leak about the server_id / internal reason.
            logger.info("invoke_tool denied (not entitled) tool=%s client=%s reason=%s",
                        tool_name, client_id, exc.reason)
            return {"type": "text", "text": "Access denied: not entitled to this tool's server"}
        logger.exception("invoke_tool pipeline error for %s", tool_name)
        return {"type": "text", "text": "Tool invocation failed (internal error). Check server logs."}


_TOOL_HANDLERS = {
    "platform_info": _handle_platform_info,
    "security_pulse_summary": _handle_security_pulse_summary,
    "enrollment_status": _handle_enrollment_status,
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

    # Bug 2 fix: prefer per-message batch sub-ID over the shared request.state.request_id.
    # This ensures every audit event in a batch carries a unique correlation ID.
    from uuid import uuid4 as _uuid4
    _effective_request_id: str = (
        body.get("_request_id")
        or getattr(request.state, "request_id", str(_uuid4()))
    )

    logger.info("MCP %s from %s roles=%s", method, client_id, roles)

    # ── Notifications (no id → no response) ─────────────────────────────
    if method in ("notifications/initialized", "notifications/cancelled",
                  "notifications/progress"):
        return None

    # ── Core protocol ────────────────────────────────────────────────────
    if method == "initialize":
        from app.core.config import get_settings
        base_url = get_settings().PROXY_BASE_URL
        enrollment = await _get_enrollment_status(client_id, base_url)
        pending = [
            {"service": s["service"], "enrollment_url": s["enrollment_url"]}
            for s in enrollment
            if not s["enrolled"]
        ]
        meta: dict[str, Any] = {}
        if pending:
            meta["pending_enrollments"] = pending
            meta["enrollment_hint"] = (
                f"{len(pending)} service(s) need browser authentication before their tools will work. "
                "Call the 'enrollment_status' tool for details and URLs, or open each "
                "enrollment_url directly in your browser while authenticated."
            )
        return _ok(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {"listChanged": False}},
            **({"_meta": meta} if meta else {}),
        })

    if method == "ping":
        return _ok(req_id, {})

    # ── Tool methods ──────────────────────────────────────────────────────
    if method == "tools/list":
        platform_tools = _visible_tools(roles)
        registry_tools = await _registered_tools_for_client(client_id, roles)
        tools = platform_tools + registry_tools
        logger.info(
            "MCP tools/list client=%s roles=%s visible=%d (platform=%d registry=%d)",
            client_id, roles, len(tools), len(platform_tools), len(registry_tools),
        )
        return _ok(req_id, {"tools": tools})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}

        # Registry tool — route directly through the security pipeline
        if not _can_call(name, roles):
            return await _route_to_registry(name, args, request, req_id)

        # OPA policy check for internal platform tools.
        # 'invoke_tool' runs its own full pipeline — skip here to avoid double-evaluation.
        if name != "invoke_tool":
            from app.services.policy import evaluate_policy
            from app.services.invocation import emit_internal_tool_event
            from uuid import uuid4
            # 6.1: evaluate OPA under the REAL caller identity, not a hardcoded
            # platform_internal/platform_admin principal. authz.rego authorizes
            # platform meta-tools by role (platform_meta_tool_roles) without
            # requiring a per-client grant.
            #
            # is_platform_meta=true is the ONLY trigger for the meta-tool rules in
            # authz.rego. It is set exclusively on this inline dispatch path; the
            # registry invoke path (services/invocation.py) never sets it. This
            # prevents a registry tool *registered* with a reserved meta-tool name
            # (e.g. "platform_info") from inheriting the meta-tool risk/grant
            # bypass — the policy must not trust tool_name alone.
            opa_input = {
                "client_id": client_id,
                "client_roles": roles,
                "tool_id": "",
                "tool_name": name,
                "tool_status": "active",
                "tool_risk_level": "low",
                "params": args,
                "anomaly_score": 0.0,
                "is_testing": False,
                "is_platform_meta": True,
            }
            opa_result = await evaluate_policy(opa_input)
            if not opa_result["allow"]:
                await emit_internal_tool_event(
                    tool_name=name,
                    client_id=client_id,
                    outcome="deny",
                    deny_reasons=opa_result.get("reasons", []),
                    request_id=_effective_request_id,
                    latency_ms=0,
                    opa_decision_id=f"dec_{uuid4().hex[:16]}",
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
                from app.services.invocation import emit_internal_tool_event
                from uuid import uuid4
                await emit_internal_tool_event(
                    tool_name=name,
                    client_id=client_id,
                    outcome="allow",
                    deny_reasons=[],
                    request_id=_effective_request_id,
                    latency_ms=latency_ms,
                    opa_decision_id=f"dec_{uuid4().hex[:16]}",
                )
            return _ok(req_id, {"content": [content]})
        except Exception as exc:
            logger.exception("Tool handler error: %s", name)
            return _err(req_id, -32603, "Tool execution error (internal). Check server logs.")

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

    # Per-client rate limiting (applied before processing regardless of message shape).
    # client_id is always set post-auth (AuthMiddleware); the IP fallback handles the
    # theoretical case where client_id is None so no request can slip through unlimited.
    client_id = getattr(request.state, "client_id", None)
    rl_key_id = client_id or (request.client.host if request.client else "unknown")
    allowed = await _check_rate_limit(rl_key_id)
    if not allowed:
        return JSONResponse(
            {"error": {"code": "RATE_LIMITED", "message": "Too many requests"}},
            status_code=429,
        )

    # Single message
    if isinstance(body, dict):
        result = await _dispatch(body, request)
        if result is None:
            return JSONResponse({}, status_code=202)
        return JSONResponse(result)

    # Batch
    if isinstance(body, list):
        if len(body) > _MAX_BATCH_SIZE:
            return JSONResponse(
                _err(None, -32600, f"Batch too large: max {_MAX_BATCH_SIZE} messages per request"),
                status_code=400,
            )
        # Bug 2 fix: inject per-message correlation IDs so every audit event in a
        # batch carries a unique request_id (format: <batch_id>#<index>).
        from uuid import uuid4 as _uuid4
        batch_request_id = getattr(request.state, "request_id", str(_uuid4()))
        tagged = []
        for i, msg in enumerate(body):
            if isinstance(msg, dict):
                msg = dict(msg)  # shallow copy — do not mutate caller's object
                msg["_batch_index"] = i
                msg["_request_id"] = f"{batch_request_id}#{i}"
                tagged.append(msg)
        responses = await asyncio.gather(*[_dispatch(msg, request) for msg in tagged])
        responses = [r for r in responses if r is not None]
        if not responses:
            return JSONResponse({}, status_code=202)
        return JSONResponse(responses)

    return JSONResponse(_err(None, -32600, "Invalid request"), status_code=400)


@router.get("/mcp", response_model=None)
async def mcp_get(request: Request) -> JSONResponse | StreamingResponse:
    """
    MCP GET — Streamable HTTP transport (MCP spec 2024-11-05 §6.3.2).

    Clients that send Accept: text/event-stream get a persistent SSE stream
    (server-to-client push channel + keepalive).  Other clients (probes,
    healthchecks) get the plain server-info JSON.
    """
    import asyncio

    accept = request.headers.get("accept", "")
    if "text/event-stream" not in accept:
        return JSONResponse({
            "server": SERVER_INFO,
            "transport": "streamable-http",
            "authenticated_as": getattr(request.state, "client_id", None),
            "roles": getattr(request.state, "client_roles", []),
        })

    async def _sse_keepalive():
        """Yield SSE keepalive comments until the client disconnects."""
        # Initial endpoint event so the client knows the stream is live.
        yield "event: endpoint\ndata: {\"endpoint\":\"/mcp\"}\n\n"
        try:
            while True:
                if await request.is_disconnected():
                    break
                yield ": keepalive\n\n"
                await asyncio.sleep(15)
        except Exception:
            pass

    return StreamingResponse(
        _sse_keepalive(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
