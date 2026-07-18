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
from app.credential_broker.dispatcher import (
    CredentialEnrollmentRequiredError,
    ServiceCredentialMissingError,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["MCP"])

# INV-015: sentinel used to distinguish a Redis connection exception from a
# genuine cache miss (None).  A Redis exception must NEVER fall through to a
# live DB call — that would re-introduce the fail-open for a different path.
_SENTINEL_FAIL_CLOSED = object()


class _ProfileLookupUnavailable(Exception):
    """Raised by _dispatch when ProfileLookupError propagates from _registered_tools_for_client.

    Carries the JSON-RPC error body so mcp_post can return it with HTTP 503.
    INV-015: profile lookup fail-closed — DB error + cache miss → 503.
    """
    def __init__(self, rpc_error: dict) -> None:
        self.rpc_error = rpc_error
        super().__init__("Profile lookup unavailable")

# ---------------------------------------------------------------------------
# Resource guards
# ---------------------------------------------------------------------------

_MAX_BATCH_SIZE = 20  # MCP spec doesn't define a limit; 20 is generous for real clients

# tools/list catalogue query for standard MCP clients. Rows flagged
# metadata.hidden=true (legacy server-alias rows) stay callable via the
# invoke_tool meta-tool but are excluded from tools/list discovery.
REGISTERED_TOOLS_QUERY = (
    "SELECT name, description, schema, tags, server_id, metadata "
    "FROM tool_registry "
    "WHERE status = 'active' AND deleted_at IS NULL "
    "AND COALESCE(metadata->>'hidden', 'false') <> 'true' "
    "ORDER BY name"
)

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
_OAUTH_SERVICES: list[str] = ["m365", "bitbucket", "dex", "netbox"]


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
    # ------------------------------------------------------------------
    # Self-service profile management tools — available to all roles so
    # non-technical stakeholders can manage their own MCP access via the
    # MCP protocol itself (not just the UI portal).
    # ------------------------------------------------------------------
    {
        "name": "list_available_mcps",
        "description": (
            "List all MCP servers available on this platform and whether each is enabled "
            "for your profile. Use this to see what AI tools you have access to."
        ),
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "_roles": {"admin", "analyst", "viewer", "editor", "platform_admin", "agent"},
    },
    {
        "name": "get_my_profile",
        "description": (
            "Return your current access profile: which MCP servers are enabled, "
            "and (if configured) which individual functions within each server you can use."
        ),
        "inputSchema": {"type": "object", "properties": {}, "required": []},
        "_roles": {"admin", "analyst", "viewer", "editor", "platform_admin"},
    },
    {
        "name": "enable_mcp_server",
        "description": "Enable an MCP server for your profile so you can call its tools.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_name": {
                    "type": "string",
                    "description": "The server_name from list_available_mcps (e.g. 'poc-echo-server').",
                }
            },
            "required": ["server_name"],
        },
        "_roles": {"admin", "analyst", "editor", "platform_admin"},
    },
    {
        "name": "disable_mcp_server",
        "description": "Disable an MCP server for your profile so its tools are no longer callable.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "server_name": {
                    "type": "string",
                    "description": "The server_name from list_available_mcps (e.g. 'poc-echo-server').",
                }
            },
            "required": ["server_name"],
        },
        "_roles": {"admin", "analyst", "editor", "platform_admin"},
    },
]


# Frozen set of platform meta-tool names. Computed once at import time so the
# tools/call dispatch guard (PRIVESC-004) never diverges across requests and
# cannot be widened by a future dynamic _TOOLS update within a single process.
_PLATFORM_NAMES: frozenset[str] = frozenset(t["name"] for t in _TOOLS)


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


def _load_tools_meta() -> dict:
    """Return tools metadata dict from data.json (mcp.tools section).

    This half of the old _load_grants_data() is still file-based because
    tools_meta is static tag metadata used for NULL-server_id tag matching
    and lives in the signed OPA bundle.  It does NOT contain per-client grants.
    """
    candidates = [
        "/app/policies/data.json",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../policies/rego/data.json"),
    ]
    for grants_path in candidates:
        if os.path.exists(grants_path):
            try:
                with open(grants_path) as f:
                    return json.load(f).get("mcp", {}).get("tools", {})
            except Exception:
                pass
    return {}


async def _load_grants_data(client_id: str) -> tuple[dict, dict]:
    """Return (grants, tools_metadata) for the given client_id.

    grants dict shape: {client_id: {"allowed_tools": [...], "allowed_tags": [...], "max_risk_level": "..."}}
    tools_meta dict shape: {tool_name: {"tags": [...]}} — loaded from data.json (static, unchanged).

    N4 fix: grants are now read from the client_grants DB table rather than the
    static policies/rego/data.json file, so admin API grant additions/revocations
    are immediately visible to tools/list without a container restart.

    Stale snapshot may list revoked tools for up to 60s; OPA re-enforces on invoke.

    Fallback chain on DB error:
      1. Redis cache key grants_snapshot:{client_id} (60s TTL write-through)
      2. Empty grants dict — tools/list is best-effort; OPA enforces on invoke
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.core.redis_client import redis_pool

    tools_meta = _load_tools_meta()
    cache_key = f"grants_snapshot:{client_id}"

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT allowed_tools, allowed_tags, max_risk_level "
                    "FROM client_grants WHERE client_id = :client_id"
                ),
                {"client_id": client_id},
            )
            row = result.mappings().fetchone()

        if row is None:
            return {}, tools_meta

        grants = {
            client_id: {
                "allowed_tools": row["allowed_tools"] or [],
                "allowed_tags": row["allowed_tags"] or [],
                "max_risk_level": row["max_risk_level"] or "high",
            }
        }

        # Write-through to Redis so the cache reflects the live DB state.
        try:
            redis = redis_pool.client
            await redis.setex(cache_key, 60, json.dumps(grants))
        except Exception as cache_exc:
            logger.debug("grants cache write-through failed client_id=%s: %s", client_id, cache_exc)

        return grants, tools_meta

    except Exception as db_exc:
        logger.warning("DB error loading grants for client_id=%s: %s — trying cache", client_id, db_exc)

        # Fallback: Redis snapshot (may be up to 60s stale).
        try:
            redis = redis_pool.client
            cached = await redis.get(cache_key)
            if cached:
                grants = json.loads(cached)
                return grants, tools_meta
        except Exception as cache_exc:
            logger.warning("grants cache fallback also failed client_id=%s: %s", client_id, cache_exc)

        # Both DB and cache unavailable — return empty grants.
        # tools/list is best-effort; OPA re-enforces on invoke (INV-004).
        return {}, tools_meta


async def _lookup_profile_row(profile_id: str, mcp_name: str):
    """Return the mcp_profiles row for (profile_id, mcp_name), or None if absent.

    Absence means no explicit restriction — platform default applies (enabled=true,
    all functions).  A row with enabled=False means this MCP is disabled for the
    caller's profile.

    INV-015: fail-closed semantics.
      DB success:             write-through to Redis (TTL 120s), return row or None.
      DB error + cache hit:   return cached value (last-known-state).
      DB error + cache miss:  raise ProfileLookupError → caller converts to 503.
      Redis exception:        treat as _SENTINEL_FAIL_CLOSED — never fall through
                              to a live DB call on Redis exception.

    Separate function so tests can patch it cleanly.
    """
    import json as _json
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.core.redis_client import redis_pool
    from app.services.invocation import ProfileLookupError
    from redis.exceptions import RedisError

    cache_key = f"profile_row:{profile_id}:{mcp_name}"
    _SENTINEL_NO_ROW = "__NO_PROFILE_ROW__"

    # ── Try DB first ────────────────────────────────────────────────────────
    db_raised = False
    db_row = None
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT enabled FROM mcp_profiles "
                    "WHERE profile_id = :pid AND mcp_name = :mcp_name LIMIT 1"
                ),
                {"pid": profile_id, "mcp_name": mcp_name},
            )
            db_row = result.mappings().fetchone()

        # DB succeeded — write-through to Redis (best-effort)
        try:
            redis = redis_pool.client
            value = _json.dumps(dict(db_row)) if db_row is not None else _SENTINEL_NO_ROW
            await redis.setex(cache_key, 120, value)
        except Exception as _cache_exc:
            logger.debug(
                "profile_row cache write-through failed profile_id=%s mcp_name=%s: %s",
                profile_id, mcp_name, _cache_exc,
            )
        return db_row

    except Exception as exc:
        db_raised = True
        logger.warning(
            "mcp_profiles lookup failed profile_id=%s mcp_name=%s: %s",
            profile_id, mcp_name, exc,
        )

    # ── DB failed — try Redis cache (SENTINEL pattern, INV-015) ────────────
    cached = _SENTINEL_FAIL_CLOSED
    try:
        redis = redis_pool.client
        cached = await redis.get(cache_key)
    except RedisError as _redis_exc:
        logger.warning(
            "profile_row Redis fallback failed profile_id=%s mcp_name=%s: %s",
            profile_id, mcp_name, _redis_exc,
        )
        cached = _SENTINEL_FAIL_CLOSED

    if cached is _SENTINEL_FAIL_CLOSED or (db_raised and cached is None):
        raise ProfileLookupError(
            f"DB unreachable and no cached mcp_profiles row for {profile_id}/{mcp_name}"
        )

    if cached == _SENTINEL_NO_ROW:
        return None  # cached "no row" — default allow
    try:
        return _json.loads(cached)
    except Exception:
        raise ProfileLookupError(
            f"Malformed cache entry for mcp_profiles {profile_id}/{mcp_name}"
        )


async def _lookup_profile_mcp_binding(profile_uuid: str, mcp_name: str):
    """Return the profile_mcp_bindings row for (profile_uuid, mcp_name), or None if absent.

    Task 4.3: named-profile binding lookup. Absence = default (enabled=true, all functions).
    A row with enabled=False means this MCP is disabled for the profile.

    INV-015: fail-closed semantics (same pattern as _lookup_profile_row).
      DB success:             write-through to Redis (TTL 120s), return row or None.
      DB error + cache hit:   return cached value (last-known-state).
      DB error + cache miss:  raise ProfileLookupError → caller converts to 503.
      Redis exception:        treat as _SENTINEL_FAIL_CLOSED — never fall through
                              to a live DB call on Redis exception.

    Separate function so tests can patch it cleanly.
    """
    import json as _json
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.core.redis_client import redis_pool
    from app.services.invocation import ProfileLookupError
    from redis.exceptions import RedisError

    cache_key = f"profile_binding:{profile_uuid}:{mcp_name}"
    _SENTINEL_NO_ROW = "__NO_PROFILE_ROW__"

    # ── Try DB first ────────────────────────────────────────────────────────
    db_raised = False
    db_row = None
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT enabled, allowed_functions FROM profile_mcp_bindings "
                    "WHERE profile_id = :pid AND mcp_name = :mcp_name LIMIT 1"
                ),
                {"pid": profile_uuid, "mcp_name": mcp_name},
            )
            db_row = result.mappings().fetchone()

        # DB succeeded — write-through to Redis (best-effort)
        try:
            redis = redis_pool.client
            value = _json.dumps(dict(db_row)) if db_row is not None else _SENTINEL_NO_ROW
            await redis.setex(cache_key, 120, value)
        except Exception as _cache_exc:
            logger.debug(
                "profile_binding cache write-through failed profile_uuid=%s mcp_name=%s: %s",
                profile_uuid, mcp_name, _cache_exc,
            )
        return db_row

    except Exception as exc:
        db_raised = True
        logger.warning(
            "profile_mcp_bindings lookup failed profile_uuid=%s mcp_name=%s: %s",
            profile_uuid, mcp_name, exc,
        )

    # ── DB failed — try Redis cache (SENTINEL pattern, INV-015) ────────────
    cached = _SENTINEL_FAIL_CLOSED
    try:
        redis = redis_pool.client
        cached = await redis.get(cache_key)
    except RedisError as _redis_exc:
        logger.warning(
            "profile_binding Redis fallback failed profile_uuid=%s mcp_name=%s: %s",
            profile_uuid, mcp_name, _redis_exc,
        )
        cached = _SENTINEL_FAIL_CLOSED

    if cached is _SENTINEL_FAIL_CLOSED or (db_raised and cached is None):
        raise ProfileLookupError(
            f"DB unreachable and no cached profile_mcp_bindings row for {profile_uuid}/{mcp_name}"
        )

    if cached == _SENTINEL_NO_ROW:
        return None  # cached "no row" — default allow
    try:
        return _json.loads(cached)
    except Exception:
        raise ProfileLookupError(
            f"Malformed cache entry for profile_mcp_bindings {profile_uuid}/{mcp_name}"
        )


async def _registered_tools_for_client(
    client_id: str,
    roles: list[str],
    principal_id: str | None = None,
    principal_type: str | None = None,
    profile_uuid: str | None = None,
) -> list[dict]:
    """Return active registry tools visible to this client.

    Task 4.1 — filters applied to ALL callers (admin bypass removed):
      1. Server-linked tools (server_id IS NOT NULL): principal must be entitled to
         the tool's server via check_entitlement().  There is no admin exception —
         this mirrors the invoke path (enforce_tool_entitlement has no role bypass).
      2. Profile gate: if mcp_profiles has enabled=false for (principal_id, tool_name)
         the tool is excluded regardless of entitlement.
      3. NULL-server_id tools (legacy / unlinked): shown only when the caller has an
         explicit data.json grant (allowed_tools or allowed_tags). This mirrors the
         OPA-only invoke path for unlinked tools (entitlement.py:78-80).

    Task 4.3 — named profile filter:
      When profile_uuid is set, ALSO filter by profile_mcp_bindings:
        - If a binding row exists with enabled=False: exclude the tool.
        - Absence of a binding row = default (enabled=true, not filtered).
      This is an additional gate on top of the existing profile check.
      Falls back to legacy mcp_profiles gate when profile_uuid is None.

    Discovery == invoke invariant: the set returned here equals the set that
    enforce_tool_entitlement + profile check on the invoke path would allow.
    OPA still re-enforces on every tools/call (advisory layer stays unchanged).

    If principal_id or principal_type are absent, server-linked tools are hidden
    (fail-closed: same as enforce_tool_entitlement with unresolved principal).

    INV-015: ProfileLookupError raised by _lookup_profile_row /
    _lookup_profile_mcp_binding is NOT caught here — it propagates to the
    tools/list handler which returns a JSON-RPC 503 error.
    """
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.services.entitlement import check_entitlement

    grants, tools_meta = await _load_grants_data(client_id)

    # Caller's DB grants — used for NULL-server_id tools (grants-only path).
    grant = grants.get(client_id, {})
    allowed_tools: set[str] = set(grant.get("allowed_tools", []))
    allowed_tags: set[str] = set(grant.get("allowed_tags", []))

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(REGISTERED_TOOLS_QUERY)
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

        server_id = row["server_id"]

        if server_id is None:
            # ── NULL-server_id: grants-only visibility (OPA-only invoke path) ──
            meta_tags = set(tools_meta.get(row["name"], {}).get("tags", []))
            if row["name"] not in allowed_tools and not (meta_tags & allowed_tags):
                continue
        else:
            # ── Server-linked: entitlement gate (no admin bypass) ──────────────
            if not principal_id or not principal_type:
                # Fail-closed: unresolved principal cannot see server-scoped tools.
                continue
            ent = await check_entitlement(
                principal_type=principal_type,
                principal_id=principal_id,
                server_id=str(server_id),
            )
            if not ent.entitled:
                continue

        # ── Profile gate ────────────────────────────────────────────────────
        # Task 4.3: when profile_uuid is set, check profile_mcp_bindings first.
        # Absence of a binding row = default (enabled=true, not filtered).
        if profile_uuid:
            pmb = await _lookup_profile_mcp_binding(profile_uuid, row["name"])
            if pmb is not None and not pmb["enabled"]:
                continue
        elif principal_id:
            # Legacy path: mcp_profiles.enabled check keyed by principal_id.
            # Only meaningful when we have a resolvable principal identity.
            # Absence of a profile row = platform default (enabled=true).
            profile = await _lookup_profile_row(
                profile_id=principal_id,
                mcp_name=row["name"],
            )
            if profile is not None and not profile["enabled"]:
                continue

        # required_roles: discovery-time role gate (Part C of the reviewer-
        # tools design). Absent/empty = unrestricted, matching every existing
        # row. This is belt-and-suspenders — OPA still re-enforces on invoke.
        required_roles = (row.get("metadata") or {}).get("required_roles")
        if required_roles and not (set(required_roles) & set(roles)):
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


def _absolute_enrollment_url(request: Request, exc: Any) -> str:
    """Absolute ``/auth/enroll/<service>`` URL pointing at the host the user reached
    the gateway on (so the link is clickable and matches the OAuth callback host).
    Falls back to the dispatcher-provided value if host derivation fails."""
    try:
        from app.core.public_url import derive_public_base_url
        return derive_public_base_url(request).rstrip("/") + f"/auth/enroll/{exc.service}"
    except Exception:
        return getattr(exc, "enrollment_url", "") or f"/auth/enroll/{getattr(exc, 'service', '')}"


async def _invoke_registry_tool(
    tool_record: dict,
    json_rpc_request: dict,
    client_id: str,
    client_roles: list[str],
    request: Request,
    request_id: str,
) -> dict:
    """Shared invoke_tool() wiring for the direct tools/call dispatch path.

    Used both by _route_to_registry's actual dispatch and by
    _resolve_upstream_subtool_name's tools/list discovery call (R-2), so the
    two callers can't drift on which request.state fields get threaded through.
    """
    from app.services import invocation as inv_svc

    async with _INVOKE_SEMAPHORE:
        return await inv_svc.invoke_tool(
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
            # CR-10 (WP-A1): typed principal issuer/display-sub, forwarded
            # downstream as X-Principal-Issuer / X-Principal-Display-Sub.
            principal_issuer=getattr(request.state, "principal_issuer", None),
            principal_display_sub=getattr(request.state, "principal_display_sub", None),
            # 6.3: caller KC token for oauth_user_token (RFC 8693) on-behalf-of.
            user_kc_token=getattr(request.state, "user_kc_token", None),
            # P1-F1: thread who-fields so MCP-path audit rows are non-NULL
            # (mirrors the REST path pattern in routers/tools.py ~1241-1245).
            source_ip=(
                request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                or (request.client.host if request.client else None)
            ),
            session_jti=getattr(request.state, "session_jti", None),
            # Task 4.3: named profile UUID — profile_uuid-scoped mcp_profiles lookup.
            profile_uuid=getattr(request.state, "profile_uuid", None),
        )


# R-2 fix: single-tool-per-server wrappers (e.g. "gitea-repos") register the
# *server's* name in tool_registry.name, but the upstream MCP server's real
# tools/call target is a different, per-function name (e.g. "list_repos") —
# forwarding tool_registry.name verbatim as params.name always bounced with
# "Unknown tool: <server name>". Cache of resolved primary upstream tool name
# per tool_id, populated lazily on the first such bounce; TTL keeps it correct
# if the upstream server's tool list changes without a proxy restart.
_WRAPPER_SUBTOOL_CACHE_TTL_SECONDS = 300
_wrapper_subtool_cache: dict[str, tuple[float, str]] = {}


async def _resolve_upstream_subtool_name(
    tool_record: dict,
    client_id: str,
    client_roles: list[str],
    request: Request,
    request_id: str,
) -> str | None:
    """Discover the upstream server's real primary tool name via tools/list.

    Reuses the same invoke_tool() pipeline (entitlement/OPA/credential
    injection) as the actual dispatch, so this does not bypass authorization —
    it is the same tools/list a well-behaved caller would have made before
    tools/call.
    """
    import time

    tool_id = str(tool_record.get("tool_id") or tool_record.get("name"))
    cached = _wrapper_subtool_cache.get(tool_id)
    if cached and (time.monotonic() - cached[0]) < _WRAPPER_SUBTOOL_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        discovery = await _invoke_registry_tool(
            tool_record,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            client_id, client_roles, request, request_id,
        )
    except Exception as exc:
        logger.warning("Upstream tools/list resolution failed for %s: %s", tool_record.get("name"), exc)
        return None

    tools = discovery.get("result", {}).get("tools", []) if isinstance(discovery, dict) else []
    if not tools:
        return None
    subtool_name = tools[0].get("name")
    if not subtool_name:
        return None
    _wrapper_subtool_cache[tool_id] = (time.monotonic(), subtool_name)
    return subtool_name


async def _route_to_registry(name: str, args: dict, request: Request, req_id: Any) -> dict:
    """Route a direct tools/call for a registry tool through the full security pipeline."""
    from uuid import uuid4
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    client_id = getattr(request.state, "client_id", "unknown")
    client_roles = getattr(request.state, "client_roles", [])
    request_id = getattr(request.state, "request_id", str(uuid4()))

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text(
                    "SELECT * FROM tool_registry WHERE name = :name "
                    "AND status NOT IN ('deprecated', 'quarantined', 'disabled')"
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
        upstream = await _invoke_registry_tool(
            tool_record, json_rpc_request, client_id, client_roles, request, request_id
        )
    except Exception as exc:
        from app.services.entitlement import NotEntitledError
        if isinstance(exc, NotEntitledError):
            # 6.2 discovery==invoke: caller is not entitled to this tool's server.
            # Return a deny without leaking the server_id / reason internals.
            logger.info("MCP invoke denied (not entitled) tool=%s client=%s reason=%s",
                        name, client_id, exc.reason)
            return _err(req_id, -32003, "Access denied: not entitled to this tool's server")
        from app.services.invocation import TaintFloorDenyError, ScanFreshnessError, ServerInMaintenanceError
        if isinstance(exc, ScanFreshnessError):
            logger.warning("MCP invoke denied (stale scan) tool=%s client=%s", name, client_id)
            return _err(req_id, -32003, "Access denied: server supply-chain scan is stale")
        if isinstance(exc, ServerInMaintenanceError):
            logger.info("MCP invoke denied (maintenance mode) tool=%s client=%s server=%s",
                        name, client_id, exc.server_id)
            return _err(req_id, -32003, "MCP server is in maintenance")
        if isinstance(exc, TaintFloorDenyError):
            # PRD-0001 M2: taint floor denied a high-sensitivity sink in a tainted
            # session. Audit already emitted in invoke_tool (INV-001). No internals leaked.
            logger.info("MCP invoke denied (taint floor) tool=%s client=%s", name, client_id)
            return _err(req_id, -32003, "Access denied: session restricted by trust policy")
        if isinstance(exc, CredentialEnrollmentRequiredError):
            # Surface an ABSOLUTE enrollment URL IN THE MESSAGE (not just data):
            # standard MCP clients render the JSON-RPC error message but often ignore
            # `data`, so the actionable link must be inline. The host is derived from
            # the request so the link points at whatever address the user reached the
            # gateway on (and matches the OAuth callback host).
            enroll_url = _absolute_enrollment_url(request, exc)
            return _err(
                req_id,
                -32010,
                (
                    f"OAuth enrollment required for '{exc.service}'. Open this URL in your "
                    f"browser while signed in to the proxy, then retry the tool: "
                    f"{enroll_url}"
                ),
                data={
                    "service": exc.service,
                    "enrollment_url": enroll_url,
                    "action": "open_browser",
                    "instructions": (
                        f"Open {enroll_url} in your browser while authenticated "
                        "to the proxy. After completing consent, retry this tool call."
                    ),
                },
            )
        # ORDERING INVARIANT: ServiceCredentialMissingError MUST precede any future
        # isinstance(exc, CredentialInjectionError) guard — it subclasses it and would
        # be shadowed, silently regressing to the generic -32603.
        if isinstance(exc, ServiceCredentialMissingError):
            # Service-mode credential is admin-provisioned, not user-enrolled.
            # Surface an admin-actionable deny instead of a generic 500 (and
            # never a misleading "log in first" prompt).
            logger.warning("MCP invoke: service credential missing tool=%s service=%s",
                           name, exc.service)
            return _err(
                req_id,
                -32011,
                f"Service credential not provisioned for '{exc.service}'",
                data={
                    "service": exc.service,
                    "action": "contact_admin",
                    "instructions": (
                        f"The '{exc.service}' tool uses a shared service credential that a "
                        "platform administrator must provision. Contact your platform admin; "
                        "this is not something you can self-enroll."
                    ),
                },
            )
        from app.services.policy import OPADenyError
        if isinstance(exc, OPADenyError):
            # Distinguish a policy denial (e.g. anomaly_threshold_exceeded,
            # mcp_disabled_for_profile) from a genuine internal error — same
            # reason list a client would get calling the tool directly.
            logger.info("MCP invoke denied (OPA) tool=%s client=%s reasons=%s",
                        name, client_id, exc.reasons)
            return _err(req_id, -32003, "Access denied by policy", data={"reasons": exc.reasons})
        logger.exception("Registry tool invocation error for %s", name)
        return _err(req_id, -32603, f"Tool invocation failed: {exc}")

    if "error" in upstream:
        err = upstream["error"]
        # R-2: single-tool-per-server wrappers forwarded tool_registry.name
        # (e.g. "gitea-repos") as params.name, which the upstream server
        # doesn't recognize as one of its own tools (real names are e.g.
        # "list_repos"). On that specific bounce, resolve the upstream's real
        # primary tool name and retry once before surfacing a deny.
        if "unknown tool" in str(err.get("message", "")).lower():
            resolved_name = await _resolve_upstream_subtool_name(
                tool_record, client_id, client_roles, request, request_id
            )
            if resolved_name and resolved_name != name:
                retry_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": resolved_name, "arguments": args},
                }
                try:
                    upstream = await _invoke_registry_tool(
                        tool_record, retry_request, client_id, client_roles, request, request_id
                    )
                except Exception as retry_exc:
                    logger.exception("Registry tool retry invocation error for %s -> %s", name, resolved_name)
                    return _err(req_id, -32603, f"Tool invocation failed: {retry_exc}")
                if "error" in upstream:
                    err = upstream["error"]
                    return _err(req_id, err.get("code", -32603), err.get("message", "Upstream error"),
                                data=err.get("data"))
            else:
                # Preserve `data` — it carries the downstream auth challenge
                # (www_authenticate / resource metadata) for Case-3 passthrough.
                return _err(req_id, err.get("code", -32603), err.get("message", "Upstream error"),
                            data=err.get("data"))
        else:
            # Preserve `data` — it carries the downstream auth challenge
            # (www_authenticate / resource metadata) for Case-3 passthrough.
            return _err(req_id, err.get("code", -32603), err.get("message", "Upstream error"),
                        data=err.get("data"))

    content = upstream.get("result", {}).get("content", [])
    if not content:
        content = [{"type": "text", "text": json.dumps(upstream.get("result", {}))}]
    from app.services.trust_labeler import get_labeler as _get_labeler, build_envelope_result as _build_envelope_result
    _upstream_meta = upstream.get("meta", {})
    _server_id = _upstream_meta.get("server_id", "")
    _result_payload = _build_envelope_result(
        content=content,
        labeler=_get_labeler(),
        tool_name=name,
        server_id=_server_id,
        result_id=request_id,
        trust_tier=_upstream_meta.get("trust_tier"),
        sensitivity_label=_upstream_meta.get("sensitivity_label"),
    )
    # M4 W4.2: passive inline observer — verify the envelope we just built.
    # Never blocks or raises; advisory only (D4/D5/D6 demo scenarios).
    from app.core.config import get_settings as _gs
    if _gs().TRUST_OBSERVER_ENABLED:
        from app.services.trust_observer import observe_result as _observe
        from app.services.trust_verifier import get_verifier as _get_verifier
        _verdict = _observe(
            _result_payload,
            verifier=_get_verifier(),
            tool_name=name,
            server_id=_server_id,
            result_id=request_id,
        )
        # TRUST_ENVELOPE_ENFORCE (opt-in, default off): promote a subset of
        # fail-closed verifier reasons from advisory-log to a real deny. Scoped
        # to the reasons that indicate the envelope itself is untrustworthy
        # (forged/absent/broken chain), not transient/config reasons.
        if _gs().TRUST_ENVELOPE_ENFORCE and not _verdict.accepted and (_verdict.reason or "").startswith(
            ("signature_invalid", "no_envelope", "chain_validation_failed")
        ):
            return _err(
                req_id, -32603,
                "Tool result rejected: trust envelope verification failed",
                data={"reason": _verdict.reason},
            )
    return _ok(req_id, _result_payload)


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



def _invoke_lookup_name(tool_name: str, method: str, arguments: dict) -> str | None:
    """The registry row to authorize/dispatch against. For tools/call the
    effective tool is the sub-tool in arguments.name (so per-tool quarantine/
    OPA apply); a missing sub-tool name is invalid. For other methods it is the
    named tool/alias itself."""
    if method == "tools/call":
        sub = (arguments or {}).get("name", "")
        return sub.strip() or None
    return (tool_name or "").strip() or None


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

    lookup_name = _invoke_lookup_name(tool_name, method, arguments)
    if not lookup_name:
        return {"type": "text", "text": "tools/call requires arguments.name (the tool to invoke)"}

    # Look up tool_record from the DB. Prefer a row for the sub-tool itself
    # (lookup_name) — backends onboarded with per-function granularity (e.g.
    # check_submission_status) register each sub-tool individually, so OPA/
    # quarantine apply per sub-tool. Multi-function backends onboarded as a
    # single server row (e.g. notes-store's create_note/list_notes/...) have
    # no such row; fall back to the parent tool_name row so the call still
    # authorizes/dispatches against the server, forwarding the sub-tool name
    # in params (already set below) unchanged.
    try:
        async with AsyncSessionLocal() as session:
            # CR-18/quarantine-bypass fix: check for ANY row (including
            # quarantined/deprecated/disabled) first. The old query filtered
            # status in the same SELECT used to decide "does lookup_name have
            # its own row" — so a quarantined sub-tool's row looked identical
            # to "no row exists" and silently fell back to the outer tool_name
            # row instead (e.g. invoke_tool called with tool_name='ping',
            # method='tools/call', arguments={name:'slow_tool'} — slow_tool
            # quarantined — resolved to *ping's* active/entitled tool_record,
            # authorized against ping, then dispatched slow_tool to the
            # upstream anyway). A quarantined lookup_name row must deny
            # immediately, never fall through to a different tool's identity.
            any_status_result = await session.execute(
                text("SELECT status FROM tool_registry WHERE name = :name AND deleted_at IS NULL LIMIT 1"),
                {"name": lookup_name},
            )
            any_status_row = any_status_result.mappings().fetchone()
            if any_status_row is not None and any_status_row["status"] in ("quarantined", "deprecated", "disabled"):
                return {"type": "text", "text": f"Tool '{lookup_name}' is {any_status_row['status']} and cannot be invoked"}

            result = await session.execute(
                text("SELECT * FROM tool_registry WHERE name = :name AND status NOT IN ('deprecated', 'quarantined', 'disabled') AND deleted_at IS NULL LIMIT 1"),
                {"name": lookup_name},
            )
            row = result.mappings().fetchone()
            if row is None and lookup_name != tool_name:
                result = await session.execute(
                    text("SELECT * FROM tool_registry WHERE name = :name AND status NOT IN ('deprecated', 'quarantined', 'disabled') AND deleted_at IS NULL LIMIT 1"),
                    {"name": tool_name},
                )
                row = result.mappings().fetchone()
    except Exception as exc:
        logger.error("DB error looking up tool %s: %s", lookup_name, exc)
        return {"type": "text", "text": "Tool lookup failed (internal error). Check server logs."}

    if row is None:
        return {"type": "text", "text": f"Tool '{lookup_name}' not found in registry"}

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
                # CR-10 (WP-A1): typed principal issuer/display-sub, forwarded
                # downstream as X-Principal-Issuer / X-Principal-Display-Sub.
                principal_issuer=getattr(request.state, "principal_issuer", None),
                principal_display_sub=getattr(request.state, "principal_display_sub", None),
                # 6.3: caller KC token for oauth_user_token (RFC 8693) on-behalf-of.
                user_kc_token=getattr(request.state, "user_kc_token", None),
                # P1-F1: thread who-fields so MCP-path audit rows are non-NULL
                # (mirrors the REST path pattern in routers/tools.py ~1241-1245).
                source_ip=(
                    request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                    or (request.client.host if request.client else None)
                ),
                session_jti=getattr(request.state, "session_jti", None),
                # Task 4.3: named profile UUID — profile_uuid-scoped mcp_profiles lookup.
                profile_uuid=getattr(request.state, "profile_uuid", None),
            )
        # R-2/Fix-3: mirror _route_to_registry's single-tool-per-server wrapper
        # retry. tool_registry.name (e.g. "search-kb") can differ from the
        # upstream's real primary tool name (e.g. "search" — see lab/mcp-servers/
        # search/server.py's @mcp.tool() def search(...)). Without this, every
        # tools/call routed through this meta-tool bounced with a JSON-RPC
        # "Unknown tool: <registry name>" error baked straight into the returned
        # text, even though _route_to_registry's direct-call path already
        # resolves and retries this exact case.
        if (
            method == "tools/call"
            and isinstance(result, dict)
            and "error" in result
            and "unknown tool" in str(result["error"].get("message", "")).lower()
        ):
            resolved_name = await _resolve_upstream_subtool_name(
                tool_record, client_id, client_roles, request, request_id
            )
            if resolved_name and resolved_name != lookup_name:
                retry_request = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": resolved_name,
                        "arguments": arguments.get("arguments") or {},
                    },
                }
                try:
                    async with _INVOKE_SEMAPHORE:
                        result = await inv_svc.invoke_tool(
                            tool_record=tool_record,
                            json_rpc_request=retry_request,
                            client_id=client_id,
                            client_roles=client_roles,
                            is_testing=False,
                            request_id=request_id,
                            inbound_auth=request.headers.get("x-downstream-authorization"),
                            principal_id=getattr(request.state, "principal_id", None),
                            principal_type=getattr(request.state, "principal_type", None),
                            principal_issuer=getattr(request.state, "principal_issuer", None),
                            principal_display_sub=getattr(
                                request.state, "principal_display_sub", None
                            ),
                            user_kc_token=getattr(request.state, "user_kc_token", None),
                            source_ip=(
                                request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                                or (request.client.host if request.client else None)
                            ),
                            session_jti=getattr(request.state, "session_jti", None),
                            profile_uuid=getattr(request.state, "profile_uuid", None),
                        )
                except Exception:
                    logger.exception(
                        "invoke_tool wrapper retry error for %s -> %s", lookup_name, resolved_name
                    )
                    return {
                        "type": "text",
                        "text": "Tool invocation failed (internal error). Check server logs.",
                    }
        return {"type": "text", "text": json.dumps(result, indent=2)}
    except Exception as exc:
        from app.services.entitlement import NotEntitledError
        if isinstance(exc, NotEntitledError):
            # 6.2 discovery==invoke: not entitled to this tool's server. Clean
            # deny, no info leak about the server_id / internal reason.
            logger.info("invoke_tool denied (not entitled) tool=%s client=%s reason=%s",
                        tool_name, client_id, exc.reason)
            return {"type": "text", "text": "Access denied: not entitled to this tool's server"}
        from app.services.invocation import TaintFloorDenyError, ScanFreshnessError, ServerInMaintenanceError
        if isinstance(exc, ScanFreshnessError):
            logger.warning("invoke_tool denied (stale scan) tool=%s client=%s", tool_name, client_id)
            return {"type": "text", "text": "Access denied: server supply-chain scan is stale"}
        if isinstance(exc, ServerInMaintenanceError):
            logger.info("invoke_tool denied (maintenance mode) tool=%s client=%s server=%s",
                        tool_name, client_id, exc.server_id)
            return {"type": "text", "text": "MCP server is in maintenance"}
        if isinstance(exc, TaintFloorDenyError):
            logger.info("invoke_tool denied (taint floor) tool=%s client=%s", tool_name, client_id)
            return {"type": "text", "text": "Access denied: session restricted by trust policy"}
        if isinstance(exc, CredentialEnrollmentRequiredError):
            logger.info("invoke_tool needs enrollment tool=%s client=%s service=%s",
                        tool_name, client_id, exc.service)
            enroll_url = _absolute_enrollment_url(request, exc)
            return {"type": "text", "text": (
                f"\U0001F510 Login required for '{exc.service}'.\n\n"
                f"This tool acts on your behalf, but your {exc.service} account "
                f"isn't connected yet.\n\n"
                f"\U0001F449 Open this link in your browser (while signed in to the "
                f"proxy) to log in:\n    {enroll_url}\n\n"
                f"After you finish sign-in/consent, retry this tool call."
            )}
        # ORDERING INVARIANT: same as _route_to_registry — ServiceCredentialMissingError
        # before any CredentialInjectionError parent-class guard.
        if isinstance(exc, ServiceCredentialMissingError):
            logger.warning("invoke_tool: service credential missing tool=%s service=%s",
                           tool_name, exc.service)
            return {"type": "text", "text": (
                f"⛔ Service credential not provisioned for '{exc.service}'.\n\n"
                f"This tool uses a shared service credential that a platform administrator "
                f"must provision — it is not something you can self-enroll.\n\n"
                f"\U0001F449 Contact your platform admin to provision the '{exc.service}' credential."
            )}
        from app.services.policy import OPADenyError
        if isinstance(exc, OPADenyError):
            logger.info("invoke_tool denied (OPA) tool=%s client=%s reasons=%s",
                        tool_name, client_id, exc.reasons)
            return {"type": "text", "text": f"Access denied by policy: {', '.join(exc.reasons)}"}
        logger.exception("invoke_tool pipeline error for %s", tool_name)
        return {"type": "text", "text": "Tool invocation failed (internal error). Check server logs."}


async def _handle_list_available_mcps(args: dict, request: Request) -> dict:
    client_id: str = getattr(request.state, "client_id", "")
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    try:
        async with AsyncSessionLocal() as db:
            tools = await db.execute(
                text(
                    "SELECT name, description, status, risk_level "
                    "FROM tool_registry WHERE deleted_at IS NULL ORDER BY name"
                )
            )
            rows = tools.mappings().all()
            names = [r["name"] for r in rows]
            enabled_map: dict = {}
            if names:
                prof = await db.execute(
                    text(
                        "SELECT mcp_name, enabled FROM mcp_profiles "
                        "WHERE profile_id = :pid AND mcp_name = ANY(:names)"
                    ),
                    {"pid": client_id, "names": names},
                )
                enabled_map = {r["mcp_name"]: r["enabled"] for r in prof.mappings().all()}
    except Exception as exc:
        logger.exception("list_available_mcps DB error for %s", client_id)
        return {"type": "text", "text": f"Error fetching server catalog: {exc}"}
    catalog = [
        {
            "tool_name": r["name"],
            "description": r["description"] or "",
            "status": r["status"] or "unknown",
            "risk_level": r["risk_level"] or "unknown",
            # Absence of an mcp_profiles row means "no explicit restriction"
            # platform-wide (see _lookup_profile_row) — enforcement treats that
            # as enabled. Defaulting the display to False here previously lied:
            # the catalog said disabled while an actual call would go through.
            "enabled_for_your_profile": enabled_map.get(r["name"], True),
        }
        for r in rows
    ]
    return {"type": "text", "text": json.dumps({"tools": catalog, "total": len(catalog)}, indent=2)}


async def _handle_get_my_profile(args: dict, request: Request) -> dict:
    principal: str = getattr(request.state, "client_id", "")
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text(
                    "SELECT mcp_name, enabled, allowed_functions "
                    "FROM mcp_profiles WHERE profile_id = :pid ORDER BY mcp_name"
                ),
                {"pid": principal},
            )
            rows = result.mappings().all()
    except Exception as exc:
        logger.exception("get_my_profile DB error for %s", principal)
        return {"type": "text", "text": f"Error fetching profile: {exc}"}
    mcps = []
    for row in rows:
        fns_raw = row["allowed_functions"]
        fn_list = []
        if fns_raw:
            try:
                fn_list = json.loads(fns_raw) if isinstance(fns_raw, str) else (fns_raw or [])
            except Exception:
                pass
        mcps.append({
            "server_name": row["mcp_name"],
            "enabled": bool(row["enabled"]),
            "allowed_functions": fn_list or None,
        })
    return {
        "type": "text",
        "text": json.dumps({"principal": principal, "mcps": mcps}, indent=2),
    }


async def _handle_enable_mcp_server(args: dict, request: Request) -> dict:
    principal: str = getattr(request.state, "client_id", "")
    server_name: str = args.get("server_name", "").strip()
    if not server_name:
        return {"type": "text", "text": "Error: server_name is required"}
    from app.routers.profiles import _assert_mcp_exists, _get_profile_row, _upsert_profile_row, _invalidate_profile_cache
    from fastapi import HTTPException
    try:
        await _assert_mcp_exists(server_name)
    except HTTPException as exc:
        return {"type": "text", "text": f"Error: {exc.detail}"}
    except Exception as exc:
        return {"type": "text", "text": f"Error validating server: {exc}"}
    try:
        row = await _get_profile_row(principal, server_name)
        allowed_fns = row["allowed_functions"] if row else None
        await _upsert_profile_row(principal, server_name, True, allowed_fns, principal)
        await _invalidate_profile_cache(principal, server_name, {"enabled": True, "allowed_functions": allowed_fns})
    except Exception as exc:
        logger.exception("enable_mcp_server error for %s/%s", principal, server_name)
        return {"type": "text", "text": f"Error enabling server: {exc}"}
    return {
        "type": "text",
        "text": json.dumps({
            "ok": True,
            "server_name": server_name,
            "enabled": True,
            "message": f"'{server_name}' is now enabled for your profile.",
        }, indent=2),
    }


async def _handle_disable_mcp_server(args: dict, request: Request) -> dict:
    principal: str = getattr(request.state, "client_id", "")
    server_name: str = args.get("server_name", "").strip()
    if not server_name:
        return {"type": "text", "text": "Error: server_name is required"}
    from app.routers.profiles import _assert_mcp_exists, _get_profile_row, _upsert_profile_row, _invalidate_profile_cache
    from fastapi import HTTPException
    try:
        await _assert_mcp_exists(server_name)
    except HTTPException as exc:
        return {"type": "text", "text": f"Error: {exc.detail}"}
    except Exception as exc:
        return {"type": "text", "text": f"Error validating server: {exc}"}
    try:
        row = await _get_profile_row(principal, server_name)
        allowed_fns = row["allowed_functions"] if row else None
        await _upsert_profile_row(principal, server_name, False, allowed_fns, principal)
        await _invalidate_profile_cache(principal, server_name, {"enabled": False, "allowed_functions": allowed_fns})
    except Exception as exc:
        logger.exception("disable_mcp_server error for %s/%s", principal, server_name)
        return {"type": "text", "text": f"Error disabling server: {exc}"}
    return {
        "type": "text",
        "text": json.dumps({
            "ok": True,
            "server_name": server_name,
            "enabled": False,
            "message": f"'{server_name}' is now disabled for your profile.",
        }, indent=2),
    }


_TOOL_HANDLERS = {
    "platform_info": _handle_platform_info,
    "security_pulse_summary": _handle_security_pulse_summary,
    "enrollment_status": _handle_enrollment_status,
    "list_registered_tools": _handle_list_registered_tools,
    "invoke_tool": _handle_invoke_tool_real,
    "list_available_mcps": _handle_list_available_mcps,
    "get_my_profile": _handle_get_my_profile,
    "enable_mcp_server": _handle_enable_mcp_server,
    "disable_mcp_server": _handle_disable_mcp_server,
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
        from app.services.invocation import ProfileLookupError
        platform_tools = _visible_tools(roles)
        principal_id: str | None = getattr(request.state, "principal_id", None)
        principal_type: str | None = getattr(request.state, "principal_type", None)
        try:
            registry_tools = await _registered_tools_for_client(
                client_id=client_id,
                roles=roles,
                principal_id=principal_id,
                principal_type=principal_type,
                # Task 4.3: named profile UUID — filters tools by profile_mcp_bindings.
                profile_uuid=getattr(request.state, "profile_uuid", None),
            )
        except ProfileLookupError:
            # INV-015: DB error + cache miss on profile lookup → fail-closed 503.
            # Raise _ProfileLookupUnavailable so mcp_post returns HTTP 503.
            logger.error(
                "tools/list profile lookup unavailable client=%s — returning 503",
                client_id,
            )
            raise _ProfileLookupUnavailable(
                _err(req_id, -32603, "Profile lookup unavailable — service degraded")
            )
        tools = platform_tools + registry_tools
        logger.info(
            "MCP tools/list client=%s roles=%s visible=%d (platform=%d registry=%d)",
            client_id, roles, len(tools), len(platform_tools), len(registry_tools),
        )
        return _ok(req_id, {"tools": tools})

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments") or {}

        # PRIVESC-004 fix: if the name matches a platform meta-tool but the caller
        # lacks the required role, return 403 instead of falling through to the
        # registry. Falling through would allow an admin to shadow-register a tool
        # with the same name as a platform meta-tool and have low-priv callers reach
        # it by bypassing _roles.  Uses the module-level _PLATFORM_NAMES frozenset
        # (computed at import time) rather than rebuilding per request.
        if name in _PLATFORM_NAMES and not _can_call(name, roles):
            return _err(req_id, -32003, "Authorization denied")

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

        from app.services.invocation import AuditEmissionError
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
            from app.services.trust_labeler import get_labeler as _get_labeler, build_envelope_result as _build_envelope_result
            _platform_payload = _build_envelope_result(
                content=[content],
                labeler=_get_labeler(),
                tool_name=name,
                server_id="__platform__",
                result_id=_effective_request_id,
                trust_tier=4,
                sensitivity_label="low",
            )
            # T1(b): close the invoke_tool observation blind spot — this wrapper
            # signs an envelope like the direct-dispatch path (~line 979) but
            # never observed it. Advisory-only here (no enforcement branch):
            # invoke_tool's own downstream pipeline already applies its own
            # entitlement/quarantine/policy gates before reaching this point.
            from app.core.config import get_settings as _gs2
            if _gs2().TRUST_OBSERVER_ENABLED:
                from app.services.trust_observer import observe_result as _observe2
                from app.services.trust_verifier import get_verifier as _get_verifier2
                _observe2(
                    _platform_payload,
                    verifier=_get_verifier2(),
                    tool_name=name,
                    server_id="__platform__",
                    result_id=_effective_request_id,
                )
            return _ok(req_id, _platform_payload)
        except AuditEmissionError:
            # INV-001 (SR-2): an audit-emission failure on the meta-tool ALLOW
            # path must fail-closed (propagate → AuditMiddleware HTTP 500), never
            # be swallowed into a JSON-RPC tool-execution error. The meta-tools
            # are read-only, so a post-execution 500 has no side effect to undo.
            raise
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
    from app.core.config import get_settings, get_rate_limit_for_roles
    from app.services.limits import get_rate_limit
    _roles = getattr(request.state, "client_roles", [])
    _role_default = get_rate_limit_for_roles(_roles, get_settings())
    _limit = await get_rate_limit(rl_key_id, role_default=_role_default)
    allowed = await _check_rate_limit(rl_key_id, limit=_limit)
    if not allowed:
        return JSONResponse(
            {"error": {"code": "RATE_LIMITED", "message": "Too many requests"}},
            status_code=429,
        )

    # Single message
    if isinstance(body, dict):
        try:
            result = await _dispatch(body, request)
        except _ProfileLookupUnavailable as _plu:
            # INV-015: profile lookup fail-closed — DB error + cache miss → 503.
            return JSONResponse(_plu.rpc_error, status_code=503)
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
        try:
            responses = await asyncio.gather(*[_dispatch(msg, request) for msg in tagged])
        except _ProfileLookupUnavailable as _plu:
            # INV-015: profile lookup fail-closed — one batch message triggered 503.
            return JSONResponse(_plu.rpc_error, status_code=503)
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
