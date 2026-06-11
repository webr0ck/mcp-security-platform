"""
MCP Security Platform — Profile CRUD Router (Task 4.2)

Exposes per-identity MCP profile management as a core proxy REST API.
Ported from lab/mcp-servers/self-service/server.py — identity comes from
request.state (auth middleware), NOT from X-User-* headers.

Routes:
  GET    /api/v1/profiles/{principal}/mcps/{mcp_name}         — get profile row
  PUT    /api/v1/profiles/{principal}/mcps/{mcp_name}         — upsert profile row
  POST   /api/v1/profiles/{principal}/mcps/{mcp_name}/enable  — enable MCP
  POST   /api/v1/profiles/{principal}/mcps/{mcp_name}/disable — disable MCP
  POST   /api/v1/profiles/{principal}/mcps/{mcp_name}/functions/{fn}/enable  — enable function
  POST   /api/v1/profiles/{principal}/mcps/{mcp_name}/functions/{fn}/disable — disable function

Authorization:
  - Self-service: any authenticated principal may manage their own profile
    (principal path param == caller's client_id).
  - Cross-profile admin: only callers whose roles include "admin" or "platform_admin"
    may manage another principal's profile.

Cache invalidation (Task 1.10):
  Every profile mutation invalidates/updates the Redis key:
    mcp_profile:{principal}:{mcp_name}
  used by _lookup_profile_with_cache in invocation.py, so a disable cannot
  be ignored for the full cache TTL.

INV-001: profile mutations emit an append-only mcp_profile_events row.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/profiles", tags=["Profiles"])

# Roles that can manage other principals' profiles
_ADMIN_ROLES = frozenset({"admin", "platform_admin"})

# Cache sentinel — must match the value in invocation.py
_SENTINEL_NO_ROW = "__NO_PROFILE_ROW__"

# Cache TTL (seconds) — must match _PROFILE_CACHE_TTL_SECONDS in invocation.py
_PROFILE_CACHE_TTL_SECONDS = 300


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ProfileUpsertBody(BaseModel):
    enabled: bool
    allowed_functions: list[str] | None = None

    @field_validator("allowed_functions")
    @classmethod
    def _no_empty_strings(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and any(not fn.strip() for fn in v):
            raise ValueError("allowed_functions entries must not be blank")
        return v


# ---------------------------------------------------------------------------
# Authorization helper
# ---------------------------------------------------------------------------

def _assert_may_write(request: Request, principal: str) -> None:
    """
    Raise HTTP 403 if the caller may not modify *principal*'s profile.

    Self-service: caller's client_id == principal → allowed for any role.
    Cross-profile: caller must have an admin role.
    """
    caller_id: str = getattr(request.state, "client_id", "") or ""
    if not caller_id:
        raise HTTPException(status_code=401, detail="Caller identity not resolved")
    if caller_id == principal:
        return  # self-service always allowed
    caller_roles: list[str] = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in _ADMIN_ROLES for r in caller_roles):
        raise HTTPException(
            status_code=403,
            detail="Admin role required to manage another principal's profile",
        )


def _assert_may_read(request: Request, principal: str) -> None:
    """
    Raise HTTP 403 if the caller may not read *principal*'s profile.

    Self-service read is allowed. Admin/auditor may read any profile.
    """
    caller_id: str = getattr(request.state, "client_id", "") or ""
    if not caller_id:
        raise HTTPException(status_code=401, detail="Caller identity not resolved")
    if caller_id == principal:
        return
    caller_roles: list[str] = list(getattr(request.state, "client_roles", []) or [])
    if not any(r in _ADMIN_ROLES | {"auditor"} for r in caller_roles):
        raise HTTPException(
            status_code=403,
            detail="Admin or auditor role required to read another principal's profile",
        )


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

async def _get_profile_row(principal: str, mcp_name: str) -> dict | None:
    """Return {enabled, allowed_functions} or None if no row exists."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "SELECT enabled, allowed_functions "
                "FROM mcp_profiles WHERE profile_id=:pid AND mcp_name=:mname LIMIT 1"
            ),
            {"pid": principal, "mname": mcp_name},
        )
        row = result.mappings().first()
    if row is None:
        return None
    return {"enabled": row["enabled"], "allowed_functions": row["allowed_functions"]}


async def _assert_mcp_exists(mcp_name: str) -> None:
    """Raise HTTP 404 if the MCP name is not in tool_registry."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text("SELECT 1 FROM tool_registry WHERE name=:n AND deleted_at IS NULL LIMIT 1"),
            {"n": mcp_name},
        )
        if result.fetchone() is None:
            raise HTTPException(status_code=404, detail=f"MCP '{mcp_name}' not found in registry")


async def _upsert_profile_row(
    principal: str,
    mcp_name: str,
    enabled: bool,
    allowed_functions: list | None,
    changed_by: str,
) -> None:
    """Insert or update an mcp_profiles row."""
    af_json = json.dumps(allowed_functions) if allowed_functions is not None else None
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                """
                INSERT INTO mcp_profiles
                    (profile_id, mcp_name, enabled, allowed_functions, updated_by, updated_at)
                VALUES (:pid, :mname, :enabled, :af::jsonb, :changed_by, now())
                ON CONFLICT (profile_id, mcp_name) DO UPDATE SET
                    enabled           = EXCLUDED.enabled,
                    allowed_functions = EXCLUDED.allowed_functions,
                    updated_by        = EXCLUDED.updated_by,
                    updated_at        = now()
                """
            ),
            {
                "pid": principal,
                "mname": mcp_name,
                "enabled": enabled,
                "af": af_json,
                "changed_by": changed_by,
            },
        )
        await db.commit()


async def _emit_profile_event(
    principal: str,
    mcp_name: str,
    event_type: str,
    old_state: dict | None,
    new_state: dict | None,
    changed_by: str,
) -> None:
    """Append an immutable row to mcp_profile_events (audit trail)."""
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                """
                INSERT INTO mcp_profile_events
                    (profile_id, mcp_name, event_type, old_state, new_state, changed_by)
                VALUES (:pid, :mname, :etype, :old::jsonb, :new::jsonb, :by)
                """
            ),
            {
                "pid": principal,
                "mname": mcp_name,
                "etype": event_type,
                "old": json.dumps(old_state) if old_state is not None else None,
                "new": json.dumps(new_state) if new_state is not None else None,
                "by": changed_by,
            },
        )
        await db.commit()


# ---------------------------------------------------------------------------
# Cache invalidation — must call after every profile mutation
# ---------------------------------------------------------------------------

async def _invalidate_profile_cache(principal: str, mcp_name: str, new_value: dict | None) -> None:
    """
    Write the updated profile value into the Redis cache used by
    _lookup_profile_with_cache (invocation.py Task 1.10).

    Cache key: mcp_profile:{principal}:{mcp_name}

    If new_value is None → write the sentinel (no profile row = default allow).
    On Redis errors: log + continue (best-effort; fail-closed path is in invocation.py).
    """
    try:
        from app.core.redis_client import redis_pool
        redis = redis_pool.client
        cache_key = f"mcp_profile:{principal}:{mcp_name}"
        value = json.dumps(new_value) if new_value is not None else _SENTINEL_NO_ROW
        await redis.setex(cache_key, _PROFILE_CACHE_TTL_SECONDS, value)
        logger.debug(
            "Profile cache updated after mutation",
            extra={"principal": principal, "mcp_name": mcp_name},
        )
    except Exception as exc:
        logger.warning(
            "Failed to invalidate profile cache after mutation — "
            "invocation.py will use stale cache for up to TTL seconds",
            extra={"principal": principal, "mcp_name": mcp_name, "error": str(exc)},
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/{principal}/mcps/{mcp_name}")
async def get_profile_mcp(principal: str, mcp_name: str, request: Request) -> JSONResponse:
    """
    Get the profile row for (principal, mcp_name).

    Returns the stored {enabled, allowed_functions} or the default state if
    no explicit row exists (enabled=true, allowed_functions=null).

    RBAC: self-service for own profile; admin/auditor for others.
    """
    _assert_may_read(request, principal)

    row = await _get_profile_row(principal, mcp_name)
    if row is None:
        # No explicit profile row — return defaults
        return JSONResponse(
            {
                "principal": principal,
                "mcp_name": mcp_name,
                "enabled": True,
                "allowed_functions": None,
                "explicit_row": False,
            }
        )
    return JSONResponse(
        {
            "principal": principal,
            "mcp_name": mcp_name,
            "enabled": row["enabled"],
            "allowed_functions": row["allowed_functions"],
            "explicit_row": True,
        }
    )


@router.put("/{principal}/mcps/{mcp_name}")
async def upsert_profile_mcp(
    principal: str,
    mcp_name: str,
    body: ProfileUpsertBody,
    request: Request,
) -> JSONResponse:
    """
    Create or overwrite the profile row for (principal, mcp_name).

    Emits an MCP_PROFILE_SET event to mcp_profile_events.
    Invalidates/updates the Redis cache (Task 1.10).

    RBAC: self-service for own profile; admin for others.
    """
    _assert_may_write(request, principal)
    await _assert_mcp_exists(mcp_name)

    actor: str = getattr(request.state, "client_id", "unknown")
    old = await _get_profile_row(principal, mcp_name)

    await _upsert_profile_row(
        principal, mcp_name,
        enabled=body.enabled,
        allowed_functions=body.allowed_functions,
        changed_by=actor,
    )

    new_state = {"enabled": body.enabled, "allowed_functions": body.allowed_functions}
    await _emit_profile_event(
        principal, mcp_name, "MCP_PROFILE_SET",
        old_state=old,
        new_state=new_state,
        changed_by=actor,
    )
    await _invalidate_profile_cache(principal, mcp_name, new_state)

    return JSONResponse(
        {
            "ok": True,
            "principal": principal,
            "mcp_name": mcp_name,
            "enabled": body.enabled,
            "allowed_functions": body.allowed_functions,
        }
    )


@router.post("/{principal}/mcps/{mcp_name}/enable")
async def enable_mcp(principal: str, mcp_name: str, request: Request) -> JSONResponse:
    """
    Enable an MCP server for a principal. Idempotent.

    Preserves existing allowed_functions restriction.
    Emits MCP_ENABLED event. Updates Redis cache.

    RBAC: self-service for own profile; admin for others.
    """
    _assert_may_write(request, principal)
    await _assert_mcp_exists(mcp_name)

    actor: str = getattr(request.state, "client_id", "unknown")
    old = await _get_profile_row(principal, mcp_name)

    await _upsert_profile_row(
        principal, mcp_name,
        enabled=True,
        allowed_functions=old["allowed_functions"] if old else None,
        changed_by=actor,
    )
    await _emit_profile_event(
        principal, mcp_name, "MCP_ENABLED",
        old_state=old,
        new_state={"enabled": True},
        changed_by=actor,
    )
    new_cache = {
        "enabled": True,
        "allowed_functions": old["allowed_functions"] if old else None,
    }
    await _invalidate_profile_cache(principal, mcp_name, new_cache)

    return JSONResponse(
        {"ok": True, "principal": principal, "mcp_name": mcp_name, "enabled": True}
    )


@router.post("/{principal}/mcps/{mcp_name}/disable")
async def disable_mcp(principal: str, mcp_name: str, request: Request) -> JSONResponse:
    """
    Disable an MCP server for a principal.

    Preserves existing allowed_functions restriction.
    Emits MCP_DISABLED event. Updates Redis cache.

    RBAC: self-service for own profile; admin for others.
    """
    _assert_may_write(request, principal)
    await _assert_mcp_exists(mcp_name)

    actor: str = getattr(request.state, "client_id", "unknown")
    old = await _get_profile_row(principal, mcp_name)

    await _upsert_profile_row(
        principal, mcp_name,
        enabled=False,
        allowed_functions=old["allowed_functions"] if old else None,
        changed_by=actor,
    )
    await _emit_profile_event(
        principal, mcp_name, "MCP_DISABLED",
        old_state=old,
        new_state={"enabled": False},
        changed_by=actor,
    )
    new_cache = {
        "enabled": False,
        "allowed_functions": old["allowed_functions"] if old else None,
    }
    await _invalidate_profile_cache(principal, mcp_name, new_cache)

    return JSONResponse(
        {"ok": True, "principal": principal, "mcp_name": mcp_name, "enabled": False}
    )


@router.post("/{principal}/mcps/{mcp_name}/functions/{fn_name}/enable")
async def enable_function(
    principal: str,
    mcp_name: str,
    fn_name: str,
    request: Request,
) -> JSONResponse:
    """
    Enable a specific function on an MCP server for a principal.

    If the profile is currently unrestricted (allowed_functions=null), this is
    a no-op (all functions are already allowed). To build a restricted list,
    first disable unwanted functions.

    Emits FUNCTION_ENABLED event. Updates Redis cache.

    RBAC: self-service for own profile; admin for others.
    """
    _assert_may_write(request, principal)
    await _assert_mcp_exists(mcp_name)

    actor: str = getattr(request.state, "client_id", "unknown")
    old = await _get_profile_row(principal, mcp_name)
    current_af: list | None = old["allowed_functions"] if old else None

    if current_af is None:
        # Already unrestricted — all functions allowed
        return JSONResponse(
            {
                "ok": True,
                "principal": principal,
                "mcp_name": mcp_name,
                "function_name": fn_name,
                "enabled": True,
                "note": "Profile is unrestricted — all functions already allowed",
            }
        )

    if fn_name in current_af:
        return JSONResponse(
            {
                "ok": True,
                "principal": principal,
                "mcp_name": mcp_name,
                "function_name": fn_name,
                "enabled": True,
                "note": "Function already enabled",
            }
        )

    new_af = sorted(set(current_af) | {fn_name})
    await _upsert_profile_row(
        principal, mcp_name,
        enabled=old["enabled"] if old else True,
        allowed_functions=new_af,
        changed_by=actor,
    )
    await _emit_profile_event(
        principal, mcp_name, "FUNCTION_ENABLED",
        old_state={"allowed_functions": current_af},
        new_state={"allowed_functions": new_af},
        changed_by=actor,
    )
    new_cache = {"enabled": old["enabled"] if old else True, "allowed_functions": new_af}
    await _invalidate_profile_cache(principal, mcp_name, new_cache)

    return JSONResponse(
        {
            "ok": True,
            "principal": principal,
            "mcp_name": mcp_name,
            "function_name": fn_name,
            "enabled": True,
            "allowed_functions": new_af,
        }
    )


@router.post("/{principal}/mcps/{mcp_name}/functions/{fn_name}/disable")
async def disable_function(
    principal: str,
    mcp_name: str,
    fn_name: str,
    request: Request,
) -> JSONResponse:
    """
    Disable a specific function on an MCP server for a principal.

    If the profile is currently unrestricted (allowed_functions=null), the function
    list is narrowed to exclude fn_name. Because the available function set is not
    known at this layer (no upstream call), the allowed_functions list is set to an
    empty list minus fn_name — the caller is expected to then enable the functions
    they want. This mirrors the lab server's semantics.

    Emits FUNCTION_DISABLED event. Updates Redis cache.

    RBAC: self-service for own profile; admin for others.
    """
    _assert_may_write(request, principal)
    await _assert_mcp_exists(mcp_name)

    actor: str = getattr(request.state, "client_id", "unknown")
    old = await _get_profile_row(principal, mcp_name)
    current_af: list | None = old["allowed_functions"] if old else None

    if current_af is not None and fn_name not in current_af:
        # Already not in the allowed set — already effectively disabled
        return JSONResponse(
            {
                "ok": True,
                "principal": principal,
                "mcp_name": mcp_name,
                "function_name": fn_name,
                "enabled": False,
                "note": "Function was not in allowed_functions — already effectively disabled",
                "allowed_functions": current_af,
            }
        )

    if current_af is None:
        # Unrestricted → start with an empty restriction list (function is now excluded)
        new_af: list = []
    else:
        new_af = sorted(set(current_af) - {fn_name})

    await _upsert_profile_row(
        principal, mcp_name,
        enabled=old["enabled"] if old else True,
        allowed_functions=new_af,
        changed_by=actor,
    )
    await _emit_profile_event(
        principal, mcp_name, "FUNCTION_DISABLED",
        old_state={"allowed_functions": current_af},
        new_state={"allowed_functions": new_af},
        changed_by=actor,
    )
    new_cache = {"enabled": old["enabled"] if old else True, "allowed_functions": new_af}
    await _invalidate_profile_cache(principal, mcp_name, new_cache)

    return JSONResponse(
        {
            "ok": True,
            "principal": principal,
            "mcp_name": mcp_name,
            "function_name": fn_name,
            "enabled": False,
            "allowed_functions": new_af,
        }
    )
