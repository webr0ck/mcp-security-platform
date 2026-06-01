"""
MCP Security Platform — Server Registry Router

CRUD endpoints for the server_registry table.
Platform admins register and approve MCP server endpoints.
Approval locks the injection_mode and records the owner.

GET  /api/v1/admin/servers            — list all servers (platform_admin)
POST /api/v1/admin/servers            — register a new server (platform_admin)
GET  /api/v1/admin/servers/{id}       — get a server (platform_admin)
PATCH /api/v1/admin/servers/{id}      — update server metadata (platform_admin)
DELETE /api/v1/admin/servers/{id}     — soft-delete (platform_admin; sets deleted_at, status→suspended)
POST /api/v1/admin/servers/{id}/approve — approve a pending server (platform_admin)

GET /api/v1/servers                   — list approved servers visible to authenticated caller (any role)
"""
from __future__ import annotations

import datetime
import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.services.ssrf import SSRFError, validate_server_url

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = frozenset({"admin", "platform_admin"})
_PATCH_ALLOWED = frozenset({"name", "upstream_url", "service_name"})


def _require_platform_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="platform_admin role required")


class ServerCreate(BaseModel):
    name: str
    upstream_url: str
    injection_mode: str = "none"
    service_name: Optional[str] = None
    owner_sub: Optional[str] = None  # defaults to request.state.client_id

    @field_validator("injection_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid = {"none", "service", "user", "service_account", "oauth_user_token"}
        if v not in valid:
            raise ValueError(f"injection_mode must be one of {valid}")
        return v


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    service_name: Optional[str] = None


def _serialize(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, (datetime.datetime, datetime.date)):
            out[k] = v.isoformat()
        elif v is None or isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


@router.get("/api/v1/admin/servers")
async def list_servers(request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                "SELECT server_id, name, upstream_url, status, owner_sub, "
                "injection_mode, created_at, approved_at "
                "FROM server_registry WHERE deleted_at IS NULL ORDER BY created_at DESC"
            )
        )
        servers = [_serialize(dict(r._mapping)) for r in rows]
    return JSONResponse({"servers": servers})


@router.post("/api/v1/admin/servers", status_code=201)
async def create_server(body: ServerCreate, request: Request):
    _require_platform_admin(request)
    # Always attribute ownership to the authenticated requester, not the submitted value
    effective_owner_sub = getattr(request.state, "client_id", "unknown")
    owner = effective_owner_sub
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "INSERT INTO server_registry "
                "(name, upstream_url, injection_mode, service_name, owner_sub, status) "
                "VALUES (:name, :url, :mode::injection_mode_enum, :svc, :owner, 'pending') "
                "RETURNING server_id, name, status, created_at"
            ),
            {"name": body.name, "url": body.upstream_url, "mode": body.injection_mode,
             "svc": body.service_name, "owner": owner},
        )
        await db.commit()
        row = result.fetchone()
    return JSONResponse(
        {"server_id": str(row.server_id), "name": row.name, "status": row.status},
        status_code=201,
    )


@router.get("/api/v1/admin/servers/{server_id}")
async def get_server(server_id: str, request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            text("SELECT * FROM server_registry WHERE server_id = :id AND deleted_at IS NULL"),
            {"id": server_id},
        )
        record = row.mappings().fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return JSONResponse(_serialize(dict(record)))


@router.patch("/api/v1/admin/servers/{server_id}")
async def update_server(server_id: str, body: ServerUpdate, request: Request):
    _require_platform_admin(request)
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    # Filter to allowed fields — injection_mode changes after approval require owner consent (Plan 7)
    updates = {k: v for k, v in updates.items() if k in _PATCH_ALLOWED}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    # SSRF guard: validate upstream_url changes the same way approve_server does (C4 fix).
    if "upstream_url" in updates:
        try:
            validate_server_url(updates["upstream_url"])
        except SSRFError as exc:
            raise HTTPException(status_code=422, detail=f"upstream_url blocked by SSRF policy: {exc}") from exc

    # Column names are interpolated — frozenset above is the ONLY guard.
    # Never add user-supplied strings to the allowlist.
    assert all(re.match(r'^[a-z_]+$', k) for k in updates), f"Unsafe column names: {updates.keys()}"
    set_clauses = ", ".join(f"{k} = :{k}" for k in updates)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                f"UPDATE server_registry SET {set_clauses} "
                "WHERE server_id = :server_id AND deleted_at IS NULL "
                "RETURNING server_id"
            ),
            {**updates, "server_id": server_id},
        )
        await db.commit()
        rows_updated = result.rowcount
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    return JSONResponse({"server_id": server_id, "updated": list(updates)})


@router.delete("/api/v1/admin/servers/{server_id}", status_code=204)
async def delete_server(server_id: str, request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        # Soft-delete: set deleted_at + suspend. Status 'deleted' is NOT a valid enum value.
        await db.execute(
            text(
                "UPDATE server_registry SET deleted_at = now(), status = 'suspended' "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        await db.commit()


@router.post("/api/v1/admin/servers/{server_id}/approve")
async def approve_server(server_id: str, request: Request):
    _require_platform_admin(request)
    approver = getattr(request.state, "client_id", "unknown")

    # D1 SSRF allowlist: validate the upstream URL before approval
    async with AsyncSessionLocal() as db:
        url_row = await db.execute(
            text("SELECT upstream_url FROM server_registry WHERE server_id = :id AND deleted_at IS NULL"),
            {"id": server_id},
        )
        url_record = url_row.fetchone()
    if url_record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    try:
        validate_server_url(url_record[0])
    except SSRFError as exc:
        raise HTTPException(status_code=422, detail=f"SSRF validation failed: {exc}") from exc

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "UPDATE server_registry "
                "SET status = 'approved', mode_locked_at_approval = TRUE, "
                "    approved_at = now(), approved_by = :approver, url_allowlist_checked = TRUE "
                "WHERE server_id = :id AND deleted_at IS NULL AND status = 'pending' "
                "RETURNING server_id"
            ),
            {"id": server_id, "approver": approver},
        )
        await db.commit()
        rows_updated = result.rowcount
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found or not in pending state")
    return JSONResponse({"server_id": server_id, "status": "approved"})


@router.get("/api/v1/servers")
async def list_approved_servers(request: Request):
    """List approved servers — visible to any authenticated caller."""
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                "SELECT server_id, name, upstream_url, injection_mode "
                "FROM server_registry "
                "WHERE status = 'approved' AND deleted_at IS NULL "
                "ORDER BY name"
            )
        )
        servers = [_serialize(dict(r._mapping)) for r in rows]
    return JSONResponse({"servers": servers})
