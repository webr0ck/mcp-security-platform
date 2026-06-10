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
POST /api/v1/admin/servers/{id}/approve — approve a pending server (platform_admin + owner consent token)

POST /api/v1/servers/{id}/consent     — mint owner consent token (server_owner or platform_admin)
GET /api/v1/servers                   — list approved servers visible to authenticated caller (any role)

Consent flow (D3 dual-control):
  1. Server owner calls POST /api/v1/servers/{id}/consent → receives a single-use consent_token (15 min TTL)
  2. Platform admin calls POST /api/v1/admin/servers/{id}/approve with {"consent_token": "<token>"}
     The handler: verifies HMAC signature + server binding, consumes the token (marks jti used),
     then commits the approval — all in a single transaction.
  Without both steps, the approve handler returns 409 owner_consent_required.
"""
from __future__ import annotations

import datetime
import hashlib
import logging
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.services.consent import (
    ConsentTokenAlreadyConsumedError,
    ConsentTokenError,
    consume_consent_token,
    issue_approve_consent_token,
    persist_consent_token,
    verify_approve_consent_token,
)
from app.services.ssrf import SSRFError, validate_server_url
from app.credential_broker.adapters.healthcheck import get_healthcheck, HealthcheckFailed

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


class ConsentRequest(BaseModel):
    """Request body for POST /api/v1/servers/{id}/consent — mint a single-use approval token."""
    action: str = "approve"

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in {"approve"}:
            raise ValueError("action must be 'approve'")
        return v


class ApproveBody(BaseModel):
    """Request body for POST /api/v1/admin/servers/{id}/approve — requires owner consent token."""
    consent_token: str


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


@router.delete("/api/v1/admin/servers/{server_id}", status_code=204, response_class=Response)
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


@router.post("/api/v1/servers/{server_id}/consent", status_code=201)
async def mint_consent_token(server_id: str, body: ConsentRequest, request: Request):
    """
    Mint a single-use consent token for the 'approve' action (D3 dual-control).

    The server owner calls this endpoint to produce a token, which the platform admin
    then passes to POST /api/v1/admin/servers/{id}/approve as {"consent_token": "<token>"}.

    Roles: server_owner or platform_admin.
    The owner_sub bound into the token is the authenticated caller's client_id.
    """
    caller_roles = getattr(request.state, "client_roles", [])
    _allowed = {"server_owner", "platform_admin", "admin"}
    if not any(r in _allowed for r in caller_roles):
        raise HTTPException(status_code=403, detail="server_owner or platform_admin role required")

    owner_sub = getattr(request.state, "client_id", "unknown")

    # Verify the server exists and hasn't been deleted
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            text("SELECT server_id, status FROM server_registry WHERE server_id = :id AND deleted_at IS NULL"),
            {"id": server_id},
        )
        record = row.fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if record.status != "pending":
        raise HTTPException(status_code=409, detail=f"Server is not pending approval (status={record.status})")

    token_str, jti = issue_approve_consent_token(
        server_id=server_id,
        owner_sub=owner_sub,
        ttl_seconds=900,  # 15 minutes
    )

    # Persist the jti so consume_consent_token() can mark it used on first verification.
    # Without this, consume_consent_token() silently no-ops and replay is possible.
    payload_hash = hashlib.sha256(token_str.encode()).hexdigest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=900)
    await persist_consent_token(
        jti=jti,
        server_id=server_id,
        old_mode="__approve_pending__",
        new_mode="__approve_approved__",
        owner_sub=owner_sub,
        payload_hash=payload_hash,
        expires_at=expires_at,
    )

    logger.info(
        "consent_token_issued server_id=%s jti=%s owner_sub=%s action=approve",
        server_id, jti, owner_sub,
    )
    return JSONResponse(
        {"consent_token": token_str, "jti": jti, "expires_in_seconds": 900},
        status_code=201,
    )


@router.post("/api/v1/admin/servers/{server_id}/approve")
async def approve_server(server_id: str, body: ApproveBody, request: Request):
    """
    Approve a pending server (D3 dual-control).

    Requires a valid, single-use consent token minted by the server owner via
    POST /api/v1/servers/{id}/consent.

    The token is verified AND consumed atomically before the state change commits.
    If consume_consent_token returns False (already consumed or never persisted),
    the request is rejected with 409 — this prevents replay within the 15-minute window.
    """
    _require_platform_admin(request)
    approver = getattr(request.state, "client_id", "unknown")

    # D1 SSRF allowlist: validate the upstream URL before approval
    async with AsyncSessionLocal() as db:
        url_row = await db.execute(
            text(
                "SELECT upstream_url, owner_sub, adapter_name FROM server_registry "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        url_record = url_row.fetchone()
    if url_record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    try:
        validate_server_url(url_record[0])
    except SSRFError as exc:
        raise HTTPException(status_code=422, detail=f"SSRF validation failed: {exc}") from exc

    owner_sub = url_record[1]
    adapter_name = url_record[2]

    # Task 6: Adapter healthcheck at approval
    # Verify the upstream server is reachable before marking as approved.
    # If the server has an adapter_name, validate it's healthy via healthcheck.
    if adapter_name:
        try:
            healthcheck_adapter = get_healthcheck(adapter_name, url_record[0])
            await healthcheck_adapter.healthcheck()
        except HealthcheckFailed as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Healthcheck failed: {exc}",
            ) from exc

    # D3 dual-control: verify the consent token before committing the state change.
    # verify_approve_consent_token raises ConsentTokenError subclasses on any failure.
    try:
        consent_payload = verify_approve_consent_token(
            token=body.consent_token,
            expected_server_id=server_id,
            expected_owner_sub=owner_sub,
        )
    except ConsentTokenError as exc:
        raise HTTPException(status_code=409, detail=f"owner_consent_required: {exc}") from exc

    # consume_consent_token returns False if already consumed (replay) or never persisted.
    # Treat False as a hard reject — never allow-through on ambiguous consent state.
    consumed = await consume_consent_token(consent_payload.jti)
    if not consumed:
        raise HTTPException(
            status_code=409,
            detail="owner_consent_required: consent token already used or invalid",
        )

    # Both verify and consume succeeded — commit the approval.
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "UPDATE server_registry "
                "SET status = 'approved', mode_locked_at_approval = TRUE, "
                "    approved_at = now(), approved_by = :approver, url_allowlist_checked = TRUE, "
                "    consent_jti = :consent_jti "
                "WHERE server_id = :id AND deleted_at IS NULL AND status = 'pending' "
                "RETURNING server_id"
            ),
            {"id": server_id, "approver": approver, "consent_jti": consent_payload.jti},
        )
        await db.commit()
        rows_updated = result.rowcount
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found or not in pending state")

    logger.info(
        "server_approved server_id=%s approver=%s consent_jti=%s",
        server_id, approver, consent_payload.jti,
    )
    return JSONResponse({
        "server_id": server_id,
        "status": "approved",
        "approved_by": approver,
        "consent_jti": consent_payload.jti,
    })


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
