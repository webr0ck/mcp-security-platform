"""
MCP Security Platform — Entitlement CRUD Router

Manages per-server entitlements: which principals (human / agent / kc_group)
are allowed to invoke a given registered MCP server.

Routes:
  GET  /api/v1/servers/mine                           — servers where caller has a role grant
  GET  /api/v1/servers/{server_id}/entitlements       — list entitlement rows for a server
  POST /api/v1/servers/{server_id}/entitlements       — grant entitlement (idempotent re-grant)
  DELETE /api/v1/servers/{server_id}/entitlements/{ent_id} — soft-revoke an entitlement

Ownership model:
  - Ownership check: server_role_grant WHERE server_id=$id AND principal_id=$caller
    AND role IN ('server_owner', 'manager').
  - platform_admin (or the legacy 'admin' alias) always passes.
  - Any other role → 403.

INV-001: every mutation emits a synchronous audit event BEFORE responding.
         If the audit emit fails, return 500 — never silently skip.

Never hard-delete entitlements — soft-revoke only (revoked_at = now()).
"""
from __future__ import annotations

import datetime
import hashlib
import logging
from typing import Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.core.database import engine as _db_engine

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Entitlements"])

# Roles that can own/manage a server (server_role_grant.role values)
_OWNER_ROLES = frozenset({"server_owner", "manager"})
# Roles that always pass the ownership check
_PLATFORM_ADMIN_ROLES = frozenset({"platform_admin", "admin"})

_VALID_PRINCIPAL_TYPES = frozenset({"human", "agent", "kc_group"})


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class EntitlementGrantBody(BaseModel):
    principal_id: str
    principal_type: Literal["human", "agent", "kc_group"]

    @field_validator("principal_id")
    @classmethod
    def principal_id_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("principal_id must not be empty")
        return v.strip()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_row(d: dict) -> dict:
    """Convert datetime/UUID objects to JSON-safe representations."""
    out: dict = {}
    for k, v in d.items():
        if isinstance(v, (datetime.datetime, datetime.date)):
            out[k] = v.isoformat()
        elif v is None or isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


async def _require_server_owner(server_id: str, request: Request) -> None:
    """
    Raise HTTP 403 if the caller is not a platform_admin and does not hold
    a server_role_grant row for this server with role in ('server_owner', 'manager').

    Raises HTTP 404 if the server does not exist at all (prevents information
    leakage about servers the caller cannot see).
    """
    caller_roles: list[str] = getattr(request.state, "client_roles", [])

    # platform_admin always passes — check this first
    if any(r in _PLATFORM_ADMIN_ROLES for r in caller_roles):
        return

    caller_id: str = getattr(request.state, "client_id", "")
    if not caller_id:
        raise HTTPException(status_code=401, detail="Caller identity not resolved")

    # Verify server exists (return 403 not 404 to avoid leaking server existence to
    # callers who are missing the ownership grant — but we must still distinguish
    # "server does not exist" from "no grant"; 404 only if server is genuinely absent)
    async with AsyncSessionLocal() as db:
        srv_row = await db.execute(
            text(
                "SELECT 1 FROM server_registry WHERE server_id = :sid AND deleted_at IS NULL"
            ),
            {"sid": server_id},
        )
        if srv_row.fetchone() is None:
            raise HTTPException(status_code=404, detail="Server not found")

        grant_row = await db.execute(
            text(
                """
                SELECT 1 FROM server_role_grant
                WHERE server_id = :sid
                  AND principal_id = :caller
                  AND role IN ('server_owner', 'manager')
                LIMIT 1
                """
            ),
            {"sid": server_id, "caller": caller_id},
        )
        if grant_row.fetchone() is None:
            raise HTTPException(
                status_code=403,
                detail="You do not have owner or manager access to this server",
            )


async def _emit_entitlement_audit(
    *,
    event_type: str,
    server_id: str,
    entitlement_id: str,
    principal_id: str,
    principal_type: str,
    actor: str,
    request_id: str,
) -> None:
    """
    Emit a synchronous audit event for an entitlement mutation.

    INV-001: must be called BEFORE the response is returned.
    Raises RuntimeError on failure — caller must propagate as HTTP 500.

    audit_events has no event_type column; the event semantics are encoded
    in tool_name using the pattern 'entitlement:{event_type}:{server_id}'.
    sha256 is computed over a deterministic preimage for tamper-detection.
    """
    try:
        event_id = str(uuid4())
        ts = datetime.datetime.now(datetime.timezone.utc)
        # Preimage encodes all relevant fields — sha256_hash in audit_events
        # acts as a tamper-evident seal.
        sha256_hash = hashlib.sha256(
            f"{event_id}|{event_type}|{server_id}|{entitlement_id}"
            f"|{principal_id}|{principal_type}|{actor}|{ts.isoformat()}".encode()
        ).hexdigest()

        async with _db_engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO audit_events (
                        event_id, client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, :client_id, :tool_name,
                        'allow', :request_id, :sha256_hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "client_id": actor,
                    "tool_name": f"entitlement:{event_type}:{server_id}",
                    "request_id": request_id,
                    "sha256_hash": sha256_hash,
                },
            )
    except Exception as exc:
        logger.error(
            "Entitlement audit emission failed — INV-001 violation",
            extra={
                "event_type": event_type,
                "server_id": server_id,
                "entitlement_id": entitlement_id,
                "error": str(exc),
            },
        )
        raise RuntimeError(f"audit event emission failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/api/v1/servers/mine")
async def list_my_servers(request: Request):
    """
    List servers where the caller holds a server_role_grant row.

    Allowed roles: server_owner, manager, platform_admin (and legacy 'admin').
    """
    caller_id: str = getattr(request.state, "client_id", "")
    if not caller_id:
        raise HTTPException(status_code=401, detail="Caller identity not resolved")

    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                """
                SELECT
                    sr.server_id,
                    sr.name,
                    sr.status,
                    srg.role
                FROM server_registry sr
                JOIN server_role_grant srg
                    ON srg.server_id = sr.server_id
                WHERE srg.principal_id = :caller
                  AND sr.deleted_at IS NULL
                ORDER BY sr.name
                """
            ),
            {"caller": caller_id},
        )
        servers = [_serialize_row(dict(r._mapping)) for r in rows]

    return JSONResponse({"servers": servers, "count": len(servers)})


@router.get("/api/v1/servers/{server_id}/entitlements")
async def list_server_entitlements(server_id: str, request: Request):
    """
    List all entitlement rows for a server (including revoked).

    Allowed: owner-of-{server_id}, platform_admin.
    """
    await _require_server_owner(server_id, request)

    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                """
                SELECT
                    entitlement_id AS ent_id,
                    principal_id,
                    principal_type,
                    granted_by,
                    created_at AS granted_at,
                    revoked_at
                FROM entitlement
                WHERE server_id = :sid
                ORDER BY created_at DESC
                """
            ),
            {"sid": server_id},
        )
        entitlements = [_serialize_row(dict(r._mapping)) for r in rows]

    return JSONResponse({"server_id": server_id, "entitlements": entitlements})


@router.post("/api/v1/servers/{server_id}/entitlements")
async def grant_entitlement(
    server_id: str,
    body: EntitlementGrantBody,
    request: Request,
):
    """
    Grant an entitlement on a server to a principal.

    Idempotent:
    - If an active entitlement already exists: return 200 with the existing row.
      Still audit-log the attempted re-grant.
    - If a revoked entitlement exists: clear revoked_at (un-revoke) and return 200.
      Emit an entitlement_granted audit event.
    - If no row exists: INSERT and return 201. Emit entitlement_granted audit.

    Allowed: owner-of-{server_id}, platform_admin.
    INV-001: audit BEFORE response.
    """
    await _require_server_owner(server_id, request)

    actor: str = getattr(request.state, "client_id", "unknown")
    request_id: str = getattr(request.state, "request_id", "unknown")

    async with AsyncSessionLocal() as db:
        # Check for existing row (unique on server_id, principal_id, principal_type)
        existing = await db.execute(
            text(
                """
                SELECT entitlement_id, revoked_at
                FROM entitlement
                WHERE server_id = :sid
                  AND principal_id = :pid
                  AND principal_type = :ptype::principal_type_enum
                """
            ),
            {
                "sid": server_id,
                "pid": body.principal_id,
                "ptype": body.principal_type,
            },
        )
        row = existing.fetchone()

        if row is not None:
            ent_id = str(row.entitlement_id)
            is_revoked = row.revoked_at is not None

            if is_revoked:
                # Un-revoke: clear revoked_at
                await db.execute(
                    text(
                        """
                        UPDATE entitlement
                        SET revoked_at = NULL
                        WHERE entitlement_id = :eid
                        """
                    ),
                    {"eid": ent_id},
                )
                # INV-001: emit audit BEFORE committing so that if audit fails
                # the UPDATE is not yet durable and rolls back automatically.
                try:
                    await _emit_entitlement_audit(
                        event_type="entitlement_granted",
                        server_id=server_id,
                        entitlement_id=ent_id,
                        principal_id=body.principal_id,
                        principal_type=body.principal_type,
                        actor=actor,
                        request_id=request_id,
                    )
                except RuntimeError as exc:
                    raise HTTPException(status_code=500, detail=str(exc)) from exc
                await db.commit()
            else:
                # Already active: no DB mutation, but still audit the re-grant attempt.
                # INV-001: audit before returning the response.
                try:
                    await _emit_entitlement_audit(
                        event_type="entitlement_granted",
                        server_id=server_id,
                        entitlement_id=ent_id,
                        principal_id=body.principal_id,
                        principal_type=body.principal_type,
                        actor=actor,
                        request_id=request_id,
                    )
                except RuntimeError as exc:
                    raise HTTPException(status_code=500, detail=str(exc)) from exc

            # Fetch the current row state to return
            result = await db.execute(
                text(
                    """
                    SELECT
                        entitlement_id AS ent_id,
                        principal_id,
                        principal_type,
                        granted_by,
                        created_at AS granted_at,
                        revoked_at
                    FROM entitlement
                    WHERE entitlement_id = :eid
                    """
                ),
                {"eid": ent_id},
            )
            record = result.mappings().fetchone()
            return JSONResponse(
                _serialize_row(dict(record)),
                status_code=200,
            )

        # No existing row — INSERT new entitlement
        result = await db.execute(
            text(
                """
                INSERT INTO entitlement (server_id, principal_id, principal_type, granted_by)
                VALUES (
                    :sid,
                    :pid,
                    :ptype::principal_type_enum,
                    :granted_by
                )
                RETURNING
                    entitlement_id AS ent_id,
                    principal_id,
                    principal_type,
                    granted_by,
                    created_at AS granted_at,
                    revoked_at
                """
            ),
            {
                "sid": server_id,
                "pid": body.principal_id,
                "ptype": body.principal_type,
                "granted_by": actor,
            },
        )
        new_row = result.mappings().fetchone()
        ent_id = str(new_row["ent_id"])

        # INV-001: emit audit BEFORE committing so that if audit fails the
        # INSERT is not yet durable and rolls back automatically.
        try:
            await _emit_entitlement_audit(
                event_type="entitlement_granted",
                server_id=server_id,
                entitlement_id=ent_id,
                principal_id=body.principal_id,
                principal_type=body.principal_type,
                actor=actor,
                request_id=request_id,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        await db.commit()
        return JSONResponse(_serialize_row(dict(new_row)), status_code=201)


@router.delete("/api/v1/servers/{server_id}/entitlements/{ent_id}")
async def revoke_entitlement(
    server_id: str,
    ent_id: str,
    request: Request,
):
    """
    Soft-revoke an entitlement. Sets revoked_at = now(). Never hard-deletes.

    Allowed: owner-of-{server_id}, platform_admin.
    INV-001: audit BEFORE response.
    Returns 404 if the entitlement does not belong to this server or is already revoked.
    """
    await _require_server_owner(server_id, request)

    actor: str = getattr(request.state, "client_id", "unknown")
    request_id: str = getattr(request.state, "request_id", "unknown")

    async with AsyncSessionLocal() as db:
        # Only revoke active (non-revoked) entitlements on this server
        result = await db.execute(
            text(
                """
                UPDATE entitlement
                SET revoked_at = now()
                WHERE entitlement_id = :eid
                  AND server_id = :sid
                  AND revoked_at IS NULL
                RETURNING entitlement_id, principal_id, principal_type, revoked_at
                """
            ),
            {"eid": ent_id, "sid": server_id},
        )
        updated = result.fetchone()

        if updated is None:
            raise HTTPException(
                status_code=404,
                detail="Entitlement not found, already revoked, or does not belong to this server",
            )

        # INV-001: emit audit BEFORE committing so that if audit fails the
        # UPDATE is not yet durable and rolls back automatically.
        try:
            await _emit_entitlement_audit(
                event_type="entitlement_revoked",
                server_id=server_id,
                entitlement_id=str(updated.entitlement_id),
                principal_id=str(updated.principal_id),
                principal_type=str(updated.principal_type),
                actor=actor,
                request_id=request_id,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        await db.commit()

    return JSONResponse(
        {
            "ent_id": str(updated.entitlement_id),
            "revoked_at": updated.revoked_at.isoformat() if updated.revoked_at else None,
        }
    )
