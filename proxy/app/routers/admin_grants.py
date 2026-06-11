"""
MCP Security Platform — Admin Grants API

Provides REST endpoints for managing client_grants (Task 4.4b — SELF-F6).
Grants are the per-client tool allowlists pushed to OPA via OPADataSync.

Endpoints:
  GET    /api/v1/admin/grants              — list all client grants (admin)
  POST   /api/v1/admin/grants              — create or replace a client grant (admin)
  DELETE /api/v1/admin/grants/{client_id}  — delete a client grant (admin)
  POST   /api/v1/admin/sync-grants         — on-demand OPA resync (admin)

All mutations call push_grants() before returning to keep OPA in sync.
Role requirement: admin or platform_admin.

INV-011: client_grants table has explicit GRANT/REVOKE (see V034__client_grants.sql).
INV-012: OPA receives grants at /mcp_grants (not bundle-owned — see .manifest).
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator

from app.services import opa_data_sync as opa_data_sync_svc
from app.services.policy import PolicyEngineError

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = frozenset({"admin", "platform_admin"})
_VALID_RISK_LEVELS = frozenset({"low", "medium", "high", "critical"})


def _require_admin(request: Request) -> None:
    """Enforce admin or platform_admin role. Raises 403 if not satisfied."""
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="admin or platform_admin role required")


class ClientGrantCreate(BaseModel):
    """Request body for POST /api/v1/admin/grants — create or replace a client grant."""

    client_id: str
    allowed_tools: list[str] = []
    allowed_tags: list[str] = []
    max_risk_level: str = "low"

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("client_id must be non-empty")
        if len(v) > 256:
            raise ValueError("client_id must be <= 256 characters")
        return v.strip()

    @field_validator("max_risk_level")
    @classmethod
    def validate_max_risk_level(cls, v: str) -> str:
        if v not in _VALID_RISK_LEVELS:
            raise ValueError(f"max_risk_level must be one of {sorted(_VALID_RISK_LEVELS)}")
        return v


async def _get_db_pool():
    """Get the asyncpg pool from the module-level singleton."""
    from app.core.asyncpg_pool import asyncpg_pool

    pool = asyncpg_pool.get()
    if pool is None:
        raise HTTPException(status_code=503, detail="Database pool not available")
    return pool


@router.get("/api/v1/admin/grants")
async def list_grants(request: Request) -> dict[str, Any]:
    """
    List all client grants.

    Returns: {"grants": [{"client_id": ..., "allowed_tools": ..., ...}]}
    Requires: admin or platform_admin role.
    """
    _require_admin(request)
    pool = await _get_db_pool()

    rows = await pool.fetch(
        """
        SELECT client_id, allowed_tools, allowed_tags, max_risk_level, granted_by,
               created_at, updated_at
        FROM client_grants
        ORDER BY client_id
        """
    )

    grants = [
        {
            "client_id": row["client_id"],
            "allowed_tools": list(row["allowed_tools"]),
            "allowed_tags": list(row["allowed_tags"]),
            "max_risk_level": row["max_risk_level"],
            "granted_by": row["granted_by"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
        }
        for row in rows
    ]

    return {"grants": grants, "count": len(grants)}


@router.post("/api/v1/admin/grants", status_code=201)
async def upsert_grant(body: ClientGrantCreate, request: Request) -> dict[str, Any]:
    """
    Create or replace a client grant.

    Upserts the grant row in client_grants, then immediately pushes all grants
    to OPA via OPADataSync (fail-closed: returns 503 if OPA push fails).

    Returns: {"client_id": ..., "status": "created" | "updated"}
    Requires: admin or platform_admin role.
    """
    _require_admin(request)
    pool = await _get_db_pool()
    caller = getattr(request.state, "client_id", "unknown-admin")

    # Upsert: insert or update if client_id already exists
    result = await pool.fetchrow(
        """
        INSERT INTO client_grants (client_id, allowed_tools, allowed_tags, max_risk_level, granted_by)
        VALUES ($1, $2::jsonb, $3::jsonb, $4, $5)
        ON CONFLICT (client_id) DO UPDATE SET
            allowed_tools  = EXCLUDED.allowed_tools,
            allowed_tags   = EXCLUDED.allowed_tags,
            max_risk_level = EXCLUDED.max_risk_level,
            granted_by     = EXCLUDED.granted_by,
            updated_at     = NOW()
        RETURNING client_id, (xmax = 0) AS is_insert
        """,
        body.client_id,
        body.allowed_tools,
        body.allowed_tags,
        body.max_risk_level,
        caller,
    )

    was_insert = result["is_insert"] if result else True

    # Sync to OPA immediately (fail-closed)
    sync = opa_data_sync_svc.opa_data_sync_instance
    if sync is None:
        logger.warning(
            "OPA data sync not initialized — grant saved to DB but OPA not synced",
            extra={"client_id": body.client_id},
        )
    else:
        try:
            await sync.push_grants()
        except PolicyEngineError as exc:
            logger.error(
                "OPA sync failed after grant upsert — returning 503",
                extra={"client_id": body.client_id, "error": str(exc)},
            )
            raise HTTPException(
                status_code=503,
                detail="Grant saved but OPA sync failed — retry after OPA recovers",
            ) from exc

    logger.info(
        "Client grant upserted",
        extra={
            "client_id": body.client_id,
            "action": "created" if was_insert else "updated",
            "granted_by": caller,
        },
    )

    return {
        "client_id": body.client_id,
        "status": "created" if was_insert else "updated",
    }


@router.delete("/api/v1/admin/grants/{client_id}", status_code=200)
async def delete_grant(client_id: str, request: Request) -> dict[str, Any]:
    """
    Delete a client grant.

    Removes the grant row from client_grants, then immediately pushes all grants
    to OPA via OPADataSync (fail-closed: returns 503 if OPA push fails).

    Returns: {"client_id": ..., "status": "deleted" | "not_found"}
    Requires: admin or platform_admin role.
    """
    _require_admin(request)
    pool = await _get_db_pool()

    result = await pool.execute(
        "DELETE FROM client_grants WHERE client_id = $1",
        client_id,
    )
    # asyncpg returns "DELETE N" where N is the count of deleted rows
    deleted_count = int(result.split()[-1]) if result else 0

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Grant for '{client_id}' not found")

    # Sync to OPA immediately (fail-closed)
    sync = opa_data_sync_svc.opa_data_sync_instance
    if sync is None:
        logger.warning(
            "OPA data sync not initialized — grant deleted from DB but OPA not synced",
            extra={"client_id": client_id},
        )
    else:
        try:
            await sync.push_grants()
        except PolicyEngineError as exc:
            logger.error(
                "OPA sync failed after grant delete — returning 503",
                extra={"client_id": client_id, "error": str(exc)},
            )
            raise HTTPException(
                status_code=503,
                detail="Grant deleted but OPA sync failed — retry after OPA recovers",
            ) from exc

    logger.info("Client grant deleted", extra={"client_id": client_id})
    return {"client_id": client_id, "status": "deleted"}


@router.post("/api/v1/admin/sync-grants", status_code=200)
async def sync_grants(request: Request) -> dict[str, Any]:
    """
    On-demand OPA grants resync.

    Forces an immediate push of all client_grants to OPA at /v1/data/mcp_grants.
    Useful after manual DB changes, OPA restart, or troubleshooting grant sync issues.

    Returns: {"status": "synced", "grant_count": N}
    Requires: admin or platform_admin role.
    """
    _require_admin(request)

    sync = opa_data_sync_svc.opa_data_sync_instance
    if sync is None:
        raise HTTPException(
            status_code=503,
            detail="OPA data sync service not initialized",
        )

    # Count grants before pushing (for response)
    pool = await _get_db_pool()
    count_row = await pool.fetchrow("SELECT COUNT(*) AS cnt FROM client_grants")
    grant_count = int(count_row["cnt"]) if count_row else 0

    try:
        await sync.push_grants()
    except PolicyEngineError as exc:
        logger.error(
            "On-demand OPA sync failed",
            extra={"error": str(exc)},
        )
        raise HTTPException(
            status_code=503,
            detail=f"OPA sync failed: {exc}",
        ) from exc

    logger.info("On-demand OPA grants sync completed", extra={"grant_count": grant_count})
    return {"status": "synced", "grant_count": grant_count}
