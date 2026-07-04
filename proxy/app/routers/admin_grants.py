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

import json
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

# All platform RBAC roles a grant/revoke may target (docs/ARCHITECTURE.md §6.5).
_VALID_RBAC_ROLES = frozenset({
    "admin", "platform_admin", "security_reviewer", "auditor",
    "server_owner", "manager", "user", "agent", "readonly",
})

# role_assignments is append-only (INV-011/V050) — every grant/revoke is its
# own INSERTed event row; the most recent event per (client_id, role) decides
# current state. This subquery resolves that "current state" and is reused
# everywhere role_assignments needs to be read as if it supported update/delete.
_ACTIVE_ROLE_ASSIGNMENTS_SQL = """
    SELECT client_id, role, granted_by, expires_at, created_at
    FROM (
        SELECT DISTINCT ON (client_id, role)
               client_id, role, granted_by, revoked, expires_at, created_at
        FROM role_assignments
        ORDER BY client_id, role, created_at DESC
    ) latest
    WHERE revoked = false
      AND (expires_at IS NULL OR expires_at > now())
"""


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


@router.get("/api/v1/admin/principals")
async def list_principals(request: Request) -> dict[str, Any]:
    """
    List known principals for the admin Access UI (PRD-0003 R-2).

    There is no single principals table — this is the union of:
      - role_assignments.client_id  (anyone with an assigned role)
      - mcp_profiles.profile_id     (anyone with an explicit MCP toggle)
      - oidc_sessions.client_id_resolved for active (unrevoked, unexpired) sessions

    Keycloak admin-API sync is explicitly out of scope (P2) — this only surfaces
    principals the platform already has local rows for.
    """
    _require_admin(request)
    pool = await _get_db_pool()

    rows = await pool.fetch(
        f"""
        WITH principals AS (
            -- Only client_ids with a currently-ACTIVE role event — role_assignments
            -- is append-only (V050), so a fully-revoked grant/revoke pair (e.g. a
            -- throwaway test grant) would otherwise leave that client_id listed
            -- here forever, even with zero live roles.
            SELECT client_id AS principal FROM ({_ACTIVE_ROLE_ASSIGNMENTS_SQL}) active_ra
            UNION
            SELECT profile_id AS principal FROM mcp_profiles
            UNION
            SELECT client_id_resolved AS principal FROM oidc_sessions
            WHERE revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
              AND client_id_resolved IS NOT NULL
        )
        SELECT
            p.principal,
            COALESCE(array_agg(DISTINCT ra.role) FILTER (WHERE ra.role IS NOT NULL), '{{}}') AS roles,
            MAX(os.created_at) AS last_session_at
        FROM principals p
        LEFT JOIN ({_ACTIVE_ROLE_ASSIGNMENTS_SQL}) ra ON ra.client_id = p.principal
        LEFT JOIN oidc_sessions os ON os.client_id_resolved = p.principal
        WHERE p.principal IS NOT NULL AND p.principal != ''
        GROUP BY p.principal
        ORDER BY p.principal
        """
    )

    principals = [
        {
            "principal": row["principal"],
            "roles": list(row["roles"]),
            "last_session_at": row["last_session_at"].isoformat() if row["last_session_at"] else None,
        }
        for row in rows
    ]

    return {"principals": principals, "count": len(principals)}


class RoleGrantCreate(BaseModel):
    """Request body for POST /api/v1/admin/roles — grant a role to a client_id."""

    client_id: str
    role: str
    expires_at: str | None = None  # ISO 8601; None = permanent

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("client_id must be non-empty")
        if len(v) > 256:
            raise ValueError("client_id must be <= 256 characters")
        return v.strip()

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in _VALID_RBAC_ROLES:
            raise ValueError(f"role must be one of {sorted(_VALID_RBAC_ROLES)}")
        return v


async def _invalidate_role_cache(client_id: str) -> None:
    """Best-effort: drop the 300s role cache so a grant/revoke takes effect
    immediately rather than waiting out the TTL (middleware/auth.py::_load_roles)."""
    try:
        from app.core.redis_client import redis_pool
        await redis_pool.client.delete(f"roles:{client_id}")
    except Exception as exc:
        logger.warning("Failed to invalidate role cache", extra={"client_id": client_id, "error": str(exc)})


@router.get("/api/v1/admin/roles")
async def list_role_assignments(request: Request) -> dict[str, Any]:
    """List all currently-active role_assignments (RBAC management panel)."""
    _require_admin(request)
    pool = await _get_db_pool()
    rows = await pool.fetch(f"{_ACTIVE_ROLE_ASSIGNMENTS_SQL} ORDER BY client_id, role")
    assignments = [
        {
            "client_id": row["client_id"],
            "role": row["role"],
            "granted_by": row["granted_by"],
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "from_keycloak": row["granted_by"] == "keycloak",
        }
        for row in rows
    ]
    return {"assignments": assignments, "count": len(assignments), "valid_roles": sorted(_VALID_RBAC_ROLES)}


@router.post("/api/v1/admin/roles", status_code=201)
async def grant_role(body: RoleGrantCreate, request: Request) -> dict[str, Any]:
    """Grant a role to a client_id. Append-only INSERT (INV-011) — if the
    client already holds this role, this simply records another active grant
    event; no conflict, no update needed."""
    _require_admin(request)
    pool = await _get_db_pool()
    reviewer = getattr(request.state, "client_id", None) or "admin-panel"

    expires_at = None
    if body.expires_at:
        from datetime import datetime
        try:
            expires_at = datetime.fromisoformat(body.expires_at)
        except ValueError:
            raise HTTPException(status_code=400, detail="expires_at must be ISO 8601")

    await pool.execute(
        """
        INSERT INTO role_assignments (client_id, role, granted_by, expires_at, revoked)
        VALUES ($1, $2, $3, $4, false)
        """,
        body.client_id, body.role, reviewer, expires_at,
    )
    await _invalidate_role_cache(body.client_id)
    logger.info("Role granted", extra={"client_id": body.client_id, "role": body.role, "granted_by": reviewer})
    return {"client_id": body.client_id, "role": body.role, "status": "granted"}


@router.delete("/api/v1/admin/roles/{client_id}/{role}", status_code=200)
async def revoke_role(client_id: str, role: str, request: Request) -> dict[str, Any]:
    """Revoke a role from a client_id. Append-only (INV-011) — records a
    'revoked' event row rather than UPDATE/DELETE-ing the original grant (the
    app's DB role has no UPDATE/DELETE privilege on role_assignments, by
    design — see V009).

    Refuses to zero out platform admin access entirely: if this would revoke
    the last remaining active admin/platform_admin grant on the whole
    platform (across all clients), it's rejected with 409 rather than
    locking every admin out.
    """
    _require_admin(request)
    pool = await _get_db_pool()
    reviewer = getattr(request.state, "client_id", None) or "admin-panel"

    if role in _ADMIN_ROLES:
        remaining = await pool.fetchval(
            f"""
            SELECT COUNT(*) FROM ({_ACTIVE_ROLE_ASSIGNMENTS_SQL}) active
            WHERE role IN ('admin', 'platform_admin')
              AND NOT (client_id = $1 AND role = $2)
            """,
            client_id, role,
        )
        if remaining == 0:
            raise HTTPException(
                status_code=409,
                detail="cannot revoke the last remaining admin/platform_admin grant on the platform",
            )

    await pool.execute(
        """
        INSERT INTO role_assignments (client_id, role, granted_by, revoked)
        VALUES ($1, $2, $3, true)
        """,
        client_id, role, reviewer,
    )
    await _invalidate_role_cache(client_id)
    logger.info("Role revoked", extra={"client_id": client_id, "role": role, "revoked_by": reviewer})
    return {"client_id": client_id, "role": role, "status": "revoked"}


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

    # asyncpg returns JSONB columns as raw JSON strings, not decoded Python
    # objects (same gotcha documented/handled in services/opa_data_sync.py
    # load_all_grants) — list(raw_json_string) iterates it character by
    # character, which is why the UI showed '[', '"', 'g', 'r', 'a', 'f', ...
    # instead of tool names.
    def _as_list(v: Any) -> list:
        if isinstance(v, str):
            return json.loads(v)
        return list(v) if v is not None else []

    grants = [
        {
            "client_id": row["client_id"],
            "allowed_tools": _as_list(row["allowed_tools"]),
            "allowed_tags": _as_list(row["allowed_tags"]),
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

    # Fail-closed: refuse to commit if OPA sync is unavailable.
    # A grant acknowledged with 200 but never pushed to OPA gives false confidence
    # — the client's access state would diverge from what the admin intended (FO-002).
    sync = opa_data_sync_svc.opa_data_sync_instance
    if sync is None:
        logger.error(
            "OPA data sync not initialized — refusing grant upsert (fail-closed)",
            extra={"client_id": body.client_id},
        )
        raise HTTPException(
            status_code=503,
            detail="OPA data sync service not initialized — grant not saved",
        )

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
        json.dumps(body.allowed_tools),
        json.dumps(body.allowed_tags),
        body.max_risk_level,
        caller,
    )

    was_insert = result["is_insert"] if result else True

    # Sync to OPA immediately (fail-closed)
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

    # Fail-closed: refuse to commit if OPA sync is unavailable.
    # A revocation acknowledged with 200 but never pushed to OPA gives false confidence
    # — the revoked client would retain access (FO-002).
    sync = opa_data_sync_svc.opa_data_sync_instance
    if sync is None:
        logger.error(
            "OPA data sync not initialized — refusing grant delete (fail-closed)",
            extra={"client_id": client_id},
        )
        raise HTTPException(
            status_code=503,
            detail="OPA data sync service not initialized — grant not deleted",
        )

    result = await pool.execute(
        "DELETE FROM client_grants WHERE client_id = $1",
        client_id,
    )
    # asyncpg returns "DELETE N" where N is the count of deleted rows
    deleted_count = int(result.split()[-1]) if result else 0

    if deleted_count == 0:
        raise HTTPException(status_code=404, detail=f"Grant for '{client_id}' not found")

    # Sync to OPA immediately (fail-closed)
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


# ---------------------------------------------------------------------------
# API key issuance — the missing piece client_grants alone can't provide.
#
# client_grants (above) is authorization-only: it says what an ALREADY
# authenticated client_id may do. It was possible to write a grant for a
# client_id with no way to ever authenticate as it — there was no admin
# endpoint anywhere that actually minted a credential; api_keys was only
# ever populated by the lab seeder script. These endpoints close that gap:
# generate a real key, HMAC-hash it (matching middleware/auth.py's
# _resolve_api_key lookup), and grant matching role_assignments rows so the
# new client_id can actually do something — api_keys.roles itself is never
# read by the auth resolver (only role_assignments is), so it's kept here
# only for at-a-glance display, not as the authorization source of truth.
# ---------------------------------------------------------------------------

class ApiKeyCreate(BaseModel):
    client_id: str
    roles: list[str] = ["agent"]
    rate_limit_rpm: int = 120

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("client_id must be non-empty")
        if len(v) > 256:
            raise ValueError("client_id must be <= 256 characters")
        return v.strip()

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, v: list[str]) -> list[str]:
        bad = [r for r in v if r not in _VALID_RBAC_ROLES]
        if bad:
            raise ValueError(f"unknown role(s): {bad}")
        return v


@router.get("/api/v1/admin/api-keys")
async def list_api_keys(request: Request) -> dict[str, Any]:
    """List active (non-revoked) API keys. Never returns key_hash."""
    _require_admin(request)
    pool = await _get_db_pool()
    rows = await pool.fetch(
        """
        SELECT key_id, client_id, roles, rate_limit_rpm, created_at, created_by, expires_at
        FROM api_keys
        WHERE revoked_at IS NULL
        ORDER BY created_at DESC
        """
    )
    keys = [
        {
            "key_id": str(row["key_id"]),
            "client_id": row["client_id"],
            "roles": list(row["roles"]),
            "rate_limit_rpm": row["rate_limit_rpm"],
            "created_at": row["created_at"].isoformat() if row["created_at"] else None,
            "created_by": row["created_by"],
            "expires_at": row["expires_at"].isoformat() if row["expires_at"] else None,
        }
        for row in rows
    ]
    return {"keys": keys, "count": len(keys)}


@router.post("/api/v1/admin/api-keys", status_code=201)
async def create_api_key(body: ApiKeyCreate, request: Request) -> dict[str, Any]:
    """
    Issue a new API key: generates a random secret, stores only its HMAC hash
    (matching middleware/auth.py::_resolve_api_key), and grants matching
    role_assignments rows so the client_id can actually authenticate and do
    something. Returns the plaintext key ONCE — it is never retrievable again
    (only the hash is stored, by design; this mirrors every other credential
    in this platform).
    """
    import secrets
    from app.core.security import hash_api_key

    _require_admin(request)
    pool = await _get_db_pool()
    caller = getattr(request.state, "client_id", "unknown-admin")

    raw_key = secrets.token_hex(32)
    key_hash = hash_api_key(raw_key)

    async with pool.acquire() as conn:
        async with conn.transaction():
            key_row = await conn.fetchrow(
                """
                INSERT INTO api_keys (key_hash, client_id, roles, rate_limit_rpm, created_by)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING key_id, created_at
                """,
                key_hash, body.client_id, body.roles, body.rate_limit_rpm, caller,
            )
            for role in body.roles:
                await conn.execute(
                    """
                    INSERT INTO role_assignments (client_id, role, granted_by)
                    VALUES ($1, $2, $3)
                    """,
                    body.client_id, role, caller,
                )

    try:
        from app.core.redis_client import redis_pool
        await redis_pool.client.delete(f"roles:{body.client_id}")
    except Exception as exc:
        logger.warning("Failed to invalidate role cache after key creation", extra={"error": str(exc)})

    logger.info("API key created", extra={"client_id": body.client_id, "roles": body.roles})
    return {
        "key_id": str(key_row["key_id"]),
        "client_id": body.client_id,
        "roles": body.roles,
        "rate_limit_rpm": body.rate_limit_rpm,
        "created_at": key_row["created_at"].isoformat(),
        "api_key": raw_key,
        "warning": "This key is shown once and cannot be retrieved again. Store it securely now.",
    }


@router.delete("/api/v1/admin/api-keys/{key_id}", status_code=200)
async def revoke_api_key(key_id: str, request: Request) -> dict[str, Any]:
    """Revoke an API key (sets revoked_at — the credential itself is append-only,
    same INV-011 pattern as everything else in this file; the key row is never
    deleted, just marked revoked so _resolve_api_key's WHERE revoked_at IS NULL
    stops matching it)."""
    _require_admin(request)
    pool = await _get_db_pool()

    result = await pool.execute(
        "UPDATE api_keys SET revoked_at = NOW() WHERE key_id = $1 AND revoked_at IS NULL",
        key_id,
    )
    updated = int(result.split()[-1]) if result else 0
    if updated == 0:
        raise HTTPException(status_code=404, detail="API key not found or already revoked")

    logger.info("API key revoked", extra={"key_id": key_id})
    return {"key_id": key_id, "status": "revoked"}
