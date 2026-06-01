"""
Entitlement service — per-principal per-server access grants.

Resolves whether a typed principal (human:... or agent:...) is entitled
to access a specific server with a given role, using the entitlement and
server_role_grant tables populated by Plan 4 migrations.

Discovery == invoke invariant:
  A principal who can DISCOVER a server (it appears in their catalog) can INVOKE it.
  A principal who cannot invoke cannot discover. Single resolver enforces this.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# Role ordering for deduplication when a principal has multiple grants.
# Higher value = more permissive / senior role.
ROLE_LEVELS: dict[str, int] = {
    "user": 0,
    "manager": 1,
    "server_owner": 2,
    "auditor": 3,
    "platform_admin": 4,
}


@dataclass(frozen=True)
class EntitlementResult:
    entitled: bool
    role: str | None          # highest role granted, or None
    server_id: str | None
    reason: str               # 'entitlement_table' | 'role_grant' | 'not_found' | 'server_not_approved'


async def check_entitlement(
    principal_type: str,
    principal_id: str,
    server_id: str,
) -> EntitlementResult:
    """
    Return whether the principal is entitled to access server_id.

    Checks:
    1. server_registry: server must exist and have status='approved'
    2. entitlement table: explicit per-principal grant
    3. server_role_grant table: role-based grant (fallback)

    Returns EntitlementResult with entitled=True and highest role if any grant found.
    Returns server_not_approved if the entitlement tables do not yet exist
    (e.g. Plan 4 migrations are pending) to prevent a 500 surfacing to callers.
    """
    try:
        async with AsyncSessionLocal() as db:
            # Step 1: Verify server exists and is approved.
            row = await db.execute(
                text(
                    "SELECT server_id, status FROM server_registry "
                    "WHERE server_id = :server_id AND deleted_at IS NULL"
                ),
                {"server_id": server_id},
            )
            server_row = row.mappings().first()

            if server_row is None or server_row["status"] != "approved":
                return EntitlementResult(
                    entitled=False,
                    role=None,
                    server_id=None,
                    reason="server_not_approved",
                )

            # Step 2: Check entitlement table (explicit per-principal grant).
            ent_row = await db.execute(
                text(
                    "SELECT role FROM entitlement "
                    "WHERE principal_type = :pt "
                    "  AND principal_id = :pid "
                    "  AND server_id = :sid "
                    "  AND revoked_at IS NULL"
                ),
                {"pt": principal_type, "pid": principal_id, "sid": server_id},
            )
            ent = ent_row.mappings().first()
            if ent is not None:
                return EntitlementResult(
                    entitled=True,
                    role=ent["role"],
                    server_id=server_id,
                    reason="entitlement_table",
                )

            # Step 3: Fallback to server_role_grant.
            srg_row = await db.execute(
                text(
                    "SELECT role FROM server_role_grant "
                    "WHERE principal_type = :pt "
                    "  AND principal_id = :pid "
                    "  AND server_id = :sid"
                ),
                {"pt": principal_type, "pid": principal_id, "sid": server_id},
            )
            srg = srg_row.mappings().first()
            if srg is not None:
                return EntitlementResult(
                    entitled=True,
                    role=srg["role"],
                    server_id=server_id,
                    reason="role_grant",
                )

            return EntitlementResult(
                entitled=False,
                role=None,
                server_id=server_id,
                reason="not_found",
            )
    except Exception as exc:
        # Catches missing tables (UndefinedTableError) or any other DB error.
        # Return server_not_approved so callers see an empty catalog / 404,
        # not an unhandled 500. Log at WARNING so the missing migration is visible.
        logger.warning(
            "check_entitlement DB error for server_id=%s principal=%s: %s",
            server_id,
            principal_id,
            exc,
        )
        return EntitlementResult(
            entitled=False,
            role=None,
            server_id=None,
            reason="server_not_approved",
        )


async def list_entitled_servers(
    principal_type: str,
    principal_id: str,
) -> list[dict]:
    """
    Return the list of approved servers this principal is entitled to access,
    with their role. Used for server catalog filtering.

    Enforces discovery == invoke: only servers the principal can invoke appear here.
    Returns an empty list if the entitlement tables do not yet exist (migration
    pending) rather than propagating a 500 to the caller.
    """
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text(
                    """
                    SELECT
                        sr.server_id::TEXT  AS server_id,
                        sr.name             AS name,
                        sr.upstream_url     AS upstream_url,
                        sr.custody_mode     AS custody_mode,
                        combined.role       AS role
                    FROM server_registry sr
                    JOIN (
                        -- Explicit per-principal grants (not revoked)
                        SELECT server_id, role
                        FROM entitlement
                        WHERE principal_type = :pt
                          AND principal_id   = :pid
                          AND revoked_at IS NULL

                        UNION ALL

                        -- Role-based grants
                        SELECT server_id, role
                        FROM server_role_grant
                        WHERE principal_type = :pt
                          AND principal_id   = :pid
                    ) AS combined ON sr.server_id = combined.server_id
                    WHERE sr.status = 'approved'
                      AND sr.deleted_at IS NULL
                    """
                ),
                {"pt": principal_type, "pid": principal_id},
            )
            rows = result.mappings().all()
    except Exception as exc:
        # Missing tables (Plan 4 migration pending) or transient DB error.
        # Return empty list so the catalog endpoint returns 200 [] instead of 500.
        logger.warning(
            "list_entitled_servers DB error for principal=%s: %s",
            principal_id,
            exc,
        )
        return []

    # Deduplicate by server_id, keeping the highest role per ROLE_LEVELS ordering.
    best: dict[str, dict] = {}
    for row in rows:
        sid = row["server_id"]
        row_level = ROLE_LEVELS.get(row["role"], -1)
        if sid not in best or row_level > ROLE_LEVELS.get(best[sid]["role"], -1):
            best[sid] = {
                "server_id": sid,
                "name": row["name"],
                "upstream_url": row["upstream_url"],
                "custody_mode": row["custody_mode"],
                "role": row["role"],
            }

    return list(best.values())
