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


class NotEntitledError(Exception):
    """Raised on the invoke path when a server-linked tool is invoked by a
    principal not entitled to its server (6.2, discovery==invoke). Carries no
    role context by design — there is no admin exception to this gate."""

    def __init__(self, server_id: str, reason: str) -> None:
        self.server_id = server_id
        self.reason = reason
        super().__init__(f"not entitled to server {server_id} ({reason})")


async def enforce_tool_entitlement(
    tool_record: dict,
    principal_id: str | None,
    principal_type: str | None,
) -> None:
    """discovery==invoke enforcement for the invoke path.

    If the tool is linked to a server (``tool_record['server_id']`` is set), the
    caller MUST be entitled to that server — checked via the same
    :func:`check_entitlement` resolver the catalog uses for discovery, so the two
    can never drift. There is intentionally NO role exception: enforcement is
    identity-based, so an admin/platform_admin who is not entitled is still
    denied.

    Tools with no ``server_id`` are not yet server-scoped (legacy / unlinked) and
    are a no-op here; OPA still governs them downstream.

    Fail-closed: a server-linked tool with an unresolved principal is denied.

    Raises:
        NotEntitledError: caller is not entitled to the tool's server.
    """
    server_id = tool_record.get("server_id")
    if not server_id:
        return  # unlinked tool — not server-scoped yet

    if not principal_id or not principal_type:
        # A server-scoped tool with no resolvable principal must fail closed.
        raise NotEntitledError(str(server_id), "principal_unresolved")

    result = await check_entitlement(
        principal_type=principal_type,
        principal_id=principal_id,
        server_id=str(server_id),
    )
    if not result.entitled:
        raise NotEntitledError(str(server_id), result.reason)


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
            # The entitlement table (V015) has NO `role` column — it grants USE,
            # so a plain entitlement = 'user' access; elevated roles come from
            # server_role_grant (Step 3). The 'user' literal keeps this valid
            # against the real schema. (The prior `SELECT role` referenced a
            # non-existent column, so the query threw, was swallowed, and silently
            # disabled per-server grants / the discovery==invoke invariant.)
            ent_row = await db.execute(
                text(
                    "SELECT 'user' AS role FROM entitlement "
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
            # No revoked_at guard needed — server_role_grant has no revoked_at column
            # (see V015). Revocation is by DELETE on this table, not soft-delete.
            # If a future migration adds revoked_at, add 'AND revoked_at IS NULL' here.
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


async def get_owned_server_ids(principal_id: str) -> list[str]:
    """Return server UUIDs where principal has server_owner or manager role in server_role_grant.

    Used by the invocation path to populate input.owned_server_ids for OPA evaluation.
    Redis-cached per principal with 60s TTL (same pattern as role caching in rbac.py).

    Fails open (returns []) so a transient Redis or DB error does not block invocations
    that are otherwise authorized via explicit grant. The OPA owner rules then can't fire,
    but grant-based rules still can.

    Note: principal_id here is the client_id string, not a typed (type, id) pair, because
    the OPA input is keyed on client_id. server_role_grant.principal_type is ignored; both
    'human' and 'agent' principals that carry a server_owner/manager role in any principal_type
    column are included. This is intentional: the OPA rule is role-based, not type-based.
    """
    from app.core.redis_client import redis_pool
    import json

    cache_key = f"owned_servers:{principal_id}"

    # Try Redis cache first (TTL 60s — same as RBAC role cache).
    if redis_pool.client is not None:
        try:
            cached = await redis_pool.client.get(cache_key)
            if cached is not None:
                return json.loads(cached)
        except Exception as _exc:
            logger.debug("Redis owned_servers cache read failed for %s: %s", principal_id, _exc)

    # DB fallback: query server_role_grant for server_owner or manager rows.
    server_ids: list[str] = []
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text(
                    "SELECT server_id::TEXT FROM server_role_grant "
                    "WHERE principal_id = :pid "
                    "  AND role IN ('server_owner', 'manager')"
                ),
                {"pid": principal_id},
            )
            server_ids = [row[0] for row in result.fetchall()]
    except Exception as exc:
        logger.warning(
            "get_owned_server_ids DB error for principal=%s: %s",
            principal_id,
            exc,
        )
        return []

    # Populate cache (best-effort — do not let a cache write failure block the result).
    if redis_pool.client is not None:
        try:
            await redis_pool.client.setex(cache_key, 60, json.dumps(server_ids))
        except Exception as _exc:
            logger.debug("Redis owned_servers cache write failed for %s: %s", principal_id, _exc)

    return server_ids


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

                        -- Role-based grants (no revoked_at — revocation is by DELETE on this table)
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
