"""
Dependency-CVE waiver CRUD (CR-12 / WP-B2).

Waivers are written ONLY through this module, which is only ever called from
the authenticated admin/reviewer API path (see
proxy/app/routers/submission.py::create_scan_waiver /
revoke_scan_waiver) — never from the scanner-worker (which has no DB grant
on scan_waivers at all, see infra/db/migrations/V066__scan_waivers.sql).

Every waiver creation emits an audit event via the same HMAC-signed audit
chain as every other tool-invocation / admin-config event (see
app/services/admin_audit.py::emit_admin_config_event, which this module
reuses directly rather than re-inventing the emit path).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.admin_audit import emit_admin_config_event

logger = logging.getLogger(__name__)

_VALID_PRINCIPAL_TYPES = {"human", "agent", "service"}


class InvalidWaiverRequest(ValueError):
    """Raised for a structurally invalid waiver request (never silently coerced)."""


async def create_waiver(
    session: AsyncSession,
    *,
    server_id: str,
    package: str,
    version: str,
    vuln_id: str,
    ecosystem: str | None,
    reason: str,
    expires_at: datetime,
    principal_id: str,
    principal_type: str,
    principal_issuer: str | None,
) -> dict[str, Any]:
    """Insert a new waiver row and emit its audit event. Returns the created row.

    Validation is intentionally strict and fail-closed: a waiver with a
    missing package/version/vuln_id, an empty reason, an expiry in the past,
    or an unrecognized principal_type is a client (422) error, never
    silently defaulted.
    """
    if not package or not package.strip():
        raise InvalidWaiverRequest("package is required")
    if not version or not version.strip():
        raise InvalidWaiverRequest("version is required")
    if not vuln_id or not vuln_id.strip():
        raise InvalidWaiverRequest("vuln_id is required")
    if not reason or not reason.strip():
        raise InvalidWaiverRequest("reason is required — a waiver with no recorded rationale is not permitted")
    if principal_type not in _VALID_PRINCIPAL_TYPES:
        raise InvalidWaiverRequest(f"principal_type must be one of {sorted(_VALID_PRINCIPAL_TYPES)}")
    if not principal_id or not principal_id.strip():
        raise InvalidWaiverRequest("waived_by principal_id is required — a waiver must be attributable")
    now = datetime.now(timezone.utc)
    if expires_at <= now:
        raise InvalidWaiverRequest("expires_at must be in the future — an already-expired waiver is a no-op")

    row = (await session.execute(text(
        """
        INSERT INTO scan_waivers
            (server_id, package, version, vuln_id, ecosystem, reason,
             waived_by_principal_id, waived_by_principal_type, waived_by_principal_issuer,
             expires_at)
        VALUES
            (:server_id, :package, :version, :vuln_id, :ecosystem, :reason,
             :principal_id, :principal_type, :principal_issuer, :expires_at)
        RETURNING waiver_id, server_id, package, version, vuln_id, ecosystem, reason,
                  waived_by_principal_id, waived_by_principal_type, waived_by_principal_issuer,
                  created_at, expires_at, revoked_at
        """
    ), {
        "server_id": server_id, "package": package, "version": version, "vuln_id": vuln_id,
        "ecosystem": ecosystem, "reason": reason,
        "principal_id": principal_id, "principal_type": principal_type, "principal_issuer": principal_issuer,
        "expires_at": expires_at,
    })).mappings().first()
    await session.commit()

    waiver = dict(row)
    try:
        await emit_admin_config_event(
            principal_id, "scan_waiver.create", server_id,
            {
                "waiver_id": str(waiver["waiver_id"]), "package": package, "version": version,
                "vuln_id": vuln_id, "ecosystem": ecosystem, "reason": reason,
                "expires_at": expires_at.isoformat(),
            },
        )
    except Exception as exc:
        # Consistent with emit_admin_config_event's own contract: an audit
        # emit failure must never roll back or hide the already-committed
        # waiver — it is logged loudly instead.
        logger.error("waiver audit emit failed waiver_id=%s server_id=%s: %s",
                    waiver.get("waiver_id"), server_id, exc)
    return waiver


async def revoke_waiver(session: AsyncSession, *, waiver_id: str, revoked_by_principal_id: str) -> bool:
    row = (await session.execute(text(
        """
        UPDATE scan_waivers
        SET revoked_at = now(), revoked_by_principal_id = :revoked_by
        WHERE waiver_id = :waiver_id AND revoked_at IS NULL
        RETURNING server_id
        """
    ), {"waiver_id": waiver_id, "revoked_by": revoked_by_principal_id})).mappings().first()
    await session.commit()
    if row is None:
        return False
    try:
        await emit_admin_config_event(
            revoked_by_principal_id, "scan_waiver.revoke", str(row["server_id"]), {"waiver_id": str(waiver_id)},
        )
    except Exception as exc:
        logger.error("waiver revoke audit emit failed waiver_id=%s: %s", waiver_id, exc)
    return True


async def list_waivers(session: AsyncSession, server_id: str, *, active_only: bool = False) -> list[dict]:
    """All waivers for a server, newest first. Waived findings stay visible in
    the SBOM/review UI regardless of expiry/revocation — this returns the
    full history, not just active rows, unless active_only=True."""
    clause = "AND revoked_at IS NULL AND expires_at > now()" if active_only else ""
    rows = (await session.execute(text(
        f"""
        SELECT waiver_id, server_id, package, version, vuln_id, ecosystem, reason,
               waived_by_principal_id, waived_by_principal_type, waived_by_principal_issuer,
               created_at, expires_at, revoked_at, revoked_by_principal_id
        FROM scan_waivers
        WHERE server_id = :server_id {clause}
        ORDER BY created_at DESC
        """
    ), {"server_id": server_id})).mappings().all()
    return [dict(r) for r in rows]


async def get_active_waivers_for_evaluation(session: AsyncSession, server_id: str) -> list[dict]:
    """Waivers passed to dependency_policy.evaluate_dependency_findings — keys
    match what _waiver_active/_waiver_matches_group expect (waiver_id,
    package, version, vuln_id, expires_at, revoked_at)."""
    rows = (await session.execute(text(
        """
        SELECT waiver_id, package, version, vuln_id, expires_at, revoked_at
        FROM scan_waivers
        WHERE server_id = :server_id AND revoked_at IS NULL AND expires_at > now()
        """
    ), {"server_id": server_id})).mappings().all()
    return [dict(r) for r in rows]
