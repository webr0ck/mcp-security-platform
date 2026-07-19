"""
MCP Security Platform — Audit Log Access Router

Implements docs/API.md Section 2.8.

Endpoints:
  GET /api/v1/audit/events — Query the audit event index (admin, auditor, agent-own)

Note: Full event content is in Loki (not this API). This endpoint returns
the PostgreSQL audit_events index for correlation and compliance queries.

RBAC: agents may only see their own audit events (client_id auto-filter per RBAC.md 3.7).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

router = APIRouter(prefix="/audit")


@router.get("/events")
async def list_audit_events(
    request: Request,
    client_id: str | None = Query(None),
    tool_name: str | None = Query(None),
    outcome: str | None = Query(None, pattern="^(allow|deny)$"),
    from_date: str | None = Query(None, alias="from"),
    to_date: str | None = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Query audit event index.
    Required role: admin, auditor (full access), agent (own events only).

    IMPORTANT: For agent role, client_id filter is automatically set to the
    calling agent's client_id regardless of what client_id query param is provided.

    Per RBAC.md section 3.7:
      - admin/auditor: full access across all clients
      - agent: own events only (client_id auto-forced to calling agent's ID)
      - readonly: 403 FORBIDDEN
    """
    import json as _json
    import logging

    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    caller_client_id: str = getattr(request.state, "client_id", "")

    # readonly role is denied (RBAC.md 3.7)
    if not any(r in {"admin", "auditor", "agent"} for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Insufficient role for audit access."},
        )

    # For agents: force client_id filter to their own ID (RBAC.md 3.7)
    effective_client_id = client_id
    if "agent" in roles and "admin" not in roles and "auditor" not in roles:
        effective_client_id = caller_client_id

    conditions = ["1=1"]
    params: dict = {}

    if effective_client_id:
        conditions.append("client_id = :client_id")
        params["client_id"] = effective_client_id
    if tool_name:
        conditions.append("tool_name = :tool_name")
        params["tool_name"] = tool_name
    if outcome:
        conditions.append("outcome = :outcome")
        params["outcome"] = outcome
    if from_date:
        conditions.append("created_at >= :from_date::timestamptz")
        params["from_date"] = from_date
    if to_date:
        conditions.append("created_at <= :to_date::timestamptz")
        params["to_date"] = to_date

    where_clause = " AND ".join(conditions)
    offset = (page - 1) * page_size

    try:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) FROM audit_events WHERE {where_clause}"),
            params,
        )
        total_items = count_result.scalar() or 0

        rows_result = await db.execute(
            text(
                f"""
                SELECT event_id, created_at, client_id, tool_name, tool_id,
                       outcome, latency_ms, sha256_hash, anomaly_score, notices
                FROM audit_events
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": page_size, "offset": offset},
        )
        rows = rows_result.fetchall()
    except Exception as exc:
        logger.error("audit_events query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    data = [
        {
            "event_id": str(row.event_id),
            "timestamp": row.created_at.isoformat(),
            "client_id": row.client_id,
            "tool_name": row.tool_name,
            "tool_id": str(row.tool_id) if row.tool_id else None,
            "outcome": row.outcome,
            "latency_ms": row.latency_ms,
            "sha256_hash": row.sha256_hash,
            "anomaly_score": float(row.anomaly_score) if row.anomaly_score else None,
            # V083: advisory-only notices (e.g. taint-floor notify-only
            # disclaimer), distinct from opa_reasons/deny_reasons.
            "notices": row.notices if isinstance(row.notices, list) else (
                _json.loads(row.notices) if row.notices else []
            ),
        }
        for row in rows
    ]

    return JSONResponse(content={
        "data": data,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": max(1, -(-total_items // page_size)),
        },
    })
