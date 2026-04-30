"""
MCP Security Platform — Anomaly Detection Router

Implements docs/API.md Section 2.7.

Endpoints:
  GET   /api/v1/anomaly/baselines           — List all client baselines (admin, auditor)
  GET   /api/v1/anomaly/alerts              — List anomaly alerts (admin, auditor)
  PATCH /api/v1/anomaly/alerts/{alert_id}   — Resolve or annotate alert (admin only)
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/anomaly")


def _require_roles(request: Request, allowed: set[str]) -> None:
    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in allowed for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Insufficient role."},
        )


@router.get("/baselines")
async def list_anomaly_baselines(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List anomaly baselines for all registered clients.
    Required role: admin, auditor.
    Per RBAC.md section 4.3: agents cannot read baselines (prevents adversarial poisoning).
    """
    _require_roles(request, {"admin", "auditor"})

    offset = (page - 1) * page_size
    try:
        count_result = await db.execute(text("SELECT COUNT(*) FROM anomaly_baselines"))
        total_items = count_result.scalar() or 0

        rows_result = await db.execute(
            text(
                """
                SELECT client_id, baseline_version, tools_in_baseline,
                       jsonb_array_length(sequence_patterns::jsonb) AS sequence_patterns,
                       last_updated, anomaly_threshold
                FROM anomaly_baselines
                ORDER BY last_updated DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {"limit": page_size, "offset": offset},
        )
        rows = rows_result.fetchall()
    except Exception as exc:
        logger.error("anomaly_baselines list error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    data = [
        {
            "client_id": row.client_id,
            "baseline_version": row.baseline_version,
            "tools_in_baseline": row.tools_in_baseline or [],
            "sequence_patterns": row.sequence_patterns or 0,
            "last_updated": row.last_updated.isoformat(),
            "anomaly_score_threshold": float(row.anomaly_threshold),
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


@router.get("/alerts")
async def list_anomaly_alerts(
    request: Request,
    client_id: Optional[str] = Query(None),
    resolved: bool = Query(False),
    from_date: Optional[str] = Query(None, alias="from"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List anomaly alerts. Unresolved only by default.
    Required role: admin, auditor.
    """
    _require_roles(request, {"admin", "auditor"})

    conditions = ["1=1"]
    params: dict = {}

    if client_id:
        conditions.append("client_id = :client_id")
        params["client_id"] = client_id
    if not resolved:
        conditions.append("resolved = false")
    if from_date:
        conditions.append("detected_at >= :from_date::timestamptz")
        params["from_date"] = from_date

    where_clause = " AND ".join(conditions)
    offset = (page - 1) * page_size

    try:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) FROM anomaly_alerts WHERE {where_clause}"),
            params,
        )
        total_items = count_result.scalar() or 0

        rows_result = await db.execute(
            text(
                f"""
                SELECT alert_id, client_id, detected_at, anomaly_score,
                       pattern, description, invocation_ids, resolved,
                       resolved_at, resolved_by, resolution_note
                FROM anomaly_alerts
                WHERE {where_clause}
                ORDER BY detected_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": page_size, "offset": offset},
        )
        rows = rows_result.fetchall()
    except Exception as exc:
        logger.error("anomaly_alerts list error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    data = [
        {
            "alert_id": str(row.alert_id),
            "client_id": row.client_id,
            "detected_at": row.detected_at.isoformat(),
            "anomaly_score": float(row.anomaly_score),
            "pattern": row.pattern,
            "description": row.description,
            "invocation_ids": [str(i) for i in (row.invocation_ids or [])],
            "resolved": row.resolved,
            "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
            "resolved_by": row.resolved_by,
            "resolution_note": row.resolution_note,
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


@router.patch("/alerts/{alert_id}")
async def update_anomaly_alert(
    alert_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Resolve or annotate an anomaly alert.
    Required role: admin.
    Emits ANOMALY_ALERT_RESOLVED audit event on resolution.
    """
    _require_roles(request, {"admin"})

    try:
        body = await request.json()
        resolved = body.get("resolved")
        resolution_note = body.get("resolution_note")
    except Exception:
        raise HTTPException(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON body."})

    client_id = getattr(request.state, "client_id", "unknown")

    try:
        # Fetch current alert
        result = await db.execute(
            text("SELECT * FROM anomaly_alerts WHERE alert_id = :alert_id LIMIT 1"),
            {"alert_id": str(alert_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        logger.error("anomaly_alert fetch error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Alert '{alert_id}' not found."})

    updates = ["updated_at = NOW()"]
    update_params: dict = {"alert_id": str(alert_id)}

    if resolved is not None:
        updates.append("resolved = :resolved")
        update_params["resolved"] = resolved
        if resolved:
            updates.append("resolved_at = NOW()")
            updates.append("resolved_by = :resolved_by")
            update_params["resolved_by"] = client_id

    if resolution_note is not None:
        updates.append("resolution_note = :resolution_note")
        update_params["resolution_note"] = resolution_note

    try:
        await db.execute(
            text(
                f"UPDATE anomaly_alerts SET {', '.join(updates)} WHERE alert_id = :alert_id"
            ),
            update_params,
        )
        await db.commit()
    except Exception as exc:
        logger.error("anomaly_alert update error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Update failed."})

    # Emit ANOMALY_ALERT_RESOLVED audit event if resolving
    if resolved:
        try:
            from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
            audit_logger = MCPAuditLogger()
            event = AuditEvent(
                event_type=AuditEventType.ANOMALY_ALERT_RESOLVED,
                client_id=client_id,
                request_id=getattr(request.state, "request_id", ""),
            )
            audit_logger.emit_admin_event(event, extra_fields={
                "alert_id": str(alert_id),
                "resolution_note": resolution_note or "",
            })
        except Exception as exc:
            logger.error("Anomaly alert audit emit failed", extra={"error": str(exc)})

    # Return updated record
    result = await db.execute(
        text("SELECT * FROM anomaly_alerts WHERE alert_id = :alert_id LIMIT 1"),
        {"alert_id": str(alert_id)},
    )
    updated = result.fetchone()

    return JSONResponse(content={
        "alert_id": str(updated.alert_id),
        "client_id": updated.client_id,
        "detected_at": updated.detected_at.isoformat(),
        "anomaly_score": float(updated.anomaly_score),
        "pattern": updated.pattern,
        "description": updated.description,
        "invocation_ids": [str(i) for i in (updated.invocation_ids or [])],
        "resolved": updated.resolved,
        "resolved_at": updated.resolved_at.isoformat() if updated.resolved_at else None,
        "resolved_by": updated.resolved_by,
        "resolution_note": updated.resolution_note,
    })
