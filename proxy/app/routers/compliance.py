"""
MCP Security Platform — Compliance Reporting Router

Implements docs/API.md Section 2.6.

Endpoints:
  GET  /api/v1/compliance/reports        — List compliance reports (admin, auditor)
  GET  /api/v1/compliance/reports/{id}   — Get full compliance report (admin, auditor)
  POST /api/v1/compliance/reports/run    — Trigger on-demand compliance run (admin)
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

router = APIRouter(prefix="/compliance")


def _require_roles(request: Request, allowed: set[str]) -> None:
    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in allowed for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Insufficient role."},
        )


@router.get("/reports")
async def list_compliance_reports(
    request: Request,
    status: Optional[str] = Query(None, pattern="^(pass|fail|in_progress|error)$"),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List compliance report runs, optionally filtered by status and date range.
    Required role: admin, auditor.
    Returns paginated list matching API.md Section 2.6 response shape.
    """
    _require_roles(request, {"admin", "auditor"})

    conditions = ["1=1"]
    params: dict = {}

    if status:
        conditions.append("status = :status")
        params["status"] = status
    if from_date:
        conditions.append("run_at >= :from_date::timestamptz")
        params["from_date"] = from_date
    if to_date:
        conditions.append("run_at <= :to_date::timestamptz")
        params["to_date"] = to_date

    where_clause = " AND ".join(conditions)
    offset = (page - 1) * page_size

    try:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) FROM compliance_reports WHERE {where_clause}"),
            params,
        )
        total_items = count_result.scalar() or 0

        rows_result = await db.execute(
            text(
                f"""
                SELECT report_id, run_at, status, sample_size,
                       categories_checked, categories_failed, archive_url
                FROM compliance_reports
                WHERE {where_clause}
                ORDER BY run_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": page_size, "offset": offset},
        )
        rows = rows_result.fetchall()
    except Exception as exc:
        logger.error("compliance_reports list error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    data = [
        {
            "report_id": str(row.report_id),
            "run_at": row.run_at.isoformat(),
            "status": row.status,
            "sample_size": row.sample_size,
            "categories_checked": row.categories_checked,
            "categories_failed": row.categories_failed,
            "archive_url": row.archive_url,
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


@router.get("/reports/{report_id}")
async def get_compliance_report(
    report_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Retrieve full compliance report including per-category results and hash integrity.
    Required role: admin, auditor.
    """
    _require_roles(request, {"admin", "auditor"})

    try:
        result = await db.execute(
            text(
                """
                SELECT report_id, run_at, period_start, period_end, status,
                       sample_size, categories_checked, categories_failed,
                       results, hash_integrity, archive_url
                FROM compliance_reports
                WHERE report_id = :report_id
                LIMIT 1
                """
            ),
            {"report_id": str(report_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        logger.error("compliance_report fetch error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"Report '{report_id}' not found."},
        )

    results_data = row.results or {}
    categories = results_data.get("categories", [])

    return JSONResponse(content={
        "report_id": str(row.report_id),
        "run_at": row.run_at.isoformat(),
        "status": row.status,
        "sample_size": row.sample_size,
        "period_start": row.period_start.isoformat(),
        "period_end": row.period_end.isoformat(),
        "categories": categories,
        "hash_integrity": row.hash_integrity,
        "archive_url": row.archive_url,
    })


@router.post("/reports/run", status_code=202)
async def trigger_compliance_run(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Trigger an on-demand compliance report run.
    Does not replace the scheduled daily run (COMPLIANCE_CRON_SCHEDULE).
    Required role: admin. Returns 202 with job_id and estimated_seconds.
    """
    from uuid import uuid4
    _require_roles(request, {"admin"})

    try:
        body = await request.json()
        sample_size = int(body.get("sample_size", 500))
        period_hours = int(body.get("period_hours", 24))
        if not (1 <= sample_size <= 10000) or not (1 <= period_hours <= 8760):
            raise ValueError("Out of range")
    except Exception:
        raise HTTPException(400, {"code": "VALIDATION_ERROR", "message": "Invalid body."})

    client_id = getattr(request.state, "client_id", "unknown")
    job_id = f"job_{uuid4().hex[:16]}"

    try:
        await db.execute(
            text(
                """
                INSERT INTO audit_jobs
                  (job_id, job_type, status, created_by, created_at, updated_at)
                VALUES (:job_id, 'compliance_run', 'queued', :created_by, NOW(), NOW())
                """
            ),
            {"job_id": job_id, "created_by": client_id},
        )
        await db.commit()
    except Exception as exc:
        logger.error("audit_jobs insert failed", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Failed to queue job."})

    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
        audit_logger = MCPAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.COMPLIANCE_RUN_TRIGGERED,
            client_id=client_id,
            request_id=getattr(request.state, "request_id", ""),
        )
        audit_logger.emit_admin_event(event, extra_fields={"job_id": job_id})
    except Exception as exc:
        logger.error("Compliance run audit emit failed", extra={"error": str(exc)})

    return JSONResponse(status_code=202, content={
        "job_id": job_id,
        "status": "queued",
        "estimated_seconds": 120,
    })
