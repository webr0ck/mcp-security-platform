"""
MCP Security Platform — Tool Registry Router

Implements the tool registry API per docs/API.md Section 2.2 and 2.3.

Endpoints:
  POST   /api/v1/tools/register          — Register a new MCP tool (admin only)
  GET    /api/v1/tools                   — List tools (admin, auditor, readonly)
  GET    /api/v1/tools/{tool_id}         — Get full tool record
  PATCH  /api/v1/tools/{tool_id}         — Update tool status/metadata (admin only)
  DELETE /api/v1/tools/{tool_id}         — Soft-delete tool (admin only)
  GET    /api/v1/tools/{tool_id}/audit   — Get audit result (admin, auditor)
  POST   /api/v1/tools/{tool_id}/audit/rerun  — Re-run audit (admin only)
  GET    /api/v1/tools/{tool_id}/sbom    — Get SBOM (admin, auditor, readonly)
  POST   /api/v1/tools/{tool_id}/invoke  — Invoke a tool (agent, admin)
"""
from __future__ import annotations

import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

router = APIRouter(prefix="/tools")


# ---------------------------------------------------------------------------
# POST /tools/register
# ---------------------------------------------------------------------------
@router.post("/register", status_code=201)
async def register_tool(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Register a new MCP tool. Triggers Tool Manifest Auditor and SBOM generation.
    Required role: admin.

    Per ARCHITECTURE.md Section 5.2 registration pipeline:
    1. Validate and parse request body
    2. Check for duplicate name+version (409 CONFLICT)
    3. Run Tool Manifest Auditor (static + LLM scoring)
    4. Generate and sign CycloneDX SBOM (INV-006)
    5. Persist tool_registry + sbom_records + tool_audit_results rows
    6. Emit TOOL_REGISTERED audit event
    7. If risk_level=critical: quarantine + optional Jira issue
    """
    import json
    import logging
    from datetime import datetime, timezone
    from uuid import uuid4

    from sqlalchemy import text

    from app.models.tool import ToolCreate
    from app.services.auditor import run_audit as _run_audit
    from app.services.sbom import generate_cyclonedx_sbom, publish_to_artifactory

    logger = logging.getLogger(__name__)

    client_roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "unknown")
    request_id: str = getattr(request.state, "request_id", "")

    if "admin" not in client_roles:
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Requires admin role."},
        )

    try:
        raw_body = await request.json()
        tool_in = ToolCreate(**raw_body)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "VALIDATION_ERROR", "message": str(exc)},
        )

    # Duplicate check (name + version)
    dup_result = await db.execute(
        text(
            "SELECT tool_id FROM tool_registry WHERE name = :name AND version = :version LIMIT 1"
        ),
        {"name": tool_in.name, "version": tool_in.version},
    )
    if dup_result.fetchone() is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "CONFLICT",
                "message": f"Tool '{tool_in.name}@{tool_in.version}' already registered.",
            },
        )

    # Run auditor
    tool_id = str(uuid4())
    audit_result = await _run_audit(
        tool_id=tool_id,
        tool_name=tool_in.name,
        description=tool_in.description,
        schema=tool_in.schema,
        source_repo=tool_in.source_repo,
        tags=tool_in.tags,
    )

    risk_score = audit_result.risk_score
    risk_level = audit_result.risk_level
    risk_reasons = json.dumps(audit_result.risk_reasons)

    # Critical-risk tools start quarantined (API.md §2.2)
    initial_status = "quarantined" if risk_level == "critical" else "active"

    # Generate and sign SBOM (INV-006)
    bom_document, schema_hash, sbom_signature = generate_cyclonedx_sbom(
        tool_id=tool_id,
        tool_name=tool_in.name,
        tool_version=tool_in.version,
        description=tool_in.description,
        schema=tool_in.schema,
        source_repo=tool_in.source_repo,
        source_commit=tool_in.source_commit,
        tags=tool_in.tags,
        risk_score=risk_score,
        risk_level=risk_level,
    )

    sbom_id = str(uuid4())
    bom_serial = str(uuid4())
    registered_at = datetime.now(timezone.utc)

    try:
        # Persist tool_registry
        await db.execute(
            text(
                """
                INSERT INTO tool_registry
                  (tool_id, name, version, description, schema, status,
                   risk_score, risk_level, risk_reasons, upstream_url,
                   source_repo, source_commit, tags, metadata,
                   registered_by, created_at, updated_at)
                VALUES
                  (:tool_id, :name, :version, :description, :schema, :status,
                   :risk_score, :risk_level, :risk_reasons::jsonb, :upstream_url,
                   :source_repo, :source_commit, :tags, :metadata::jsonb,
                   :registered_by, :created_at, :created_at)
                """
            ),
            {
                "tool_id": tool_id,
                "name": tool_in.name,
                "version": tool_in.version,
                "description": tool_in.description,
                "schema": json.dumps(tool_in.schema),
                "status": initial_status,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "risk_reasons": risk_reasons,
                "upstream_url": str(tool_in.upstream_url),
                "source_repo": tool_in.source_repo,
                "source_commit": tool_in.source_commit,
                "tags": tool_in.tags,
                "metadata": json.dumps(tool_in.metadata),
                "registered_by": client_id,
                "created_at": registered_at,
            },
        )

        # Persist sbom_records (INV-006: signature NOT NULL)
        await db.execute(
            text(
                """
                INSERT INTO sbom_records
                  (sbom_id, tool_id, bom_ref, cyclonedx_json,
                   schema_hash, signature, auditor_version, created_at)
                VALUES
                  (:sbom_id, :tool_id, :bom_ref, :cyclonedx_json::jsonb,
                   :schema_hash, :signature, :auditor_version, NOW())
                """
            ),
            {
                "sbom_id": sbom_id,
                "tool_id": tool_id,
                "bom_ref": bom_serial,
                "cyclonedx_json": json.dumps(bom_document),
                "schema_hash": schema_hash,
                "signature": sbom_signature,
                "auditor_version": (
                    audit_result.auditor_version
                    if hasattr(audit_result, "auditor_version")
                    else "1.0.0"
                ),
            },
        )

        # Persist tool_audit_results (immutable)
        await db.execute(
            text(
                """
                INSERT INTO tool_audit_results
                  (audit_result_id, tool_id, auditor_version, risk_score, risk_level,
                   findings, llm_analysis, static_analysis, created_at)
                VALUES
                  (:audit_result_id, :tool_id, :auditor_version, :risk_score, :risk_level,
                   :findings::jsonb, :llm_analysis::jsonb, :static_analysis::jsonb,
                   NOW())
                """
            ),
            {
                "audit_result_id": str(uuid4()),
                "tool_id": tool_id,
                "auditor_version": audit_result.auditor_version if hasattr(audit_result, "auditor_version") else "1.0.0",
                "risk_score": risk_score,
                "risk_level": risk_level,
                "findings": json.dumps([]),
                "llm_analysis": json.dumps(audit_result.llm_analysis or {}),
                "static_analysis": json.dumps(audit_result.static_analysis or {}),
            },
        )

        await db.commit()

    except Exception as exc:
        logger.error("Tool registration DB write failed", extra={"error": str(exc), "tool_name": tool_in.name})
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL_ERROR", "message": "Tool registration failed."},
        )

    # Emit TOOL_REGISTERED audit event
    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
        audit_logger = MCPAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.TOOL_REGISTERED,
            client_id=client_id,
            request_id=request_id,
        )
        audit_logger.emit_admin_event(event, extra_fields={
            "tool_id": tool_id,
            "tool_name": tool_in.name,
            "version": tool_in.version,
            "risk_level": risk_level,
        })
    except Exception as exc:
        logger.error("Tool registration audit emit failed", extra={"error": str(exc)})

    # Optional: Publish SBOM to Artifactory
    try:
        await publish_to_artifactory(tool_in.name, tool_in.version, bom_document)
    except Exception as exc:
        logger.warning("Artifactory publish failed (non-blocking)", extra={"error": str(exc)})

    # Optional: Create Jira issue for critical/quarantined tools
    if risk_level == "critical":
        logger.info(
            "Critical-risk tool registered; Jira issue creation would fire here",
            extra={"tool_id": tool_id, "tool_name": tool_in.name},
        )

    return JSONResponse(
        status_code=201,
        content={
            "tool_id": tool_id,
            "name": tool_in.name,
            "version": tool_in.version,
            "status": initial_status,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_reasons": json.loads(risk_reasons),
            "sbom_ref": sbom_id,
            "sbom_signature": sbom_signature,
            "registered_at": registered_at.isoformat(),
            "registered_by": client_id,
        },
    )


# ---------------------------------------------------------------------------
# GET /tools
# ---------------------------------------------------------------------------
@router.get("")
async def list_tools(
    request: Request,
    status: Optional[str] = Query(None, pattern="^(active|quarantined|deprecated)$"),
    risk_level: Optional[str] = Query(None, pattern="^(low|medium|high|critical)$"),
    tag: Optional[list[str]] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    List registered tools. Response fields filtered by caller role.
    Required role: admin, auditor, readonly (readonly gets name/version only).
    """
    import json
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in {"admin", "agent", "auditor", "readonly"} for r in roles):
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Insufficient role."})

    is_readonly = "readonly" in roles and "admin" not in roles and "auditor" not in roles

    conditions = ["deleted_at IS NULL"]
    params: dict = {}
    if status:
        conditions.append("status = :status")
        params["status"] = status
    if risk_level:
        conditions.append("risk_level = :risk_level")
        params["risk_level"] = risk_level
    if tag:
        conditions.append("tags @> :tags")
        params["tags"] = tag

    where_clause = " AND ".join(conditions)
    offset = (page - 1) * page_size

    try:
        count_result = await db.execute(
            text(f"SELECT COUNT(*) FROM tool_registry WHERE {where_clause}"), params
        )
        total_items = count_result.scalar() or 0

        rows_result = await db.execute(
            text(
                f"""
                SELECT tool_id, name, version, status, risk_score, risk_level, tags, created_at
                FROM tool_registry
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """
            ),
            {**params, "limit": page_size, "offset": offset},
        )
        rows = rows_result.fetchall()
    except Exception as exc:
        logger.error("list_tools query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    data = []
    for row in rows:
        item: dict = {
            "tool_id": str(row.tool_id),
            "name": row.name,
            "version": row.version,
            "status": row.status,
            "tags": row.tags or [],
            "registered_at": row.created_at.isoformat(),
        }
        if not is_readonly:
            item["risk_score"] = row.risk_score
            item["risk_level"] = row.risk_level
        data.append(item)

    return JSONResponse(content={
        "data": data,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total_items": total_items,
            "total_pages": max(1, -(-total_items // page_size)),
        },
    })


# ---------------------------------------------------------------------------
# GET /tools/{tool_id}
# ---------------------------------------------------------------------------
@router.get("/{tool_id}")
async def get_tool(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Get full tool record. Fields filtered by caller role.
    Per RBAC.md: readonly omits schema, upstream_url, source_commit, risk_reasons.
    Required role: admin, auditor, readonly, agent.
    """
    import json
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in {"admin", "auditor", "readonly", "agent"} for r in roles):
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Insufficient role."})

    is_readonly = "readonly" in roles and not any(r in {"admin", "auditor", "agent"} for r in roles)

    try:
        result = await db.execute(
            text(
                """
                SELECT t.tool_id, t.name, t.version, t.description, t.schema,
                       t.status, t.risk_score, t.risk_level, t.risk_reasons,
                       t.source_repo, t.source_commit, t.upstream_url,
                       t.tags, t.metadata, t.registered_by, t.created_at, t.updated_at,
                       s.sbom_id, s.signature
                FROM tool_registry t
                LEFT JOIN sbom_records s ON s.tool_id = t.tool_id
                WHERE t.tool_id = :tool_id AND t.deleted_at IS NULL
                ORDER BY s.created_at DESC
                LIMIT 1
                """
            ),
            {"tool_id": str(tool_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        logger.error("get_tool query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."})

    data: dict = {
        "tool_id": str(row.tool_id),
        "name": row.name,
        "version": row.version,
        "description": row.description,
        "status": row.status,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "tags": row.tags or [],
        "metadata": row.metadata or {},
        "registered_by": row.registered_by,
        "registered_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "sbom_ref": str(row.sbom_id) if row.sbom_id else None,
    }

    if not is_readonly:
        data["schema"] = row.schema
        data["upstream_url"] = row.upstream_url
        data["source_repo"] = row.source_repo
        data["source_commit"] = row.source_commit
        data["risk_reasons"] = row.risk_reasons or []
        data["sbom_signature"] = row.signature

    return JSONResponse(content=data)


# ---------------------------------------------------------------------------
# PATCH /tools/{tool_id}
# ---------------------------------------------------------------------------
@router.patch("/{tool_id}")
async def update_tool(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Update tool status or metadata. Cannot change name, version, or schema.
    Required role: admin.
    Emits TOOL_STATUS_CHANGED audit event on status change.
    Per INV-006: activating a tool requires a valid SBOM signature.
    """
    import json
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "unknown")

    if "admin" not in roles:
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Requires admin role."})

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON."})

    new_status = body.get("status")
    new_metadata = body.get("metadata")

    # Fetch current tool
    try:
        result = await db.execute(
            text("SELECT status, sbom_id FROM tool_registry t LEFT JOIN sbom_records s ON s.tool_id = t.tool_id WHERE t.tool_id = :id AND t.deleted_at IS NULL ORDER BY s.created_at DESC LIMIT 1"),
            {"id": str(tool_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": str(exc)})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."})

    old_status = row.status

    updates = ["updated_at = NOW()"]
    update_params: dict = {"tool_id": str(tool_id)}

    if new_status:
        # INV-006: cannot activate without SBOM signature
        if new_status == "active" and not row.sbom_id:
            raise HTTPException(
                status_code=422,
                detail={"code": "SCHEMA_INVALID", "message": "Cannot activate: tool has no signed SBOM (INV-006)."},
            )
        updates.append("status = :new_status")
        update_params["new_status"] = new_status

    if new_metadata is not None:
        # Merge (not replace) metadata
        updates.append("metadata = metadata || :new_metadata::jsonb")
        update_params["new_metadata"] = json.dumps(new_metadata)

    try:
        await db.execute(
            text(f"UPDATE tool_registry SET {', '.join(updates)} WHERE tool_id = :tool_id"),
            update_params,
        )
        await db.commit()
    except Exception as exc:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Update failed."})

    # Emit audit event on status change
    if new_status and new_status != old_status:
        try:
            from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
            audit_logger = MCPAuditLogger()
            event = AuditEvent(
                event_type=AuditEventType.TOOL_STATUS_CHANGED,
                client_id=client_id,
                request_id=getattr(request.state, "request_id", ""),
            )
            audit_logger.emit_admin_event(event, extra_fields={
                "tool_id": str(tool_id),
                "old_status": old_status,
                "new_status": new_status,
            })
        except Exception as exc:
            logger.error("update_tool audit emit failed", extra={"error": str(exc)})

    # Return updated record via get_tool
    return await get_tool(tool_id, request, db)


# ---------------------------------------------------------------------------
# DELETE /tools/{tool_id}
# ---------------------------------------------------------------------------
@router.delete("/{tool_id}", status_code=204)
async def delete_tool(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Soft-delete a tool (sets deleted_at, status=deprecated).
    Required role: admin.
    Historical audit references remain valid.
    """
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "unknown")

    if "admin" not in roles:
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Requires admin role."})

    try:
        result = await db.execute(
            text("SELECT name FROM tool_registry WHERE tool_id = :id AND deleted_at IS NULL LIMIT 1"),
            {"id": str(tool_id)},
        )
        row = result.fetchone()
    except Exception:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."})

    tool_name = row.name

    try:
        await db.execute(
            text(
                "UPDATE tool_registry SET status = 'deprecated', deleted_at = NOW(), updated_at = NOW() WHERE tool_id = :id"
            ),
            {"id": str(tool_id)},
        )
        await db.commit()
    except Exception as exc:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Delete failed."})

    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
        audit_logger = MCPAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.TOOL_DELETED,
            client_id=client_id,
            request_id=getattr(request.state, "request_id", ""),
        )
        audit_logger.emit_admin_event(event, extra_fields={
            "tool_id": str(tool_id),
            "tool_name": tool_name,
        })
    except Exception as exc:
        logger.error("delete_tool audit emit failed", extra={"error": str(exc)})


# ---------------------------------------------------------------------------
# GET /tools/{tool_id}/audit
# ---------------------------------------------------------------------------
@router.get("/{tool_id}/audit")
async def get_tool_audit(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Get the Tool Manifest Auditor result for a tool (latest audit run).
    Required role: admin, auditor.
    """
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in {"admin", "auditor"} for r in roles):
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Insufficient role."})

    try:
        result = await db.execute(
            text(
                """
                SELECT audit_result_id, tool_id, auditor_version, risk_score, risk_level,
                       findings, llm_analysis, static_analysis, created_at, audited_at
                FROM tool_audit_results
                WHERE tool_id = :tool_id
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"tool_id": str(tool_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        logger.error("get_tool_audit query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"No audit found for tool '{tool_id}'."})

    return JSONResponse(content={
        "tool_id": str(row.tool_id),
        "audit_id": str(row.audit_result_id),
        "audited_at": (row.audited_at or row.created_at).isoformat(),
        "auditor_version": row.auditor_version,
        "risk_score": row.risk_score,
        "risk_level": row.risk_level,
        "findings": row.findings or [],
        "llm_analysis": row.llm_analysis,
        "static_analysis": row.static_analysis,
    })


# ---------------------------------------------------------------------------
# POST /tools/{tool_id}/audit/rerun
# ---------------------------------------------------------------------------
@router.post("/{tool_id}/audit/rerun", status_code=202)
async def rerun_audit(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Re-run the Tool Manifest Auditor on an existing tool (e.g. after Ollama model update).
    Required role: admin.
    Returns 202 Accepted with audit_job_id and estimated_seconds.
    """
    import logging
    from uuid import uuid4
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "unknown")

    if "admin" not in roles:
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Requires admin role."})

    # Verify tool exists
    try:
        result = await db.execute(
            text("SELECT tool_id FROM tool_registry WHERE tool_id = :id AND deleted_at IS NULL LIMIT 1"),
            {"id": str(tool_id)},
        )
        if result.fetchone() is None:
            raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."})
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": str(exc)})

    job_id = f"job_{uuid4().hex[:16]}"

    try:
        await db.execute(
            text(
                """
                INSERT INTO audit_jobs
                  (job_id, job_type, status, reference_id, created_by, created_at, updated_at)
                VALUES (:job_id, 'tool_audit', 'queued', :reference_id, :created_by, NOW(), NOW())
                """
            ),
            {"job_id": job_id, "reference_id": str(tool_id), "created_by": client_id},
        )
        await db.commit()
    except Exception as exc:
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Failed to queue job."})

    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
        audit_logger = MCPAuditLogger()
        event = AuditEvent(
            event_type=AuditEventType.AUDIT_RERUN_TRIGGERED,
            client_id=client_id,
            request_id=getattr(request.state, "request_id", ""),
        )
        audit_logger.emit_admin_event(event, extra_fields={
            "tool_id": str(tool_id),
            "job_id": job_id,
        })
    except Exception as exc:
        logger.error("rerun_audit audit emit failed", extra={"error": str(exc)})

    return JSONResponse(status_code=202, content={
        "audit_job_id": job_id,
        "status": "queued",
        "estimated_seconds": 15,
    })


# ---------------------------------------------------------------------------
# GET /tools/{tool_id}/sbom
# ---------------------------------------------------------------------------
@router.get("/{tool_id}/sbom")
async def get_tool_sbom(
    tool_id: uuid.UUID,
    request: Request,
    format: Optional[str] = Query("cyclonedx", pattern="^(cyclonedx|spdx)$"),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Retrieve the CycloneDX SBOM for a registered tool.
    Required role: admin, auditor, readonly (readonly: no signature field per RBAC.md 3.2).
    Content-Type: application/vnd.cyclonedx+json
    """
    import json
    import logging
    from sqlalchemy import text

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    if not any(r in {"admin", "auditor", "readonly"} for r in roles):
        raise HTTPException(403, {"code": "FORBIDDEN", "message": "Insufficient role."})

    is_readonly = "readonly" in roles and not any(r in {"admin", "auditor"} for r in roles)

    try:
        result = await db.execute(
            text(
                """
                SELECT s.sbom_id, s.cyclonedx_json, s.signature
                FROM sbom_records s
                WHERE s.tool_id = :tool_id
                ORDER BY s.created_at DESC
                LIMIT 1
                """
            ),
            {"tool_id": str(tool_id)},
        )
        row = result.fetchone()
    except Exception as exc:
        logger.error("get_tool_sbom query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"No SBOM found for tool '{tool_id}'."})

    bom_doc = row.cyclonedx_json if isinstance(row.cyclonedx_json, dict) else json.loads(row.cyclonedx_json)

    # Readonly: strip signature field (RBAC.md 3.2)
    if is_readonly:
        bom_doc.pop("signature", None)

    content_type = "application/vnd.cyclonedx+json"
    return JSONResponse(content=bom_doc, headers={"Content-Type": content_type})


# ---------------------------------------------------------------------------
# POST /tools/{tool_id}/invoke
# ---------------------------------------------------------------------------
@router.post("/{tool_id}/invoke")
async def invoke_tool(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Invoke a registered MCP tool (primary MCP JSON-RPC proxy endpoint).
    Required role: agent (OPA-gated), admin (for testing only).

    Critical security path — ARCHITECTURE.md Section 5.1:
    INV-001: Audit event emitted before response, synchronously.
    INV-004: Returns 503 if OPA is unreachable (fail-closed).
    INV-005: Quarantined tools blocked before OPA evaluation.
    """
    from app.services.invocation import (
        ToolDeprecatedError,
        ToolQuarantinedError,
        invoke_tool as _invoke,
    )
    from app.services.policy import OPADenyError, OPAUnavailableError

    client_roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "")
    request_id: str = getattr(request.state, "request_id", "")

    # Role check: only agent and admin may invoke tools
    if not any(r in {"admin", "agent"} for r in client_roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Tool invocation requires agent or admin role."},
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail={"code": "VALIDATION_ERROR", "message": "Invalid JSON body."},
        )

    # Validate JSON-RPC structure
    if body.get("jsonrpc") != "2.0" or body.get("method") != "tools/call":
        raise HTTPException(
            status_code=400,
            detail={
                "code": "VALIDATION_ERROR",
                "message": "Request must be JSON-RPC 2.0 with method 'tools/call'.",
            },
        )

    is_testing = "admin" in client_roles and "agent" not in client_roles

    # Load tool record
    from sqlalchemy import text

    result = await db.execute(
        text(
            """
            SELECT tool_id, name, version, status, risk_level, upstream_url
            FROM tool_registry
            WHERE tool_id = :tool_id AND deleted_at IS NULL
            LIMIT 1
            """
        ),
        {"tool_id": str(tool_id)},
    )
    tool_row = result.fetchone()
    if tool_row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."},
        )

    tool_record = {
        "tool_id": str(tool_row.tool_id),
        "name": tool_row.name,
        "version": tool_row.version,
        "status": tool_row.status,
        "risk_level": tool_row.risk_level,
        "upstream_url": tool_row.upstream_url,
    }

    try:
        response = await _invoke(
            tool_record=tool_record,
            json_rpc_request=body,
            client_id=client_id,
            client_roles=client_roles,
            is_testing=is_testing,
            request_id=request_id,
        )
        return JSONResponse(content=response)

    except ToolQuarantinedError as exc:
        return JSONResponse(
            status_code=403,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Tool invocation denied.",
                    "data": {
                        "opa_reasons": ["TOOL_QUARANTINED"],
                        "detail": str(exc),
                    },
                },
            },
        )
    except ToolDeprecatedError as exc:
        return JSONResponse(
            status_code=403,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Tool is deprecated.",
                    "data": {"detail": str(exc)},
                },
            },
        )
    except OPADenyError as exc:
        return JSONResponse(
            status_code=403,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "error": {
                    "code": -32603,
                    "message": "Tool invocation denied by policy.",
                    "data": {
                        "opa_reasons": exc.reasons if hasattr(exc, "reasons") else [str(exc)],
                        "audit_id": "see X-Request-ID",
                    },
                },
            },
        )
    except OPAUnavailableError as exc:
        # INV-004: fail-closed on OPA unreachable
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "OPA_UNAVAILABLE",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )
    except RuntimeError as exc:
        # INV-001: audit emission failure
        if "audit" in str(exc).lower():
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Audit emission failed. Invocation aborted per INV-001.",
                        "request_id": request_id,
                    }
                },
            )
        raise
