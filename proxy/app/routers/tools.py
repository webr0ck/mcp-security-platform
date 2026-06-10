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
  POST   /api/v1/servers/{server_id}/discover-tools  — Discover upstream tools (admin only, Task 13)
"""
from __future__ import annotations

import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tools")
# Also register under /servers for discovery endpoint
servers_router = APIRouter(prefix="/servers")


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

    # MCP-005: cross-server tool-name collision / shadowing check.
    # A tool name registered by a DIFFERENT source than an existing one can
    # shadow a trusted tool in tools/list. Until a server_id FK exists, detect
    # the collision against source_repo and quarantine the newcomer rather than
    # silently allowing two same-named tools to coexist.
    name_collision = await db.execute(
        text(
            "SELECT source_repo FROM tool_registry "
            "WHERE name = :name AND COALESCE(source_repo, '') <> COALESCE(:source_repo, '') "
            "LIMIT 1"
        ),
        {"name": tool_in.name, "source_repo": tool_in.source_repo},
    )
    collision_row = name_collision.fetchone()
    shadow_collision = collision_row is not None

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
    risk_reasons = json.dumps(audit_result.static_analysis.get("risk_flags", []))

    # Critical-risk tools start quarantined (API.md §2.2).
    # MCP-005: a cross-source name collision also starts quarantined — a human
    # must clear it, preventing automatic tool shadowing.
    initial_status = "quarantined" if (risk_level == "critical" or shadow_collision) else "active"
    if shadow_collision:
        logger.warning(
            "MCP-005 tool-name collision: '%s' already registered by a different source "
            "(existing=%r, new=%r) — quarantining the new registration.",
            tool_in.name,
            collision_row[0] if collision_row else None,
            tool_in.source_repo,
        )

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
                   :risk_score, :risk_level, CAST(:risk_reasons AS jsonb), :upstream_url,
                   :source_repo, :source_commit, :tags, CAST(:metadata AS jsonb),
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
                   schema_hash, signature, auditor_version, generated_at)
                VALUES
                  (:sbom_id, :tool_id, :bom_ref, CAST(:cyclonedx_json AS jsonb),
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
                   CAST(:findings AS jsonb), CAST(:llm_analysis AS jsonb), CAST(:static_analysis AS jsonb),
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
                       t.server_id, s.sbom_id, s.signature
                FROM tool_registry t
                LEFT JOIN sbom_records s ON s.tool_id = t.tool_id
                WHERE t.tool_id = :tool_id AND t.deleted_at IS NULL
                ORDER BY s.generated_at DESC
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
        "server_id": str(row.server_id) if row.server_id else None,
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

    # "internal" is NOT a DB-settable status — it is reserved for first-party platform
    # tools and exists only as an OPA policy bypass signal.  Allowing any operator to
    # PATCH a tool's status to "internal" via the API would bypass all OPA gates
    # (quarantine check, risk threshold, and grant checks) for every authenticated role.
    _PATCHABLE_STATUSES = {"active", "quarantined", "deprecated"}
    if new_status and new_status not in _PATCHABLE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_ERROR",
                "message": f"status must be one of {sorted(_PATCHABLE_STATUSES)}",
            },
        )

    # Fetch current tool (with server_id for Task 13)
    try:
        result = await db.execute(
            text("SELECT t.status, t.server_id, s.sbom_id FROM tool_registry t LEFT JOIN sbom_records s ON s.tool_id = t.tool_id WHERE t.tool_id = :id AND t.deleted_at IS NULL ORDER BY s.generated_at DESC LIMIT 1"),
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
        updates.append("metadata = metadata || CAST(:new_metadata AS jsonb)")
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
@router.delete("/{tool_id}", status_code=204, response_class=Response)
async def delete_tool(
    tool_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
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

    # SPDX is not implemented (roadmap). Be honest: return 501 rather than silently
    # serving CycloneDX content under an SPDX request.
    if format == "spdx":
        raise HTTPException(
            501,
            {"code": "NOT_IMPLEMENTED", "message": "SPDX SBOM is not implemented; CycloneDX only."},
        )

    try:
        result = await db.execute(
            text(
                """
                SELECT s.sbom_id, s.cyclonedx_json, s.signature
                FROM sbom_records s
                WHERE s.tool_id = :tool_id
                ORDER BY s.generated_at DESC
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
    from app.services.entitlement import NotEntitledError
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
            SELECT tool_id, name, version, status, risk_level, upstream_url,
                   injection_mode, service_name, inject_header, inject_prefix,
                   kc_client_id, kc_token_audience, server_id
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
        # Credential injection metadata — required by dispatcher (FIND-002 fix)
        "injection_mode": tool_row.injection_mode or "none",
        "service_name": tool_row.service_name,
        "inject_header": tool_row.inject_header or "Authorization",
        "inject_prefix": tool_row.inject_prefix or "Bearer",
        "kc_client_id": tool_row.kc_client_id,
        "kc_token_audience": tool_row.kc_token_audience,
        "server_id": str(tool_row.server_id) if tool_row.server_id else None,
    }

    # ENTITLEMENT CHECK (discovery == invoke invariant)
    #
    # 6.2: per-server entitlement is now enforced inside invoke_tool()
    # (services/invocation.py → enforce_tool_entitlement) using tool_record's
    # server_id (V023). It applies to ALL callers with no role exception and
    # surfaces as NotEntitledError (mapped to 403 below).
    #
    # The status/role guards below remain as defense-in-depth: reject non-active
    # tools and verify the caller holds at least the 'agent' role.
    if tool_record["status"] != "active":
        # INV-001: emit audit event for non-active tool rejections before returning 403.
        # The entitlement check fires before invoke_tool, so we must audit here to
        # preserve the invariant that every invocation attempt is recorded.
        try:
            from app.services.invocation import _emit_audit_event
            await _emit_audit_event(
                tool_id=str(tool_record["tool_id"]),
                tool_name=tool_record["name"],
                tool_version=tool_record.get("version"),
                client_id=client_id,
                outcome="deny",
                deny_reasons=[f"tool_{tool_record['status']}"],
                request_id=request_id,
                latency_ms=0,
                anomaly_score=0.0,
                opa_decision_id="",
                is_testing=False,
            )
        except Exception as _audit_exc:
            logger.warning("Audit emit failed for NOT_ENTITLED denial: %s", _audit_exc)
        raise HTTPException(
            status_code=403,
            detail={
                "code": "NOT_ENTITLED",
                "message": (
                    f"Tool '{tool_record['name']}' has status '{tool_record['status']}' "
                    f"and cannot be invoked."
                ),
            },
        )

    principal_has_agent_role = any(r in {"agent", "admin"} for r in client_roles)
    if not principal_has_agent_role:
        # Belt-and-suspenders: the role check above already blocks this path,
        # but kept here so the entitlement block is self-contained.
        raise HTTPException(
            status_code=403,
            detail={"code": "NOT_ENTITLED", "message": "Principal lacks agent role for tool invocation."},
        )

    try:
        response = await _invoke(
            tool_record=tool_record,
            json_rpc_request=body,
            client_id=client_id,
            client_roles=client_roles,
            is_testing=is_testing,
            request_id=request_id,
            # 6.2: typed principal for the discovery==invoke entitlement gate.
            principal_id=getattr(request.state, "principal_id", None),
            principal_type=getattr(request.state, "principal_type", None),
            # 6.3: caller KC token for oauth_user_token (RFC 8693) on-behalf-of.
            user_kc_token=getattr(request.state, "user_kc_token", None),
        )
        return JSONResponse(content=response)

    except NotEntitledError:
        # 6.2 discovery==invoke: caller not entitled to this tool's server.
        # The synchronous deny audit (INV-001) is emitted at the chokepoint
        # inside invoke_tool() so every path records it uniformly; here we only
        # map to HTTP 403 without leaking the server_id / internal reason.
        raise HTTPException(
            status_code=403,
            detail={
                "code": "NOT_ENTITLED",
                "message": "Not entitled to this tool's server.",
            },
        )

    except ToolQuarantinedError as exc:
        # INV-001: emit audit event for quarantined tool blocks
        try:
            from app.services.invocation import _emit_audit_event
            await _emit_audit_event(
                tool_id=tool_record["tool_id"],
                tool_name=tool_record["name"],
                tool_version=tool_record.get("version"),
                client_id=client_id,
                outcome="deny",
                deny_reasons=["TOOL_QUARANTINED"],
                request_id=request_id,
                latency_ms=0,
                anomaly_score=0.0,
                opa_decision_id="",
                is_testing=is_testing,
            )
        except Exception as audit_exc:
            # OD-004: fail closed. A quarantined-tool block is a high-sensitivity
            # security event; if it cannot be audited synchronously we must not
            # emit a "clean" 403 that leaves no trace. Surface a 500 like every
            # other deny path so the missing audit record is never silent.
            logger.error(
                "Audit emit failed on TOOL_QUARANTINED deny path — failing closed: %s",
                audit_exc,
            )
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "AUDIT_FAILURE",
                    "message": "Denied (quarantined) but audit logging failed; failing closed.",
                },
            ) from audit_exc
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
        # INV-001: audit emission failure is a hard abort.
        # Any other RuntimeError (e.g. credential not found) also returns 500 rather
        # than propagating as an unhandled exception through the ASGI stack.
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": (
                        "Audit emission failed. Invocation aborted per INV-001."
                        if "audit" in str(exc).lower()
                        else str(exc)
                    ),
                    "request_id": request_id,
                }
            },
        )
    except Exception as exc:
        # Catch-all for unexpected exceptions from the invocation layer
        # (e.g. httpx.TimeoutException from upstream, credential errors).
        # Return 503 so the caller knows the upstream is unavailable, not the proxy.
        import httpx as _httpx
        status = 503 if isinstance(exc, (_httpx.TimeoutException, _httpx.ConnectError)) else 500
        return JSONResponse(
            status_code=status,
            content={
                "error": {
                    "code": "UPSTREAM_ERROR",
                    "message": str(exc),
                    "request_id": request_id,
                }
            },
        )


# ---------------------------------------------------------------------------
# POST /servers/{server_id}/discover-tools (Task 13)
# ---------------------------------------------------------------------------
@servers_router.post("/{server_id}/discover-tools", status_code=200)
async def discover_tools(
    server_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Discover tools from an approved upstream MCP server.

    Calls the upstream server's /tools/list endpoint, registers returned tools
    with status='quarantined' (INV-005 default), and returns discovery results.

    Required role: admin (platform_admin)

    Per Task 13 specification:
    1. Verify server exists and status='approved' (404 if not)
    2. Call upstream {server.upstream_url}/tools/list via MCP tools/list endpoint
    3. For each tool returned:
       - Check if (server_id, tool_name) already exists
       - If new: INSERT into tool_registry with status='quarantined', server_id set
       - If exists: skip (idempotent)
    4. Return {"discovered": N, "tools": [...]}

    INV-005: New tools start quarantined. No role exception.
    """
    import json
    import logging
    from sqlalchemy import text
    import httpx

    logger = logging.getLogger(__name__)

    roles: list[str] = getattr(request.state, "client_roles", [])
    client_id: str = getattr(request.state, "client_id", "unknown")

    if "admin" not in roles and "platform_admin" not in roles:
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Requires admin role."},
        )

    # Step 1: Fetch and validate server
    try:
        result = await db.execute(
            text(
                """
                SELECT server_id, upstream_url, service_name, status
                FROM server_registry
                WHERE server_id = :server_id AND deleted_at IS NULL
                LIMIT 1
                """
            ),
            {"server_id": server_id},
        )
        server_row = result.fetchone()
    except Exception as exc:
        logger.error("discover_tools query error", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Query failed."})

    if server_row is None:
        raise HTTPException(404, {"code": "NOT_FOUND", "message": f"Server '{server_id}' not found."})

    if server_row.status != "approved":
        raise HTTPException(
            403,
            {
                "code": "FORBIDDEN",
                "message": f"Server must be approved to discover tools (status={server_row.status}).",
            },
        )

    upstream_url = server_row.upstream_url

    # Step 2: Call upstream server's /tools/list endpoint
    # Format: POST {upstream_url} with MCP tools/list JSON-RPC request
    try:
        async with httpx.AsyncClient() as client:
            # Initialize session (if needed by the upstream server)
            init_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "mcp-security-platform",
                        "version": "1.0.0",
                    },
                },
            }
            init_resp = await client.post(upstream_url, json=init_payload, timeout=10)
            init_resp.raise_for_status()

            # Get tools/list (session_id from init may be needed)
            session_id = init_resp.headers.get("Mcp-Session-Id")
            tools_payload = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            }
            headers = {}
            if session_id:
                headers["Mcp-Session-Id"] = session_id

            tools_resp = await client.post(upstream_url, json=tools_payload, headers=headers, timeout=10)
            tools_resp.raise_for_status()
            tools_data = tools_resp.json()

    except httpx.TimeoutException as exc:
        logger.warning(
            "discover_tools upstream timeout",
            extra={"server_id": server_id, "upstream_url": upstream_url, "error": str(exc)},
        )
        raise HTTPException(
            503,
            {"code": "UPSTREAM_UNAVAILABLE", "message": f"Upstream server unreachable: {exc}"},
        )
    except Exception as exc:
        logger.error(
            "discover_tools upstream call failed",
            extra={"server_id": server_id, "upstream_url": upstream_url, "error": str(exc)},
        )
        raise HTTPException(
            503,
            {"code": "UPSTREAM_ERROR", "message": f"Failed to call upstream: {exc}"},
        )

    # Extract tools from MCP response
    tools_list = tools_data.get("result", {}).get("tools", [])

    # Step 3: Register each tool
    discovered = 0
    registered_tools = []

    for tool_data in tools_list:
        tool_name = tool_data.get("name")
        if not tool_name:
            logger.warning("Skipping tool with no name from upstream")
            continue

        # Check if already registered for this server
        try:
            dup_result = await db.execute(
                text(
                    """
                    SELECT tool_id FROM tool_registry
                    WHERE server_id = :server_id AND name = :name
                    LIMIT 1
                    """
                ),
                {"server_id": server_id, "name": tool_name},
            )
            if dup_result.fetchone() is not None:
                logger.info(
                    "Tool already registered for server",
                    extra={"server_id": server_id, "tool_name": tool_name},
                )
                continue
        except Exception as exc:
            logger.error("duplicate check failed", extra={"error": str(exc)})
            continue

        # Insert new tool with status='quarantined' (INV-005)
        try:
            tool_id = str(uuid.uuid4())
            description = tool_data.get("description", f"{tool_name} from {server_row.service_name}")
            input_schema = tool_data.get("inputSchema", {"type": "object", "properties": {}})
            risk_level = tool_data.get("risk", "medium")  # advisory, not enforced

            await db.execute(
                text(
                    """
                    INSERT INTO tool_registry (
                        tool_id, name, version, description, schema,
                        upstream_url, server_id, status, risk_level, risk_score,
                        risk_reasons, registered_by, created_at, updated_at
                    ) VALUES (
                        :tool_id, :name, :version, :description, CAST(:schema AS jsonb),
                        :upstream_url, :server_id, 'quarantined', :risk_level, 20,
                        CAST(:risk_reasons AS jsonb), :registered_by, NOW(), NOW()
                    )
                    """
                ),
                {
                    "tool_id": tool_id,
                    "name": tool_name,
                    "version": "1.0.0",  # Tools from discovery are versioned 1.0.0
                    "description": description,
                    "schema": json.dumps(input_schema),
                    "upstream_url": upstream_url,
                    "server_id": server_id,
                    "risk_level": risk_level,
                    "risk_reasons": json.dumps(["discovered"]),
                    "registered_by": client_id,
                },
            )
            discovered += 1
            registered_tools.append({
                "tool_id": tool_id,
                "name": tool_name,
                "status": "quarantined",
                "server_id": server_id,
            })

            logger.info(
                "Tool discovered and registered",
                extra={"tool_id": tool_id, "tool_name": tool_name, "server_id": server_id},
            )

        except Exception as exc:
            logger.error(
                "Tool registration failed",
                extra={"tool_name": tool_name, "server_id": server_id, "error": str(exc)},
            )
            continue

    # Commit all registrations
    try:
        await db.commit()
    except Exception as exc:
        logger.error("discover_tools commit failed", extra={"error": str(exc)})
        raise HTTPException(500, {"code": "INTERNAL_ERROR", "message": "Tool registration failed."})

    return JSONResponse(
        status_code=200,
        content={
            "discovered": discovered,
            "tools": registered_tools,
        },
    )
