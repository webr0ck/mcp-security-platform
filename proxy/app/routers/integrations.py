"""
MCP Security Platform — Integration Webhooks Router

Implements docs/API.md Section 2.10.

Endpoints:
  POST /api/v1/integrations/jira/webhook — Receive Jira issue state changes

Authentication: Verified via X-Jira-Webhook-Secret header (shared secret).
This endpoint does NOT use the standard RBAC middleware — it is verified by secret.

See docs/ARCHITECTURE.md Section 8.2 for Jira integration design.
"""
from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import verify_jira_webhook
from fastapi import Depends

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/integrations")

# Jira status names that indicate security review approval.
# "Done" and "Approved" are conventional; extend via JIRA_APPROVAL_STATUSES env var if needed.
_JIRA_APPROVAL_STATUSES: frozenset[str] = frozenset({"done", "approved", "resolved"})


@router.post("/jira/webhook")
async def jira_webhook(
    request: Request,
    x_jira_webhook_secret: str = Header(default="", alias="X-Jira-Webhook-Secret"),
    db: AsyncSession = Depends(get_db),
) -> JSONResponse:
    """
    Receive Jira issue state change webhooks.

    Authenticated by X-Jira-Webhook-Secret shared secret (not RBAC role).
    Used to activate quarantined tools after security team approval in Jira.

    Processing logic (API.md §2.10):
      1. Verify X-Jira-Webhook-Secret against JIRA_WEBHOOK_SECRET env var (HMAC-SHA-256).
      2. Parse Jira webhook payload — extract issue.key and issue.status.name.
      3. If status in {done, approved, resolved}: look up tool linked to Jira issue.
      4. Set tool status to 'active' if currently 'quarantined'.
      5. Emit TOOL_STATUS_CHANGED audit event.
      6. Return {"processed": true, "action": "tool_activated", "tool_id": ...}

    If the issue status does not indicate approval, returns action: "no_action".
    If no quarantined tool is linked to the Jira issue key, returns action: "tool_not_found".

    Raises:
        HTTP 503 if JIRA_ENABLED is false.
        HTTP 401 if webhook secret verification fails.
        HTTP 422 if the payload is malformed (missing issue.key or issue.status.name).
    """
    if not settings.JIRA_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={"code": "JIRA_DISABLED", "message": "Jira integration is not enabled."},
        )

    body_bytes = await request.body()

    if not verify_jira_webhook(body_bytes, x_jira_webhook_secret):
        logger.warning(
            "Jira webhook secret verification failed",
            extra={"remote": request.client.host if request.client else "unknown"},
        )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "WEBHOOK_AUTH_FAILED",
                "message": "Jira webhook secret verification failed.",
            },
        )

    # Parse the Jira webhook JSON payload
    try:
        payload: dict[str, Any] = await request.json()
    except Exception:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_PAYLOAD", "message": "Webhook payload is not valid JSON."},
        )

    # Extract issue key and status from Jira payload structure.
    # Standard Jira webhook: {"issue": {"key": "MSEC-123", "fields": {"status": {"name": "Done"}}}}
    issue: dict[str, Any] = payload.get("issue", {})
    issue_key: str = issue.get("key", "").strip()
    issue_fields: dict[str, Any] = issue.get("fields", {})
    status_obj: dict[str, Any] = issue_fields.get("status", {})
    status_name: str = status_obj.get("name", "").strip()

    if not issue_key:
        raise HTTPException(
            status_code=422,
            detail={"code": "MISSING_ISSUE_KEY", "message": "Jira webhook payload missing issue.key."},
        )
    if not status_name:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "MISSING_ISSUE_STATUS",
                "message": "Jira webhook payload missing issue.fields.status.name.",
            },
        )

    logger.info(
        "Jira webhook received",
        extra={"issue_key": issue_key, "status_name": status_name},
    )

    # Check if this status indicates approval
    if status_name.lower() not in _JIRA_APPROVAL_STATUSES:
        return JSONResponse(
            status_code=200,
            content={
                "processed": True,
                "action": "no_action",
                "reason": f"Status '{status_name}' is not an approval status.",
            },
        )

    # Look up tool linked to this Jira issue key.
    # Convention: tool_registry.metadata->>'jira_issue_key' holds the linked issue.
    try:
        row_result = await db.execute(
            text(
                """
                SELECT tool_id, name, status
                FROM tool_registry
                WHERE metadata->>'jira_issue_key' = :issue_key
                  AND deleted_at IS NULL
                LIMIT 1
                """
            ),
            {"issue_key": issue_key},
        )
        tool_row = row_result.fetchone()
    except Exception as exc:
        logger.error("DB error looking up tool for Jira issue", extra={"issue_key": issue_key, "error": str(exc)})
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL_ERROR", "message": "Database lookup failed."},
        )

    if tool_row is None:
        logger.info(
            "No tool linked to Jira issue",
            extra={"issue_key": issue_key},
        )
        return JSONResponse(
            status_code=200,
            content={
                "processed": True,
                "action": "tool_not_found",
                "reason": f"No tool linked to Jira issue {issue_key}.",
            },
        )

    tool_id: UUID = tool_row.tool_id
    tool_name: str = tool_row.name
    tool_status: str = tool_row.status

    # Only activate quarantined tools — already-active tools are a no-op.
    if tool_status != "quarantined":
        logger.info(
            "Tool is not quarantined — no action taken",
            extra={"tool_id": str(tool_id), "tool_name": tool_name, "status": tool_status},
        )
        return JSONResponse(
            status_code=200,
            content={
                "processed": True,
                "action": "no_action",
                "reason": f"Tool '{tool_name}' has status '{tool_status}'; only quarantined tools can be activated via Jira webhook.",
            },
        )

    # Check that a signed SBOM exists before allowing activation (INV-006).
    try:
        sbom_check_result = await db.execute(
            text(
                """
                SELECT sbom_id FROM sbom_records
                WHERE tool_id = :tool_id
                  AND signature IS NOT NULL
                ORDER BY created_at DESC
                LIMIT 1
                """
            ),
            {"tool_id": str(tool_id)},
        )
        sbom_row = sbom_check_result.fetchone()
    except Exception as exc:
        logger.error("DB error checking SBOM for tool", extra={"tool_id": str(tool_id), "error": str(exc)})
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL_ERROR", "message": "SBOM verification check failed."},
        )

    if sbom_row is None:
        logger.warning(
            "Activation blocked — no signed SBOM found (INV-006)",
            extra={"tool_id": str(tool_id), "tool_name": tool_name, "issue_key": issue_key},
        )
        return JSONResponse(
            status_code=200,
            content={
                "processed": True,
                "action": "activation_blocked",
                "reason": "Tool cannot be activated: no signed SBOM found (INV-006 requirement).",
                "tool_id": str(tool_id),
            },
        )

    # Activate the tool: set status = 'active', clear quarantine_reason.
    try:
        await db.execute(
            text(
                """
                UPDATE tool_registry
                SET status = 'active',
                    updated_at = NOW(),
                    metadata = metadata || jsonb_build_object(
                        'jira_activated_by', :issue_key,
                        'jira_activated_at', NOW()::text
                    )
                WHERE tool_id = :tool_id
                  AND status = 'quarantined'
                """
            ),
            {"tool_id": str(tool_id), "issue_key": issue_key},
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.error("DB error activating tool", extra={"tool_id": str(tool_id), "error": str(exc)})
        raise HTTPException(
            status_code=500,
            detail={"code": "INTERNAL_ERROR", "message": "Tool activation failed."},
        )

    # Emit TOOL_STATUS_CHANGED audit event (INV-001: audit before response).
    request_id: str = getattr(request.state, "request_id", "unknown")
    try:
        from datetime import datetime, timezone
        from uuid import uuid4
        from app.core.database import engine as _db_engine

        audit_event_id = str(uuid4())
        audit_ts = datetime.now(timezone.utc)

        # Use a separate DB connection for the audit write to ensure it commits
        # even if the outer transaction were rolled back.
        async with _db_engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    INSERT INTO audit_events (
                        event_id, event_type, created_at,
                        client_id, tool_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, 'TOOL_STATUS_CHANGED', :ts,
                        'jira-webhook', :tool_id, :tool_name,
                        'allow', :request_id, '', 0
                    )
                    """
                ),
                {
                    "event_id": audit_event_id,
                    "ts": audit_ts,
                    "tool_id": str(tool_id),
                    "tool_name": tool_name,
                    "request_id": request_id,
                },
            )
    except Exception as exc:
        # Audit failure is a hard error per INV-001.
        logger.error(
            "Audit event emission failed after Jira activation — INV-001 violation",
            extra={"tool_id": str(tool_id), "error": str(exc)},
        )
        raise RuntimeError(f"audit event emission failed: {exc}") from exc

    logger.info(
        "Tool activated via Jira webhook",
        extra={"tool_id": str(tool_id), "tool_name": tool_name, "issue_key": issue_key},
    )

    return JSONResponse(
        status_code=200,
        content={
            "processed": True,
            "action": "tool_activated",
            "tool_id": str(tool_id),
        },
    )
