"""
MCP Security Platform — Audit Middleware

Wraps every request to:
  1. Assign a unique request_id for log correlation (if not already set by AuthMiddleware)
  2. Attach X-Request-ID to every response header
  3. Enforce INV-001 boundary: if audit emission raises RuntimeError, return 500

Per INV-001: "There is no path where a tool executes and no audit record is produced."
Any RuntimeError from mcp-audit-logger propagates here and results in a 500 response,
which surfaces the audit failure visibly to the caller rather than silently succeeding.

The actual per-invocation audit event is emitted by services/invocation.py.
This middleware handles the global error boundary for audit emission failures.
"""
from __future__ import annotations

import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.security import generate_request_id

logger = logging.getLogger(__name__)


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Request ID injection middleware with INV-001 audit failure boundary.

    Adds X-Request-ID to all responses. Catches and surfaces audit emission
    failures as HTTP 500 rather than silently continuing without an audit record.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: object) -> Response:
        # Assign request_id if AuthMiddleware hasn't done it yet
        if not hasattr(request.state, "request_id"):
            request.state.request_id = generate_request_id()

        request_id = request.state.request_id

        from app.services.invocation import AuditEmissionError

        try:
            response: Response = await call_next(request)  # type: ignore[misc]
        except AuditEmissionError as exc:
            # INV-001: Audit failure must surface as 500, not be swallowed.
            # Typed exception — no fragile string match on the message.
            logger.error(
                "INV-001 boundary: audit emission failure returning 500",
                extra={"request_id": request_id, "error": str(exc)},
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "AUDIT_EMISSION_FAILED",
                        "message": "Audit event emission failed. Invocation aborted per INV-001.",
                        "request_id": request_id,
                    }
                },
            )

        response.headers["X-Request-ID"] = request_id
        return response
