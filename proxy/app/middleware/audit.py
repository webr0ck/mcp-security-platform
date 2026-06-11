"""
MCP Security Platform — Audit Middleware

Wraps every request to:
  1. Assign a unique request_id for log correlation (if not already set by AuthMiddleware)
  2. Attach X-Request-ID to every response header
  3. Enforce INV-001 boundary: audit emission failures → 500 (never swallowed)

Per INV-001 (extended Task 1.1): "There is no path where a tool executes — or where
authentication is rejected — without an audit record."

Any AuditEmissionError from mcp-audit-logger propagates here and results in a 500
response, which surfaces the audit failure visibly to the caller rather than silently
succeeding. This applies to BOTH invocation-path failures (emitted by invocation.py)
AND auth-layer rejections (401/403, emitted here).

The per-invocation audit event is emitted by services/invocation.py.
The per-rejection audit event (401/403) is emitted here in dispatch().

Also provides IPRateLimitMiddleware: a global per-IP request limiter (default 100 req/min)
that runs before auth, covering unauthenticated flooding of any endpoint.
"""
from __future__ import annotations

import logging

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.security import generate_request_id

logger = logging.getLogger(__name__)


def _audit_500_response(request_id: str, error: str) -> JSONResponse:
    """Return the canonical INV-001 500 envelope used by both audit failure paths."""
    logger.error(
        "INV-001 boundary: audit emission failure returning 500",
        extra={"request_id": request_id, "error": error},
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


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Request ID injection middleware with INV-001 audit failure boundary.

    Adds X-Request-ID to all responses. Catches and surfaces audit emission
    failures as HTTP 500 rather than silently continuing without an audit record.

    Task 1.1: auth-layer rejections (401/403) are now also fail-closed — the
    emit for those responses is wrapped in its own AuditEmissionError boundary.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: object) -> Response:
        # Assign request_id if AuthMiddleware hasn't done it yet
        if not hasattr(request.state, "request_id"):
            request.state.request_id = generate_request_id()

        request_id = request.state.request_id

        from app.services.invocation import AuditEmissionError

        # ----------------------------------------------------------------
        # Run the inner handler.  AuditEmissionError from the invocation
        # path surfaces as 500 here.
        # ----------------------------------------------------------------
        try:
            response: Response = await call_next(request)  # type: ignore[misc]
        except AuditEmissionError as exc:
            # INV-001: Audit failure must surface as 500, not be swallowed.
            # Typed exception — no fragile string match on the message.
            return _audit_500_response(request_id, str(exc))

        # ----------------------------------------------------------------
        # Audit authentication and authorization failures (401/403).
        # INV-001 extension (Task 1.1): emission failure → 500 (fail-closed).
        # An attacker who can break audit emission must not gain a quieter
        # brute-force channel.
        # Residual: the recorded method/path strings are attacker-chosen —
        # they are run through redact_string before recording (INV-002).
        # ----------------------------------------------------------------
        if response.status_code in (401, 403):
            try:
                from uuid import uuid4

                from app.services.invocation import _emit_audit_event

                # Redact the path: it may contain token-shaped segments
                # supplied by the attacker (e.g. /api/v1/tools/eyJ...).
                from mcp_audit_logger.redaction import redact_string as _redact
                raw_path = f"{request.method} {request.url.path}"
                safe_tool_name = f"[{response.status_code}] {_redact(raw_path)}"

                await _emit_audit_event(
                    tool_id=None,
                    tool_name=safe_tool_name,
                    tool_version=None,
                    client_id=getattr(request.state, "client_id", "unauthenticated"),
                    outcome="deny",
                    deny_reasons=[f"HTTP_{response.status_code}"],
                    request_id=getattr(request.state, "request_id", str(uuid4())),
                    latency_ms=0,
                    anomaly_score=0.0,
                    opa_decision_id=f"dec_{uuid4().hex[:16]}",
                    is_testing=False,
                )
            except AuditEmissionError as exc:
                # Fail-closed: emission failure for an auth-layer rejection
                # must surface as 500.  The original 401/403 is not returned
                # because there is no audit record — that is the invariant.
                return _audit_500_response(request_id, str(exc))

        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Global per-IP rate limiter
# ---------------------------------------------------------------------------

# Endpoints that are exempt from IP-level rate limiting (health probes, metrics).
_IP_RL_EXEMPT_PATHS = frozenset({"/health", "/health/ready", "/health/live", "/metrics"})

# Default: 100 requests per minute per IP, across all endpoints.
_IP_RL_LIMIT = 100
_IP_RL_WINDOW = 60


class IPRateLimitMiddleware(BaseHTTPMiddleware):
    """
    Global per-source-IP rate limiter. Runs before auth and RBAC so it covers
    unauthenticated flooding of any endpoint, including discovery endpoints,
    /oauth/register, and the MCP endpoint.

    Keyed by the real client IP (request.client.host). In production behind a
    reverse proxy, ensure the proxy sets X-Forwarded-For and that Starlette's
    ProxyHeadersMiddleware is added so request.client.host reflects the real IP.

    Health/metrics paths are exempted to avoid interfering with load balancer probes.
    Fails open if Redis is unavailable.
    """

    def __init__(self, app: ASGIApp, limit: int = _IP_RL_LIMIT, window: int = _IP_RL_WINDOW) -> None:
        super().__init__(app)
        self.limit = limit
        self.window = window

    async def dispatch(self, request: Request, call_next: object) -> Response:
        if request.url.path in _IP_RL_EXEMPT_PATHS:
            return await call_next(request)  # type: ignore[misc]

        client_ip = request.client.host if request.client else "unknown"
        try:
            from app.core.redis_client import redis_pool
            rl_client = redis_pool.rate_limit_client
            key = f"rl:ip:{client_ip}"
            pipe = rl_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, self.window)
            results = await pipe.execute()
            count = results[0]
        except Exception:
            count = 0  # fail-open

        if count > self.limit:
            logger.warning(
                "IP rate limit exceeded",
                extra={"client_ip": client_ip, "count": count, "limit": self.limit},
            )
            return JSONResponse(
                status_code=429,
                content={"error": {"code": "RATE_LIMITED", "message": "Too many requests from this IP"}},
            )

        return await call_next(request)  # type: ignore[misc]
