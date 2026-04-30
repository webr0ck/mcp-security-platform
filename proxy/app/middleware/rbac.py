"""
MCP Security Platform — RBAC Middleware

Enforces role-based access control at the FastAPI middleware layer.
This is enforcement layer [2] per docs/RBAC.md Section 5.

After AuthMiddleware resolves client_id and client_roles, this middleware:
- Looks up the role for the client from request.state.client_roles
- Checks whether the role is permitted to access the requested endpoint
- Returns 403 FORBIDDEN if the role lacks permission
- Applies field-level response filtering for readonly role (handled in response hooks)

The RBAC permission matrix is defined in docs/RBAC.md Section 3.
OPA provides the fine-grained layer [3] for invocation endpoints.
"""
from __future__ import annotations

import logging
from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# Endpoints exempt from RBAC (already exempt from auth in AuthMiddleware)
PUBLIC_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/ready",
    "/api/v1/auth/oidc/login",
    "/api/v1/auth/oidc/callback",
})

# Minimum role required per path prefix.
# More specific paths are checked first (longer prefix wins).
# Role hierarchy for access comparison (higher index = more privilege):
ROLE_LEVELS: dict[str, int] = {
    "readonly": 0,
    "agent": 1,
    "auditor": 2,
    "admin": 3,
}

# Endpoint → minimum required role (most permissive)
PATH_ROLE_MAP: list[tuple[str, str, set[str]]] = [
    # (method_or_ANY, path_prefix, allowed_roles)
    ("POST", "/api/v1/tools/{tool_id}/invoke", {"admin", "agent"}),
    ("POST", "/api/v1/tools", {"admin"}),
    ("PATCH", "/api/v1/tools", {"admin"}),
    ("DELETE", "/api/v1/tools", {"admin"}),
    ("GET", "/api/v1/tools", {"admin", "agent", "auditor", "readonly"}),
    ("GET", "/api/v1/policy/rules", {"admin", "auditor"}),
    ("POST", "/api/v1/policy/evaluate", {"admin"}),
    ("GET", "/api/v1/compliance", {"admin", "auditor"}),
    ("POST", "/api/v1/compliance", {"admin"}),
    ("GET", "/api/v1/anomaly", {"admin", "auditor"}),
    ("PATCH", "/api/v1/anomaly", {"admin"}),
    ("GET", "/api/v1/audit", {"admin", "auditor", "agent"}),
    ("POST", "/api/v1/integrations/jira/webhook", {"__webhook__"}),
]


def _resolve_allowed_roles(method: str, path: str) -> set[str] | None:
    """Return allowed roles for a given method+path, or None if unconstrained."""
    for rule_method, prefix, roles in PATH_ROLE_MAP:
        if rule_method not in ("ANY", method):
            continue
        # Normalize path for matching (strip UUIDs)
        if path.startswith(prefix.split("{")[0].rstrip("/")):
            return roles
    return None


class RBACMiddleware(BaseHTTPMiddleware):
    """
    Checks role membership after auth. Returns 403 if role is not permitted.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:  # type: ignore[override]
        if request.url.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        # Jira webhook is authenticated by secret, not by role
        if request.url.path == "/api/v1/integrations/jira/webhook":
            return await call_next(request)

        client_roles: list[str] = getattr(request.state, "client_roles", [])
        client_id: str | None = getattr(request.state, "client_id", None)

        allowed_roles = _resolve_allowed_roles(request.method, request.url.path)

        if allowed_roles is not None:
            if not any(role in allowed_roles for role in client_roles):
                logger.warning(
                    "RBAC deny: client=%s roles=%s path=%s method=%s",
                    client_id,
                    client_roles,
                    request.url.path,
                    request.method,
                )
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "code": "FORBIDDEN",
                            "message": "Your role does not permit this operation.",
                            "request_id": getattr(request.state, "request_id", "unknown"),
                        }
                    },
                )

        return await call_next(request)
