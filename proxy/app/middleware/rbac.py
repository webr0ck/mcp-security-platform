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

# Endpoints exempt from RBAC (already exempt from auth in AuthMiddleware).
# PUBLIC_PATHS must match AuthMiddleware.PUBLIC_PATHS exactly.
# Diff last verified: 2026-06-01
PUBLIC_PATHS: frozenset[str] = frozenset({
    "/health",
    "/health/ready",
    "/api/v1/auth/oidc/login",
    "/api/v1/auth/oidc/callback",
    # Jira webhook is authenticated by JIRA_WEBHOOK_SECRET, not by role.
    # Must match AuthMiddleware.PUBLIC_PATHS to remain reachable.
    "/api/v1/integrations/jira/webhook",
    # RFC 7591 dynamic client registration — pre-auth, no role required.
    "/oauth/register",
})

# Minimum role required per path prefix.
# More specific paths are checked first (longer prefix wins).
# Role hierarchy for access comparison (higher index = more privilege):
ROLE_LEVELS: dict[str, int] = {
    # v3 roles
    "user": 0,
    "manager": 1,
    "server_owner": 2,
    "auditor": 3,
    "platform_admin": 4,
    # legacy aliases — kept for backward compat during migration
    "readonly": 0,
    "agent": 0,
    "admin": 4,
}

# Endpoint → minimum required role (most permissive)
PATH_ROLE_MAP: list[tuple[str, str, set[str]]] = [
    # (method_or_ANY, path_prefix, allowed_roles)
    ("POST", "/api/v1/tools/{tool_id}/invoke", {"admin", "platform_admin", "agent", "user"}),
    # CR-07 (WP-B3): release_tool's OWN inline role check (routers/tools.py)
    # accepts admin/platform_admin/security_reviewer, but without this rule
    # the plain-prefix "/api/v1/tools" POST rule below (admin/platform_admin
    # only) matches first and denies a security_reviewer-only principal
    # before release_tool's code ever runs — found live (WP-B3 phase 2-6
    # acceptance test): a Keycloak realm role of "security_reviewer" alone
    # 403'd here despite being an explicitly-accepted role in the handler.
    # Must precede the generic /api/v1/tools rule (longer/more-specific
    # match wins by being listed first — see _resolve_allowed_roles).
    ("POST", "/api/v1/tools/{tool_id}/release", {"admin", "platform_admin", "security_reviewer"}),
    ("POST", "/api/v1/tools", {"admin", "platform_admin"}),
    ("PATCH", "/api/v1/tools", {"admin", "platform_admin"}),
    ("DELETE", "/api/v1/tools", {"admin", "platform_admin"}),
    ("GET", "/api/v1/tools", {"admin", "platform_admin", "agent", "user", "auditor", "readonly", "manager", "server_owner"}),
    ("GET", "/api/v1/policy/rules", {"admin", "platform_admin", "auditor"}),
    ("POST", "/api/v1/policy/evaluate", {"admin", "platform_admin"}),
    ("GET", "/api/v1/compliance", {"admin", "platform_admin", "auditor"}),
    ("POST", "/api/v1/compliance", {"admin", "platform_admin"}),
    ("GET", "/api/v1/anomaly", {"admin", "platform_admin", "auditor"}),
    ("PATCH", "/api/v1/anomaly", {"admin", "platform_admin"}),
    ("GET", "/api/v1/audit", {"admin", "platform_admin", "auditor"}),
    ("POST", "/api/v1/integrations/jira/webhook", {"__webhook__"}),
    # Admin credential UI — platform_admin only
    ("GET",    "/admin/credentials", {"admin", "platform_admin"}),
    ("PUT",    "/admin/credentials", {"admin", "platform_admin"}),
    ("DELETE", "/admin/credentials", {"admin", "platform_admin"}),
    # Server registry — platform_admin manages, all authenticated can list approved
    ("ANY", "/api/v1/admin/servers", {"admin", "platform_admin"}),
    # Parameterized /servers/* rules MUST precede plain /api/v1/servers prefix rules.
    # Plain prefix rules match any path starting with /api/v1/servers/ (too greedy),
    # so all parameterized and longer-match rules come first.
    # Consent token minting — server_owner or platform_admin (D3 dual-control).
    ("POST", "/api/v1/servers/{id}/consent", {"admin", "platform_admin", "server_owner"}),
    # Entitlement CRUD — ownership check also enforced in handler (_require_server_owner).
    ("GET",    "/api/v1/servers/mine",                   {"admin", "platform_admin", "server_owner", "manager"}),
    ("GET",    "/api/v1/servers/{id}/entitlements",      {"admin", "platform_admin", "server_owner", "manager"}),
    ("POST",   "/api/v1/servers/{id}/entitlements",      {"admin", "platform_admin", "server_owner", "manager"}),
    # Debug mode / maintainers — self-service submitters hold "agent"/"user"
    # roles (not "server_owner"), so this must admit those too; the actual
    # per-server ownership check is enforced in the handler
    # (_require_owner_or_maintainer in routers/server_registry.py), RBAC here
    # only needs to let a plausible owner's role through.
    ("PUT",    "/api/v1/servers/{id}/maintainers",       {"admin", "platform_admin", "server_owner", "manager", "user", "agent"}),
    ("POST",   "/api/v1/servers/{id}/debug-mode",        {"admin", "platform_admin", "server_owner", "manager", "user", "agent"}),
    # DELETE /{id}/entitlements/{ent_id}: use plain prefix matching (two path params not
    # supported by parameterized rule logic). The /entitlements/ infix ensures this only
    # matches entitlement DELETE operations, not other /servers/* DELETEs.
    ("DELETE", "/api/v1/servers",                        {"admin", "platform_admin", "server_owner", "manager"}),
    # Self-service registration — server_owner or platform_admin (Task 7).
    # Plain prefix rule — comes AFTER all parameterized /servers/* rules above.
    ("POST", "/api/v1/servers", {"admin", "platform_admin", "server_owner"}),
    # Broad /servers listing — all authenticated roles. Must come AFTER the more-specific rules above.
    ("GET", "/api/v1/servers", {"admin", "platform_admin", "server_owner", "manager", "user", "agent", "auditor", "readonly"}),
    # /mcp — all authenticated roles (AuthMiddleware enforces identity; RBAC enforces role)
    ("ANY", "/mcp", {"admin", "platform_admin", "agent", "user", "manager", "server_owner", "auditor", "readonly"}),
    # Portal — admin-only fragments/actions listed first (longer-prefix wins)
    ("POST",  "/portal/actions/save-grants", {"admin", "platform_admin"}),  # OPA grant management
    # Submissions review queue: also security_reviewer (mirrors submission.py's
    # _require_submission_reviewer). Must precede the generic
    # /portal/fragments/admin rule below (admin/platform_admin only), and the
    # generic /portal/admin/{tab} direct-URL route falls under the plain
    # /portal catch-all further down — security_reviewer added there too so a
    # reviewer-only principal (no auditor role) can still open the shell.
    ("GET",   "/portal/fragments/admin/submissions", {"admin", "platform_admin", "security_reviewer"}),
    ("GET",   "/portal/fragments/admin",     {"admin", "platform_admin"}),  # admin tab and sub-tabs
    ("GET",   "/portal",                     {"admin", "platform_admin", "agent", "user", "manager", "server_owner", "auditor", "security_reviewer"}),  # general portal access
    ("ANY",   "/portal",                     {"admin", "platform_admin", "agent", "user", "manager", "server_owner", "auditor", "security_reviewer"}),  # catch-all for portal
    # Catalog endpoints
    ("GET",   "/api/v1/catalog",             {"admin", "platform_admin", "user", "agent", "manager", "server_owner", "auditor"}),
]


def _resolve_allowed_roles(method: str, path: str) -> set[str] | None:
    """Return allowed roles for a given method+path, or None if unconstrained."""
    for rule_method, prefix, roles in PATH_ROLE_MAP:
        if rule_method not in ("ANY", method):
            continue
        if "{" in prefix:
            # Parameterized rule: check prefix AND static suffix after the param.
            # e.g. /api/v1/tools/{tool_id}/invoke → prefix=/api/v1/tools/, suffix=/invoke
            norm = prefix.split("{")[0].rstrip("/")
            after_param = prefix.split("}", 1)[-1] if "}" in prefix else ""
            if path.startswith(norm + "/") and path.endswith(after_param):
                return roles
        else:
            norm = prefix.rstrip("/")
            if path == norm or path.startswith(norm + "/"):
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
