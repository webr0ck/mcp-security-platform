"""
Self-Service MCP — per-identity MCP permission management.

Task 2.2b: Rewritten to be a thin HTTP client of the proxy profile API
(proxy/app/routers/profiles.py) instead of accessing the database directly.
No proxy-db-net or DATABASE_URL required — the DB connection is exclusively
owned by the proxy.

Tools (all return tight JSON, no bloat):
  list_available_mcps    List MCPs visible to this account with enabled status
  get_profile            Full permission profile for an identity
  enable_mcp             Enable an MCP for this account (or a named profile)
  disable_mcp            Disable an MCP for this account (or a named profile)
  list_functions         List functions on an MCP with per-identity enabled status
  enable_function        Enable a specific function on an MCP for a profile
  disable_function       Disable a specific function on an MCP for a profile

Identity is resolved from the X-User-Sub and X-User-Role headers injected by
the proxy (credential approach A). The caller can only manage their own profile
unless they hold admin role (signaled via X-User-Role header).

Authentication to the proxy profile API:
  This server authenticates with an API key (SELF_SERVICE_API_KEY env var).
  The key is seeded by lab/seeder/seed.py into the proxy's api_keys table
  under the service identity "lab-self-service".
  The proxy then enforces RBAC: the self-service server may only modify a
  principal's profile if the X-User-Sub header (set by the proxy when routing
  tool calls) matches the target principal, or the caller has admin role.

  When routing tool calls, the proxy injects X-User-Sub and X-User-Role as
  HTTP headers into the MCP request. The self-service server extracts these
  and uses X-User-Sub as the principal for profile API calls. This means the
  *proxy* is the trust anchor for identity — not the self-service server.

Network: mcp-self-service-net (pairwise with proxy, internal: true).
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

# Proxy profile API base URL — reachable via mcp-self-service-net (pairwise)
PROXY_PROFILE_API_URL = os.environ.get(
    "PROXY_PROFILE_API_URL", "http://mcp-proxy:8000/api/v1/profiles"
).rstrip("/")

PROXY_BASE_URL = os.environ.get("PROXY_BASE_URL", "http://mcp-proxy:8000")

# Service API key for authenticating to the proxy profile API.
# Seeded by lab/seeder/seed.py into api_keys table as service "lab-self-service".
# Must be set — no default. Compose fail-fast enforces this at startup.
SELF_SERVICE_API_KEY = os.environ.get("SELF_SERVICE_API_KEY", "")
if not SELF_SERVICE_API_KEY:
    import sys
    print("FATAL: SELF_SERVICE_API_KEY is not set. Run the lab seeder first.", file=sys.stderr)
    sys.exit(1)

log = logging.getLogger("self-service-mcp")

# ContextVars populated by _IdentityMiddleware for each request.
# The proxy injects X-User-Sub, X-User-Role, and (for passthrough tools)
# Authorization headers. Tools read from these vars.
_ctx_caller_sub: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ctx_caller_sub", default="anonymous"
)
_ctx_caller_role: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ctx_caller_role", default="agent"
)
# Raw Authorization header as received by this server (kept for completeness /
# future passthrough tools). NOT used for submission API owner attribution —
# passthrough only forwards a client-supplied X-Downstream-Authorization
# header, which normal MCP clients never send, so this is empty in practice.
# See _oauth_headers() for how owner attribution actually works (X-On-Behalf-Of).
_ctx_user_token: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_ctx_user_token", default=""
)


class _IdentityMiddleware(BaseHTTPMiddleware):
    """Populate identity ContextVars from proxy-injected HTTP headers."""

    async def dispatch(self, request, call_next):
        sub = request.headers.get("x-user-sub", "anonymous")
        role = request.headers.get("x-user-role", "agent")
        # In passthrough mode the proxy forwards the caller's Authorization header.
        auth = request.headers.get("authorization", "")
        tok_sub = _ctx_caller_sub.set(sub)
        tok_role = _ctx_caller_role.set(role)
        tok_user = _ctx_user_token.set(auth)
        try:
            return await call_next(request)
        finally:
            _ctx_caller_sub.reset(tok_sub)
            _ctx_caller_role.reset(tok_role)
            _ctx_user_token.reset(tok_user)


# stateless_http=True is REQUIRED so the identity ContextVars set by
# _IdentityMiddleware (from the proxy-injected X-User-Sub/X-User-Role headers)
# reach the tool handlers. In the default stateful streamable-http mode, tools
# run in a long-lived session-init task group and the per-request ContextVar
# never propagates — tools would always read the "anonymous"/"agent" defaults
# (symptom: get_profile -> 401 "no identity resolved"). Stateless mode runs each
# request in its own task spawned from the request context.
mcp = FastMCP("self-service-mcp", stateless_http=True)

# ── proxy profile API client ──────────────────────────────────────────────────


def _auth_headers() -> dict[str, str]:
    """Return auth headers for proxy profile API requests (service identity)."""
    return {
        "Authorization": f"Bearer {SELF_SERVICE_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _oauth_headers() -> dict[str, str]:
    """Return auth headers for submission API calls, attributed to the real caller.

    T2 trust-bridge fix: this server always authenticates to the submission
    API with its OWN service credential (SELF_SERVICE_API_KEY) — passthrough
    injection_mode does NOT forward the caller's session token here (it only
    forwards a client-supplied X-Downstream-Authorization header; see
    docs/spec/02-credential-broker.md §3.2), so _ctx_user_token is normally
    empty and a prior version of this function silently fell back to the
    service key with no way for the proxy to learn the real user — every
    submission was attributed to "lab-self-service".

    Fix: attach X-On-Behalf-Of: <caller sub>. The proxy's submissions router
    only honours this header from a caller holding the dedicated
    `submission_service` role (granted to lab-self-service only, see
    lab/seeder/seed.py) — the real caller's sub is trustworthy here because
    it came from X-User-Sub, which the proxy itself injected into this
    server's request (the proxy is the trust anchor for identity, this
    server is not — see module docstring). Omitted when there's no resolved
    caller (e.g. called directly in tests without a session) so the
    submission API falls back to attributing to the service account.
    """
    headers = {
        "Authorization": f"Bearer {SELF_SERVICE_API_KEY}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    caller_sub = _ctx_caller_sub.get()
    if caller_sub and caller_sub != "anonymous":
        headers["X-On-Behalf-Of"] = caller_sub
    return headers


async def _proxy_get(path: str) -> dict:
    """GET from proxy profile API. Returns parsed JSON or error dict."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=_auth_headers())
        if r.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API GET %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


async def _proxy_post(path: str, body: dict | None = None) -> dict:
    """POST to proxy profile API."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(
                url, headers=_auth_headers(),
                content=json.dumps(body) if body else b"",
            )
        if r.status_code == 404:
            return {"error": "not_found", "status_code": 404}
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API POST %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


async def _proxy_patch(path: str, body: dict) -> dict:
    """PATCH to proxy API."""
    url = f"{PROXY_BASE_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.patch(url, headers=_auth_headers(), content=json.dumps(body))
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code, "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy PATCH %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


async def _proxy_put(path: str, body: dict) -> dict:
    """PUT to proxy profile API."""
    url = f"{PROXY_PROFILE_API_URL}{path}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.put(url, headers=_auth_headers(),
                                 content=json.dumps(body))
        if r.status_code >= 400:
            return {"error": "api_error", "status_code": r.status_code,
                    "detail": r.text[:200]}
        return r.json()
    except Exception as exc:
        log.error("Proxy profile API PUT %s failed: %s", path, exc)
        return {"error": "proxy_unreachable", "detail": str(exc)}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── MCP tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_available_mcps(
    include_disabled: bool = False,
) -> dict:
    """
    List all MCP servers available on the platform with their enabled status for this account.

    Identity is resolved from the X-User-Sub header injected by the proxy.

    Args:
        include_disabled: If true, include MCPs the caller has explicitly disabled.

    Returns compact JSON: {mcps: [{name, enabled_for_account}]}
    """
    caller_sub = _ctx_caller_sub.get()
    # Use the registry endpoint on the proxy (tool discovery via /api/v1/tools)
    # For now, return a note directing the user to the proxy registry endpoint.
    # The profile API is per-MCP; to list available MCPs, query the proxy tool registry.
    return {
        "note": (
            "For a full registry listing, query GET /api/v1/tools on the proxy. "
            "This tool returns only your profile entries below."
        ),
        "profile_id": caller_sub,
        "mcps": [],
        "hint": (
            "Use get_profile to see your full profile including all MCPs. "
            "Use enable_mcp/disable_mcp to change per-MCP settings."
        ),
    }


@mcp.tool()
async def get_profile(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Get the permission profile for (principal, mcp_name).

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to query.
        target_profile: Profile to retrieve. Defaults to caller identity. Admin/auditor required for others.

    Returns: {principal, mcp_name, enabled, allowed_functions, explicit_row}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin", "auditor"):
        return {"error": "forbidden", "detail": "Only admin/auditor can view other profiles"}

    return await _proxy_get(f"/{profile_id}/mcps/{mcp_name}")


@mcp.tool()
async def enable_mcp(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Enable an MCP server for an account. Idempotent.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to enable (must exist in tool_registry).
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.

    Returns: {ok: true, principal, mcp_name, enabled: true}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/enable")


@mcp.tool()
async def disable_mcp(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Disable an MCP server for an account.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: Name of the MCP to disable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.

    Returns: {ok: true, principal, mcp_name, enabled: false}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden", "detail": "Only admin can modify other profiles"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/disable")


@mcp.tool()
async def list_functions(
    mcp_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Get the function-level restrictions for an MCP on this account.

    Args:
        mcp_name: Name of the MCP server.
        target_profile: Profile to query. Defaults to caller.

    Returns: {mcp_name, allowed_functions (null=all), enabled}
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin", "auditor"):
        return {"error": "forbidden"}

    result = await _proxy_get(f"/{profile_id}/mcps/{mcp_name}")
    if "error" in result:
        return result
    return {
        "mcp_name": mcp_name,
        "profile_id": profile_id,
        "enabled": result.get("enabled", True),
        "allowed_functions": result.get("allowed_functions"),
        "note": "null allowed_functions means all functions permitted",
    }


@mcp.tool()
async def enable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Enable a specific function on an MCP server for a profile.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: MCP server name.
        function_name: Function to enable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/functions/{function_name}/enable")


@mcp.tool()
async def disable_function(
    mcp_name: str,
    function_name: str,
    target_profile: Optional[str] = None,
) -> dict:
    """
    Disable a specific function on an MCP server for a profile.

    Identity is resolved from the X-User-Sub and X-User-Role headers injected by the proxy.

    Args:
        mcp_name: MCP server name.
        function_name: Function to disable.
        target_profile: Profile to modify. Defaults to caller identity. Admin required for others.
    """
    caller_sub = _ctx_caller_sub.get()
    caller_role = _ctx_caller_role.get()
    profile_id = target_profile or caller_sub
    if profile_id != caller_sub and caller_role not in ("admin", "platform_admin"):
        return {"error": "forbidden"}

    return await _proxy_post(f"/{profile_id}/mcps/{mcp_name}/functions/{function_name}/disable")


# ── MCP server onboarding tools ───────────────────────────────────────────────

@mcp.tool()
async def plan_mcp_server(intent: str) -> dict:
    """
    Start the MCP server onboarding flow.

    Describe what you want the MCP server to do and this tool will return
    the questions you (or the user) need to answer before building and
    submitting it.  Call this first; then call get_auth_mode_recommendation
    with the answers.

    Args:
        intent: A plain-language description of the server's purpose,
                e.g. "query our internal Jira instance on behalf of each user".

    Returns: {questions, next_tool, guidance}
    """
    url = f"{PROXY_BASE_URL}/api/v1/design-assist"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=_oauth_headers())
        data = r.json() if r.status_code == 200 else {}
    except Exception as exc:
        data = {}
        log.error("design-assist GET failed: %s", exc)

    return {
        "intent": intent,
        "next_step": "Answer the questions below, then call get_auth_mode_recommendation",
        "auth_questions": [
            "Does your server call any upstream system that requires authentication? (yes/no)",
            "If yes: is the upstream the same Keycloak instance this platform uses? (yes/no)",
            "If external: Microsoft Entra, static API key/bearer, or another OAuth IdP?",
            "If API key / bearer: is one shared credential used for all callers, or does each user have their own?",
            "If per-user: stored credentials or live OAuth token exchange?",
        ],
        "data_questions": [
            "What categories of data does the server expose? "
            "(pii / financial / health / internal_docs / source_code / email_calendar / infrastructure / public)",
            "Does the server perform write operations (create/update/delete)? (yes/no)",
        ],
        "backend_questions": [
            "What will this server actually do, in a sentence a security reviewer can approve on? "
            "(this becomes submit_mcp_server's required 'description' — a reviewer cannot approve "
            "a server they don't understand)",
            "Where will it run — the URL or IP of the backend, if you have one yet? "
            "(this becomes submit_mcp_server's 'upstream_url'; required for any submission with a "
            "github_repo_url, informational only pre-approval — you still confirm the live URL "
            "after approval via check_submission_status's provide-url step)",
        ],
        "decision_tree": data.get("decision_tree", []),
        "hint": "Once you have the answers, call get_auth_mode_recommendation.",
    }


@mcp.tool()
async def get_auth_mode_recommendation(
    has_upstream_auth: bool,
    same_keycloak: Optional[bool] = None,
    upstream_idp_type: Optional[str] = None,
    per_user: Optional[bool] = None,
) -> dict:
    """
    Returns the recommended authentication injection mode for an MCP server.

    Args:
        has_upstream_auth: True if the server calls an upstream system that requires auth.
        same_keycloak: True if the upstream is the same Keycloak realm as the platform.
        upstream_idp_type: "entra", "api_key", "oauth" — which upstream IdP (if not Keycloak).
        per_user: True if each caller needs their own credential; False if shared.

    Returns: {recommended_mode, reason, next_tool}
    """
    if not has_upstream_auth:
        mode, reason = "none", "No credential injection needed."
    elif same_keycloak:
        mode, reason = "kc_token_exchange", "Token exchange — no secret at rest. Full per-user attribution."
    elif upstream_idp_type == "entra":
        if per_user:
            mode, reason = "entra_user_token", "Entra delegated token. Full per-user attribution in Entra."
        else:
            mode, reason = "entra_client_credentials", "Entra app identity (machine). Attribution at gateway only."
    elif upstream_idp_type == "oauth":
        if per_user:
            mode, reason = "oauth_user_token", "Per-user OAuth token from external IdP."
        else:
            mode, reason = "service_account", "Shared OAuth service account token."
    else:  # api_key / bearer
        if per_user:
            mode, reason = "user", "Per-user stored credential. Full per-user attribution. Users enroll their own token via the portal."
        else:
            mode, reason = "service", "Shared service account credential."

    return {
        "recommended_mode": mode,
        "reason": reason,
        "next_tool": "submit_mcp_server",
        "hint": f"Pass injection_mode='{mode}' to submit_mcp_server.",
    }


@mcp.tool()
async def submit_mcp_server(
    name: str,
    description: str,
    injection_mode: str,
    data_categories: list,
    has_write_ops: bool,
    upstream_url: str,
    github_repo_url: Optional[str] = None,
    upstream_idp_type: Optional[str] = None,
    upstream_idp_issuer: Optional[str] = None,
    upstream_idp_client_id: Optional[str] = None,
    upstream_idp_scopes: Optional[list] = None,
) -> dict:
    """
    Create and submit an MCP server for security review.

    A reviewer cannot approve a server they don't understand or locate.
    description, injection_mode (the auth TYPE — never the secret itself),
    and upstream_url are all required and checked before this call even
    reaches the platform. There is no code-less/no-URL shortcut into the
    review queue: if you don't have a server running yet, call
    get_server_scaffold instead — that needs no submission at all and never
    touches the review queue. Only call submit_mcp_server once you have a
    real (even if not-yet-public) upstream_url to give a reviewer.

    If github_repo_url is provided the platform will clone and scan it
    automatically before human review. If omitted the submission goes
    straight to human review (no automated scan possible without code).

    Args:
        name: Unique server name, 2-63 chars, lowercase letters/numbers/hyphens.
        description: What the server does — required, shown in the review queue.
                     Write this so a security reviewer can approve on it alone.
        injection_mode: Auth mode (the TYPE of credential the server needs —
                        never the credential value itself, that is uploaded
                        separately after approval) — one of: none, service,
                        user, service_account, oauth_user_token,
                        entra_client_credentials, entra_user_token,
                        kc_token_exchange.
        data_categories: List of data sensitivity categories the server exposes.
                         Values: pii, financial, health, internal_docs, source_code,
                         email_calendar, infrastructure, public.
        has_write_ops: True if the server performs any create/update/delete operations.
        upstream_url: The URL/IP this server runs (or will run) at. Required —
                      informational for the reviewer only, not validated yet.
                      You still confirm the live URL after approval
                      (check_submission_status will tell you when).
        github_repo_url: https://github.com/<owner>/<repo> — leave None if no code yet.
        upstream_idp_type: Required for OAuth-family injection_mode values (currently
                           entra_client_credentials, entra_user_token, oauth_user_token) —
                           e.g. 'entra'. Approval is blocked with OAUTH_POLICY_VIOLATION
                           without this and upstream_idp_issuer/upstream_idp_client_id set,
                           and this cannot be added later once submitted (the submission
                           becomes non-editable after scan/submit) — get it right up front.
        upstream_idp_issuer: The IdP's issuer URL, e.g.
                             'https://login.microsoftonline.com/<tenant>/v2.0' for Entra.
                             Required alongside upstream_idp_type for OAuth modes.
        upstream_idp_client_id: The OAuth client_id this server authenticates as at the
                                upstream IdP. Required alongside upstream_idp_type for
                                OAuth modes. Never the client secret — that is uploaded
                                separately after approval, same as any other credential.
        upstream_idp_scopes: Optional list of OAuth scopes to request, e.g.
                             ['https://graph.microsoft.com/.default'] for Entra app-only.

    Returns: {server_id, submission_status, next_steps}
    """
    if not description or not description.strip():
        return {"error": "description_required",
                "detail": "description is required — a reviewer cannot approve a server they don't understand."}
    if not injection_mode or not injection_mode.strip():
        return {"error": "injection_mode_required",
                "detail": "injection_mode is required — a reviewer needs to know the auth TYPE, even if the credential itself is uploaded later."}
    if not upstream_url or not upstream_url.strip():
        return {"error": "upstream_url_required",
                "detail": "upstream_url is required — where does/will this server run? No code yet? Call get_server_scaffold instead; it needs no submission."}
    _OAUTH_MODES = {"entra_client_credentials", "entra_user_token", "oauth_user_token"}
    if injection_mode in _OAUTH_MODES and not (upstream_idp_type and upstream_idp_issuer and upstream_idp_client_id):
        return {"error": "upstream_idp_config_required",
                "detail": f"injection_mode={injection_mode!r} requires upstream_idp_type, "
                          "upstream_idp_issuer, and upstream_idp_client_id — approval is "
                          "blocked without them (OAUTH_POLICY_VIOLATION), and this cannot be "
                          "added after submission (the submission becomes non-editable once "
                          "scanned/submitted). Provide all three now."}

    caller_sub = _ctx_caller_sub.get()
    base = f"{PROXY_BASE_URL}/api/v1/submissions"
    hdrs = _oauth_headers()  # user's OAuth token — proxy resolves real owner_sub

    # 1. Create draft
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(base, headers=hdrs, content=json.dumps({
            "name": name,
            "description": description,
            "github_repo_url": github_repo_url,
        }))
    if r.status_code >= 400:
        return {"error": "create_failed", "detail": r.text[:300]}
    draft = r.json()
    sid = draft["server_id"]

    # 2. Patch with design data
    patch_body = {
        "injection_mode": injection_mode,
        "data_categories": data_categories,
        "has_write_ops": has_write_ops,
        "requested_upstream_url": upstream_url,
    }
    if upstream_idp_type:
        patch_body["upstream_idp_type"] = upstream_idp_type
        patch_body["upstream_idp_config"] = {
            "issuer": upstream_idp_issuer,
            "client_id": upstream_idp_client_id,
            **({"scopes": upstream_idp_scopes} if upstream_idp_scopes else {}),
        }
    async with httpx.AsyncClient(timeout=10) as client:
        patch_resp = await client.patch(f"{base}/{sid}", headers=hdrs, content=json.dumps(patch_body))
    if patch_resp.status_code >= 400:
        return {"error": "patch_failed", "server_id": sid, "detail": patch_resp.text[:300]}

    # 3. Submit
    async with httpx.AsyncClient(timeout=10) as client:
        r2 = await client.post(f"{base}/{sid}/submit", headers=hdrs, content=b"{}")
    if r2.status_code >= 400:
        return {"error": "submit_failed", "server_id": sid, "detail": r2.text[:300]}
    result = r2.json()
    status = result.get("submission_status", "unknown")

    if github_repo_url:
        next_steps = [
            f"Your server (id={sid}) is being scanned. Poll status with check_submission_status.",
            "If the scan passes, the security team will review. This typically takes 1-2 business days.",
            "Once approved, you'll need to provide the running server URL.",
        ]
    else:
        next_steps = [
            f"No code provided. Download your scaffold: GET /api/v1/submissions/{sid}/scaffold",
            f"Or call get_server_scaffold(injection_mode='{injection_mode}') to see the starter code.",
            "Implement your server, push to GitHub, then re-submit with a github_repo_url.",
        ]

    return {
        "server_id": sid,
        "submission_status": status,
        "submitter": caller_sub,
        "next_steps": next_steps,
    }


@mcp.tool()
async def check_submission_status(server_id: str) -> dict:
    """
    Check the current status of an MCP server submission.

    Args:
        server_id: The UUID returned by submit_mcp_server.

    Returns: {submission_status, scan_status, scan_findings_count, blocked_count, review_notes}
    """
    url = f"{PROXY_BASE_URL}/api/v1/submissions/{server_id}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=_oauth_headers())
        if r.status_code == 404:
            return {"error": "not_found"}
        if r.status_code >= 400:
            return {"error": "api_error", "detail": r.text[:200]}
        data = r.json()
    except Exception as exc:
        return {"error": "proxy_unreachable", "detail": str(exc)}

    scan_report = data.get("scan_report") or []
    blocked = [f for f in scan_report if f.get("block")]
    findings = [
        {"scanner": f.get("scanner"), "file": f.get("file"), "message": f.get("message")}
        for f in scan_report
    ]

    status = data.get("submission_status", "unknown")
    guidance = {
        "draft":                "Submission is still a draft. Call submit_mcp_server to submit.",
        "scan_pending":         "Clone + scan queued. Check back in a minute.",
        "scan_running":         "Scan in progress. Check back in a minute.",
        "scan_blocked":         "Scan found issues — fix them in your repo, then re-submit.",
        "awaiting_review":      "Scan passed. Security team is reviewing.",
        "changes_requested":    "Reviewer requested changes. See review_notes.",
        "approved_pending_url": "Approved! Deploy your server and provide the running URL via the portal.",
        "active":               "Active — the server is live.",
        "rejected":             "Rejected. See review_notes for details.",
    }.get(status, "")

    return {
        "server_id": server_id,
        "submission_status": status,
        "scan_status": data.get("scan_status"),
        "scan_findings": len(scan_report),
        "blocked_findings": len(blocked),
        "findings": findings[:5],  # first 5 for readability
        "review_notes": data.get("review_notes"),
        "guidance": guidance,
    }


@mcp.tool()
async def get_server_scaffold(injection_mode: str) -> dict:
    """
    Return starter scaffold code for an MCP server with the given auth mode.

    Useful when the user has no code yet.  Returns the contents of server.py,
    requirements.txt, Dockerfile, and README.md so the agent can show or
    save them directly.

    Args:
        injection_mode: One of: none, service, user, service_account,
                        oauth_user_token, entra_client_credentials,
                        entra_user_token, kc_token_exchange.

    Returns: {files: {filename: content}, next_steps}
    """
    url = f"{PROXY_BASE_URL}/api/v1/design-assist/scaffold"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url, headers=_oauth_headers(), params={"mode": injection_mode})
        if r.status_code == 200:
            data = r.json()
            return {
                "files": data.get("files", {}),
                "next_steps": [
                    "Save server.py, requirements.txt, Dockerfile, and README.md to your project.",
                    "Implement your tools inside the @srv.tool() function stubs.",
                    "Push to GitHub, then call submit_mcp_server with your repo URL.",
                ],
            }
    except Exception as exc:
        log.error("scaffold GET failed: %s", exc)

    return {"error": "scaffold_unavailable", "detail": "Could not fetch scaffold from platform."}


# ── startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = mcp.streamable_http_app()
    app.add_middleware(_IdentityMiddleware)
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
