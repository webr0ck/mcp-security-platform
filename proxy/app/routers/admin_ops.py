"""
MCP Security Platform — Server Lifecycle Ops Router (WS-A)

Thin authz + forwarding layer in front of the isolated `ops-agent` service,
which is the only thing that actually holds the container-runtime socket
(least-privilege / fail-closed thesis — see docs/spec/11-server-lifecycle-
and-hardening-batch.md §WS-A). This router never touches podman directly.

Endpoints:
  GET  /api/v1/admin/servers/{id}/logs?tail=N  — gated on debug_mode=TRUE
  POST /api/v1/admin/servers/{id}/restart
  POST /api/v1/admin/servers/{id}/rebuild

Authz: all three endpoints live under the /api/v1/admin/ prefix, which the
RBAC middleware (middleware/rbac.py) already restricts to admin roles — so in
practice every lifecycle op here is admin-only, and a non-admin owner/maintainer
is rejected at the middleware before this router runs (verified live). We
therefore require platform_admin explicitly here too (defense-in-depth, and so
the code matches the effective authz rather than implying a broader access):
  - logs (read-only): platform_admin + debug_mode=TRUE. Tying it to debug_mode
    means logs are only exposed while the server is deliberately flagged for
    debugging, not on demand.
  - restart/rebuild (destructive lifecycle): platform_admin ONLY. Two
    automated security reviews (2026-07-18) flagged deriving the target
    container from the mutable upstream_url as a confused-deputy/IDOR risk;
    restricting these to platform_admin closes it (upstream_url is itself
    platform_admin-only mutable via PATCH, so this is the tightest binding).

The container/service name acted upon is NEVER taken from client input —
it's derived server-side from urlparse(server.upstream_url).hostname, so a
caller cannot ask the ops-agent to act on an arbitrary container even if they
control the request body. As defense-in-depth, the derived hostname is also
checked against the same mcp-/lab-mcp- allowlist prefix the ops-agent itself
enforces, so a malformed/foreign upstream_url is rejected here rather than
relying solely on the ops-agent's own check.

Fail-closed: if OPS_AGENT_URL or OPS_AGENT_TOKEN is unset, or the agent is
unreachable, every endpoint here returns 503 rather than silently no-op'ing
or falling back to a direct podman call.
"""
from __future__ import annotations

import json
import logging
import uuid
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.routers.server_registry import _require_owner_or_maintainer, _require_platform_admin
from app.services import scan_queue
from app.services.server_lifecycle import (
    RequestChangeNotEligibleError,
    ServerNotFoundError,
    request_change_for_server,
    snapshot_tool_schema,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_MAX_TAIL = 1000
# Mirrors the ops-agent's own container-name allowlist (ops-agent/app.py) —
# defense-in-depth so a malformed/foreign upstream_url is rejected here
# rather than relying solely on the ops-agent's own check.
_CONTAINER_ALLOWLIST_PREFIXES = ("mcp-", "lab-mcp-")


async def _get_server_row(server_id: str) -> dict | None:
    async with AsyncSessionLocal() as db:
        row = (await db.execute(
            text(
                "SELECT server_id, owner_sub, maintainers, debug_mode, upstream_url, "
                "github_repo_url, is_self_hosted "
                "FROM server_registry WHERE server_id = :sid AND deleted_at IS NULL"
            ),
            {"sid": server_id},
        )).fetchone()
    return dict(row._mapping) if row else None


def _derive_container_name(upstream_url: str) -> str:
    """
    Derive the container/service name the ops-agent should act on from the
    server's own upstream_url — never from client-supplied input. e.g.
    http://lab-mcp-echo:8000/mcp -> "lab-mcp-echo".
    """
    hostname = urlparse(upstream_url).hostname
    if not hostname:
        raise HTTPException(
            status_code=422, detail="server upstream_url has no resolvable hostname"
        )
    if not hostname.startswith(_CONTAINER_ALLOWLIST_PREFIXES):
        raise HTTPException(
            status_code=422,
            detail=f"derived container {hostname!r} is not an MCP backend "
                   "(expected an mcp-/lab-mcp- prefixed host)",
        )
    return hostname


def _require_debug_mode(row: dict) -> None:
    if not row.get("debug_mode"):
        raise HTTPException(
            status_code=409,
            detail="server lifecycle operations require debug_mode=TRUE on this server "
                   "(POST /api/v1/servers/{id}/debug-mode)",
        )


async def _require_authz(server_id: str, request: Request, *, admin_only: bool = False) -> dict:
    """
    Authorize a lifecycle op on server_id and return the server row.

    admin_only=False (logs): this server's owner/maintainer, or a platform_admin.
    admin_only=True (restart/rebuild): platform_admin ONLY. The admin check runs
      BEFORE the row is fetched so a non-admin cannot distinguish an existing
      server (would be 403) from a missing one (404).
    """
    if admin_only:
        _require_platform_admin(request)
    row = await _get_server_row(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if not admin_only:
        _require_owner_or_maintainer(row, request, allow_platform_admin=True)
    return row


def _require_ops_agent_configured() -> tuple[str, str]:
    url = (settings.OPS_AGENT_URL or "").strip()
    token = (settings.OPS_AGENT_TOKEN or "").strip()
    if not url or not token:
        raise HTTPException(
            status_code=503,
            detail="ops-agent is not configured (OPS_AGENT_URL/OPS_AGENT_TOKEN unset) "
                   "— server lifecycle operations are unavailable",
        )
    return url, token


async def _call_ops_agent(method: str, path: str, **kwargs) -> httpx.Response:
    url, token = _require_ops_agent_configured()
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method, f"{url.rstrip('/')}{path}",
                headers={"X-Ops-Token": token},
                **kwargs,
            )
    except httpx.RequestError as exc:
        logger.error("ops-agent unreachable: %s %s: %s", method, path, exc)
        raise HTTPException(status_code=503, detail=f"ops-agent unreachable: {exc}") from exc
    return resp


def _forward_error(resp: httpx.Response) -> None:
    """Surface a non-2xx ops-agent response as the equivalent proxy error."""
    try:
        detail = resp.json().get("detail", resp.text)
    except Exception:
        detail = resp.text
    status = resp.status_code if resp.status_code >= 400 else 502
    raise HTTPException(status_code=status, detail=detail)


@router.get("/api/v1/admin/servers/{server_id}/logs")
async def get_server_logs(
    server_id: str, request: Request, tail: int = Query(200, ge=1, le=_MAX_TAIL)
):
    row = await _require_authz(server_id, request, admin_only=True)
    _require_debug_mode(row)
    container = _derive_container_name(row["upstream_url"])

    resp = await _call_ops_agent(
        "GET", "/ops/logs", params={"container": container, "tail": tail}
    )
    if resp.status_code != 200:
        _forward_error(resp)

    return JSONResponse(resp.json())


@router.post("/api/v1/admin/servers/{server_id}/restart")
async def restart_server(server_id: str, request: Request):
    row = await _require_authz(server_id, request, admin_only=True)
    _require_debug_mode(row)
    container = _derive_container_name(row["upstream_url"])

    resp = await _call_ops_agent("POST", "/ops/restart", json={"container": container})
    if resp.status_code != 200:
        _forward_error(resp)

    actor = getattr(request.state, "client_id", "unknown")
    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor=actor, action="server_restart", client_id=server_id,
        details={"server_id": server_id, "container": container},
    )
    return JSONResponse(resp.json())


async def _apply_platform_rebuild_rereview(
    server_id: str, actor: str, github_repo_url: str,
) -> dict:
    """
    Route a freshly-rebuilt platform-hosted (is_self_hosted=FALSE) server's
    code through the same guarded re-scan + reviewer re-approval sequence
    PRD-0012 C3 (server_lifecycle.request_change_for_server) uses for
    self-hosted servers — but request_change_for_server itself explicitly
    REJECTS is_self_hosted=FALSE rows with a 400 ("platform-deployed servers
    use the /apply rebuild path instead" — see its docstring), so it cannot
    be called directly for the exact servers this "git pull & rebuild"
    feature targets. This is that "/apply rebuild path": the same
    demote-and-quarantine + guarded-rescan shape, reproduced here rather
    than in server_lifecycle.py (outside this router's ownership), and
    scoped to is_self_hosted=FALSE via the WHERE clause below so it can
    never CAS-demote a self-hosted row (self-hosted rows keep going through
    request_change_for_server, unchanged, in rebuild_server below).

    Mirrors request_change_for_server's code_change branch: snapshot the
    live tool schema, CAS-demote status='approved'->'quarantined' /
    submission_status->'awaiting_review' (guarded — a concurrent
    reject/delete/mid-scan row is rejected, never silently overwritten),
    quarantine every tool_registry row, enqueue a 'change_rereview_scan' job
    (force=True — a rebuild-triggered re-review must always get a fresh
    job), and record the same SERVER_CHANGE_REQUESTED audit event so
    downstream consumers of that event type see a uniform trail regardless
    of which code path produced it. scan_evaluator._evaluate_change_rereview_scan
    itself has no is_self_hosted gate, so it processes this identically to
    the self-hosted path.
    """
    async with AsyncSessionLocal() as session:
        tool_schema_snapshot = await snapshot_tool_schema(session, server_id)

        result = await session.execute(
            text(
                """
                UPDATE server_registry
                SET status = 'quarantined',
                    submission_status = 'awaiting_review',
                    last_good_upstream_url = upstream_url,
                    last_good_scan_commit = scan_commit,
                    last_good_tool_schema = CAST(:tool_schema AS jsonb),
                    last_good_recorded_at = now(),
                    updated_at = now()
                WHERE server_id = :sid AND deleted_at IS NULL AND status = 'approved'
                  AND submission_status IN ('approved', 'active') AND is_self_hosted = FALSE
                RETURNING server_id
                """
            ),
            {"sid": server_id, "tool_schema": json.dumps(tool_schema_snapshot)},
        )
        if result.rowcount == 0:
            await session.rollback()
            raise RequestChangeNotEligibleError(
                "server is not in a live, platform-hosted state (status='approved', "
                "submission_status in ('approved','active'), is_self_hosted=FALSE) — "
                "rebuild re-review only applies to a currently-live platform-hosted server",
                status_code=409,
            )

        quarantine_result = await session.execute(
            text(
                """
                UPDATE tool_registry
                SET status = 'quarantined', updated_at = now()
                WHERE server_id = :sid AND deleted_at IS NULL AND status != 'quarantined'
                """
            ),
            {"sid": server_id},
        )
        tools_quarantined = quarantine_result.rowcount or 0

        event_id = str(uuid.uuid4())
        await session.execute(
            text(
                """
                INSERT INTO audit_events
                (event_id, event_type, client_id, tool_name, outcome, request_id,
                 sha256_hash, latency_ms)
                VALUES (:eid, 'SERVER_CHANGE_REQUESTED', :actor, :server_id, 'allow', :rid, '', 0)
                """
            ),
            {"eid": event_id, "actor": actor, "server_id": server_id, "rid": event_id},
        )
        await session.commit()

    logger.info(
        "apply_platform_rebuild_rereview demoted server_id=%s actor=%s tools_quarantined=%s",
        server_id, actor, tools_quarantined,
    )

    job_id = await scan_queue.enqueue_scan(
        server_id, github_repo_url, job_type="change_rereview_scan", force=True,
    )
    return {
        "server_id": server_id,
        "classification": "code_change",
        "submission_status": "awaiting_review",
        "tools_quarantined": tools_quarantined,
        "job_id": job_id,
    }


@router.post("/api/v1/admin/servers/{server_id}/rebuild")
async def rebuild_server(server_id: str, request: Request):
    """
    "Update from git & rebuild": pull the latest code for a platform-hosted
    server whose source is a public git repo, rebuild+recreate its
    container via the ops-agent, then route the rebuilt code through the
    guarded re-scan + reviewer re-approval sequence (PRD-0012 C3) — a
    rebuild must never itself grant PASS/approved status; it only starts
    the same review path a fresh submission or a self-hosted request-change
    would.

    Scope/limitation: this only works for servers the ops-agent can
    actually reach and rebuild — a platform-hosted container behind the
    podman socket this agent holds. A server hosted on the owner's own
    infrastructure is never reachable here; that owner updates their own
    process and calls POST /api/v1/servers/{id}/request-change directly.
    """
    row = await _require_authz(server_id, request, admin_only=True)
    _require_debug_mode(row)

    github_repo_url = (row.get("github_repo_url") or "").strip()
    if not github_repo_url:
        raise HTTPException(status_code=400, detail="no git repo configured for this server")

    container = _derive_container_name(row["upstream_url"])

    resp = await _call_ops_agent(
        "POST", "/ops/rebuild-from-git", json={"service": container, "git_url": github_repo_url}
    )
    if resp.status_code != 200:
        # Rebuild itself failed (or ops-agent unreachable, via
        # _call_ops_agent's own 503) — never trigger request-change/
        # re-review on a rebuild that didn't actually happen.
        _forward_error(resp)

    actor = getattr(request.state, "client_id", "unknown")
    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor=actor, action="server_rebuild", client_id=server_id,
        details={"server_id": server_id, "service": container, "git_url": github_repo_url},
    )

    try:
        if row.get("is_self_hosted", True):
            # Unusual (a self-hosted row's upstream_url resolved to an
            # ops-agent-reachable mcp-/lab-mcp- host) but not impossible —
            # request_change_for_server already handles this case exactly
            # as PRD-0012 C3 specifies.
            change_result = await request_change_for_server(
                server_id, actor, new_github_repo_url=github_repo_url, asserted_ip_only=False,
            )
        else:
            change_result = await _apply_platform_rebuild_rereview(
                server_id, actor, github_repo_url,
            )
    except ServerNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RequestChangeNotEligibleError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    return JSONResponse({
        "rebuilt": True,
        "service": container,
        "git_url": github_repo_url,
        "rebuild_output": resp.json(),
        "change_review": change_result,
    })
