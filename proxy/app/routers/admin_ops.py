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

Authz:
  - logs (read-only, debug_mode-gated): platform_admin OR this server's own
    owner/maintainer (reusing the _require_owner_or_maintainer pattern from
    server_registry.py — a caller must actually be *this* server's owner_sub
    or a listed maintainer, not merely hold a role called "server_owner").
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

import logging
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.routers.server_registry import _require_owner_or_maintainer, _require_platform_admin

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
                "SELECT server_id, owner_sub, maintainers, debug_mode, upstream_url "
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
    row = await _require_authz(server_id, request)
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


@router.post("/api/v1/admin/servers/{server_id}/rebuild")
async def rebuild_server(server_id: str, request: Request):
    row = await _require_authz(server_id, request, admin_only=True)
    _require_debug_mode(row)
    container = _derive_container_name(row["upstream_url"])

    resp = await _call_ops_agent("POST", "/ops/rebuild", json={"service": container})
    if resp.status_code != 200:
        _forward_error(resp)

    actor = getattr(request.state, "client_id", "unknown")
    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor=actor, action="server_rebuild", client_id=server_id,
        details={"server_id": server_id, "service": container},
    )
    return JSONResponse(resp.json())
