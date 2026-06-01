"""
MCP Security Platform — Server Catalog Router

Exposes a principal-scoped view of approved MCP servers.
Enforces the discovery == invoke invariant: a principal sees exactly
the servers they are entitled to call — no more, no less.

GET /api/v1/catalog/servers              — list servers this principal can invoke
GET /api/v1/catalog/servers/{server_id}  — detail for one server (404 if not entitled)
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request

from app.services.entitlement import check_entitlement, list_entitled_servers

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/catalog", tags=["Catalog"])


@router.get("/servers")
async def list_my_servers(request: Request):
    """
    Return approved servers this principal is entitled to access.

    Enforces discovery==invoke: only servers you can invoke appear here.
    Uses typed principal from request.state.principal_id + principal_type.
    """
    principal_id = getattr(request.state, "principal_id", None)
    principal_type = getattr(request.state, "principal_type", None)

    if not principal_id or not principal_type:
        raise HTTPException(status_code=401, detail="Principal identity not resolved")

    servers = await list_entitled_servers(
        principal_type=principal_type,
        principal_id=principal_id,
    )
    return {"servers": servers, "count": len(servers)}


@router.get("/servers/{server_id}")
async def get_server_detail(server_id: str, request: Request):
    """
    Return details for a specific server if the principal is entitled.

    Returns 404 if not entitled — never 403. This prevents information leakage
    about server existence to principals who are not entitled to access it.
    """
    principal_id = getattr(request.state, "principal_id", None)
    principal_type = getattr(request.state, "principal_type", None)

    if not principal_id or not principal_type:
        raise HTTPException(status_code=401, detail="Principal identity not resolved")

    result = await check_entitlement(
        principal_type=principal_type,
        principal_id=principal_id,
        server_id=server_id,
    )

    if not result.entitled:
        # Return 404 regardless of whether the server exists — no information leak.
        raise HTTPException(status_code=404, detail="Server not found")

    # Fetch full server details for entitled principals.
    servers = await list_entitled_servers(
        principal_type=principal_type,
        principal_id=principal_id,
    )
    server = next((s for s in servers if s["server_id"] == server_id), None)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    return {
        "server_id": server["server_id"],
        "name": server["name"],
        "upstream_url": server["upstream_url"],
        "custody_mode": server["custody_mode"],
        "role": result.role,
        "entitlement_reason": result.reason,
    }
