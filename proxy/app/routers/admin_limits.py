"""Admin per-client request limits: view counts, edit thresholds, reset counters.

Endpoints:
  GET  /api/v1/admin/limits                    — list all clients with live counts
  GET  /api/v1/admin/limits/{client_id}        — detail + blocked_by status
  PUT  /api/v1/admin/limits/{client_id}        — upsert rate_limit + anomaly_sensitivity
  POST /api/v1/admin/limits/{client_id}/reset  — clear rate / anomaly Redis counters

Role requirement: admin or platform_admin (mirrors admin_grants.py).
All mutations are recorded in the HMAC-signed audit chain via admin_audit.py.
"""
from __future__ import annotations

import logging
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.redis_client import get_anomaly_window_with_timestamps, redis_pool
from app.core.config import get_rate_limit_for_roles, get_settings
from app.services import limits as limits_svc
from app.services.admin_audit import emit_admin_config_event

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = {"admin", "platform_admin"}
_RESET_RL = 10       # max resets per client per window
_RESET_WINDOW = 300  # seconds


# ---------------------------------------------------------------------------
# Auth guard (mirrors admin_grants.py _require_admin)
# ---------------------------------------------------------------------------

def _require_admin(request: Request) -> None:
    """Enforce admin or platform_admin role. Raises 403 if not satisfied."""
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="admin or platform_admin role required")


# ---------------------------------------------------------------------------
# DB pool helper (mirrors admin_grants.py _get_db_pool)
# ---------------------------------------------------------------------------

async def _db():
    """Return the asyncpg pool or raise 503 if not initialised."""
    from app.core.asyncpg_pool import asyncpg_pool

    pool = asyncpg_pool.get()
    if pool is None:
        raise HTTPException(status_code=503, detail="Database pool not available")
    return pool


# ---------------------------------------------------------------------------
# Redis counter helper
# ---------------------------------------------------------------------------

async def _rate_count(client_id: str) -> int:
    """Return current rate-limit window count for client_id. Returns 0 on error."""
    try:
        v = await redis_pool.rate_limit_client.get(f"rl:mcp:{client_id}")
        return int(v) if v is not None else 0
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class LimitUpdate(BaseModel):
    rate_limit: Optional[int] = Field(default=None, ge=1, le=100000)
    anomaly_sensitivity: Literal["normal", "lenient", "off"] = "normal"


class ResetBody(BaseModel):
    target: Literal["rate", "anomaly", "both"] = "both"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/v1/admin/limits")
async def list_limits(request: Request) -> dict[str, Any]:
    """List all clients with live rate counts and anomaly window sizes.

    Merges clients seen in the last 24 hours of audit_events with any row
    present in client_limits, so admins can see both active clients and those
    with explicit overrides.
    """
    _require_admin(request)
    pool = await _db()

    rows = await pool.fetch(
        "SELECT DISTINCT client_id FROM audit_events WHERE created_at > NOW() - INTERVAL '24 hours' "
        "UNION "
        "SELECT client_id FROM client_limits"
    )
    overrides = {
        r["client_id"]: r
        for r in await pool.fetch(
            "SELECT client_id, rate_limit, anomaly_sensitivity, updated_by, updated_at "
            "FROM client_limits"
        )
    }

    settings = get_settings()
    out = []
    for r in rows:
        cid = r["client_id"]
        ov = overrides.get(cid)
        sens = ov["anomaly_sensitivity"] if ov else "normal"
        rate_limit_override = ov["rate_limit"] if (ov and ov["rate_limit"] is not None) else None
        effective_rate_limit = (
            rate_limit_override
            if rate_limit_override is not None
            else get_rate_limit_for_roles([], settings)
        )
        win = await get_anomaly_window_with_timestamps(cid)
        out.append({
            "client_id": cid,
            "rate": {
                "count": await _rate_count(cid),
                "limit": effective_rate_limit,
                "is_override": rate_limit_override is not None,
            },
            "anomaly": {
                "window_calls": len(win),
                "sensitivity": sens,
                "cutoff": limits_svc.cutoff_for_sensitivity(sens),
            },
            "updated_by": ov["updated_by"] if ov else None,
            "updated_at": ov["updated_at"].isoformat() if ov and ov["updated_at"] else None,
        })

    return {"limits": sorted(out, key=lambda x: x["client_id"]), "count": len(out)}


@router.get("/api/v1/admin/limits/{client_id}")
async def get_limit(client_id: str, request: Request) -> dict[str, Any]:
    """Detail view for a specific client: live score, cutoff, and blocked_by status."""
    _require_admin(request)
    pool = await _db()

    ov = await pool.fetchrow(
        "SELECT rate_limit, anomaly_sensitivity, updated_by, updated_at "
        "FROM client_limits WHERE client_id=$1",
        client_id,
    )
    sens = ov["anomaly_sensitivity"] if ov else "normal"
    cutoff = limits_svc.cutoff_for_sensitivity(sens)

    try:
        score = await limits_svc.score_window(client_id)
    except Exception:
        score = 0.0

    rate_count = await _rate_count(client_id)
    settings = get_settings()
    rate_limit = (
        ov["rate_limit"]
        if (ov and ov["rate_limit"] is not None)
        else get_rate_limit_for_roles([], settings)
    )

    blocked = []
    if rate_count > rate_limit:
        blocked.append("rate")
    if score > cutoff:
        blocked.append("anomaly")

    return {
        "client_id": client_id,
        "rate": {
            "count": rate_count,
            "limit": rate_limit,
            "is_override": bool(ov and ov["rate_limit"] is not None),
        },
        "anomaly": {"score": round(score, 3), "cutoff": cutoff, "sensitivity": sens},
        "blocked_by": "both" if len(blocked) == 2 else (blocked[0] if blocked else "none"),
        "updated_by": ov["updated_by"] if ov else None,
        "updated_at": ov["updated_at"].isoformat() if ov and ov["updated_at"] else None,
    }


@router.put("/api/v1/admin/limits/{client_id}")
async def put_limit(client_id: str, body: LimitUpdate, request: Request) -> dict[str, Any]:
    """Upsert per-client rate_limit and anomaly_sensitivity overrides.

    Invalidates the Redis limits cache so all workers pick up the change immediately.
    Emits an audit event via the HMAC-signed chain. If anomaly_sensitivity='off',
    emits a second high-visibility audit event (tool_name='admin.anomaly_disabled')
    so SIEM rules can alert on protection-disabling changes.
    """
    _require_admin(request)
    pool = await _db()
    actor = getattr(request.state, "client_id", "unknown-admin")

    prev = await pool.fetchrow(
        "SELECT rate_limit, anomaly_sensitivity FROM client_limits WHERE client_id=$1",
        client_id,
    )

    await pool.execute(
        "INSERT INTO client_limits (client_id, rate_limit, anomaly_sensitivity, updated_by) "
        "VALUES ($1, $2, $3, $4) "
        "ON CONFLICT (client_id) DO UPDATE SET "
        "rate_limit=EXCLUDED.rate_limit, "
        "anomaly_sensitivity=EXCLUDED.anomaly_sensitivity, "
        "updated_by=EXCLUDED.updated_by, "
        "updated_at=NOW()",
        client_id,
        body.rate_limit,
        body.anomaly_sensitivity,
        actor,
    )

    await limits_svc.invalidate(client_id)

    await emit_admin_config_event(
        actor,
        "set_limits",
        client_id,
        {
            "old": dict(prev) if prev else None,
            "new": {
                "rate_limit": body.rate_limit,
                "anomaly_sensitivity": body.anomaly_sensitivity,
            },
        },
    )

    if body.anomaly_sensitivity == "off":
        # High-visibility audit: SIEM rules alert on tool_name='admin.anomaly_disabled',
        # not on outcome — keep outcome='allow' so deny-rate dashboards are not polluted.
        await emit_admin_config_event(
            actor,
            "anomaly_disabled",
            client_id,
            {"sensitivity": "off"},
            outcome="allow",
        )

    return {"ok": True, "client_id": client_id}


@router.post("/api/v1/admin/limits/{client_id}/reset")
async def reset_limit(client_id: str, body: ResetBody, request: Request) -> dict[str, Any]:
    """Clear rate-limit and/or anomaly-window Redis counters for a client.

    Anti-abuse: caps resets at 10 per client per 5 minutes to prevent admins
    (or a compromised admin token) from flooding the reset path to permanently
    unblock a misbehaving client. Redis hiccups on the counter itself never
    block a legitimate reset (try/except swallows counter errors).
    """
    _require_admin(request)
    actor = getattr(request.state, "client_id", "unknown-admin")

    # Anti-abuse rate cap
    try:
        rc = redis_pool.rate_limit_client
        gkey = f"rl:adminreset:{client_id}"
        n = await rc.incr(gkey)
        await rc.expire(gkey, _RESET_WINDOW)
        if n > _RESET_RL:
            await emit_admin_config_event(
                actor,
                "reset_rate_limited",
                client_id,
                {"count": n},
                outcome="deny",
            )
            raise HTTPException(
                status_code=429,
                detail="too many resets for this client; slow down",
            )
    except HTTPException:
        raise
    except Exception:
        # Redis hiccup on the counter must never block a legitimate reset.
        pass

    cleared = []
    if body.target in ("rate", "both"):
        await redis_pool.rate_limit_client.delete(f"rl:mcp:{client_id}")
        cleared.append("rate")
    if body.target in ("anomaly", "both"):
        await redis_pool.client.delete(f"anomaly:window:{client_id}")
        cleared.append("anomaly")

    await emit_admin_config_event(
        actor,
        "reset_limits",
        client_id,
        {"target": body.target, "cleared": cleared},
    )

    return {"ok": True, "client_id": client_id, "cleared": cleared}
