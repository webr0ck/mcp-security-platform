"""
MCP Security Platform — Health and Readiness Endpoints

GET /health      — Liveness probe; public; returns service status of all dependencies.
GET /health/ready — Readiness probe for Kubernetes; returns 503 if critical deps are down.

See docs/API.md Section 2.1 for full specification.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import check_database_health
from app.core.redis_client import redis_pool

router = APIRouter()


async def _check_opa() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(f"{settings.opa_url}/health")
            return resp.status_code == 200
    except Exception:
        return False


async def _check_ollama() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.ollama_base_url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


@router.get("/health", include_in_schema=True)
async def liveness() -> JSONResponse:
    """
    Liveness probe. Returns 200 if the service is running.
    Returns 503 if all dependencies are completely unreachable (degraded service).
    Ollama failure does not change status (advisory service).
    """
    db_ok, redis_ok, opa_ok, ollama_ok = await asyncio.gather(
        check_database_health(),
        redis_pool.ping(),
        _check_opa(),
        _check_ollama(),
    )

    services = {
        "database": "ok" if db_ok else "error",
        "redis": "ok" if redis_ok else "error",
        "opa": "ok" if opa_ok else "error",
        "ollama": "ok" if ollama_ok else "error",
    }

    critical_ok = db_ok and redis_ok and opa_ok
    overall = "ok" if critical_ok else ("degraded" if any([db_ok, redis_ok, opa_ok]) else "error")

    status_code = 200 if critical_ok else 503
    return JSONResponse(
        status_code=status_code,
        content={
            "status": overall,
            "version": settings.PLATFORM_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": services,
        },
    )


@router.get("/health/ready", include_in_schema=True)
async def readiness() -> JSONResponse:
    """
    Kubernetes readiness probe.
    Returns 200 only if database, redis, and opa are all reachable.
    Ollama failure does NOT block readiness.
    """
    db_ok, redis_ok, opa_ok = await asyncio.gather(
        check_database_health(),
        redis_pool.ping(),
        _check_opa(),
    )

    if db_ok and redis_ok and opa_ok:
        return JSONResponse(status_code=200, content={"ready": True})

    reasons = []
    if not db_ok:
        reasons.append("database unreachable")
    if not redis_ok:
        reasons.append("redis unreachable")
    if not opa_ok:
        reasons.append("opa unreachable")

    return JSONResponse(
        status_code=503,
        content={"ready": False, "reason": "; ".join(reasons)},
    )
