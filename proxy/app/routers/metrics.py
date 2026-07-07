"""
GET /metrics — Prometheus scrape endpoint (CR-17 / WP-D1).

Not under /api/v1 (matches Prometheus convention + /health's own top-level
placement). No auth — scraped only from inside the lab network (see
docker-compose.yml's metrics-net + PROXY_INGRESS_TRUSTED_HOSTS); the metrics
exposed here are counts/gauges, never secret values.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.services.metrics import refresh_db_gauges

router = APIRouter()


@router.get("/metrics")
async def metrics() -> Response:
    await refresh_db_gauges()
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
