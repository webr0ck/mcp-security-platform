from __future__ import annotations

import httpx
import pytest

PROXY_URL = "http://localhost:8000"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_proxy_starts_healthy_with_telemetry_wired():
    """Proxy must boot cleanly whether or not OTEL_EXPORTER_OTLP_ENDPOINT is set —
    telemetry init/shutdown must not block or crash the lifespan."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{PROXY_URL}/health")
    assert resp.status_code == 200
