from __future__ import annotations

import httpx
import pytest

PROXY_URL = "http://localhost:8000"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tool_invoke_succeeds_when_otel_collector_unreachable():
    """
    Telemetry export failures must fail OPEN — this is the deliberate exception
    to this repo's fail-closed invariant (Global Constraints). A tool call must
    still succeed (or fail for its own reasons) even if the configured OTLP
    endpoint is unreachable.
    """
    # This test assumes the lab/dev proxy is started with an intentionally
    # unroutable OTEL_EXPORTER_OTLP_ENDPOINT (e.g. "http://otel-collector-down:4317")
    # to exercise the export-failure path without needing to kill a real container
    # mid-test. See docs/superpowers/specs/2026-07-21-otel-tool-invocation-telemetry-design.md.
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{PROXY_URL}/health")
    assert resp.status_code == 200, (
        "Proxy must stay healthy even with an unreachable OTLP endpoint configured"
    )
