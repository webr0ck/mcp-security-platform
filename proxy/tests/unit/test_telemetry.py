from __future__ import annotations

import pytest
from opentelemetry.trace import NoOpTracer
from opentelemetry.sdk.trace import Tracer as SDKTracer


@pytest.mark.unit
def test_telemetry_noop_when_endpoint_unset(monkeypatch):
    monkeypatch.setattr(
        "app.core.config.settings.OTEL_EXPORTER_OTLP_ENDPOINT", ""
    )
    from app.core.telemetry import Telemetry

    t = Telemetry()
    t.initialize()
    assert isinstance(t.tracer, NoOpTracer)


@pytest.mark.unit
def test_telemetry_real_tracer_when_endpoint_set(monkeypatch):
    monkeypatch.setattr(
        "app.core.config.settings.OTEL_EXPORTER_OTLP_ENDPOINT",
        "http://otel-collector:4317",
    )
    from app.core.telemetry import Telemetry

    t = Telemetry()
    t.initialize()
    assert isinstance(t.tracer, SDKTracer)
