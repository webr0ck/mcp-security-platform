from __future__ import annotations

import logging

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_SERVICE_NAME = "mcp-security-proxy"


class Telemetry:
    """OTel tracer wrapper. No-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set."""

    def __init__(self) -> None:
        self._tracer: trace.Tracer | None = None
        self._provider: TracerProvider | None = None

    def initialize(self) -> None:
        # get_settings() is lru_cache-backed and re-fetched here (not bound at
        # import time) because tests call get_settings.cache_clear(), which
        # would otherwise leave a module-level `settings` reference stale.
        try:
            endpoint = get_settings().OTEL_EXPORTER_OTLP_ENDPOINT
            if not endpoint:
                self._tracer = trace.NoOpTracer()
                return

            resource = Resource.create({"service.name": _SERVICE_NAME})
            provider = TracerProvider(resource=resource)
            insecure = endpoint.startswith("http://")
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            self._provider = provider
            self._tracer = provider.get_tracer(__name__)
        except Exception:
            # Telemetry must never block startup or invocation (fail-open,
            # the one deliberate exception to this repo's fail-closed rule).
            logger.warning("Telemetry initialization failed; falling back to no-op tracer", exc_info=True)
            self._provider = None
            self._tracer = trace.NoOpTracer()

    def shutdown(self) -> None:
        if self._provider is not None:
            self._provider.shutdown()

    @property
    def tracer(self) -> trace.Tracer:
        # Fail-open: if initialize() was never called (or failed before
        # setting self._tracer), hand back a no-op tracer instead of raising
        # — telemetry must never block a real tool call.
        if self._tracer is None:
            return trace.NoOpTracer()
        return self._tracer


# Module-level singleton; initialized in app lifespan
telemetry = Telemetry()
