from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from app.core.config import settings

_SERVICE_NAME = "mcp-security-proxy"


class Telemetry:
    """OTel tracer wrapper. No-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set."""

    def __init__(self) -> None:
        self._tracer: trace.Tracer | None = None
        self._provider: TracerProvider | None = None

    def initialize(self) -> None:
        endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT
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

    def shutdown(self) -> None:
        if self._provider is not None:
            self._provider.shutdown()

    @property
    def tracer(self) -> trace.Tracer:
        if self._tracer is None:
            raise RuntimeError("Telemetry not initialized. Call initialize() first.")
        return self._tracer


# Module-level singleton; initialized in app lifespan
telemetry = Telemetry()
