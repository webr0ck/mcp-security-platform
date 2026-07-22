from __future__ import annotations

import sys
import pytest
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch


def _make_sys_stubs():
    mock_anomaly = ModuleType("app.services.anomaly")
    mock_anomaly.evaluate_anomaly = AsyncMock()
    mock_anomaly.detect = AsyncMock(return_value=MagicMock(anomaly_score=0.0))

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(return_value={"allow": True, "reasons": []})
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})

    audit_event = MagicMock()
    audit_event.event_id = "audit-evt-1"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event)
    mock_audit_pkg.AuditEventType = MagicMock()
    mock_audit_pkg.AuditOutcome = MagicMock()
    mock_audit_pkg.MCPAuditLogger = MagicMock()

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }


@pytest.mark.unit
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "principal_type,client_id",
    [("human", "kc-realm:alice"), ("agent", "lab-ca:cn-123")],
)
async def test_invoke_tool_span_tags_principal_type(principal_type, client_id):
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    mock_response = MagicMock()
    mock_response.json = MagicMock(return_value={"jsonrpc": "2.0", "result": {}, "id": 1})
    mock_response.status_code = 200
    mock_response.content = b'{"jsonrpc": "2.0", "result": {}, "id": 1}'
    mock_response.headers = {"content-type": "application/json"}

    captured_spans = []

    class _FakeSpan:
        def __init__(self):
            self.attributes = {}

        def set_attribute(self, key, value):
            self.attributes[key] = value

        def __enter__(self):
            return self

        def __exit__(self, *a):
            captured_spans.append(self.attributes)
            return False

    fake_tracer = MagicMock()
    fake_tracer.start_as_current_span.return_value = _FakeSpan()
    fake_telemetry = MagicMock()
    fake_telemetry.tracer = fake_tracer

    with patch.dict(sys.modules, stubs), \
         patch("app.services.invocation.telemetry", fake_telemetry), \
         patch("app.core.config.settings.TAINT_FLOOR_ENABLED", False), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(return_value={})), \
         patch("app.services.invocation._get_or_create_session",
               AsyncMock(return_value="mcp-session-cached")), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_cls.return_value.__aenter__.return_value = mock_http

        await invoke_tool(
            tool_record={"tool_id": "tool-1", "name": "echo", "version": "1.0",
                         "status": "active", "upstream_url": "http://grafana:3000/mcp"},
            json_rpc_request={"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "echo", "arguments": {}}},
            client_id=client_id,
            client_roles=["user"],
            is_testing=True,
            request_id="req-1",
            principal_id=f"{principal_type}:{client_id}",
            principal_type=principal_type,
        )

    assert captured_spans, "expected at least one span to be recorded"
    span_attrs = captured_spans[-1]
    assert span_attrs["principal.type"] == principal_type
    assert span_attrs["client.id"] == client_id
