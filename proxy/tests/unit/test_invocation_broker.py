from __future__ import annotations
import sys
import pytest
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta


def _make_sys_stubs():
    """Build stub modules for deps that can't be imported in unit test env."""
    mock_anomaly = ModuleType("app.services.anomaly")
    mock_anomaly.evaluate_anomaly = AsyncMock()  # type: ignore[attr-defined]
    mock_anomaly.detect = AsyncMock(return_value=MagicMock(anomaly_score=0.0))  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(return_value={"allow": True, "reasons": []})  # type: ignore[attr-defined]
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    audit_event = MagicMock()
    audit_event.event_id = "audit-evt-1"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.MCPAuditLogger = MagicMock()  # type: ignore[attr-defined]

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }


@pytest.mark.unit
async def test_invoke_tool_injects_credential_header():
    """Verify that invoke_tool calls broker.resolve and injects the token."""
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    future = datetime.now(timezone.utc) + timedelta(hours=1)

    mock_credential = MagicMock()
    mock_credential.token = "injected-token"
    mock_credential.expires_at = future
    mock_credential.zero = MagicMock()

    mock_broker = AsyncMock()
    mock_broker.resolve = AsyncMock(return_value=mock_credential)

    mock_response = MagicMock()
    mock_response.json = MagicMock(return_value={"jsonrpc": "2.0", "result": {}, "id": 1})

    captured_headers: dict = {}

    async def fake_post(url, json, headers, timeout=30.0):
        captured_headers.update(headers)
        return mock_response

    tool_record = {
        "tool_id": "t1",
        "name": "grafana-query",
        "status": "active",
        "upstream_url": "http://grafana:3000/mcp",
        "service_name": "grafana",
        "credential_approach": "B",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer ",
    }

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", mock_broker), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(side_effect=fake_post)
        mock_cls.return_value = mock_http

        await invoke_tool(
            tool_record=tool_record,
            json_rpc_request={"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {}},
            client_id="alice@corp",
            client_roles=["operator"],
            is_testing=False,
            request_id="req-1",
        )

    assert "Authorization" in captured_headers
    assert captured_headers["Authorization"] == "Bearer injected-token"
    mock_broker.resolve.assert_awaited_once()
    mock_credential.zero.assert_called_once()
