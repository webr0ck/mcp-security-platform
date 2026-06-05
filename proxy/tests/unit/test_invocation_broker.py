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
    """Verify that invoke_tool merges dispatch_credential_injection output into upstream headers."""
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

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
        "injection_mode": "service",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    with patch.dict(sys.modules, stubs), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(return_value={"Authorization": "Bearer injected-token"})), \
         patch("app.services.invocation._get_or_create_session",
               AsyncMock(return_value="mcp-session-cached")), \
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


@pytest.mark.unit
async def test_invoke_tool_fails_closed_when_broker_none_and_injection_required():
    """
    broker_instance is None + tool has service_name + credential_approach
    → CredentialInjectionError must be raised (not silently skip injection).
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    tool_record = {
        "tool_id": "t2",
        "name": "grafana-query",
        "status": "active",
        "upstream_url": "http://grafana:3000/mcp",
        "service_name": "grafana",
        "injection_mode": "service",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer ",
    }

    from app.credential_broker.dispatcher import CredentialInjectionError

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", None):
        with pytest.raises(CredentialInjectionError, match="Credential broker not initialized"):
            await invoke_tool(
                tool_record=tool_record,
                json_rpc_request={"jsonrpc": "2.0", "method": "tools/call", "id": 2, "params": {}},
                client_id="alice@corp",
                client_roles=["operator"],
                is_testing=False,
                request_id="req-2",
            )


@pytest.mark.unit
async def test_invoke_tool_fails_closed_for_service_account_mode():
    """injection_mode='service_account' must raise CredentialInjectionError (G4 fix).

    A broker is present (non-None), but the tool has no kc_client_id configured —
    the dispatcher must raise rather than silently forward without credentials.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    tool = {
        "tool_id": "t1", "name": "svc-tool", "status": "active",
        "risk_level": "low", "upstream_url": "http://fake/",
        "injection_mode": "service_account", "service_name": "mysvc",
        "inject_header": None, "inject_prefix": None, "version": "1",
        # kc_client_id intentionally absent
    }

    from app.credential_broker.dispatcher import CredentialInjectionError

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", MagicMock()):  # broker is present — mode is the issue
        with pytest.raises(CredentialInjectionError, match="kc_client_id"):
            await invoke_tool(
                tool_record=tool,
                json_rpc_request={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"arguments": {}}},
                client_id="u1", client_roles=["agent"], is_testing=False, request_id="r1",
            )


@pytest.mark.unit
async def test_invoke_tool_audits_deny_on_credential_injection_failure():
    """
    CR finding #1b: when credential injection is REQUIRED but fails (e.g. caller
    not enrolled for delegated 'm365' access), invoke_tool must emit a DENY audit
    event BEFORE the error propagates — parity with OPA-stage denies. Previously
    the only signal was a -32603 to the caller with no audit trail.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    from app.credential_broker.dispatcher import CredentialInjectionError

    tool_record = {
        "tool_id": "t-m365",
        "name": "get_me",
        "status": "active",
        "risk_level": "medium",
        "version": "1.0.0",
        "upstream_url": "http://lab-mcp-m365:8000/mcp",
        "service_name": "m365",
        "injection_mode": "entra_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    emit_mock = AsyncMock(return_value="evt-deny-1")

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", MagicMock()), \
         patch.object(_inv_mod, "_emit_audit_event", emit_mock), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(side_effect=CredentialInjectionError(
                   "User alice@corp is not enrolled for delegated 'm365' access."))):
        with pytest.raises(CredentialInjectionError, match="not enrolled"):
            await invoke_tool(
                tool_record=tool_record,
                json_rpc_request={"jsonrpc": "2.0", "method": "tools/call", "id": 9,
                                  "params": {"arguments": {}}},
                client_id="alice@corp",
                client_roles=["operator"],
                is_testing=False,
                request_id="req-deny",
            )

    # A DENY audit event must have been emitted for the credential refusal.
    deny_calls = [c for c in emit_mock.await_args_list if c.kwargs.get("outcome") == "deny"]
    assert deny_calls, "no DENY audit event emitted on credential injection failure"
    kw = deny_calls[-1].kwargs
    assert "credential_injection_failed" in kw.get("deny_reasons", [])
    assert kw.get("client_id") == "alice@corp"
    assert kw.get("tool_name") == "get_me"


@pytest.mark.unit
async def test_invoke_tool_passes_when_broker_none_and_no_injection_required():
    """
    broker_instance is None + tool has NO service_name (injection not required)
    → must NOT raise; call proceeds normally.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    tool_record_no_injection = {
        "tool_id": "t3",
        "name": "no-cred-tool",
        "status": "active",
        "upstream_url": "http://some-server:8080/mcp",
        "injection_mode": "none",   # explicit: no injection
    }

    mock_response = MagicMock()
    mock_response.content = b'{"jsonrpc": "2.0", "result": {}, "id": 3}'
    mock_response.headers = {"content-type": "application/json"}

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", None), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_response)
        mock_cls.return_value = mock_http

        result = await invoke_tool(
            tool_record=tool_record_no_injection,
            json_rpc_request={"jsonrpc": "2.0", "method": "tools/call", "id": 3, "params": {}},
            client_id="alice@corp",
            client_roles=["operator"],
            is_testing=False,
            request_id="req-3",
        )

    # Result must be a JSON-RPC response (not a crash)
    assert result.get("jsonrpc") == "2.0"
