"""
Unit tests — Task 1.9: Per-function entitlement applies on direct tools/call.

Previously, tool_function_name was derived from json_rpc_request.params.arguments
(the tool body parameters), not from json_rpc_request.params.name (the actual
function being invoked). This meant allowed_functions restrictions were bypassed
on the direct tools/call path via /mcp.

Fix: derive tool_function_name from json_rpc_request.params.name (the JSON-RPC
function identifier), which is populated for direct tools/call requests.

Also verifies authz.rego deny rule: when allowed_functions is non-empty and
tool_function_name is empty string, deny (prevents a caller from calling an
unnamed/unidentified function when the profile restricts to specific functions).

Tests:
  (a) Profile with allowed_functions=["read_file"] + direct tools/call for
      "write_file" → OPA deny (currently bypassed because tool_function_name is "")
  (b) Profile with allowed_functions=["read_file"] + direct tools/call for
      "read_file" → OPA allow
  (c) tool_function_name="" + non-empty allowed_functions → OPA deny
      (the new authz.rego rule for empty function name)

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_per_function_entitlement.py -v
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

def _make_stubs(
    opa_allow: bool = True,
    opa_reasons: list[str] | None = None,
):
    """Build stub modules for invocation.py unit tests."""
    captured_opa_inputs: list[dict] = []

    async def _fake_evaluate_policy(input_data: dict):
        captured_opa_inputs.append(input_data)
        return {"allow": opa_allow, "reasons": opa_reasons or []}

    mock_anomaly = ModuleType("app.services.anomaly")
    anomaly_result = MagicMock()
    anomaly_result.anomaly_score = 0.0
    mock_anomaly.detect = AsyncMock(return_value=anomaly_result)  # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(side_effect=_fake_evaluate_policy)  # type: ignore[attr-defined]
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    audit_event_obj = MagicMock()
    audit_event_obj.event_id = "audit-fn-test"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    return (
        {
            "app.services.anomaly": mock_anomaly,
            "app.services.policy": mock_policy,
            "mcp_audit_logger": mock_audit_pkg,
        },
        captured_opa_inputs,
    )


def _make_tool_record(tool_id: str = "tool-fn-test") -> dict:
    return {
        "tool_id": tool_id,
        "name": "file_tool",
        "status": "active",
        "upstream_url": "http://mcp-server:8080/mcp",
        "service_name": None,
        "injection_mode": "none",
        "inject_header": None,
        "inject_prefix": None,
        "version": "1.0",
        "server_id": None,
        "risk_level": "low",
    }


def _make_direct_tools_call_request(function_name: str, arguments: dict | None = None) -> dict:
    """
    Build a JSON-RPC tools/call request as _route_to_registry builds it for
    the direct tools/call path in mcp_server.py:
      params.name = the function being invoked (e.g. "write_file")
      params.arguments = the tool body parameters
    """
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": function_name,
            "arguments": arguments or {},
        },
    }


# ===========================================================================
# (a) Profile with allowed_functions=["read_file"] + write_file call → deny
# ===========================================================================

@pytest.mark.unit
async def test_allowed_functions_blocks_write_file_on_direct_tools_call():
    """
    When a profile restricts to allowed_functions=["read_file"], a direct
    tools/call for "write_file" must be DENIED by OPA.

    Before the fix, tool_function_name was "" (empty) because it was read from
    params.arguments, not params.name. This meant allowed_functions was never
    checked for the direct tools/call path.

    After the fix, tool_function_name="write_file" and OPA denies because
    "write_file" ∉ ["read_file"].
    """
    stubs, captured_opa_inputs = _make_stubs(
        opa_allow=False,
        opa_reasons=["function_not_allowed_for_profile"],
    )

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    # Simulate a profile row that allows only "read_file"
    mock_profile_data = {
        "enabled": True,
        "allowed_functions": ["read_file"],
    }

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)):

        with pytest.raises(Exception):  # OPADenyError
            await _inv_mod.invoke_tool(
                tool_record=_make_tool_record(),
                json_rpc_request=_make_direct_tools_call_request("write_file"),
                client_id="restricted-client",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-fn-deny-001",
                # inject profile data directly — simulates what Step 2.5 would
                # produce after a DB hit; we validate via opa_input capture below
            )

    # The OPA input must have tool_function_name="write_file" (not "")
    assert len(captured_opa_inputs) >= 1, "OPA was never called"
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("tool_function_name") == "write_file", (
        f"Expected tool_function_name='write_file', got: "
        f"'{opa_input.get('tool_function_name')}'. "
        f"The function name must be derived from json_rpc_request.params.name, "
        f"not from params.arguments."
    )


# ===========================================================================
# (b) Profile with allowed_functions=["read_file"] + read_file call → allow
# ===========================================================================

@pytest.mark.unit
async def test_allowed_functions_allows_read_file_on_direct_tools_call():
    """
    When a profile restricts to allowed_functions=["read_file"], a direct
    tools/call for "read_file" must pass the OPA function check.

    We verify the OPA input contains tool_function_name="read_file".
    """
    stubs, captured_opa_inputs = _make_stubs(
        opa_allow=True,
        opa_reasons=[],
    )

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    upstream_json = {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "ok"}]}, "id": 1}
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.headers = {"content-type": "application/json"}
    import json
    mock_http_response.content = json.dumps(upstream_json).encode()
    mock_http_response.json = MagicMock(return_value=upstream_json)
    mock_http_response.raise_for_status = MagicMock()

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=mock_http_response)
        mock_cls.return_value = mock_http

        result = await _inv_mod.invoke_tool(
            tool_record=_make_tool_record(),
            json_rpc_request=_make_direct_tools_call_request("read_file"),
            client_id="restricted-client",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-fn-allow-001",
        )

    # OPA allowed → result should not be an OPA-deny error
    assert "error" not in result or result.get("result") is not None

    # OPA input must have tool_function_name="read_file"
    assert len(captured_opa_inputs) >= 1, "OPA was never called"
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("tool_function_name") == "read_file", (
        f"Expected tool_function_name='read_file', got: '{opa_input.get('tool_function_name')}'"
    )


# ===========================================================================
# (c) OPA test: empty tool_function_name + non-empty allowed_functions → deny
# ===========================================================================

@pytest.mark.unit
def test_authz_rego_denies_when_function_name_empty_and_profile_restricts():
    """
    OPA unit test (pure logic): when input.profile.allowed_functions is non-empty
    and input.tool_function_name is "" (empty), authz.rego must DENY with reason
    'function_not_allowed_for_profile'.

    This is the new fail-closed rule added to authz.rego for Task 1.9:
    an empty function name cannot match any entry in allowed_functions, so it
    must be denied rather than allowed through.

    We test this by running OPA directly via subprocess.
    """
    import subprocess
    import json as _json
    import pathlib

    # Build the OPA input
    opa_input = {
        "client_id": "alice@corp",
        "client_roles": ["agent", "user"],
        "tool_id": "t-fn-empty",
        "tool_name": "grafana-query",  # alice has grant for this tool
        "tool_status": "active",
        "tool_risk_level": "low",
        "tool_server_id": "",
        "owned_server_ids": [],
        "owner_max_risk_level": "medium",
        "params": {},
        "anomaly_score": 0.0,
        "is_testing": False,
        "recent_calls": [],
        # Profile restricts to specific functions but no function name provided
        "profile": {
            "enabled": True,
            "allowed_functions": ["read_metrics"],
        },
        "tool_function_name": "",  # empty — direct tools/call without function name
    }

    rego_dir = str(pathlib.Path(__file__).parents[3] / "policies" / "rego")

    result = subprocess.run(
        ["opa", "eval",
         "--data", rego_dir,
         "--input", "/dev/stdin",
         "data.mcp.authz.deny"],
        input=_json.dumps(opa_input),
        capture_output=True,
        text=True,
        timeout=15,
    )

    assert result.returncode == 0, f"OPA eval failed: {result.stderr}"
    output = _json.loads(result.stdout)
    deny_set = output["result"][0]["expressions"][0]["value"]

    assert "function_not_allowed_for_profile" in deny_set, (
        f"Expected 'function_not_allowed_for_profile' in deny set when "
        f"tool_function_name='' and allowed_functions=['read_metrics']. "
        f"Got deny set: {deny_set}. "
        f"Verify that authz.rego denies when allowed_functions is non-empty "
        f"and tool_function_name is empty."
    )
