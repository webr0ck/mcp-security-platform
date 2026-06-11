"""
Unit tests — Task 1.7: Wire anomaly.rego structural rules into authz deny set.

Tests:
  (a) credential_then_exec chain in recent_calls → deny (suspicious_parameter_pattern
      via anomaly structural deny reasons merged into authz deny)
  (b) OPA-down path → 503 (OPAUnavailableError propagates)
  (c) Anomaly-evaluation failure specifically (OPA reachable, anomaly path erroring)
      → 503, never allow-through

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_anomaly_rego_wire.py -v
"""
from __future__ import annotations

import sys
import json
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Stubs shared across tests
# ---------------------------------------------------------------------------

def _make_stubs(
    opa_allow: bool = True,
    opa_reasons: list[str] | None = None,
    opa_raises=None,
    anomaly_score: float = 0.0,
    anomaly_raises=None,
):
    """Build stub modules for invocation.py unit tests."""
    reasons = opa_reasons or []

    mock_anomaly = ModuleType("app.services.anomaly")
    if anomaly_raises:
        mock_anomaly.detect = AsyncMock(side_effect=anomaly_raises)  # type: ignore[attr-defined]
    else:
        anomaly_result = MagicMock()
        anomaly_result.anomaly_score = anomaly_score
        mock_anomaly.detect = AsyncMock(return_value=anomaly_result)  # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    if opa_raises:
        mock_policy.evaluate_policy = AsyncMock(side_effect=opa_raises)  # type: ignore[attr-defined]
    else:
        mock_policy.evaluate_policy = AsyncMock(  # type: ignore[attr-defined]
            return_value={"allow": opa_allow, "reasons": reasons}
        )
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {"reasons": reasons})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    audit_event_obj = MagicMock()
    audit_event_obj.event_id = "audit-1"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }


def _make_tool_record() -> dict:
    return {
        "tool_id": "tool-wire-test",
        "name": "run_command",
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


# ===========================================================================
# (a) credential_then_exec → deny via anomaly structural reasons in OPA input
# ===========================================================================

@pytest.mark.unit
async def test_credential_then_exec_chain_deny():
    """
    When recent_calls contains a credential-access tool followed by an exec tool,
    the OPA input must include recent_calls and the OPA deny set must fire.

    We verify this by:
    1. Patching evaluate_policy to capture the OPA input and assert recent_calls present
    2. Making evaluate_policy return deny with reason 'credential_access_then_exec'
       (simulating what authz.rego would return after evaluating anomaly.rego rules)
    3. Asserting invoke_tool raises / returns error (not allow-through)
    """
    captured_opa_inputs: list[dict] = []

    OPADenyError = type("OPADenyError", (Exception,), {})
    OPADenyError.reasons = ["credential_access_then_exec"]

    async def _fake_evaluate_policy(input_data: dict):
        captured_opa_inputs.append(input_data)
        # Simulate OPA denying due to credential_then_exec structural rule
        return {"allow": False, "reasons": ["credential_access_then_exec"]}

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
    audit_event_obj.event_id = "audit-2"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    stubs = {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }

    # recent_calls: credential access followed by exec
    recent_calls = [
        {"tool_name": "get_vault_secret", "timestamp": 1700000000},
        {"tool_name": "run_shell", "timestamp": 1700000001},
    ]

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    OPADenyError = mock_policy.OPADenyError

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._get_recent_calls_for_opa", AsyncMock(return_value=recent_calls)):

        with pytest.raises(Exception) as exc_info:
            await _inv_mod.invoke_tool(
                tool_record=_make_tool_record(),
                json_rpc_request={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 1,
                    "params": {"name": "run_command", "arguments": {}},
                },
                client_id="attacker-1",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-anomaly-chain-001",
            )

    # Must have raised a deny — either OPADenyError or similar
    exc_val = exc_info.value
    assert exc_val is not None, "Expected an exception (deny) but invoke_tool returned normally"

    # OPA input must contain recent_calls
    assert len(captured_opa_inputs) >= 1, "OPA was never called"
    opa_input = captured_opa_inputs[0]
    assert "recent_calls" in opa_input, (
        f"recent_calls missing from OPA input: {list(opa_input.keys())}"
    )
    assert opa_input["recent_calls"] == recent_calls, (
        f"recent_calls in OPA input does not match. Got: {opa_input['recent_calls']}"
    )


# ===========================================================================
# (b) OPA-down → 503
# ===========================================================================

@pytest.mark.unit
async def test_opa_down_yields_503():
    """
    When OPA is unreachable, invoke_tool must raise OPAUnavailableError
    (which the router converts to 503). This is the existing INV-004 test;
    here we verify it holds specifically with the anomaly wiring present.
    """
    OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})

    mock_anomaly = ModuleType("app.services.anomaly")
    anomaly_result = MagicMock()
    anomaly_result.anomaly_score = 0.0
    mock_anomaly.detect = AsyncMock(return_value=anomaly_result)  # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = OPAUnavailableError  # type: ignore[attr-defined]
    mock_policy.evaluate_policy = AsyncMock(  # type: ignore[attr-defined]
        side_effect=OPAUnavailableError("OPA unreachable")
    )

    audit_event_obj = MagicMock()
    audit_event_obj.event_id = "audit-3"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    stubs = {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._get_recent_calls_for_opa", AsyncMock(return_value=[])):

        with pytest.raises(OPAUnavailableError):
            await _inv_mod.invoke_tool(
                tool_record=_make_tool_record(),
                json_rpc_request={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 1,
                    "params": {"name": "run_command", "arguments": {}},
                },
                client_id="client-2",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-opa-down-001",
            )


# ===========================================================================
# (c) Anomaly recent_calls fetch failure → 503 (not allow-through)
# ===========================================================================

@pytest.mark.unit
async def test_anomaly_recent_calls_fetch_failure_yields_503():
    """
    When _get_recent_calls_for_opa raises (Redis/DB failure), the invocation
    must 503 (raise OPAUnavailableError), never allow-through.

    Rationale: if we cannot populate recent_calls for the OPA input, the anomaly
    structural rules cannot evaluate. Allowing through would silently bypass the
    structural deny rules — the same class as INV-004.
    """
    OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})

    mock_anomaly = ModuleType("app.services.anomaly")
    anomaly_result = MagicMock()
    anomaly_result.anomaly_score = 0.0
    mock_anomaly.detect = AsyncMock(return_value=anomaly_result)  # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = OPAUnavailableError  # type: ignore[attr-defined]
    # OPA itself is reachable — we're testing the anomaly-path failure specifically
    mock_policy.evaluate_policy = AsyncMock(  # type: ignore[attr-defined]
        return_value={"allow": True, "reasons": []}
    )

    audit_event_obj = MagicMock()
    audit_event_obj.event_id = "audit-4"
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    stubs = {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
        "mcp_audit_logger": mock_audit_pkg,
    }

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._get_recent_calls_for_opa",
               AsyncMock(side_effect=RuntimeError("Redis connection failed"))):

        with pytest.raises(OPAUnavailableError):
            await _inv_mod.invoke_tool(
                tool_record=_make_tool_record(),
                json_rpc_request={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 1,
                    "params": {"name": "run_command", "arguments": {}},
                },
                client_id="client-3",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-anomaly-fail-001",
            )
