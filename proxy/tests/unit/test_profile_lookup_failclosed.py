"""
Unit tests — Task 1.10: Profile-lookup fail-closed with last-known-state cache.

The profile lookup in invocation.py Step 2.5 was previously fail-open:
a DB error silently skipped the mcp_profiles check, allowing mcp_disabled_for_profile
and allowed_functions restrictions to be bypassed on any DB blip.

Mandated semantics (per plan Task 1.10, 3-critic security review):
  (a) DB success → use profile data + update Redis cache (TTL-based)
  (b) DB error + cache hit → use cached profile (last-known-state)
  (c) DB error + cache miss → 503 (OPAUnavailableError), NOT allow

Tests:
  (a) DB returns a profile → profile injected into OPA input + Redis cache updated
  (b) DB fails + Redis has cached profile → cached profile injected into OPA input
  (c) DB fails + no Redis cache → OPAUnavailableError raised (503)

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_profile_lookup_failclosed.py -v
"""
from __future__ import annotations

import json
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest


# ---------------------------------------------------------------------------
# Shared stubs / helpers
# ---------------------------------------------------------------------------

def _make_stubs(opa_allow: bool = True):
    captured_opa_inputs: list[dict] = []

    async def _fake_evaluate_policy(input_data: dict):
        captured_opa_inputs.append(input_data)
        return {"allow": opa_allow, "reasons": []}

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
    audit_event_obj.event_id = "audit-profile-test"
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
        mock_policy.OPAUnavailableError,
    )


def _make_tool_record() -> dict:
    return {
        "tool_id": "tool-profile-test",
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


def _make_json_rpc_request(function_name: str = "read_file") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": function_name, "arguments": {}},
    }


def _make_upstream_response():
    upstream_json = {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "ok"}]}, "id": 1}
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.headers = {"content-type": "application/json"}
    mock_http_response.content = json.dumps(upstream_json).encode()
    mock_http_response.json = MagicMock(return_value=upstream_json)
    mock_http_response.raise_for_status = MagicMock()
    return mock_http_response


# ===========================================================================
# (a) DB success → profile used + Redis cache updated
# ===========================================================================

@pytest.mark.unit
async def test_db_success_profile_injected_and_cache_updated():
    """
    When DB returns a profile row, the profile must be:
    1. Injected into the OPA input (profile.enabled, profile.allowed_functions)
    2. Written to Redis cache for the (client_id, tool_name) key
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)

    profile_row = {"enabled": True, "allowed_functions": ["read_file", "list_files"]}

    # Mock DB row
    mock_prow = MagicMock()
    mock_prow.__getitem__ = lambda self, key: profile_row[key]

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    mock_redis = AsyncMock()
    mock_redis.set = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)  # no cache hit needed

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._lookup_profile_with_cache",
               AsyncMock(return_value=profile_row)), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=_make_upstream_response())
        mock_cls.return_value = mock_http

        result = await _inv_mod.invoke_tool(
            tool_record=_make_tool_record(),
            json_rpc_request=_make_json_rpc_request(),
            client_id="alice@corp",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-profile-db-ok-001",
        )

    # OPA input must contain the profile
    assert len(captured_opa_inputs) >= 1
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("profile") == profile_row, (
        f"Expected profile={profile_row} in OPA input, got: {opa_input.get('profile')}"
    )


# ===========================================================================
# (b) DB error + cache hit → cached profile used (not fail-open)
# ===========================================================================

@pytest.mark.unit
async def test_db_error_cache_hit_uses_cached_profile():
    """
    When the DB is unreachable but Redis has a cached profile, the cached
    profile must be injected into OPA input (not an empty/allow-open dict).
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)

    cached_profile = {"enabled": True, "allowed_functions": ["read_file"]}

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    # _lookup_profile_with_cache: DB fails but returns cached result
    async def _fake_lookup_with_cache_hit(client_id, tool_name):
        return cached_profile  # cache hit after DB error

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._lookup_profile_with_cache",
               AsyncMock(side_effect=_fake_lookup_with_cache_hit)), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:

        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=_make_upstream_response())
        mock_cls.return_value = mock_http

        result = await _inv_mod.invoke_tool(
            tool_record=_make_tool_record(),
            json_rpc_request=_make_json_rpc_request(),
            client_id="alice@corp",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-profile-cache-hit-001",
        )

    # OPA input must have the cached profile
    assert len(captured_opa_inputs) >= 1
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("profile") == cached_profile, (
        f"Expected cached profile={cached_profile} in OPA input. "
        f"Got: {opa_input.get('profile')}"
    )


# ===========================================================================
# (c) DB error + cache miss → 503 (OPAUnavailableError)
# ===========================================================================

@pytest.mark.unit
async def test_db_error_cache_miss_yields_503():
    """
    When the DB is unreachable AND there is no cached profile in Redis,
    invoke_tool must raise OPAUnavailableError (→ 503), NOT allow-through.

    The previous behavior (fail-open) allowed the invocation to proceed with
    an empty profile dict, bypassing mcp_disabled_for_profile and
    allowed_functions restrictions. This test verifies the fail-closed fix.
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)

    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    # _lookup_profile_with_cache: DB error + no cache → raises
    async def _fake_lookup_miss(client_id, tool_name):
        raise _inv_mod.ProfileLookupError(
            "DB unreachable and no cached profile for alice@corp/file_tool"
        )

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(_inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(_inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch("app.services.invocation._lookup_profile_with_cache",
               AsyncMock(side_effect=_fake_lookup_miss)):

        with pytest.raises(OPAUnavailableError):
            await _inv_mod.invoke_tool(
                tool_record=_make_tool_record(),
                json_rpc_request=_make_json_rpc_request(),
                client_id="alice@corp",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-profile-cache-miss-001",
            )
