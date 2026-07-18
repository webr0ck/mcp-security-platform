"""
Unit tests — Fix 1: named-profile default-deny.

docs/spec/11-server-lifecycle-and-hardening-batch.md §1:

Named profiles (bound at OIDC login via ``?profile=<name>``) are the
access-restriction mechanism for session-bound logins. Previously, a tool
with no explicit ``mcp_profiles`` row under a named profile fell through to
``profile_data = {}`` in invoke_tool Step 2.5, which OPA treats as "no
restriction" — the same default-allow behavior as the legacy per-identity
path. That defeats a named profile's purpose: once a profile has ANY
binding row (i.e. it has been configured at all), every unbound tool must
be denied via ``mcp_disabled_for_profile``, not silently allowed.

An UNCONFIGURED named profile (zero binding rows anywhere) keeps
default-allow so a freshly created profile isn't bricked before an admin
adds the first binding.

Coverage:
  1. Named profile with >=1 binding row, tool has no binding row →
     profile_data synthesized as {"enabled": False, "allowed_functions": []}
     → OPA input carries the disabled profile.
  2. Named profile with zero binding rows → profile_data stays {} (allow-all).
  3. Legacy path (profile_uuid=None) → _named_profile_has_any_binding is
     never called; behavior is unchanged.
  4. _named_profile_has_any_binding: DB error + no Redis cache → raises
     ProfileLookupError → invoke_tool surfaces OPAUnavailableError (503).

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/services/test_invocation_profile_default_deny.py -v
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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
        "tool_id": "tool-named-profile-test",
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
    import json
    upstream_json = {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "ok"}]}, "id": 1}
    mock_http_response = MagicMock()
    mock_http_response.status_code = 200
    mock_http_response.headers = {"content-type": "application/json"}
    mock_http_response.content = json.dumps(upstream_json).encode()
    mock_http_response.json = MagicMock(return_value=upstream_json)
    mock_http_response.raise_for_status = MagicMock()
    return mock_http_response


def _fresh_invocation_module(stubs: dict):
    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415
    return _inv_mod


async def _invoke(inv_mod, *, profile_uuid: str | None, request_id: str):
    with patch("app.services.invocation.httpx.AsyncClient") as mock_cls, \
         patch("app.services.ssrf.validate_server_url", MagicMock(return_value=None)):
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=_make_upstream_response())
        mock_cls.return_value = mock_http

        return await inv_mod.invoke_tool(
            tool_record=_make_tool_record(),
            json_rpc_request=_make_json_rpc_request(),
            client_id="alice@corp",
            client_roles=["agent"],
            is_testing=False,
            request_id=request_id,
            profile_uuid=profile_uuid,
        )


# ===========================================================================
# 1. Named profile with >=1 binding row denies an unbound tool
# ===========================================================================

@pytest.mark.unit
async def test_named_profile_with_bindings_denies_unbound_tool():
    """
    Named profile is configured (has >=1 binding row somewhere) but this
    specific tool has no binding row. Per Fix 1, this must synthesize a
    disabled profile so OPA denies with mcp_disabled_for_profile — NOT
    default-allow.
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=False)
    inv_mod = _fresh_invocation_module(stubs)

    p_uuid = "profile-uuid-configured"

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    with patch.dict(sys.modules, stubs), \
         patch.object(inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_lookup_profile_with_cache", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_named_profile_has_any_binding", AsyncMock(return_value=True)) as mock_has_binding:
        from app.services.policy import OPADenyError as _OPADenyError  # noqa: F401
        with pytest.raises(Exception):
            # opa_allow=False → policy.evaluate_policy denies; invoke_tool
            # raises whatever deny-path exception it raises. We only care
            # about the OPA INPUT that was constructed before the deny.
            await _invoke(inv_mod, profile_uuid=p_uuid, request_id="req-named-deny-001")

    mock_has_binding.assert_awaited_once_with(p_uuid)
    assert len(captured_opa_inputs) >= 1
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("profile") == {"enabled": False, "allowed_functions": []}, (
        f"Expected synthesized disabled profile in OPA input, got: {opa_input.get('profile')}"
    )


# ===========================================================================
# 2. Named profile with zero binding rows keeps default-allow
# ===========================================================================

@pytest.mark.unit
async def test_named_profile_with_zero_bindings_still_allows():
    """
    Named profile exists but has NO binding rows anywhere (unconfigured).
    Must NOT synthesize a disabled profile — keeps default-allow so a
    freshly created profile isn't bricked.
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)
    inv_mod = _fresh_invocation_module(stubs)

    p_uuid = "profile-uuid-unconfigured"

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    with patch.dict(sys.modules, stubs), \
         patch.object(inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_lookup_profile_with_cache", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_named_profile_has_any_binding", AsyncMock(return_value=False)) as mock_has_binding:
        await _invoke(inv_mod, profile_uuid=p_uuid, request_id="req-named-allow-001")

    mock_has_binding.assert_awaited_once_with(p_uuid)
    assert len(captured_opa_inputs) >= 1
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("profile") == {}, (
        f"Expected empty (no-restriction) profile in OPA input for an "
        f"unconfigured named profile, got: {opa_input.get('profile')}"
    )


# ===========================================================================
# 3. Legacy path (profile_uuid=None) is unaffected
# ===========================================================================

@pytest.mark.unit
async def test_legacy_path_does_not_call_named_profile_binding_check():
    """
    Without a profile_uuid (legacy per-identity path), the new
    _named_profile_has_any_binding helper must never be invoked — the
    existing default-allow-on-no-row behavior is unchanged.
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)
    inv_mod = _fresh_invocation_module(stubs)

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    with patch.dict(sys.modules, stubs), \
         patch.object(inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_lookup_profile_with_cache", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_named_profile_has_any_binding", AsyncMock(return_value=True)) as mock_has_binding:
        await _invoke(inv_mod, profile_uuid=None, request_id="req-legacy-001")

    mock_has_binding.assert_not_awaited()
    assert len(captured_opa_inputs) >= 1
    opa_input = captured_opa_inputs[0]
    assert opa_input.get("profile") == {}, (
        f"Legacy path with no profile row must stay default-allow, got: {opa_input.get('profile')}"
    )


# ===========================================================================
# 4. _named_profile_has_any_binding: DB error + no cache → fail-closed 503
# ===========================================================================

@pytest.mark.unit
async def test_db_error_no_cache_binding_lookup_yields_503():
    """
    When the mcp_profiles binding-count DB lookup fails AND there is no
    cached value in Redis, invoke_tool must raise OPAUnavailableError
    (→ 503), not silently default-allow. A restriction mechanism must never
    fail open.
    """
    stubs, captured_opa_inputs, OPAUnavailableError = _make_stubs(opa_allow=True)
    inv_mod = _fresh_invocation_module(stubs)

    p_uuid = "profile-uuid-db-down"

    async def _fake_emit(*args, **kwargs) -> str:
        return "fake-audit-id"

    async def _fake_has_binding_raises(_p_uuid: str) -> bool:
        raise inv_mod.ProfileLookupError(
            f"DB unreachable and no cached binding-count for profile {_p_uuid}"
        )

    with patch.dict(sys.modules, stubs), \
         patch.object(inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_lookup_profile_with_cache", AsyncMock(return_value=None)), \
         patch.object(
             inv_mod, "_named_profile_has_any_binding", side_effect=_fake_has_binding_raises
         ), \
         pytest.raises(OPAUnavailableError):
        await _invoke(inv_mod, profile_uuid=p_uuid, request_id="req-named-503-001")

    # Must not have reached OPA at all (fail-closed before OPA evaluation).
    assert captured_opa_inputs == []


# ===========================================================================
# Helper-level tests: _named_profile_has_any_binding cache/DB tiers
# ===========================================================================

@pytest.mark.unit
async def test_named_profile_has_any_binding_db_success_true():
    stubs, _, _ = _make_stubs()
    inv_mod = _fresh_invocation_module(stubs)

    mock_prow = {"cnt": 3}
    mock_mappings = MagicMock()
    mock_mappings.first = MagicMock(return_value=mock_prow)
    mock_execute_result = MagicMock()
    mock_execute_result.mappings = MagicMock(return_value=mock_mappings)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_execute_result)
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis

    with patch("app.core.database.AsyncSessionLocal", MagicMock(return_value=mock_db)), \
         patch("app.core.redis_client.redis_pool", mock_redis_pool):
        result = await inv_mod._named_profile_has_any_binding("profile-x")

    assert result is True
    mock_redis.setex.assert_awaited_once()


@pytest.mark.unit
async def test_named_profile_has_any_binding_db_success_false_zero_rows():
    stubs, _, _ = _make_stubs()
    inv_mod = _fresh_invocation_module(stubs)

    mock_prow = {"cnt": 0}
    mock_mappings = MagicMock()
    mock_mappings.first = MagicMock(return_value=mock_prow)
    mock_execute_result = MagicMock()
    mock_execute_result.mappings = MagicMock(return_value=mock_mappings)

    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=mock_execute_result)
    mock_db.__aenter__ = AsyncMock(return_value=mock_db)
    mock_db.__aexit__ = AsyncMock(return_value=None)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.setex = AsyncMock()
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis

    with patch("app.core.database.AsyncSessionLocal", MagicMock(return_value=mock_db)), \
         patch("app.core.redis_client.redis_pool", mock_redis_pool):
        result = await inv_mod._named_profile_has_any_binding("profile-y")

    assert result is False


@pytest.mark.unit
async def test_named_profile_has_any_binding_cache_hit_avoids_db():
    stubs, _, _ = _make_stubs()
    inv_mod = _fresh_invocation_module(stubs)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="true")
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis

    mock_db_session_local = MagicMock()

    with patch("app.core.redis_client.redis_pool", mock_redis_pool), \
         patch("app.core.database.AsyncSessionLocal", mock_db_session_local):
        result = await inv_mod._named_profile_has_any_binding("profile-cached")

    assert result is True
    mock_db_session_local.assert_not_called()


@pytest.mark.unit
async def test_named_profile_has_any_binding_db_error_no_cache_raises():
    stubs, _, _ = _make_stubs()
    inv_mod = _fresh_invocation_module(stubs)

    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis_pool = MagicMock()
    mock_redis_pool.client = mock_redis

    mock_db_session_local = MagicMock(side_effect=RuntimeError("db down"))

    with patch("app.core.redis_client.redis_pool", mock_redis_pool), \
         patch("app.core.database.AsyncSessionLocal", mock_db_session_local), \
         pytest.raises(inv_mod.ProfileLookupError):
        await inv_mod._named_profile_has_any_binding("profile-down")
