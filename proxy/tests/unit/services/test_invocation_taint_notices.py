"""
Unit tests — Fix 7: audit taint semantics.

docs/spec/11-server-lifecycle-and-hardening-batch.md §7:

The taint-floor NOTIFY-ONLY path (Phase 0, PRD-0010) previously emitted
``_emit_audit_event(outcome="allow", deny_reasons=["taint_floor_notice:..."])``.
Putting advisory text in ``deny_reasons`` on an ALLOW event is misleading —
anything that treats a non-empty ``deny_reasons`` as "this call was denied"
would misclassify the event. The fix keeps ``deny_reasons`` empty for ALLOW
outcomes and carries the taint notice in a new, dedicated ``notices`` field
that is plumbed through the audit SDK (``AuditEvent.notices``) and the
Wazuh syslog secondary path.

Coverage:
  1. ``_emit_audit_event(..., notices=[...])`` constructs the AuditEvent with
     the given notices and leaves deny_reasons exactly as passed (empty for
     the taint notify-only caller).
  2. The Wazuh syslog secondary path receives ``notices`` and includes it in
     the emitted payload, separate from ``deny_reasons``.
  3. The taint notify-only call site in invoke_tool passes ``deny_reasons=[]``
     and ``notices=["taint_floor_notice:..."]`` — verified end-to-end through
     invoke_tool with the taint floor forced to the notify-only deny branch.
  4. No other ``outcome="allow"`` call site in invocation.py smuggles content
     into deny_reasons (source-level guard against regression).

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/services/test_invocation_taint_notices.py -v
"""
from __future__ import annotations

import os
import re
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_stubs():
    mock_anomaly = ModuleType("app.services.anomaly")
    anomaly_result = MagicMock()
    anomaly_result.anomaly_score = 0.0
    mock_anomaly.detect = AsyncMock(return_value=anomaly_result)  # type: ignore[attr-defined]
    mock_anomaly.evaluate_anomaly = mock_anomaly.detect  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(return_value={"allow": True, "reasons": []})  # type: ignore[attr-defined]
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    return {
        "app.services.anomaly": mock_anomaly,
        "app.services.policy": mock_policy,
    }


def _fresh_invocation_module(extra_stubs: dict | None = None):
    stubs = _make_stubs()
    if extra_stubs:
        stubs.update(extra_stubs)
    with patch.dict(sys.modules, stubs):
        if "app.services.invocation" in sys.modules:
            del sys.modules["app.services.invocation"]
        from app.services import invocation as _inv_mod  # noqa: PLC0415
    return _inv_mod


# ===========================================================================
# 1 + 2. _emit_audit_event: notices plumbed to AuditEvent + Wazuh syslog
# ===========================================================================

@pytest.mark.unit
async def test_emit_audit_event_passes_notices_to_audit_event_and_keeps_deny_reasons():
    captured_audit_event_kwargs: dict = {}

    def _fake_audit_event(**kwargs):
        captured_audit_event_kwargs.update(kwargs)
        ev = MagicMock()
        ev.event_id = "evt-notices-1"
        ev.event_type = kwargs.get("event_type")
        ev.timestamp = MagicMock()
        ev.timestamp.isoformat = MagicMock(return_value="2026-07-18T00:00:00+00:00")
        ev.platform_version = "1.0.0"
        return ev

    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = _fake_audit_event  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    inv_mod = _fresh_invocation_module({"mcp_audit_logger": mock_audit_pkg})
    inv_mod._SKIP_AUDIT_DB_WRITE = True

    with patch.dict(sys.modules, {"mcp_audit_logger": mock_audit_pkg}), \
         patch.object(inv_mod, "_get_audit_logger", return_value=mock_audit_logger_instance):
        await inv_mod._emit_audit_event(
            tool_id="tool-1",
            tool_name="demo-tool",
            tool_version="1.0",
            client_id="alice@corp",
            outcome="allow",
            deny_reasons=[],
            request_id="req-notices-1",
            latency_ms=0,
            anomaly_score=0.0,
            opa_decision_id="",
            is_testing=False,
            notices=["taint_floor_notice:required_integrity=1"],
        )

    assert captured_audit_event_kwargs["deny_reasons"] == []
    assert captured_audit_event_kwargs["notices"] == ["taint_floor_notice:required_integrity=1"]


@pytest.mark.unit
async def test_emit_audit_event_defaults_notices_to_empty_list_when_omitted():
    """Callers that don't pass notices must not break — default is []."""
    captured_audit_event_kwargs: dict = {}

    def _fake_audit_event(**kwargs):
        captured_audit_event_kwargs.update(kwargs)
        ev = MagicMock()
        ev.event_id = "evt-notices-2"
        ev.event_type = kwargs.get("event_type")
        ev.timestamp = MagicMock()
        ev.timestamp.isoformat = MagicMock(return_value="2026-07-18T00:00:00+00:00")
        ev.platform_version = "1.0.0"
        return ev

    mock_audit_pkg = ModuleType("mcp_audit_logger")
    mock_audit_pkg.AuditEvent = _fake_audit_event  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    inv_mod = _fresh_invocation_module({"mcp_audit_logger": mock_audit_pkg})
    inv_mod._SKIP_AUDIT_DB_WRITE = True

    with patch.dict(sys.modules, {"mcp_audit_logger": mock_audit_pkg}), \
         patch.object(inv_mod, "_get_audit_logger", return_value=mock_audit_logger_instance):
        await inv_mod._emit_audit_event(
            tool_id="tool-1",
            tool_name="demo-tool",
            tool_version="1.0",
            client_id="alice@corp",
            outcome="deny",
            deny_reasons=["some_reason"],
            request_id="req-notices-3",
            latency_ms=0,
            anomaly_score=0.0,
            opa_decision_id="",
            is_testing=False,
        )

    assert captured_audit_event_kwargs["notices"] == []
    assert captured_audit_event_kwargs["deny_reasons"] == ["some_reason"]


@pytest.mark.unit
async def test_emit_audit_event_forwards_notices_to_wazuh_syslog():
    mock_audit_pkg = ModuleType("mcp_audit_logger")
    audit_event_obj = MagicMock()
    audit_event_obj.event_id = "evt-notices-wazuh"
    mock_audit_pkg.AuditEvent = MagicMock(return_value=audit_event_obj)  # type: ignore[attr-defined]
    mock_audit_pkg.AuditEventType = MagicMock()  # type: ignore[attr-defined]
    mock_audit_pkg.AuditOutcome = MagicMock()  # type: ignore[attr-defined]
    mock_audit_logger_instance = MagicMock()
    mock_audit_logger_instance.emit = MagicMock(return_value="deadbeef" * 8)
    mock_audit_pkg.MCPAuditLogger = MagicMock(return_value=mock_audit_logger_instance)  # type: ignore[attr-defined]

    inv_mod = _fresh_invocation_module({"mcp_audit_logger": mock_audit_pkg})
    # The Wazuh syslog path only runs AFTER the primary PostgreSQL audit_events
    # INSERT succeeds (it's a secondary, best-effort path). _SKIP_AUDIT_DB_WRITE
    # short-circuits BEFORE that INSERT, so it must be False here — with the
    # DB engine mocked out instead so no real DB connection is required.
    inv_mod._SKIP_AUDIT_DB_WRITE = False

    mock_settings = MagicMock()
    mock_settings.WAZUH_SYSLOG_HOST = "wazuh.internal"
    mock_settings.WAZUH_SYSLOG_PORT = 514

    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=None)
    mock_engine_ctx = AsyncMock()
    mock_engine_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_engine_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_db_engine = MagicMock()
    mock_db_engine.begin = MagicMock(return_value=mock_engine_ctx)

    with patch.dict(sys.modules, {"mcp_audit_logger": mock_audit_pkg}), \
         patch.object(inv_mod, "_get_audit_logger", return_value=mock_audit_logger_instance), \
         patch("app.core.config.get_settings", return_value=mock_settings), \
         patch("app.core.database.engine", mock_db_engine), \
         patch.object(inv_mod, "_compute_hmac_signature", return_value=None), \
         patch("app.services.wazuh_syslog.emit") as mock_ws_emit:
        await inv_mod._emit_audit_event(
            tool_id="tool-1",
            tool_name="demo-tool",
            tool_version="1.0",
            client_id="alice@corp",
            outcome="allow",
            deny_reasons=[],
            request_id="req-notices-wazuh-1",
            latency_ms=0,
            anomaly_score=0.0,
            opa_decision_id="",
            is_testing=False,
            notices=["taint_floor_notice:required_integrity=1"],
        )

    mock_ws_emit.assert_called_once()
    _, ws_kwargs = mock_ws_emit.call_args
    assert ws_kwargs["notices"] == ["taint_floor_notice:required_integrity=1"]
    assert ws_kwargs["deny_reasons"] == []


# ===========================================================================
# 3. End-to-end through invoke_tool: taint notify-only call site
# ===========================================================================

@pytest.mark.unit
async def test_taint_notify_only_call_site_emits_empty_deny_reasons_and_notice():
    """
    Force the taint floor into its notify-only deny branch and verify the
    resulting _emit_audit_event call carries deny_reasons=[] and the taint
    notice text in notices (not in deny_reasons).
    """
    mock_taint_floor = ModuleType("app.services.taint_floor")
    mock_taint_floor.effective_injection_mode = MagicMock(return_value="none")  # type: ignore[attr-defined]
    mock_taint_floor.effective_required_integrity = MagicMock(return_value=1)  # type: ignore[attr-defined]
    mock_taint_floor.taint_floor_decision = MagicMock(return_value="deny")  # type: ignore[attr-defined]
    # Downstream write-before-forward step (unrelated to Fix 7) also imports
    # this from the same module — stub it so the call doesn't ImportError.
    mock_taint_floor.result_taints_session = MagicMock(return_value=False)  # type: ignore[attr-defined]

    mock_taint_store = ModuleType("app.services.taint_store")
    mock_taint_store.is_tainted_for_principal = AsyncMock(return_value=True)  # type: ignore[attr-defined]
    # Downstream write-before-forward step (unrelated to Fix 7) also imports
    # this from the same module — stub it so the call doesn't ImportError.
    mock_taint_store.mark_tainted_for_principal = AsyncMock(return_value=None)  # type: ignore[attr-defined]

    extra_stubs = {
        "app.services.taint_floor": mock_taint_floor,
        "app.services.taint_store": mock_taint_store,
    }
    stubs = _make_stubs()
    stubs.update(extra_stubs)
    inv_mod = _fresh_invocation_module(extra_stubs)
    inv_mod._SKIP_AUDIT_DB_WRITE = True

    captured_emit_calls: list[dict] = []

    async def _fake_emit(*args, **kwargs) -> str:
        captured_emit_calls.append(kwargs)
        return "fake-audit-id"

    from app.core.config import settings as _real_settings

    tool_record = {
        "tool_id": "tool-taint-1",
        "name": "risky-tool",
        "status": "active",
        "upstream_url": "http://mcp-server:8080/mcp",
        "service_name": None,
        "injection_mode": "none",
        "inject_header": None,
        "inject_prefix": None,
        "version": "1.0",
        "server_id": None,
        "risk_level": "high",
        "required_integrity": 1,
    }
    json_rpc_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "do_thing", "arguments": {}},
    }

    def _make_upstream_response():
        import json
        upstream_json = {"jsonrpc": "2.0", "result": {"content": []}, "id": 1}
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"content-type": "application/json"}
        resp.content = json.dumps(upstream_json).encode()
        resp.json = MagicMock(return_value=upstream_json)
        resp.raise_for_status = MagicMock()
        return resp

    with patch.dict(sys.modules, stubs), \
         patch.object(_real_settings, "TAINT_FLOOR_ENABLED", True), \
         patch.object(inv_mod, "_emit_audit_event", side_effect=_fake_emit), \
         patch.object(inv_mod, "_get_or_create_session", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_mcp_initialize", AsyncMock(return_value=None)), \
         patch.object(inv_mod, "_lookup_server_trust", AsyncMock(return_value=(1, "none"))), \
         patch.object(inv_mod, "_lookup_profile_with_cache", AsyncMock(return_value=None)), \
         patch("app.services.ssrf.validate_server_url", MagicMock(return_value=None)), \
         patch("app.services.invocation.httpx.AsyncClient") as mock_cls:
        mock_http = AsyncMock()
        mock_http.__aenter__ = AsyncMock(return_value=mock_http)
        mock_http.__aexit__ = AsyncMock(return_value=False)
        mock_http.post = AsyncMock(return_value=_make_upstream_response())
        mock_cls.return_value = mock_http

        await inv_mod.invoke_tool(
            tool_record=tool_record,
            json_rpc_request=json_rpc_request,
            client_id="tainted-client",
            client_roles=["agent"],
            is_testing=False,
            request_id="req-taint-notice-001",
        )

    taint_calls = [
        c for c in captured_emit_calls
        if any("taint_floor_notice" in n for n in c.get("notices", []))
    ]
    assert len(taint_calls) == 1, (
        f"expected exactly one taint-notice audit call, got: {captured_emit_calls}"
    )
    taint_call = taint_calls[0]
    assert taint_call["deny_reasons"] == [], (
        f"deny_reasons must be empty on the ALLOW taint-notice event, "
        f"got: {taint_call['deny_reasons']}"
    )
    assert taint_call["outcome"] == "allow"
    assert any("required_integrity=1" in n for n in taint_call["notices"])


# ===========================================================================
# 4. Source-level regression guard: no other allow-outcome call smuggles
#    content into deny_reasons.
# ===========================================================================

@pytest.mark.unit
def test_no_other_allow_outcome_call_site_uses_nonempty_deny_reasons():
    """
    Grep-level guard: every `outcome="allow"` call to _emit_audit_event in
    invocation.py must pass `deny_reasons=[]` (or omit deny_reasons /
    forward a caller-supplied empty list), never a literal non-empty list.
    This is deliberately a source check (not an execution trace) so it
    catches the *next* person who copies the old pattern, not just this one.
    """
    invocation_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "app", "services", "invocation.py",
    )
    with open(invocation_path) as f:
        source = f.read()

    # Find every `outcome="allow",` occurrence and inspect the following
    # ~400 chars of kwargs for a literal non-empty deny_reasons=[...] list.
    for match in re.finditer(r'outcome="allow"', source):
        window = source[match.end():match.end() + 600]
        deny_match = re.search(r"deny_reasons\s*=\s*(\[[^\]]*\])", window)
        if deny_match:
            literal = deny_match.group(1)
            assert literal.strip() == "[]", (
                f"outcome=\"allow\" call site near offset {match.start()} passes a "
                f"non-empty literal deny_reasons={literal} — advisory text belongs "
                f"in `notices`, not `deny_reasons` (Fix 7)."
            )
