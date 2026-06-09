"""
Enrollment-link delivery tests — P0 / R-3a

Covers:
  Task 1: -32010 JSON-RPC error shape from _route_to_registry (R-1 contract pin)
  Task 2: Synchronous deny audit on enrollment-required path (INV-001 regression guard)
  Task 3: initialize._meta.pending_enrollments shape (R-3a contract pin)
  Task 4: deny_reasons distinguishes "enrollment_required" vs "credential_injection_failed"

INV-001: every invocation must produce a synchronous audit event before responding.
INV-002: logs/audit never contain raw credentials.
"""
from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared stub builder  (matches pattern in test_invocation_broker.py)
# ---------------------------------------------------------------------------

def _make_sys_stubs() -> dict:
    mock_anomaly = ModuleType("app.services.anomaly")
    mock_anomaly.evaluate_anomaly = AsyncMock()  # type: ignore[attr-defined]
    mock_anomaly.detect = AsyncMock(return_value=MagicMock(anomaly_score=0.0))  # type: ignore[attr-defined]

    mock_policy = ModuleType("app.services.policy")
    mock_policy.evaluate_policy = AsyncMock(  # type: ignore[attr-defined]
        return_value={"allow": True, "reasons": []}
    )
    mock_policy.OPADenyError = type("OPADenyError", (Exception,), {})  # type: ignore[attr-defined]
    mock_policy.OPAUnavailableError = type("OPAUnavailableError", (Exception,), {})  # type: ignore[attr-defined]

    audit_event = MagicMock()
    audit_event.event_id = "audit-evt-enroll"
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


# ---------------------------------------------------------------------------
# Helpers to build fake Request objects for mcp_server tests
# ---------------------------------------------------------------------------

def _fake_request(client_id: str = "alice@corp", roles: list | None = None) -> MagicMock:
    """Return a minimal FastAPI Request mock that satisfies mcp_server internals."""
    req = MagicMock()
    req.state.client_id = client_id
    req.state.client_roles = roles or ["agent"]
    req.state.request_id = "req-enroll-test"
    req.state.principal_id = None
    req.state.principal_type = None
    req.state.user_kc_token = None
    req.headers = {}
    # _derive_base_url reads PROXY_BASE_URL from settings; stub it out
    req.url.scheme = "http"
    return req


# ---------------------------------------------------------------------------
# Task 1: -32010 error shape (R-1 contract pin)
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_route_to_registry_returns_32010_on_enrollment_required():
    """
    _route_to_registry must return a JSON-RPC -32010 error with the correct
    data envelope when invoke_tool raises CredentialEnrollmentRequiredError.

    Asserts:
      - error.code == -32010
      - error.data.service == "m365"
      - error.data.enrollment_url ends with /auth/enroll/m365
      - error.data.action == "open_browser"
      - error.data.instructions is a non-empty string
      - there is NO "enrollment_required" top-level field (guard against phantom field)

    INV-001 touched indirectly: the audit is emitted inside invoke_tool before re-raise.
    """
    from app.credential_broker.dispatcher import CredentialEnrollmentRequiredError

    # Build a fake tool row returned by DB
    fake_row = {
        "tool_id": "t-m365",
        "name": "m365-graph",
        "status": "active",
        "upstream_url": "http://lab-mcp-m365:8000/mcp",
        "service_name": "m365",
        "injection_mode": "entra_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "version": "1.0.0",
        "description": "Microsoft Graph tool",
        "schema": "{}",
        "risk_level": "medium",
        "server_id": None,
        "deleted_at": None,
    }

    # Fake DB result mapping
    fake_mapping = MagicMock()
    fake_mapping.fetchone = MagicMock(return_value=fake_row)

    fake_result = MagicMock()
    fake_result.mappings = MagicMock(return_value=fake_mapping)

    fake_session = AsyncMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)
    fake_session.execute = AsyncMock(return_value=fake_result)

    enrollment_exc = CredentialEnrollmentRequiredError(
        service="m365",
        enrollment_url="http://localhost:8000/auth/enroll/m365",
    )

    request = _fake_request()

    # Note: in the committed code, _route_to_registry uses exc.enrollment_url directly
    # (set by CredentialEnrollmentRequiredError constructor), so no base URL patching needed.
    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session), \
         patch("app.services.invocation.invoke_tool", AsyncMock(side_effect=enrollment_exc)):

        from app.routers.mcp_server import _route_to_registry
        response = await _route_to_registry(
            name="m365-graph",
            args={"query": "me"},
            request=request,
            req_id=42,
        )

    # Must be a valid JSON-RPC error envelope
    assert response.get("jsonrpc") == "2.0"
    assert response.get("id") == 42
    error = response.get("error")
    assert error is not None, "response must have an 'error' key"

    # Task 1 assertions
    assert error["code"] == -32010, f"expected -32010, got {error['code']}"

    data = error.get("data")
    assert data is not None, "error must have a 'data' key with enrollment details"
    assert data["service"] == "m365"
    assert data["enrollment_url"].endswith("/auth/enroll/m365"), (
        f"enrollment_url must end with /auth/enroll/m365, got: {data['enrollment_url']}"
    )
    assert data["action"] == "open_browser"
    assert data.get("instructions"), "instructions must be a non-empty string"

    # Guard: no phantom "enrollment_required" field at any level
    assert "enrollment_required" not in response, \
        "response must not have a top-level 'enrollment_required' field"
    assert "enrollment_required" not in error, \
        "error must not have a top-level 'enrollment_required' field"
    assert "enrollment_required" not in data, \
        "data must not have an 'enrollment_required' field"


# ---------------------------------------------------------------------------
# Task 2: Synchronous deny audit on enrollment-required path (INV-001)
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_invoke_tool_audits_deny_before_reraising_enrollment_error():
    """
    INV-001 regression guard: when dispatch_credential_injection raises
    CredentialEnrollmentRequiredError, invoke_tool must:
      1. emit a DENY audit event synchronously (outcome="deny")
      2. THEN re-raise the exception so the actionable message reaches the caller.

    The audit must fire even though the exception later propagates — confirm
    ordering by checking the mock was called before the exception escapes.

    INV-002: "enrollment_required" reason contains no credential material.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    from app.credential_broker.dispatcher import CredentialEnrollmentRequiredError

    tool_record = {
        "tool_id": "t-m365",
        "name": "m365-graph",
        "status": "active",
        "risk_level": "medium",
        "version": "1.0.0",
        "upstream_url": "http://lab-mcp-m365:8000/mcp",
        "service_name": "m365",
        "injection_mode": "entra_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    enrollment_exc = CredentialEnrollmentRequiredError(
        service="m365",
        enrollment_url="http://localhost:8000/auth/enroll/m365",
    )
    emit_mock = AsyncMock(return_value="evt-deny-enroll")

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", MagicMock()), \
         patch.object(_inv_mod, "_emit_audit_event", emit_mock), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(side_effect=enrollment_exc)):

        # The exception must propagate (actionable message must reach the caller)
        with pytest.raises(CredentialEnrollmentRequiredError):
            await invoke_tool(
                tool_record=tool_record,
                json_rpc_request={
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "id": 10,
                    "params": {"arguments": {}},
                },
                client_id="alice@corp",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-enroll-audit",
            )

    # INV-001: a DENY audit must have been emitted
    deny_calls = [
        c for c in emit_mock.await_args_list
        if c.kwargs.get("outcome") == "deny"
    ]
    assert deny_calls, "INV-001 violated: no DENY audit event emitted on enrollment-required path"

    kw = deny_calls[-1].kwargs
    assert kw.get("client_id") == "alice@corp"
    assert kw.get("tool_name") == "m365-graph"

    # INV-002: deny_reasons must not contain raw credential material.
    # Injection-mode labels (e.g. "entra_user_token") are allowed — they are
    # schema identifiers, not credential values. What is forbidden is any
    # bearer-token-shaped string (long base64 / JWT / UUID-like values).
    import re
    _LOOKS_LIKE_CREDENTIAL = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")
    reasons = kw.get("deny_reasons", [])
    for reason in reasons:
        assert not _LOOKS_LIKE_CREDENTIAL.search(str(reason)), \
            f"INV-002: deny reason looks like a raw credential: {reason}"


# ---------------------------------------------------------------------------
# Task 3: initialize._meta.pending_enrollments shape (R-3a)
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_initialize_meta_pending_enrollments_present_when_unenrolled():
    """
    _dispatch(initialize) must include _meta.pending_enrollments listing only
    unenrolled services, each with service + enrollment_url. enrollment_hint
    must also be present.

    R-3a contract pin: agent calling initialize before enrollment sees the hint.
    """
    # Patch _get_enrollment_status to return one enrolled + one unenrolled
    fake_status = [
        {"service": "m365", "enrolled": False, "enrollment_url": "http://localhost:8000/auth/enroll/m365"},
        {"service": "bitbucket", "enrolled": True, "enrollment_url": None},
    ]

    request = _fake_request(client_id="alice@corp", roles=["agent"])
    # _dispatch reads body dict directly, not from request
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "0.1"},
        },
    }

    # initialize calls get_settings().PROXY_BASE_URL, which is passed to
    # _get_enrollment_status. Since we patch _get_enrollment_status itself,
    # the settings call is moot but we still need it to not raise.
    mock_settings = MagicMock()
    mock_settings.PROXY_BASE_URL = "http://localhost:8000"

    with patch("app.routers.mcp_server._get_enrollment_status",
               AsyncMock(return_value=fake_status)), \
         patch("app.core.config.get_settings", return_value=mock_settings):

        from app.routers.mcp_server import _dispatch
        response = await _dispatch(body, request)

    assert response is not None
    result = response.get("result", {})

    # _meta must be present because there is one pending enrollment
    assert "_meta" in result, "result must have _meta when enrollments are pending"
    meta = result["_meta"]

    pending = meta.get("pending_enrollments")
    assert pending is not None, "_meta must have pending_enrollments"
    assert len(pending) == 1, f"only m365 is unenrolled; got {pending}"
    assert pending[0]["service"] == "m365"
    assert pending[0]["enrollment_url"] == "http://localhost:8000/auth/enroll/m365"

    # bitbucket is enrolled — must NOT appear
    services_in_pending = {p["service"] for p in pending}
    assert "bitbucket" not in services_in_pending

    # enrollment_hint must be present and non-empty
    assert meta.get("enrollment_hint"), "_meta must have a non-empty enrollment_hint"


@pytest.mark.unit
async def test_initialize_meta_absent_when_all_enrolled():
    """
    When all services are enrolled, _dispatch(initialize) must NOT include _meta.
    Matches mcp_server.py:677: **({"_meta": meta} if meta else {})
    """
    # All enrolled: no pending
    fake_status = [
        {"service": "m365", "enrolled": True, "enrollment_url": None},
        {"service": "bitbucket", "enrolled": True, "enrollment_url": None},
        {"service": "dex", "enrolled": True, "enrollment_url": None},
    ]

    request = _fake_request(client_id="alice@corp", roles=["agent"])
    body = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "clientInfo": {"name": "test-client", "version": "0.1"},
        },
    }

    mock_settings = MagicMock()
    mock_settings.PROXY_BASE_URL = "http://localhost:8000"

    with patch("app.routers.mcp_server._get_enrollment_status",
               AsyncMock(return_value=fake_status)), \
         patch("app.core.config.get_settings", return_value=mock_settings):

        from app.routers.mcp_server import _dispatch
        response = await _dispatch(body, request)

    assert response is not None
    result = response.get("result", {})
    assert "_meta" not in result, \
        "result must NOT have _meta when all services are enrolled"


# ---------------------------------------------------------------------------
# Task 4 (pre-refinement): verify current deny_reason is "credential_injection_failed"
# for generic CredentialInjectionError (establishes baseline before the split)
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_generic_injection_failure_produces_credential_injection_failed_reason():
    """
    A generic CredentialInjectionError (not enrollment-specific) must produce
    deny_reasons containing "credential_injection_failed".

    This is the baseline test that remains green both before and after Task 4.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    from app.credential_broker.dispatcher import CredentialInjectionError

    tool_record = {
        "tool_id": "t-generic",
        "name": "some-tool",
        "status": "active",
        "risk_level": "medium",
        "version": "1.0.0",
        "upstream_url": "http://fake:8000/mcp",
        "service_name": "generic-svc",
        "injection_mode": "service",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    emit_mock = AsyncMock(return_value="evt-deny-generic")

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", MagicMock()), \
         patch.object(_inv_mod, "_emit_audit_event", emit_mock), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(side_effect=CredentialInjectionError("broker down"))):

        with pytest.raises(CredentialInjectionError, match="broker down"):
            await invoke_tool(
                tool_record=tool_record,
                json_rpc_request={
                    "jsonrpc": "2.0", "method": "tools/call", "id": 11,
                    "params": {"arguments": {}},
                },
                client_id="alice@corp",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-generic-deny",
            )

    deny_calls = [
        c for c in emit_mock.await_args_list
        if c.kwargs.get("outcome") == "deny"
    ]
    assert deny_calls, "no DENY audit on generic credential injection failure"
    reasons = deny_calls[-1].kwargs.get("deny_reasons", [])
    assert "credential_injection_failed" in reasons


@pytest.mark.unit
async def test_enrollment_required_produces_enrollment_required_reason_after_refinement():
    """
    Task 4 (failing-first test): after the refinement in invocation.py,
    CredentialEnrollmentRequiredError must produce deny_reasons containing
    "enrollment_required" (NOT "credential_injection_failed").

    injection_mode is kept as the second element per plan.

    INV-002: reason contains no credential material.
    """
    stubs = _make_sys_stubs()

    with patch.dict(sys.modules, stubs):
        from app.services import invocation as _inv_mod
        invoke_tool = _inv_mod.invoke_tool

    from app.credential_broker.dispatcher import CredentialEnrollmentRequiredError

    tool_record = {
        "tool_id": "t-m365-t4",
        "name": "m365-graph",
        "status": "active",
        "risk_level": "medium",
        "version": "1.0.0",
        "upstream_url": "http://lab-mcp-m365:8000/mcp",
        "service_name": "m365",
        "injection_mode": "entra_user_token",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }

    enrollment_exc = CredentialEnrollmentRequiredError(
        service="m365",
        enrollment_url="http://localhost:8000/auth/enroll/m365",
    )
    emit_mock = AsyncMock(return_value="evt-deny-t4")

    with patch.dict(sys.modules, stubs), \
         patch.object(_inv_mod, "broker_instance", MagicMock()), \
         patch.object(_inv_mod, "_emit_audit_event", emit_mock), \
         patch("app.credential_broker.dispatcher.dispatch_credential_injection",
               AsyncMock(side_effect=enrollment_exc)):

        with pytest.raises(CredentialEnrollmentRequiredError):
            await invoke_tool(
                tool_record=tool_record,
                json_rpc_request={
                    "jsonrpc": "2.0", "method": "tools/call", "id": 12,
                    "params": {"arguments": {}},
                },
                client_id="alice@corp",
                client_roles=["agent"],
                is_testing=False,
                request_id="req-enroll-t4",
            )

    deny_calls = [
        c for c in emit_mock.await_args_list
        if c.kwargs.get("outcome") == "deny"
    ]
    assert deny_calls, "no DENY audit emitted"
    reasons = deny_calls[-1].kwargs.get("deny_reasons", [])

    # Task 4: enrollment-required path must say "enrollment_required", not "credential_injection_failed"
    assert "enrollment_required" in reasons, (
        f"Task 4: expected 'enrollment_required' in deny_reasons, got {reasons}"
    )
    assert "credential_injection_failed" not in reasons, (
        f"Task 4: 'credential_injection_failed' must not be used for enrollment-required path, got {reasons}"
    )

    # injection_mode must still be present (second element per plan)
    assert "entra_user_token" in reasons, (
        f"Task 4: injection_mode must be kept in deny_reasons, got {reasons}"
    )

    # INV-002: no raw credential material in reasons (mode labels are allowed)
    import re
    _LOOKS_LIKE_CREDENTIAL = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")
    for r in reasons:
        assert not _LOOKS_LIKE_CREDENTIAL.search(str(r)), \
            f"INV-002: deny reason looks like a raw credential: {r}"
