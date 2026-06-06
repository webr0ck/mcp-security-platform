"""
6.2 — discovery==invoke entitlement enforcement on the invoke path.

The catalog (discovery) already filters servers by check_entitlement(). These
tests pin the *invoke*-side guard: a tool linked to a server (tool_record has a
non-null server_id) may only be invoked by a principal entitled to that server —
with NO role exception (admin/platform_admin included). Tools with no server_id
are not yet server-scoped and are unaffected (OPA still applies downstream).

The guard lives in app.services.entitlement.enforce_tool_entitlement() and is
called by services.invocation.invoke_tool() before OPA evaluation, so REST and
both /mcp paths inherit it from the single chokepoint.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.entitlement import (
    EntitlementResult,
    NotEntitledError,
    enforce_tool_entitlement,
)


def _ent(entitled: bool, reason: str = "not_found", role: str | None = None):
    return EntitlementResult(entitled=entitled, role=role,
                             server_id="srv-1" if entitled else None, reason=reason)


@pytest.mark.unit
async def test_unlinked_tool_skips_entitlement():
    """A tool with no server_id is not server-scoped: the guard is a no-op and
    check_entitlement is never consulted (backward compatible)."""
    tool_record = {"tool_id": "t1", "name": "legacy-tool", "server_id": None}
    mock_check = AsyncMock()
    with patch("app.services.entitlement.check_entitlement", mock_check):
        await enforce_tool_entitlement(tool_record, "human:iss:alice", "human")
    mock_check.assert_not_awaited()


@pytest.mark.unit
async def test_entitled_principal_passes():
    tool_record = {"tool_id": "t1", "name": "srv-tool", "server_id": "srv-1"}
    mock_check = AsyncMock(return_value=_ent(True, "entitlement_table", "user"))
    with patch("app.services.entitlement.check_entitlement", mock_check):
        await enforce_tool_entitlement(tool_record, "human:iss:alice", "human")
    mock_check.assert_awaited_once_with(
        principal_type="human", principal_id="human:iss:alice", server_id="srv-1"
    )


@pytest.mark.unit
async def test_not_entitled_principal_raises():
    tool_record = {"tool_id": "t1", "name": "srv-tool", "server_id": "srv-1"}
    mock_check = AsyncMock(return_value=_ent(False, "not_found"))
    with patch("app.services.entitlement.check_entitlement", mock_check):
        with pytest.raises(NotEntitledError) as exc:
            await enforce_tool_entitlement(tool_record, "human:iss:bob", "human")
    assert exc.value.reason == "not_found"
    assert str(exc.value.server_id) == "srv-1"


@pytest.mark.unit
async def test_admin_not_entitled_still_raises():
    """discovery==invoke admits NO role exception. Enforcement is identity-based:
    the guard never receives roles, so an admin who is not entitled is denied."""
    tool_record = {"tool_id": "t1", "name": "srv-tool", "server_id": "srv-1"}
    mock_check = AsyncMock(return_value=_ent(False, "server_not_approved"))
    with patch("app.services.entitlement.check_entitlement", mock_check):
        with pytest.raises(NotEntitledError):
            # principal id/type carry no role; admin-ness cannot bypass this gate.
            await enforce_tool_entitlement(tool_record, "human:iss:admin", "human")


@pytest.mark.unit
async def test_unresolved_principal_fails_closed():
    """A server-linked tool with an unresolved principal must fail closed."""
    tool_record = {"tool_id": "t1", "name": "srv-tool", "server_id": "srv-1"}
    mock_check = AsyncMock()
    with patch("app.services.entitlement.check_entitlement", mock_check):
        with pytest.raises(NotEntitledError) as exc:
            await enforce_tool_entitlement(tool_record, None, None)
    mock_check.assert_not_awaited()
    assert exc.value.reason == "principal_unresolved"


@pytest.mark.unit
async def test_invoke_tool_enforces_entitlement_before_opa():
    """Wiring regression: invoke_tool() must run the entitlement gate BEFORE OPA.
    A not-entitled caller on a server-linked tool raises NotEntitledError and OPA
    is never consulted (the gate is pre-policy, like INV-005 quarantine)."""
    from app.services import invocation as inv_svc

    tool_record = {
        "tool_id": "t1", "name": "srv-tool", "status": "active",
        "risk_level": "low", "upstream_url": "http://upstream:9", "server_id": "srv-1",
    }
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "srv-tool", "arguments": {}}}

    deny = AsyncMock(return_value=_ent(False, "not_found"))
    opa = AsyncMock()
    audit = AsyncMock(return_value="evt-deny")
    with patch("app.services.entitlement.check_entitlement", deny), \
         patch("app.services.policy.evaluate_policy", opa), \
         patch("app.services.invocation._emit_audit_event", audit):
        with pytest.raises(NotEntitledError):
            await inv_svc.invoke_tool(
                tool_record=tool_record, json_rpc_request=rpc,
                client_id="admin-user", client_roles=["admin"],
                is_testing=False, request_id="r1",
                principal_id="human:iss:admin", principal_type="human",
            )
    opa.assert_not_awaited()  # entitlement gate fires before OPA
    # INV-001: the deny is audited at the chokepoint before the exception escapes.
    audit.assert_awaited_once()
    assert audit.call_args.kwargs["outcome"] == "deny"
    assert audit.call_args.kwargs["deny_reasons"] == ["not_entitled:not_found"]
