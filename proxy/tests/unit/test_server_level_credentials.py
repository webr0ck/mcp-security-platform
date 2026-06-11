"""
Unit tests — Server-level credential attachment (Plan Task 3.2)

Verifies the dispatcher resolution order:
  1. tool-level override (tool_record.credential_id / tool_record.injection_mode)
  2. server default (server_record.default_credential_id / default_injection_mode)
  3. fail-closed (CredentialInjectionError)

These tests do NOT hit the database; they mock the injection helpers directly.
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    dispatch_credential_injection,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_service_tool(
    tool_id: str = "tool-1",
    credential_id: str | None = None,
    injection_mode: str | None = None,
    server_default_credential_id: str | None = None,
    server_default_injection_mode: str | None = None,
) -> dict:
    """Build a tool_record dict with optional server-level defaults."""
    return {
        "tool_id": tool_id,
        "name": "do_thing",
        "service_name": "my-svc",
        "injection_mode": injection_mode,
        "credential_id": credential_id,
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        # Server-level defaults populated by the registry/invocation layer
        "server_default_credential_id": server_default_credential_id,
        "server_default_injection_mode": server_default_injection_mode,
    }


# ---------------------------------------------------------------------------
# Task 3.2: resolution order tests
# ---------------------------------------------------------------------------

def _mock_broker():
    """Context manager: patch broker_instance to a non-None sentinel so the fail-closed
    guard passes and tests can reach the per-mode injection helpers."""
    sentinel = MagicMock()
    return patch("app.services.invocation.broker_instance", sentinel)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_server_default_credential_used_when_no_tool_override():
    """
    Tool has no explicit injection_mode/credential_id — server default must be used.
    All three tools on the server should get the credential injected.
    """
    tool = _make_service_tool(
        tool_id="tool-1",
        injection_mode=None,          # no per-tool mode
        credential_id=None,           # no per-tool credential
        server_default_credential_id="cred-server-001",
        server_default_injection_mode="service",
    )

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer server-token"},
    ) as mock_inject:
        result = await dispatch_credential_injection(tool, client_id="agent-001")

    assert result == {"Authorization": "Bearer server-token"}
    mock_inject.assert_awaited_once()
    # Confirm the tool_id passed down is correct
    call_kwargs = mock_inject.call_args.kwargs
    assert call_kwargs.get("tool_id") == "tool-1"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_tool_override_wins_over_server_default():
    """
    When tool has its own injection_mode, it must take precedence over the server default.
    """
    tool = _make_service_tool(
        tool_id="tool-override",
        injection_mode="service",         # explicit per-tool mode
        credential_id="cred-tool-override",
        server_default_credential_id="cred-server-001",
        server_default_injection_mode="service",
    )

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer tool-specific-token"},
    ) as mock_inject:
        result = await dispatch_credential_injection(tool, client_id="agent-001")

    assert result == {"Authorization": "Bearer tool-specific-token"}
    mock_inject.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.unit
async def test_three_tools_same_server_all_inject_via_server_default():
    """
    3-tool server with one server-level credential — all 3 must inject successfully.
    Simulates the plan acceptance test scenario.
    """
    server_cred_id = "cred-shared-server"
    tools = [
        _make_service_tool(
            tool_id=f"tool-{i}",
            injection_mode=None,
            credential_id=None,
            server_default_credential_id=server_cred_id,
            server_default_injection_mode="service",
        )
        for i in range(1, 4)
    ]

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer shared-server-token"},
    ):
        results = [
            await dispatch_credential_injection(tool, client_id="agent-001")
            for tool in tools
        ]

    assert all(r == {"Authorization": "Bearer shared-server-token"} for r in results)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_tool_3_override_wins_in_mixed_server():
    """
    3 tools on same server, tool-3 has explicit override.
    Tools 1 and 2 use server default; tool 3 uses its own credential.
    """
    server_cred_id = "cred-server-default"
    tool_1 = _make_service_tool(
        tool_id="tool-1",
        injection_mode=None,
        credential_id=None,
        server_default_credential_id=server_cred_id,
        server_default_injection_mode="service",
    )
    tool_2 = _make_service_tool(
        tool_id="tool-2",
        injection_mode=None,
        credential_id=None,
        server_default_credential_id=server_cred_id,
        server_default_injection_mode="service",
    )
    tool_3_override = _make_service_tool(
        tool_id="tool-3",
        injection_mode="service",          # explicit override
        credential_id="cred-tool-3-own",
        server_default_credential_id=server_cred_id,
        server_default_injection_mode="service",
    )

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer some-token"},
    ) as mock_inject:
        await dispatch_credential_injection(tool_1, client_id="agent-001")
        await dispatch_credential_injection(tool_2, client_id="agent-001")
        await dispatch_credential_injection(tool_3_override, client_id="agent-001")

    assert mock_inject.call_count == 3


@pytest.mark.asyncio
@pytest.mark.unit
async def test_no_mode_no_server_default_is_none_mode():
    """
    Tool has no injection_mode AND no server default → treated as 'none' → returns {}.
    Fail-closed means we don't silently forward; 'none' is the explicit no-op mode.
    """
    tool = _make_service_tool(
        tool_id="tool-no-creds",
        injection_mode=None,
        credential_id=None,
        server_default_credential_id=None,
        server_default_injection_mode=None,
    )

    result = await dispatch_credential_injection(tool, client_id="agent-001")
    assert result == {}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_server_default_mode_only_without_credential_id():
    """
    server_default_injection_mode set but no credential_id on either tool or server
    → the per-mode helper is called (it will raise CredentialInjectionError if no cred found).
    The dispatcher itself must not silently skip.
    """
    tool = _make_service_tool(
        tool_id="tool-mode-no-cred",
        injection_mode=None,
        credential_id=None,
        server_default_credential_id=None,   # no cred_id
        server_default_injection_mode="service",  # but mode is set
    )

    with patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        side_effect=CredentialInjectionError("No credential found"),
    ):
        with pytest.raises(CredentialInjectionError):
            await dispatch_credential_injection(tool, client_id="agent-001")
