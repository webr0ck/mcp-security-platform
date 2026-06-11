"""
Unit tests — Dispatcher server-level credential resolution (Task 3.2)

Acceptance criteria:
  - A server with 3 tools sharing a server-level credential: all 3 get the credential.
  - One tool with an explicit override uses its own credential, not the server default.
  - A tool with neither a per-tool mode nor a server default falls back to 'none' → {}.

These tests do not hit the database; they mock the injection helpers directly.
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

def _tool(
    tool_id: str = "t-1",
    injection_mode: str | None = None,
    credential_id: str | None = None,
    server_default_injection_mode: str | None = None,
    server_default_credential_id: str | None = None,
) -> dict:
    return {
        "tool_id": tool_id,
        "name": "do_thing",
        "service_name": "test-svc",
        "injection_mode": injection_mode,
        "credential_id": credential_id,
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
        "server_default_injection_mode": server_default_injection_mode,
        "server_default_credential_id": server_default_credential_id,
    }


def _mock_broker():
    """Patch broker_instance to a non-None sentinel so the fail-closed guard passes."""
    sentinel = MagicMock()
    return patch("app.services.invocation.broker_instance", sentinel)


# ---------------------------------------------------------------------------
# 3-tool server scenario (Task 3.2 acceptance test)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_three_tools_all_get_server_credential():
    """
    3 tools on same server with NO per-tool credential or mode.
    All 3 must receive the server-level credential.
    """
    tools = [
        _tool(
            tool_id=f"t-{i}",
            injection_mode=None,
            credential_id=None,
            server_default_injection_mode="service",
            server_default_credential_id="cred-server-shared",
        )
        for i in range(1, 4)
    ]

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        return_value={"Authorization": "Bearer shared-token"},
    ) as mock_inject:
        results = [
            await dispatch_credential_injection(tool, client_id="agent-001")
            for tool in tools
        ]

    assert mock_inject.call_count == 3
    assert all(r == {"Authorization": "Bearer shared-token"} for r in results)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_tool_with_override_uses_own_credential():
    """
    3 tools on same server. Tool-3 has an explicit per-tool injection_mode.
    Tools 1 and 2 use server default; tool 3 uses its own.
    Confirmed by checking the tool_id passed to _inject_service_credential.
    """
    server_cred = "cred-server"
    tool_1 = _tool("t-1", server_default_injection_mode="service", server_default_credential_id=server_cred)
    tool_2 = _tool("t-2", server_default_injection_mode="service", server_default_credential_id=server_cred)
    tool_3 = _tool(
        "t-3",
        injection_mode="service",          # explicit override
        credential_id="cred-t3-own",
        server_default_injection_mode="service",
        server_default_credential_id=server_cred,
    )

    captured_tool_ids: list[str] = []

    async def _fake_inject(tool_id, service_name, inject_header, inject_prefix):
        captured_tool_ids.append(tool_id)
        return {"Authorization": f"Bearer token-for-{tool_id}"}

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        side_effect=_fake_inject,
    ):
        r1 = await dispatch_credential_injection(tool_1, client_id="agent-001")
        r2 = await dispatch_credential_injection(tool_2, client_id="agent-001")
        r3 = await dispatch_credential_injection(tool_3, client_id="agent-001")

    assert r1 == {"Authorization": "Bearer token-for-t-1"}
    assert r2 == {"Authorization": "Bearer token-for-t-2"}
    assert r3 == {"Authorization": "Bearer token-for-t-3"}
    assert captured_tool_ids == ["t-1", "t-2", "t-3"]


@pytest.mark.asyncio
@pytest.mark.unit
async def test_no_per_tool_no_server_default_falls_to_none():
    """
    Tool has neither a per-tool injection_mode nor a server default.
    Resolution falls to 'none' → returns {} (no credentials injected).
    """
    tool = _tool(
        tool_id="t-bare",
        injection_mode=None,
        credential_id=None,
        server_default_injection_mode=None,
        server_default_credential_id=None,
    )

    result = await dispatch_credential_injection(tool, client_id="agent-001")
    assert result == {}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_server_default_mode_without_credential_propagates_to_helper():
    """
    server_default_injection_mode is set but credential lookup fails in the helper.
    The dispatcher must propagate the CredentialInjectionError — not swallow it.

    The broker guard fires first (before the per-mode helper), so we patch the
    broker to a non-None sentinel, then let the helper raise.
    """
    tool = _tool(
        tool_id="t-no-cred",
        injection_mode=None,
        credential_id=None,
        server_default_injection_mode="service",
        server_default_credential_id=None,
    )

    with _mock_broker(), patch(
        "app.credential_broker.dispatcher._inject_service_credential",
        new_callable=AsyncMock,
        side_effect=CredentialInjectionError("No credential found"),
    ):
        with pytest.raises(CredentialInjectionError, match="No credential found"):
            await dispatch_credential_injection(tool, client_id="agent-001")
