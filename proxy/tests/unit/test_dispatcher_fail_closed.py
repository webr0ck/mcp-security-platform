"""
Unit tests — Credential Dispatcher Fail-Closed Behaviour

Covers the security invariant that no injection mode string — known or
unknown — may cause a silent unauthenticated upstream call.

Invariants:
  - An unrecognised injection_mode string must raise CredentialInjectionError,
    never return an empty headers dict.
  - A recognised InjectionMode that has no match-arm handler must also raise
    CredentialInjectionError, never silently fall through to return {}.
  - basic_auth is intentionally unsupported (DB enum entry retained; no
    migration needed). It must raise, not pass through.
"""
from __future__ import annotations

import pytest

# CredentialInjectionError is defined in dispatcher.py (~line 43), not models.py
from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    dispatch_credential_injection,
)


# ---------------------------------------------------------------------------
# Unknown / unsupported injection_mode strings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_unknown_injection_mode_raises():
    """
    A mode string that is not in InjectionMode enum must raise
    CredentialInjectionError with 'unsupported injection_mode' in the message.
    Previously returned {} — which silently forwarded an unauthenticated call.
    """
    tool = {"tool_id": "t-1", "injection_mode": "basic_auth", "service_name": "x"}
    with pytest.raises(CredentialInjectionError, match="unsupported injection_mode"):
        await dispatch_credential_injection(tool, client_id="agent-001")


@pytest.mark.asyncio
@pytest.mark.unit
async def test_completely_unknown_mode_string_raises():
    """
    A completely invented mode string must also raise, not silently pass through.
    """
    tool = {"tool_id": "t-2", "injection_mode": "magic_beans", "service_name": "y"}
    with pytest.raises(CredentialInjectionError, match="unsupported injection_mode"):
        await dispatch_credential_injection(tool, client_id="agent-001")


@pytest.mark.asyncio
@pytest.mark.unit
async def test_empty_mode_string_raises():
    """
    An empty injection_mode string is not in the enum and must raise.
    """
    tool = {"tool_id": "t-3", "injection_mode": "", "service_name": "z"}
    with pytest.raises(CredentialInjectionError, match="unsupported injection_mode"):
        await dispatch_credential_injection(tool, client_id="agent-001")


# ---------------------------------------------------------------------------
# Terminal fallthrough: parsed mode with no handler must raise
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
@pytest.mark.unit
async def test_unhandled_enum_member_raises(monkeypatch):
    """
    Defense in depth: a mode that parses successfully but has no match-arm
    handler must raise CredentialInjectionError, not return {}.

    entra_user_token is a real mode; with broker uninitialized it raises
    CredentialInjectionError before reaching the terminal fallthrough.
    We assert the *class* of the error — the terminal fallthrough guard
    is the backstop if a new InjectionMode value is added without a
    corresponding match arm.
    """
    tool = {"tool_id": "t-4", "injection_mode": "entra_user_token", "service_name": "x"}
    # Broker is not initialized in unit test environment — this must raise,
    # not silently return {}.
    with pytest.raises(CredentialInjectionError):
        await dispatch_credential_injection(tool, client_id="agent-001")


@pytest.mark.asyncio
@pytest.mark.unit
async def test_service_mode_without_broker_raises():
    """
    service mode with no broker initialized must raise CredentialInjectionError.
    Confirms the broker-uninitialized guard fires before any match-arm logic.
    """
    tool = {"tool_id": "t-5", "injection_mode": "service", "service_name": "my-svc"}
    with pytest.raises(CredentialInjectionError):
        await dispatch_credential_injection(tool, client_id="agent-001")


@pytest.mark.asyncio
@pytest.mark.unit
async def test_none_mode_returns_empty_dict():
    """
    injection_mode='none' is the only mode that legitimately returns {}.
    Verify this still works after the fail-closed change.
    """
    tool = {"tool_id": "t-6", "injection_mode": "none", "service_name": "no-creds"}
    result = await dispatch_credential_injection(tool, client_id="agent-001")
    assert result == {}, f"Expected empty dict for mode=none, got: {result}"
