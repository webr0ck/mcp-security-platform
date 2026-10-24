"""Tests for the self-lockout guard on disable_mcp/disable_function (F-CX-002).

A non-admin caller must never be able to disable the self-service MCP (or its
recovery functions get_profile/enable_mcp/enable_function) for themselves —
that would strand them with no tool left to re-enable it.
"""
from unittest.mock import AsyncMock, patch

import pytest

import server as ss  # mcp-servers/self-service/server.py


def test_is_self_lockout_blocks_own_disable_mcp():
    assert ss._is_self_lockout("self-service", "agent", "bob", "bob") is True


def test_is_self_lockout_blocks_own_recovery_function():
    assert ss._is_self_lockout("self-service", "agent", "bob", "bob", "get_profile") is True
    assert ss._is_self_lockout("self-service", "agent", "bob", "bob", "enable_mcp") is True
    assert ss._is_self_lockout("self-service", "agent", "bob", "bob", "enable_function") is True


def test_is_self_lockout_allows_non_recovery_function():
    assert ss._is_self_lockout("self-service", "agent", "bob", "bob", "list_functions") is False


def test_is_self_lockout_allows_other_mcps():
    assert ss._is_self_lockout("some-other-mcp", "agent", "bob", "bob") is False


def test_is_self_lockout_allows_admin():
    assert ss._is_self_lockout("self-service", "admin", "bob", "alice-admin") is False
    assert ss._is_self_lockout("self-service", "platform_admin", "bob", "bob") is False


def test_is_self_lockout_allows_admin_disabling_others():
    assert ss._is_self_lockout("self-service", "agent", "someone-else", "bob") is False


@pytest.mark.asyncio
async def test_disable_mcp_rejects_self_lockout():
    ss._ctx_caller_sub.set("bob")
    ss._ctx_caller_role.set("agent")
    with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=AssertionError("should not call proxy"))):
        result = await ss.disable_mcp("self-service")
    assert result["error"] == "self_lockout_blocked"


@pytest.mark.asyncio
async def test_disable_function_rejects_self_lockout():
    ss._ctx_caller_sub.set("bob")
    ss._ctx_caller_role.set("agent")
    with patch("httpx.AsyncClient.post", new=AsyncMock(side_effect=AssertionError("should not call proxy"))):
        result = await ss.disable_function("self-service", "get_profile")
    assert result["error"] == "self_lockout_blocked"
