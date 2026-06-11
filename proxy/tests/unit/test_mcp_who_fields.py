"""
Unit tests — P1-F1: MCP-path invoke_tool calls thread who-fields (source_ip, session_jti)

Verifies that BOTH call sites in mcp_server.py that invoke inv_svc.invoke_tool pass
non-None source_ip and session_jti when the request carries them:
  1. _route_to_registry  — direct tools/call for a registry tool
  2. _handle_invoke_tool_real — the invoke_tool meta-tool handler

Without this fix, MCP-protocol invocations produced audit rows with NULL who-fields
even when the REST path (routers/tools.py) correctly threaded them (Task 1.2).

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_mcp_who_fields.py -v
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Shared fake helpers
# ---------------------------------------------------------------------------

class _FakeRow:
    """Dict-like stand-in for a SQLAlchemy mapping row.

    Supports dict(row) via keys() + __getitem__, and .get() for direct access.
    SQLAlchemy RowMapping objects expose keys() + __getitem__; dict() calls
    keys() then __getitem__ for each key.
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    def __getitem__(self, key: str):
        return self._data[key]

    def get(self, key, default=None):
        return self._data.get(key, default)

    def keys(self):
        return self._data.keys()

    def items(self):
        return self._data.items()

    def __iter__(self):
        return iter(self._data)


class _FakeMappings:
    def __init__(self, row) -> None:
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        return [self._row] if self._row is not None else []


class _FakeResult:
    def __init__(self, row) -> None:
        self._row = row

    def mappings(self):
        return _FakeMappings(self._row)


class _FakeSession:
    def __init__(self, row) -> None:
        self._row = row

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def execute(self, *_a, **_kw):
        return _FakeResult(self._row)


def _tool_row(name: str = "test-tool") -> _FakeRow:
    return _FakeRow({
        "tool_id": "aaaaaaaa-0000-0000-0000-000000000001",
        "name": name,
        "upstream_url": "http://upstream:8080",
        "version": "1.0",
        "status": "active",
        "risk_level": "low",
        "risk_score": 10,
        "schema": "{}",
        "tags": [],
        "description": "Test tool",
        "server_id": None,
        "deleted_at": None,
    })


def _make_request(
    client_id: str = "test-client",
    roles: list[str] | None = None,
    source_ip_header: str | None = "203.0.113.5",
    session_jti: str | None = "jti-test-abc",
    principal_id: str | None = "user-001",
    principal_type: str | None = "human",
    user_kc_token: str | None = None,
    client_host: str | None = None,
) -> MagicMock:
    """Build a fake FastAPI Request with the given state / headers."""
    req = MagicMock()
    req.state = SimpleNamespace(
        client_id=client_id,
        client_roles=roles or ["agent"],
        request_id="req-test-001",
        session_jti=session_jti,
        principal_id=principal_id,
        principal_type=principal_type,
        user_kc_token=user_kc_token,
    )
    headers: dict[str, str] = {}
    if source_ip_header:
        headers["x-forwarded-for"] = source_ip_header
    req.headers = headers
    req.client = SimpleNamespace(host=client_host) if client_host else None
    return req


# ---------------------------------------------------------------------------
# Test 1: _route_to_registry threads source_ip and session_jti
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_route_to_registry_threads_source_ip_and_session_jti():
    """
    _route_to_registry must pass source_ip and session_jti to invoke_tool.
    Before the P1-F1 fix, both were absent, leaving audit rows with NULL who-fields
    on every MCP direct tools/call that hits a registry tool.
    """
    from app.routers import mcp_server

    captured: dict = {}

    async def _fake_invoke_tool(**kwargs):
        captured.update(kwargs)
        return {"result": {"content": [{"type": "text", "text": "ok"}]}}

    request = _make_request(
        source_ip_header="10.10.10.42",
        session_jti="jti-route-registry-test",
    )

    fake_session = _FakeSession(_tool_row("registry-tool-x"))

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_fake_invoke_tool):
            # Also patch the semaphore to be transparent
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    result = await mcp_server._route_to_registry(
                        name="registry-tool-x",
                        args={"foo": "bar"},
                        request=request,
                        req_id=1,
                    )

    assert "source_ip" in captured, (
        "_route_to_registry did not pass source_ip to invoke_tool — audit rows would be NULL"
    )
    assert captured["source_ip"] == "10.10.10.42", (
        f"source_ip mismatch: expected '10.10.10.42', got {captured['source_ip']!r}"
    )
    assert "session_jti" in captured, (
        "_route_to_registry did not pass session_jti to invoke_tool — audit rows would be NULL"
    )
    assert captured["session_jti"] == "jti-route-registry-test", (
        f"session_jti mismatch: expected 'jti-route-registry-test', got {captured['session_jti']!r}"
    )


# ---------------------------------------------------------------------------
# Test 2: _handle_invoke_tool_real threads source_ip and session_jti
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_handle_invoke_tool_real_threads_source_ip_and_session_jti():
    """
    _handle_invoke_tool_real (the invoke_tool meta-tool handler) must pass
    source_ip and session_jti to invoke_tool.
    Before the P1-F1 fix, both were absent on the MCP meta-tool invocation path.
    """
    from app.routers import mcp_server

    captured: dict = {}

    async def _fake_invoke_tool(**kwargs):
        captured.update(kwargs)
        return {"result": {"content": [{"type": "text", "text": "ok"}]}}

    request = _make_request(
        source_ip_header="192.168.99.1",
        session_jti="jti-invoke-tool-handler-test",
    )

    fake_session = _FakeSession(_tool_row("wrapped-tool"))

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_fake_invoke_tool):
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    result = await mcp_server._handle_invoke_tool_real(
                        args={
                            "tool_name": "wrapped-tool",
                            "method": "tools/list",
                            "arguments": {},
                        },
                        request=request,
                    )

    assert "source_ip" in captured, (
        "_handle_invoke_tool_real did not pass source_ip to invoke_tool"
    )
    assert captured["source_ip"] == "192.168.99.1", (
        f"source_ip mismatch: expected '192.168.99.1', got {captured['source_ip']!r}"
    )
    assert "session_jti" in captured, (
        "_handle_invoke_tool_real did not pass session_jti to invoke_tool"
    )
    assert captured["session_jti"] == "jti-invoke-tool-handler-test", (
        f"session_jti mismatch: expected 'jti-invoke-tool-handler-test', got {captured['session_jti']!r}"
    )


# ---------------------------------------------------------------------------
# Test 3: source_ip falls back to request.client.host when no XFF header
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_route_to_registry_source_ip_fallback_to_client_host():
    """
    When x-forwarded-for header is absent, source_ip must fall back to
    request.client.host (same logic as the REST path in tools.py).
    """
    from app.routers import mcp_server

    captured: dict = {}

    async def _fake_invoke_tool(**kwargs):
        captured.update(kwargs)
        return {"result": {"content": []}}

    request = _make_request(
        source_ip_header=None,       # no XFF header
        client_host="10.20.30.40",   # client.host fallback
        session_jti="jti-fallback",
    )

    fake_session = _FakeSession(_tool_row("fallback-tool"))

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_fake_invoke_tool):
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    await mcp_server._route_to_registry(
                        name="fallback-tool",
                        args={},
                        request=request,
                        req_id=2,
                    )

    assert captured.get("source_ip") == "10.20.30.40", (
        f"source_ip fallback to client.host failed: got {captured.get('source_ip')!r}"
    )


# ---------------------------------------------------------------------------
# Test 4: None session_jti is passed as None (not coerced to a string)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_route_to_registry_none_session_jti_passes_none():
    """
    When request.state has no session_jti (e.g. API-key caller), None must be
    passed through — not coerced to the string 'None'.
    """
    from app.routers import mcp_server

    captured: dict = {}

    async def _fake_invoke_tool(**kwargs):
        captured.update(kwargs)
        return {"result": {"content": []}}

    request = _make_request(
        source_ip_header="1.2.3.4",
        session_jti=None,  # API-key caller — no JTI
    )

    fake_session = _FakeSession(_tool_row("no-jti-tool"))

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_fake_invoke_tool):
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    await mcp_server._route_to_registry(
                        name="no-jti-tool",
                        args={},
                        request=request,
                        req_id=3,
                    )

    assert captured.get("session_jti") is None, (
        f"session_jti should be None for API-key callers, got {captured.get('session_jti')!r}"
    )
