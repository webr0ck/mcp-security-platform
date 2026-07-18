"""
Unit tests — Fix 3 (docs/spec/11-server-lifecycle-and-hardening-batch.md):
`search-kb` listed active + enabled_for_your_profile but every invoke returned
"Unknown tool: search-kb".

Root cause: tool_registry.name for the search server is 'search-kb', but the
upstream lab-mcp-search server registers its tool under FastMCP's default name
derived from the function (@mcp.tool() async def search(...) -> tool name
'search'), so tools/call {"name": "search-kb"} bounces with an upstream
"Unknown tool: search-kb" JSON-RPC error. This is the same single-tool-per-
server wrapper mismatch class as the R-2 fix (e.g. gitea-repos -> list_repos).

_route_to_registry (the direct top-level tools/call path) already resolves
and retries this via _resolve_upstream_subtool_name (R-2). The invoke_tool
meta-tool handler (_handle_invoke_tool_real) did NOT have this retry — it
forwarded the caller's params.name verbatim and returned the raw upstream
"Unknown tool" JSON-RPC error as text. These tests pin both paths.

Run from proxy/ with:
  .venv/bin/python -m pytest tests/unit/test_search_kb_wrapper_retry.py -v
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class _FakeRow:
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


def _search_kb_row() -> _FakeRow:
    return _FakeRow({
        "tool_id": "bbbbbbbb-0000-0000-0000-000000000002",
        "name": "search-kb",
        "version": "1.0.0",
        "upstream_url": "http://lab-mcp-search:8000/mcp",
        "status": "active",
        "risk_level": "low",
        "risk_score": 10,
        "schema": "{}",
        "tags": [],
        "description": "Full-text search over MCP security knowledge base.",
        "server_id": "cccccccc-0000-0000-0000-000000000003",
        "deleted_at": None,
    })


def _make_request() -> MagicMock:
    req = MagicMock()
    req.state = SimpleNamespace(
        client_id="alice",
        client_roles=["agent"],
        request_id="req-search-kb-001",
        session_jti="jti-search-kb",
        principal_id="human:keycloak:alice@corp",
        principal_type="human",
        principal_issuer=None,
        principal_display_sub=None,
        user_kc_token=None,
        profile_uuid=None,
    )
    req.headers = {}
    req.client = SimpleNamespace(host="10.10.10.1")
    return req


def _unknown_tool_error(name: str) -> dict:
    return {"error": {"code": -32601, "message": f"Unknown tool: {name}"}}


def _tools_list_result() -> dict:
    return {"result": {"tools": [{"name": "search", "description": "search the kb"}]}}


def _success_result() -> dict:
    return {"result": {"content": [{"type": "text", "text": json.dumps({"results": []})}]}}


def _make_side_effect():
    """First tools/call('search-kb') -> Unknown tool. tools/list -> ['search'].
    Retried tools/call('search') -> success. Mirrors real upstream behavior."""

    async def _fake_invoke_tool(**kwargs):
        req = kwargs["json_rpc_request"]
        method = req.get("method")
        params = req.get("params") or {}
        if method == "tools/list":
            return _tools_list_result()
        if method == "tools/call" and params.get("name") == "search-kb":
            return _unknown_tool_error("search-kb")
        if method == "tools/call" and params.get("name") == "search":
            return _success_result()
        raise AssertionError(f"unexpected upstream call: {req}")

    return _fake_invoke_tool


@pytest.mark.asyncio
async def test_route_to_registry_resolves_search_kb_wrapper_mismatch():
    """Direct top-level tools/call('search-kb') must resolve to the upstream's
    real tool name ('search') and succeed, not surface 'Unknown tool: search-kb'."""
    from app.routers import mcp_server

    request = _make_request()
    fake_session = _FakeSession(_search_kb_row())

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_make_side_effect()):
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    result = await mcp_server._route_to_registry(
                        name="search-kb",
                        args={"query": "SSRF", "limit": 5},
                        request=request,
                        req_id=1,
                    )

    assert "error" not in result, f"search-kb still failing: {result}"
    assert "result" in result


@pytest.mark.asyncio
async def test_invoke_tool_meta_tool_resolves_search_kb_wrapper_mismatch():
    """The invoke_tool meta-tool handler must apply the same wrapper-name
    resolution/retry as _route_to_registry. Before the fix, this path forwarded
    'search-kb' verbatim and returned the raw 'Unknown tool: search-kb' JSON-RPC
    error as the tool's text output."""
    from app.routers import mcp_server

    request = _make_request()
    fake_session = _FakeSession(_search_kb_row())

    with patch("app.core.database.AsyncSessionLocal", return_value=fake_session):
        with patch("app.services.invocation.invoke_tool", side_effect=_make_side_effect()):
            with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aenter__", new=AsyncMock()):
                with patch.object(mcp_server._INVOKE_SEMAPHORE, "__aexit__", new=AsyncMock()):
                    result = await mcp_server._handle_invoke_tool_real(
                        args={
                            "tool_name": "search-kb",
                            "method": "tools/call",
                            "arguments": {
                                "name": "search-kb",
                                "arguments": {"query": "SSRF", "limit": 5},
                            },
                        },
                        request=request,
                    )

    text = result.get("text", "")
    assert "Unknown tool" not in text, (
        f"invoke_tool still surfaces the raw upstream 'Unknown tool' bounce: {text}"
    )
    payload = json.loads(text)
    assert "error" not in payload, f"search-kb still failing via invoke_tool: {payload}"
    assert "result" in payload
