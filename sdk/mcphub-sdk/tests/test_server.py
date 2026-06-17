"""
Tests for mcphub_sdk.server — PlatformMCPServer.

Covers:
  - H11: end-to-end test that identity().sub reaches a tool (not "anonymous")
  - H1: /health route present and returns 200 {"status":"ok"}
  - H2: require_proxy=True rejects un-proxied requests before tools run
  - H5: .app() always returns the middlewared app (no un-middlewared path)
  - H6: tool() delegation — inputSchema not collapsed (verified against FastMCP baseline)
  - H1/H5: /health accessible without proxy headers (exempted by middleware)
"""
from __future__ import annotations

import json
import pytest
from starlette.testclient import TestClient

from mcphub_sdk import PlatformMCPServer, identity, credential
from mcphub_sdk.server import PlatformMCPServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(name: str = "test-mcp", **kwargs) -> PlatformMCPServer:
    return PlatformMCPServer(name, **kwargs)


def _mcp_post(client: TestClient, method: str, params: dict) -> dict:
    """Send a JSON-RPC 2.0 request to /mcp and return the parsed response."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }
    resp = client.post(
        "/mcp",
        content=json.dumps(payload),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "X-User-Sub": "test-user@corp",  # satisfy require_proxy
        },
    )
    return resp


# ---------------------------------------------------------------------------
# Test: H1 — /health route present
# ---------------------------------------------------------------------------


def test_health_route_present_and_ok():
    """GET /health returns 200 {"status":"ok","server":"<name>"}."""
    srv = _make_server("hello-mcp")
    client = TestClient(srv.app(), raise_server_exceptions=True)
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["server"] == "hello-mcp"


def test_health_accessible_without_proxy_headers():
    """H1+H2: /health is reachable with require_proxy=True and no X-User-Sub."""
    srv = _make_server(require_proxy=True)
    client = TestClient(srv.app(), raise_server_exceptions=True)
    resp = client.get("/health")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test: H2 — require_proxy blocks un-proxied requests to non-health paths
# ---------------------------------------------------------------------------


def test_require_proxy_blocks_unproxied_to_mcp():
    """POST /mcp without X-User-Sub → 403 when require_proxy=True.

    The middleware rejects the request before it reaches the MCP handler,
    so no lifespan is needed — the 403 is returned by _ContextMiddleware.
    """
    srv = _make_server(require_proxy=True)
    # Context-manager form used for consistency; the 403 fires in middleware
    # before the session manager is reached so it also works without it,
    # but using 'with' is the safe default for all MCP-path requests.
    with TestClient(srv.app(), raise_server_exceptions=True) as client:
        resp = client.post(
            "/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            headers={"Content-Type": "application/json"},
            # No X-User-Sub intentionally
        )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test: H5 — .app() always includes middleware
# ---------------------------------------------------------------------------


def test_app_always_middlewared():
    """H5: .app() always wraps with _ContextMiddleware; there is no un-middlewared path.

    Two independent PlatformMCPServer instances are tested, each with a fresh
    FastMCP + session manager.  (The same instance cannot be reused because
    StreamableHTTPSessionManager.run() is single-use by design in mcp>=1.28.)
    """
    for i in range(2):
        srv = _make_server(f"middlewared-check-{i}", require_proxy=True)
        with TestClient(srv.app(), raise_server_exceptions=True) as client:
            # Unproxied /mcp rejected by _ContextMiddleware before it reaches the MCP handler
            resp = client.post(
                "/mcp",
                content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
                headers={"Content-Type": "application/json"},
            )
        assert resp.status_code == 403, (
            f"Middleware missing on instance {i} — un-proxied request was not rejected"
        )


# ---------------------------------------------------------------------------
# Test: H6 — tool() delegation preserves inputSchema
# ---------------------------------------------------------------------------


def test_tool_delegation_preserves_schema():
    """Registering a typed function via srv.tool() and via bare FastMCP.tool()
    must produce identical inputSchema structures.

    H6: if tool() wrapped the function instead of delegating, the schema would
    collapse to {} or *args/**kwargs — catching this is the point of the test.
    """
    from mcp.server.fastmcp import FastMCP

    # Baseline: register directly on a bare FastMCP
    baseline = FastMCP("baseline-mcp", stateless_http=True)

    @baseline.tool()
    async def echo_args_baseline(message: str, count: int = 1, tag: str = "") -> dict:
        return {}

    # SDK path: register via PlatformMCPServer.tool()
    srv = _make_server("sdk-mcp")

    @srv.tool()
    async def echo_args_sdk(message: str, count: int = 1, tag: str = "") -> dict:
        return {}

    # Retrieve registered tools from both
    baseline_tools = baseline._tool_manager.list_tools()
    sdk_tools = srv.mcp._tool_manager.list_tools()

    # Find our tool in each
    def _find(tools, name):
        for t in tools:
            if t.name == name:
                return t
        raise AssertionError(f"Tool {name!r} not found in: {[t.name for t in tools]}")

    baseline_tool = _find(baseline_tools, "echo_args_baseline")
    sdk_tool = _find(sdk_tools, "echo_args_sdk")

    # Both should have properties for message, count, tag
    b_props = baseline_tool.parameters.get("properties", {})
    s_props = sdk_tool.parameters.get("properties", {})

    assert set(b_props.keys()) == {"message", "count", "tag"}, (
        f"Baseline schema missing props: {b_props}"
    )
    assert set(s_props.keys()) == {"message", "count", "tag"}, (
        f"SDK schema missing props (delegation collapsed?): {s_props}"
    )

    # required fields should match
    assert baseline_tool.parameters.get("required") == sdk_tool.parameters.get("required"), (
        f"required mismatch: baseline={baseline_tool.parameters.get('required')!r} "
        f"sdk={sdk_tool.parameters.get('required')!r}"
    )


# ---------------------------------------------------------------------------
# Test: H11 — identity ContextVar reaches tool (the most important test)
#
# This is the end-to-end stateless_http=True proof.  We register a tool that
# calls identity().sub and drive a tools/call via the MCP JSON-RPC protocol.
# Without stateless_http=True the tool would always see "anonymous".
# ---------------------------------------------------------------------------


def _parse_mcp_tool_result(resp_text: str) -> dict:
    """Parse an MCP tools/call response — handles both SSE and plain JSON."""
    import re

    body = resp_text.strip()
    if body.startswith("event:") or body.startswith("data:"):
        # SSE stream: find the JSON-RPC result message
        matches = re.findall(r"^data: (.+)$", body, re.MULTILINE)
        assert matches, f"No SSE data lines found: {body!r}"
        for m in matches:
            try:
                parsed = json.loads(m)
                if "result" in parsed:
                    return parsed["result"]
            except json.JSONDecodeError:
                continue
        raise AssertionError(f"No JSON-RPC result in SSE: {matches}")
    else:
        return json.loads(body).get("result", {})


def test_identity_reaches_tool_via_mcp_protocol():
    """H11: identity().sub inside a tool == X-User-Sub from the request header.

    Drives the full MCP JSON-RPC tools/call via TestClient in context-manager
    mode (required to trigger ASGI lifespan startup, which initialises the
    StreamableHTTPSessionManager task group).

    This is the end-to-end stateless_http=True proof: without it, the ContextVar
    set by _ContextMiddleware on the per-request task does NOT propagate to the
    tool task group, so identity().sub would always be "anonymous".
    """
    srv = _make_server("h11-test-mcp", require_proxy=False)

    @srv.tool()
    async def get_sub() -> dict:
        """Return the caller sub from the ContextVar."""
        who = identity()
        return {"sub": who.sub}

    proxied_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-User-Sub": "alice@corp",
        "X-User-Role": "agent",
    }

    # Context-manager form triggers ASGI lifespan (startup/shutdown) which
    # initialises the MCP session manager task group.
    with TestClient(srv.app(), raise_server_exceptions=True) as client:
        call_resp = client.post(
            "/mcp",
            content=json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "get_sub", "arguments": {}},
            }),
            headers=proxied_headers,
        )

    assert call_resp.status_code == 200, f"tools/call failed: {call_resp.text}"

    result = _parse_mcp_tool_result(call_resp.text)
    content = result.get("content", [])
    assert content, f"No content in result: {result}"
    tool_output = json.loads(content[0]["text"])

    assert tool_output["sub"] == "alice@corp", (
        f"H11 FAILED: identity().sub in tool was {tool_output['sub']!r}, expected 'alice@corp'. "
        "This means stateless_http=True is not working or ContextVar propagation is broken."
    )


# ---------------------------------------------------------------------------
# Test: PlatformMCPServer.mcp property returns FastMCP
# ---------------------------------------------------------------------------


def test_mcp_property_returns_fastmcp():
    from mcp.server.fastmcp import FastMCP

    srv = _make_server()
    assert isinstance(srv.mcp, FastMCP)


# ---------------------------------------------------------------------------
# Test: credential_env stored on server
# ---------------------------------------------------------------------------


def test_credential_env_stored():
    srv = _make_server(credential_env="MY_TOKEN")
    assert srv.credential_env == "MY_TOKEN"


# ---------------------------------------------------------------------------
# Test: require_proxy stored and defaults to True
# ---------------------------------------------------------------------------


def test_require_proxy_defaults_true():
    srv = _make_server()
    assert srv.require_proxy is True


def test_require_proxy_can_be_disabled():
    srv = _make_server(require_proxy=False)
    assert srv.require_proxy is False
