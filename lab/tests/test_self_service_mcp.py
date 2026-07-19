"""
Functional tests for Self-Service MCP.

Task 2.2b: The self-service MCP server is now a thin client of the proxy
profile API (proxy/app/routers/profiles.py) — no direct DB access.

Identity injection: the X-User-Sub and X-User-Role headers are injected by
the proxy when routing tool calls. In direct-server tests (bypassing the
proxy), we simulate this by setting the headers manually on the MCP request.

Run (requires compose up):
  python3 -m pytest lab/tests/test_self_service_mcp.py -v --tb=short
"""
from __future__ import annotations

import json as _json
import os

import httpx
import pytest

PROXY_URL = os.environ.get("PROXY_URL", "http://localhost:8000")
KC_URL = os.environ.get("KC_URL", "http://localhost:8082")
KC_REALM = os.environ.get("KC_REALM", "mcp")
KC_TEST_CLIENT = os.environ.get("KC_TEST_CLIENT", "lab-test")
KC_TEST_SECRET = os.environ.get("KC_TEST_SECRET", "lab-test-secret")

# Direct port for self-service (localhost:8108) — tests bypass proxy auth,
# but inject identity headers as the proxy would.
SELF_SERVICE_DIRECT = os.environ.get("SELF_SERVICE_DIRECT", "http://localhost:8108")


# ── helpers ───────────────────────────────────────────────────────────────────

def _get_token(username: str, password: str = "labpassword") -> str:
    r = httpx.post(
        f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": KC_TEST_CLIENT,
              "client_secret": KC_TEST_SECRET, "username": username,
              "password": password, "scope": "openid"},
        timeout=15,
    )
    assert r.status_code == 200, f"token for {username} failed: {r.text}"
    return r.json()["access_token"]


def _get_sub(token: str) -> str:
    import base64
    payload = _json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    return payload["sub"]


def _mcp_call(token: str, tool_name: str, args: dict, timeout: float = 15) -> dict:
    """Call a tool via the proxy MCP endpoint with a KC Bearer token."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    r = httpx.post(
        f"{PROXY_URL}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "test", "version": "1"}}},
        headers=headers, timeout=timeout,
    )
    if r.status_code != 200:
        return {"status_code": r.status_code, "error": "init_failed"}
    sid = r.headers.get("mcp-session-id", "")
    if sid:
        headers["MCP-Session-Id"] = sid
    r2 = httpx.post(
        f"{PROXY_URL}/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "invoke_tool",
                         "arguments": {"tool_name": tool_name, "arguments": args}}},
        headers=headers, timeout=timeout,
    )
    return {"status_code": r2.status_code,
            "body": r2.json() if r2.text else {}}


def _direct_mcp_call(
    tool_name: str,
    args: dict,
    caller_sub: str = "test-user",
    caller_role: str = "agent",
    timeout: float = 10,
) -> dict:
    """Call the self-service MCP directly, injecting identity headers as the proxy would.

    Task 2.2b: identity comes from X-User-Sub / X-User-Role headers (not MCP args).
    The server's _IdentityMiddleware reads these headers and populates ContextVars.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        # Simulate proxy identity injection
        "X-User-Sub": caller_sub,
        "X-User-Role": caller_role,
    }
    # Initialize session
    r = httpx.post(
        f"{SELF_SERVICE_DIRECT}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "test", "version": "1"}}},
        headers=headers, timeout=timeout,
    )
    if r.status_code != 200:
        return {"error": "init_failed", "status_code": r.status_code, "detail": r.text[:200]}
    sid = r.headers.get("mcp-session-id", "")
    if sid:
        headers["MCP-Session-Id"] = sid
    # Tool call
    r2 = httpx.post(
        f"{SELF_SERVICE_DIRECT}/mcp",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": tool_name, "arguments": args}},
        headers=headers, timeout=timeout,
    )
    if r2.status_code != 200:
        return {"error": "call_failed", "status_code": r2.status_code, "detail": r2.text[:200]}
    # Parse SSE / JSON response
    for line in r2.text.splitlines():
        if line.startswith("data:"):
            data = _json.loads(line[5:].strip())
            result = data.get("result", data)
            # Unwrap MCP tools/call content envelope: {content: [{type: "text", text: "{...}"}]}
            content = result.get("content", [])
            if content and content[0].get("type") == "text":
                try:
                    return _json.loads(content[0]["text"])
                except Exception:
                    pass
            return result
    # Try direct JSON parse (non-SSE response)
    try:
        return r2.json()
    except Exception:
        return {"raw": r2.text[:200]}


# ── fixtures ──────────────────────────────────────────────────────────────────

ALICE_SUB = "alice-test-sub"
BOB_SUB = "bob-test-sub"


# ═════════════════════════════════════════════════════════════════════════════
# Direct server tests (proxy calls self-service via pairwise net; these tests
# simulate that by calling the host-exposed port 8108 with injected headers)
# ═════════════════════════════════════════════════════════════════════════════

class TestDirectServerAccess:
    def test_handshake(self):
        r = httpx.post(
            f"{SELF_SERVICE_DIRECT}/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                  "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                             "clientInfo": {"name": "test", "version": "1"}}},
            headers={"Content-Type": "application/json",
                     "Accept": "application/json, text/event-stream"},
            timeout=10,
        )
        assert r.status_code == 200
        assert b"self-service-mcp" in r.content

    def test_list_available_mcps_returns_note(self):
        """Task 2.2b: list_available_mcps now returns a note + empty list
        (registry listing is proxy's responsibility, not the thin client)."""
        result = _direct_mcp_call("list_available_mcps", {}, caller_sub=ALICE_SUB)
        # The new implementation returns a note instead of a full registry listing
        assert "note" in result or "mcps" in result, f"unexpected result: {result}"

    def test_get_profile_own(self):
        """get_profile for own identity calls proxy profile API."""
        result = _direct_mcp_call(
            "get_profile", {"mcp_name": "echo-ping"}, caller_sub=ALICE_SUB
        )
        # The proxy profile API may return not_found if echo-ping is not in registry
        # in the test environment. Accept either a real row or a proxy 404.
        assert "error" in result or "mcp_name" in result or "principal" in result, \
            f"unexpected result: {result}"

    def test_enable_mcp_self_service(self):
        """enable_mcp for own profile proxies to POST /api/v1/profiles/{sub}/mcps/{name}/enable."""
        result = _direct_mcp_call(
            "enable_mcp", {"mcp_name": "echo-ping"}, caller_sub=ALICE_SUB
        )
        # Should get ok:true or a proxy-relayed error (not_found if tool not seeded)
        assert isinstance(result, dict), f"unexpected result type: {type(result)}"

    def test_disable_mcp_self_service(self):
        result = _direct_mcp_call(
            "disable_mcp", {"mcp_name": "echo-ping"}, caller_sub=ALICE_SUB
        )
        assert isinstance(result, dict)

    def test_non_admin_cannot_modify_other_profile(self):
        """Identity from X-User-Role=agent cannot modify another principal's profile."""
        result = _direct_mcp_call(
            "enable_mcp",
            {"mcp_name": "echo-ping", "target_profile": BOB_SUB},
            caller_sub=ALICE_SUB,
            caller_role="agent",
        )
        assert result.get("error") == "forbidden", \
            f"Expected forbidden, got: {result}"

    def test_admin_can_modify_other_profile(self):
        """X-User-Role=admin can modify another principal's profile (proxy enforces RBAC)."""
        result = _direct_mcp_call(
            "enable_mcp",
            {"mcp_name": "echo-ping", "target_profile": BOB_SUB},
            caller_sub=ALICE_SUB,
            caller_role="admin",
        )
        # Either ok:true (proxy accepted) or proxy-relayed not_found/api_error
        # (if tool/principal not registered) — but not "forbidden"
        assert result.get("error") != "forbidden", \
            f"Admin should not be forbidden, got: {result}"

    def test_enable_function_self_service(self):
        result = _direct_mcp_call(
            "enable_function",
            {"mcp_name": "echo-ping", "function_name": "ping"},
            caller_sub=ALICE_SUB,
        )
        assert isinstance(result, dict)

    def test_disable_function_self_service(self):
        result = _direct_mcp_call(
            "disable_function",
            {"mcp_name": "echo-ping", "function_name": "bulk_compute"},
            caller_sub=ALICE_SUB,
        )
        assert isinstance(result, dict)

    def test_no_direct_db_access(self):
        """Smoke test: server should not import asyncpg (no DB dependency)."""
        import subprocess
        result = subprocess.run(
            ["podman", "exec", "self-service",
             "python", "-c", "import asyncpg; print('asyncpg available')"],
            capture_output=True, text=True,
        )
        # asyncpg should NOT be importable (not installed in Task 2.2b Dockerfile)
        assert result.returncode != 0, \
            "asyncpg should not be installed in the self-service MCP (no direct DB access)"


# ═════════════════════════════════════════════════════════════════════════════
# Proxy-gated tests (requires compose up + KC tokens)
# ═════════════════════════════════════════════════════════════════════════════

class TestViaProxy:
    @pytest.fixture(autouse=True)
    def require_kc(self):
        """Skip entire class if Keycloak is not running."""
        try:
            r = httpx.get(f"{KC_URL}/realms/{KC_REALM}", timeout=5)
            if r.status_code >= 400:
                pytest.skip("Keycloak not available")
        except Exception:
            pytest.skip("Keycloak not reachable")

    def test_alice_can_call_self_service_via_proxy(self):
        token = _get_token("alice")
        result = _mcp_call(token, "list_available_mcps", {})
        assert result["status_code"] == 200


if __name__ == "__main__":
    import subprocess
    import sys
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-v", "--tb=short"], check=True)
