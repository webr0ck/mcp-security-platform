"""
test-api-server MCP wrapper — streamable-HTTP MCP server fronting the local
policy-document test API (server.py, read port 9191 / read+write port 9292).

Built on the mcphub_sdk PlatformMCPServer, matching the echo server's pattern.
Demonstrates BOTH platform credential-injection modes against the same
underlying app: read tools need no credential (injection_mode=none), the
write tool requires a broker-injected Basic credential (injection_mode=basic_auth).

The underlying policy API (server.py) is started as a background subprocess
on loopback inside this same container — see Dockerfile/CMD.

Tools:
  list_policies     — no credential required (calls the read-only :9191 port)
  search_policies   — no credential required (calls the read-only :9191 port)
  get_policy        — no credential required (calls the read-only :9191 port)
  add_policy_line   — requires a broker-injected Basic credential (calls the
                      read+write :9292 port, forwarding the injected header)
"""
from __future__ import annotations

import os

import httpx
from mcphub_sdk import PlatformMCPServer, credential, identity

SERVER_NAME = os.environ.get("SERVER_NAME", "test-api-mcp")
READ_BASE = os.environ.get("POLICY_API_READ_URL", "http://127.0.0.1:9191").rstrip("/")
RW_BASE = os.environ.get("POLICY_API_RW_URL", "http://127.0.0.1:9292").rstrip("/")

srv = PlatformMCPServer(SERVER_NAME, require_proxy=True)


@srv.tool()
async def list_policies() -> dict:
    """List all mock company security policies. No credential required."""
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"{READ_BASE}/policies")
        resp.raise_for_status()
        return resp.json()


@srv.tool()
async def search_policies(type: str = "", department: str = "", q: str = "") -> dict:
    """Search policies by type, department, or free-text query. No credential required."""
    params = {k: v for k, v in {"type": type, "department": department, "q": q}.items() if v}
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"{READ_BASE}/policies", params=params)
        resp.raise_for_status()
        return resp.json()


@srv.tool()
async def get_policy(policy_id: str) -> dict:
    """Return one policy document by id. No credential required."""
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(f"{READ_BASE}/policies/{policy_id}")
        resp.raise_for_status()
        return resp.json()


@srv.tool()
async def add_policy_line(policy_id: str, text: str) -> dict:
    """
    Append a line to a policy document. Requires a broker-injected Basic
    credential (injection_mode=basic_auth) — forwarded verbatim as the
    upstream Authorization header. Fails closed with no fallback if the
    gateway injected nothing.
    """
    token = credential()  # full injected header value, e.g. "Basic <base64>" (echo-basic's
    # whoami confirmed the SDK does NOT strip the scheme prefix — see mcp-gateway-tool-
    # exercise-log-2026-07-14.md, credential_preview: "Basic bG...cmV0")
    if not token:
        return {
            "error": "no credential injected — this tool requires basic_auth mode",
            "caller": identity().sub,
        }
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.post(
            f"{RW_BASE}/policies/{policy_id}/lines",
            json={"text": text},
            headers={"Authorization": token},
        )
        return {"status_code": resp.status_code, "body": resp.json() if resp.content else None}


@srv.tool()
async def add_policy_line_secure(policy_id: str, text: str) -> dict:
    """
    Identical to add_policy_line — a distinctly-named twin so this tool can be
    discovered under a SECOND server registration (test-api-basicauth) without
    colliding with the first (test-api-noauth)'s already-claimed tool names.
    Tool names are globally unique platform-wide (MCP-005 name-collision
    quarantine) — registering the same upstream twice under two injection
    modes only works for the names that differ between registrations.
    Requires a broker-injected Basic credential (injection_mode=basic_auth).
    """
    return await add_policy_line(policy_id, text)


if __name__ == "__main__":
    srv.run()
