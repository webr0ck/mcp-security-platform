"""
Catfacts MCP Server — real, no-auth, live-upstream lab server (T5).

Every other "none" injection_mode server in this lab is a local/mock backend
(echo talks to itself; search/notes are in-memory; rag-assistant serves a
bundled corpus). This server is the missing case: a genuinely external, live,
third-party REST API (https://catfact.ninja) that needs no credential at all
— injection_mode=none is the correct (not a placeholder) choice here, not a
stand-in for something more complex.

Built on the mcphub_sdk PlatformMCPServer, same as echo — identity/credential
context middleware, /health route, DNS-rebind disable, uvicorn loop all
handled by the SDK; this file is pure tool logic.

Egress: routes through lab-egress-proxy (HTTPS_PROXY env, honored by httpx's
default trust_env=True) — same allowlisting pattern already used by
lab-mcp-m365. catfact.ninja must be added to squid.conf's allowlist.

Tools:
  get_fact    — one random cat fact (optionally capped by max_length)
  get_breeds  — a page of cat breed records (paginated upstream API)
"""
from __future__ import annotations

import os

import httpx
from mcphub_sdk import PlatformMCPServer

SERVER_NAME = os.environ.get("SERVER_NAME", "catfacts-mcp")
UPSTREAM_BASE = os.environ.get("CATFACTS_BASE_URL", "https://catfact.ninja").rstrip("/")

srv = PlatformMCPServer(SERVER_NAME)


@srv.tool()
async def get_fact(max_length: int = 0) -> dict:
    """Fetch one random cat fact from the live catfact.ninja API.

    max_length: if > 0, forwarded to the upstream as its own max_length filter
    (upstream retries server-side until it finds a fact that fits).
    """
    params = {}
    if max_length and max_length > 0:
        params["max_length"] = max_length
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{UPSTREAM_BASE}/fact", params=params)
        resp.raise_for_status()
        data = resp.json()
    return {
        "fact": data.get("fact"),
        "length": data.get("length"),
        "server": SERVER_NAME,
        "upstream": UPSTREAM_BASE,
    }


@srv.tool()
async def get_breeds(limit: int = 5) -> dict:
    """Fetch a page of cat breed records from the live catfact.ninja API."""
    limit = max(1, min(limit, 20))  # cap to keep responses small
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{UPSTREAM_BASE}/breeds", params={"limit": limit})
        resp.raise_for_status()
        data = resp.json()
    return {
        "breeds": data.get("data", []),
        "count": len(data.get("data", [])),
        "server": SERVER_NAME,
        "upstream": UPSTREAM_BASE,
    }


if __name__ == "__main__":
    srv.run()
