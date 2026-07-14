#!/usr/bin/env python3
"""
health_check_servers.py — functional health check for every approved MCP server.

Motivation (2026-07-14): container-level healthchecks (the ones already defined
in podman-compose.lab.yml) only prove the process is up and answering `/mcp`
initialize/tools/list — they do NOT catch a tool that is registered, discovered,
active, and "healthy" by every container-level signal, but broken the moment
it's actually called. Both real bugs found in this session were exactly that
shape:
  - m365-graph: container healthy, tools/list fine, every real tools/call
    failed with a URL-construction bug (env-var fallback gotcha).
  - echo whoami: container healthy, tools/list fine, the WAF blocked this one
    specific tool NAME on any real invocation.

This script does what the container healthchecks structurally cannot: it
actually CALLS a real tool on every approved server (not just tools/list) and
reports which ones fail, closing exactly the gap that let both bugs go
undetected until manual testing found them.

Two check depths per server:
  - DEEP  : a tool with an empty required-args schema exists on this server —
            actually call it (tools/call) and require isError=false / no
            JSON-RPC error. This is the check that would have caught both
            2026-07-14 bugs.
  - SHALLOW: every tool on this server requires arguments the script cannot
            safely guess — falls back to tools/list only (proves the
            transport/auth layer is alive, but NOT that any individual tool
            actually works). Flagged distinctly in the report so a shallow
            "pass" is never confused with a deep one.

SCOPE LIMITATION (confirmed by running this against the live lab, 2026-07-14):
this script calls each server's `upstream_url` DIRECTLY (the same approach
discover_tools() uses), not through the real gateway's credential-injection
broker. That's correct for injection_mode=none tools (catfacts, gitea, notes,
search, test-api-noauth/basicauth all deep-passed for real) but means any
tool requiring broker-injected credentials (entra_client_credentials,
entra_user_token, user mode, etc.) will ALWAYS report a false failure here —
"no credential injected" is expected in that path, not a regression. A
report entry citing a credential-injection error is not actionable; one
citing an HTTP-transport error (401/404/307/connection-refused on the
tools/list handshake itself, before any credential would even be needed) is.
Distinguishing the two in the report is left as follow-up work — for now,
read the `detail` field before treating any FAIL as real.

Usage:
    ADMIN_TOKEN=... python3 scripts/health_check_servers.py [--base-url URL] [--json]

Exit code: 0 if every server passed its available check depth, 1 otherwise —
wire this into cron/LaunchAgent/CI the same way as the other check_*.py/sh
scripts in this directory; this script does not schedule itself.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class ServerResult:
    server_id: str
    name: str
    upstream_url: str
    depth: str = "unchecked"   # "deep" | "shallow" | "unchecked"
    ok: bool = False
    detail: str = ""
    latency_ms: float = 0.0
    tools_seen: list[str] = field(default_factory=list)


async def _mcp_call(
    client: httpx.AsyncClient, upstream_url: str, method: str, params: dict, session_id: str | None = None
) -> tuple[dict, str | None]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-User-Sub": "system:health-check",
        "X-User-Role": "admin",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = await client.post(
        upstream_url,
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
        headers=headers,
        timeout=10.0,
    )
    resp.raise_for_status()
    new_session = resp.headers.get("Mcp-Session-Id")
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip()), new_session
        raise ValueError("SSE response contained no data frame")
    return resp.json(), new_session


async def check_one_server(client: httpx.AsyncClient, server_id: str, name: str, upstream_url: str) -> ServerResult:
    result = ServerResult(server_id=server_id, name=name, upstream_url=upstream_url)
    t0 = time.monotonic()
    try:
        init_body, session_id = await _mcp_call(
            client, upstream_url, "initialize",
            {"protocolVersion": "2024-11-05", "capabilities": {},
             "clientInfo": {"name": "health-check", "version": "1.0"}},
        )
        if "error" in init_body:
            result.detail = f"initialize error: {init_body['error']}"
            return result

        list_body, _ = await _mcp_call(client, upstream_url, "tools/list", {}, session_id)
        tools = list_body.get("result", {}).get("tools", [])
        result.tools_seen = [t.get("name", "?") for t in tools]

        # Find a tool with no required args — the DEEP check target.
        canary = next(
            (t for t in tools if not (t.get("inputSchema", {}) or {}).get("required")),
            None,
        )
        if canary is None:
            result.depth = "shallow"
            result.ok = True
            result.detail = "tools/list only — every tool on this server requires arguments; no safe canary to call"
            return result

        call_body, _ = await _mcp_call(
            client, upstream_url, "tools/call",
            {"name": canary["name"], "arguments": {}}, session_id,
        )
        result.depth = "deep"
        if "error" in call_body:
            result.detail = f"tools/call '{canary['name']}' returned JSON-RPC error: {call_body['error']}"
            return result
        call_result = call_body.get("result", {})
        if call_result.get("isError"):
            result.detail = f"tools/call '{canary['name']}' returned isError=true: {call_result}"
            return result
        result.ok = True
        result.detail = f"tools/call '{canary['name']}' succeeded"
        return result
    except Exception as exc:  # noqa: BLE001 — report every failure mode, never crash the whole run
        result.detail = f"{type(exc).__name__}: {exc}"
        return result
    finally:
        result.latency_ms = round((time.monotonic() - t0) * 1000, 1)


async def main_async(base_url: str, admin_token: str, as_json: bool) -> int:
    async with httpx.AsyncClient(base_url=base_url, headers={"Authorization": f"Bearer {admin_token}"}) as admin_client:
        resp = await admin_client.get("/api/v1/admin/servers")
        resp.raise_for_status()
        servers = resp.json().get("servers", resp.json() if isinstance(resp.json(), list) else [])

    # Distinct upstream_url — several tool_registry rows / server_registry rows
    # can share one upstream (echo-basic/echo-sa/... all point at lab-mcp-echo);
    # checking the same live server twice adds nothing.
    seen_urls: set[str] = set()
    targets: list[tuple[str, str, str]] = []
    for s in servers:
        if s.get("status") != "approved":
            continue
        url = s.get("upstream_url") or ""
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        targets.append((s.get("server_id", "?"), s.get("name", "?"), url))

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*(check_one_server(client, sid, name, url) for sid, name, url in targets))

    if as_json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        failed = [r for r in results if not r.ok]
        shallow_pass = [r for r in results if r.ok and r.depth == "shallow"]
        deep_pass = [r for r in results if r.ok and r.depth == "deep"]
        print(f"Checked {len(results)} distinct upstream servers "
              f"({len(deep_pass)} deep-pass, {len(shallow_pass)} shallow-pass-only, {len(failed)} FAILED)\n")
        for r in results:
            status = "OK  " if r.ok else "FAIL"
            print(f"[{status}] {r.name:30s} depth={r.depth:8s} {r.latency_ms:>7.1f}ms  {r.detail}")
        if shallow_pass:
            print(f"\n{len(shallow_pass)} server(s) only shallow-checked (every tool needs args — "
                  "add a no-arg canary tool, e.g. a 'ping'/'health' tool, to get deep coverage):")
            for r in shallow_pass:
                print(f"  - {r.name}: {', '.join(r.tools_seen)}")
        if failed:
            print(f"\n{len(failed)} server(s) FAILED:")
            for r in failed:
                print(f"  - {r.name} ({r.upstream_url}): {r.detail}")

    return 1 if any(not r.ok for r in results) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url", default=os.environ.get("PROXY_BASE_URL", "http://localhost:8000"))
    parser.add_argument("--admin-token", default=os.environ.get("ADMIN_TOKEN", ""))
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if not args.admin_token:
        print("ADMIN_TOKEN env var (or --admin-token) is required.", file=sys.stderr)
        return 2

    return asyncio.run(main_async(args.base_url, args.admin_token, args.json))


if __name__ == "__main__":
    sys.exit(main())
