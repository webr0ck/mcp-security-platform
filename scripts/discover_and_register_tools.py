#!/usr/bin/env python3
"""
discover_and_register_tools.py
================================
Discovers real tools from each running lab MCP server via the MCP
tools/list JSON-RPC call, then upserts them into tool_registry.

Connects directly to the exposed Postgres port (127.0.0.1:5434) — no
proxy auth needed.  Run on the host after `docker-compose up -d`.

Usage:
  python3 scripts/discover_and_register_tools.py            # upsert all
  python3 scripts/discover_and_register_tools.py --dry-run  # print only
  python3 scripts/discover_and_register_tools.py --server lab-echo  # one server
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from typing import Any

import requests

import subprocess

# ---------------------------------------------------------------------------
# Server catalogue
# ---------------------------------------------------------------------------
# host_port:    port reachable from the Mac (podman-compose.lab.yml port mapping)
# internal_url: URL the proxy uses inside the container network (upstream_url in DB)
# injection_mode / service_name / inject_header / inject_prefix: credential config
# ---------------------------------------------------------------------------
SERVERS: list[dict[str, Any]] = [
    {
        "key": "lab-grafana",
        "host_port": 8100,
        "internal_url": "http://lab-mcp-grafana:8000/mcp",
        "injection_mode": "service",
        "service_name": "grafana",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer ",
        "risk_level": "low",
        "risk_score": 10,
        "tags": ["grafana", "observability", "lab"],
    },
    {
        "key": "lab-netbox",
        "host_port": 8101,
        "internal_url": "http://mcp-netbox:8000/mcp",
        "injection_mode": "service",
        "service_name": "netbox",
        "inject_header": "Authorization",
        "inject_prefix": "Token ",
        "risk_level": "low",
        "risk_score": 10,
        "tags": ["netbox", "dcim", "lab"],
    },
    {
        "key": "lab-gitea",
        "host_port": 8102,
        "internal_url": "http://lab-mcp-gitea:8000/mcp",
        "injection_mode": "service",
        "service_name": "gitea",
        "inject_header": "Authorization",
        "inject_prefix": "token ",
        "risk_level": "low",
        "risk_score": 10,
        "tags": ["gitea", "scm", "lab"],
    },
    {
        "key": "lab-m365",
        "host_port": 8103,
        "internal_url": "http://lab-mcp-m365:8000/mcp",
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "medium",
        "risk_score": 35,
        "tags": ["m365", "microsoft", "lab"],
    },
    {
        "key": "lab-rag-assistant",
        "host_port": 8104,
        "internal_url": "http://lab-rag-assistant:8000/mcp",
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "medium",
        "risk_score": 30,
        "tags": ["rag", "docs", "lab"],
    },
    {
        "key": "lab-echo",
        "host_port": 8105,
        "internal_url": "http://lab-mcp-echo:8000/mcp",
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "low",
        "risk_score": 5,
        "tags": ["echo", "testing", "lab"],
    },
    {
        "key": "lab-notes",
        "host_port": 8106,
        "internal_url": "http://lab-mcp-notes:8000/mcp",
        # X-User-Sub comes from forward_base_headers in invocation.py — broker not involved
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "low",
        "risk_score": 15,
        "tags": ["notes", "per-user", "lab"],
    },
    {
        "key": "lab-search",
        "host_port": 8107,
        "internal_url": "http://lab-mcp-search:8000/mcp",
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "low",
        "risk_score": 10,
        "tags": ["search", "kb", "lab"],
    },
    {
        "key": "lab-self-service",
        "host_port": 8108,
        "internal_url": "http://lab-mcp-self-service:8000/mcp",
        # X-User-Sub + X-User-Role from forward_base_headers
        "injection_mode": "none",
        "service_name": None,
        "inject_header": None,
        "inject_prefix": None,
        "risk_level": "low",
        "risk_score": 10,
        "tags": ["self-service", "rbac", "lab"],
    },
]

# ---------------------------------------------------------------------------
# DB helper — runs SQL via `docker exec mcp-db psql` (no host psycopg2 needed)
# ---------------------------------------------------------------------------
DOCKER_HOST = subprocess.run(
    ["podman", "machine", "inspect", "--format", "unix://{{.ConnectionInfo.PodmanSocket.Path}}"],
    capture_output=True, text=True,
).stdout.strip()

PSQL_ENV = {**__import__("os").environ, "DOCKER_HOST": DOCKER_HOST} if DOCKER_HOST else None


# ---------------------------------------------------------------------------
# MCP discovery helpers
# ---------------------------------------------------------------------------

def _mcp_request(session: requests.Session, base_url: str, payload: dict,
                 session_id: str | None = None,
                 timeout: int = 10) -> tuple[dict, str | None]:
    """
    Send one MCP JSON-RPC request.
    Returns (parsed_body, mcp_session_id_from_response_header).
    Mcp-Session-Id comes from the response header (FastMCP), not the body.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        # No Host override — discovery runs from the host against localhost:PORT
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = session.post(base_url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()

    returned_session_id = resp.headers.get("Mcp-Session-Id")

    # Streamable HTTP may return SSE — extract the first data: line
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:"):].strip()), returned_session_id
        raise ValueError("SSE response had no data: line")
    return resp.json(), returned_session_id


def discover_tools(host_port: int, server_key: str) -> list[dict] | None:
    """
    Run MCP initialize → tools/list against localhost:<host_port>.
    Returns list of tool dicts from the MCP server, or None if unreachable.
    """
    base_url = f"http://localhost:{host_port}/mcp"
    s = requests.Session()

    # Step 1: initialize — Mcp-Session-Id returned in response header by FastMCP
    try:
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "discover_and_register_tools", "version": "1.0.0"},
            },
        }
        _, session_id = _mcp_request(s, base_url, init_payload, timeout=8)
    except Exception as exc:
        print(f"  [SKIP] {server_key}: not reachable at :{host_port} — {exc}")
        return None

    # Step 2: tools/list — must include session ID from initialize response
    try:
        list_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        list_resp, _ = _mcp_request(s, base_url, list_payload, session_id=session_id, timeout=10)
    except Exception as exc:
        print(f"  [SKIP] {server_key}: tools/list failed — {exc}")
        return None

    result = list_resp.get("result", {})
    tools = result.get("tools", [])
    print(f"  [OK]   {server_key}: found {len(tools)} tools at :{host_port}")
    return tools


# ---------------------------------------------------------------------------
# DB upsert — generates SQL executed via docker exec mcp-db psql
# ---------------------------------------------------------------------------

def _sql_str(v: str | None) -> str:
    """Escape a string for SQL (single-quote with doubling of internal quotes)."""
    if v is None:
        return "NULL"
    return "'" + v.replace("'", "''") + "'"


def _sql_array(items: list[str]) -> str:
    escaped = ", ".join("'" + t.replace("'", "''") + "'" for t in items)
    return f"ARRAY[{escaped}]::text[]"


def tool_upsert_sql(tool: dict, server: dict) -> str:
    """Generate idempotent SQL for one tool (INSERT ... ON CONFLICT UPDATE)."""
    name = tool["name"]
    version = "1.0.0"
    description = (tool.get("description") or f"{name} tool from {server['key']}").replace("'", "''")
    schema_json = json.dumps(tool.get("inputSchema") or {"type": "object", "properties": {}}).replace("'", "''")
    upstream_url = server["internal_url"]
    injection_mode = server["injection_mode"]
    service_name = server["service_name"]
    inject_header = server["inject_header"]
    inject_prefix = server["inject_prefix"]
    risk_level = server["risk_level"]
    risk_score = server["risk_score"]
    tags = server["tags"] + [name]

    return f"""
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, upstream_url,
    status, risk_level, risk_score, risk_reasons,
    injection_mode, service_name, inject_header, inject_prefix,
    tags, metadata, registered_by, created_at, updated_at
) VALUES (
    gen_random_uuid(), {_sql_str(name)}, {_sql_str(version)},
    '{description}', '{schema_json}'::jsonb, {_sql_str(upstream_url)},
    'active', {_sql_str(risk_level)}, {risk_score}, '[]'::jsonb,
    {_sql_str(injection_mode)}, {_sql_str(service_name)},
    {_sql_str(inject_header)}, {_sql_str(inject_prefix)},
    {_sql_array(tags)}, '{{}}'::jsonb, 'discover-script', NOW(), NOW()
)
ON CONFLICT (name, version) DO UPDATE SET
    description    = EXCLUDED.description,
    schema         = EXCLUDED.schema,
    upstream_url   = EXCLUDED.upstream_url,
    injection_mode = EXCLUDED.injection_mode,
    service_name   = EXCLUDED.service_name,
    inject_header  = EXCLUDED.inject_header,
    inject_prefix  = EXCLUDED.inject_prefix,
    tags           = EXCLUDED.tags,
    updated_at     = NOW();"""


def run_sql(sql: str) -> tuple[bool, str]:
    """Execute SQL inside mcp-db via docker exec psql. Returns (ok, output)."""
    cmd = [
        "docker", "exec", "-i", "mcp-db",
        "psql", "-U", "mcp_app", "-d", "mcp_security", "-v", "ON_ERROR_STOP=1",
    ]
    result = subprocess.run(
        cmd, input=sql, capture_output=True, text=True, env=PSQL_ENV, timeout=30,
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be done without writing to DB")
    parser.add_argument("--server", metavar="KEY",
                        help="Process only this server (e.g. lab-echo)")
    args = parser.parse_args()

    servers = SERVERS
    if args.server:
        servers = [s for s in SERVERS if s["key"] == args.server]
        if not servers:
            print(f"ERROR: unknown server key '{args.server}'")
            print("Valid keys:", ", ".join(s["key"] for s in SERVERS))
            sys.exit(1)

    print(f"{'[DRY RUN] ' if args.dry_run else ''}Discovering tools from {len(servers)} lab server(s)...\n")

    # Gather all tools first (no DB connection needed for discovery)
    discovered: list[tuple[dict, list[dict]]] = []
    for server in servers:
        tools = discover_tools(server["host_port"], server["key"])
        if tools is not None:
            discovered.append((server, tools))

    if not discovered:
        print("\nNo servers were reachable. Is the lab running?")
        print("  export DOCKER_HOST=$(podman machine inspect --format "
              "'unix://{{.ConnectionInfo.PodmanSocket.Path}}')")
        print("  docker-compose --env-file .env.lab -f docker-compose.yml "
              "-f docker-compose.dev.yml -f podman-compose.lab.yml up -d")
        sys.exit(0)

    total_ok = total_skipped = 0

    if args.dry_run:
        print("\n--- Dry-run results ---")
        for server, tools in discovered:
            print(f"\n{server['key']} ({len(tools)} tools):")
            for tool in tools:
                print(f"    {tool['name']}@1.0.0 → {server['internal_url']} "
                      f"(injection_mode={server['injection_mode']})")
        print(f"\nWould process {sum(len(t) for _, t in discovered)} tools across "
              f"{len(discovered)} server(s). Re-run without --dry-run to apply.")
        return

    print("\n--- Upserting tools via docker exec mcp-db psql ---")
    for server, tools in discovered:
        print(f"\n{server['key']}:")
        for tool in tools:
            sql = tool_upsert_sql(tool, server)
            ok, output = run_sql(sql)
            if ok:
                total_ok += 1
                action = "UPDATE" if "UPDATE" in output else "INSERT"
                print(f"  {'~' if action == 'UPDATE' else '+'} {tool['name']}@1.0.0")
            else:
                total_skipped += 1
                print(f"  ! {tool['name']}: ERROR — {output[:120]}")

    # Patch legacy rows: any tool_registry row whose injection_mode is still
    # 'none' but has a service_name or approach-B credential_approach should
    # be upgraded so the broker can inject credentials.
    print("\n--- Patching legacy rows with wrong injection_mode ---")
    patch_sql = """
UPDATE tool_registry SET
    injection_mode = CASE
        WHEN service_name IS NOT NULL
             AND (credential_approach = 'B' OR inject_header IS NOT NULL)
             THEN 'service'::injection_mode_enum
        WHEN credential_approach = 'A'
             THEN 'user'::injection_mode_enum
        ELSE injection_mode
    END,
    updated_at = NOW()
WHERE injection_mode = 'none'
  AND deleted_at IS NULL
  AND (service_name IS NOT NULL OR credential_approach IS NOT NULL);
"""
    ok, output = run_sql(patch_sql)
    print(f"  {'OK' if ok else 'ERROR'}: {output or 'no legacy rows'}")

    print(f"\n{'='*50}")
    print(f"Done.  ok={total_ok}  errors={total_skipped}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
