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

try:
    import psycopg2
    import psycopg2.extras
    _HAS_PSYCOPG2 = True
except ImportError:
    _HAS_PSYCOPG2 = False

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
# DB connection (host-exposed port)
# ---------------------------------------------------------------------------
DB_DSN = "host=127.0.0.1 port=5434 dbname=mcp_security user=mcp_app password=devpassword"


# ---------------------------------------------------------------------------
# MCP discovery helpers
# ---------------------------------------------------------------------------

def _mcp_request(session: requests.Session, base_url: str, payload: dict,
                 session_id: str | None = None, timeout: int = 10) -> dict:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Host": "localhost",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    resp = session.post(base_url, json=payload, headers=headers, timeout=timeout)
    resp.raise_for_status()

    # Streamable HTTP may return SSE — extract the first data: line
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[len("data:"):].strip())
        raise ValueError("SSE response had no data: line")
    return resp.json()


def discover_tools(host_port: int, server_key: str) -> list[dict] | None:
    """
    Run MCP initialize → tools/list against localhost:<host_port>.
    Returns list of tool dicts from the MCP server, or None if unreachable.
    """
    base_url = f"http://localhost:{host_port}/mcp"
    s = requests.Session()

    # Step 1: initialize
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
        init_resp = _mcp_request(s, base_url, init_payload, timeout=5)
    except Exception as exc:
        print(f"  [SKIP] {server_key}: not reachable at :{host_port} — {exc}")
        return None

    session_id = None
    # Some FastMCP versions return session ID in the response body
    if isinstance(init_resp.get("result"), dict):
        session_id = init_resp["result"].get("sessionId")

    # Step 2: tools/list
    try:
        list_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        list_resp = _mcp_request(s, base_url, list_payload, session_id=session_id, timeout=10)
    except Exception as exc:
        print(f"  [SKIP] {server_key}: tools/list failed — {exc}")
        return None

    result = list_resp.get("result", {})
    tools = result.get("tools", [])
    print(f"  [OK]   {server_key}: found {len(tools)} tools at :{host_port}")
    return tools


# ---------------------------------------------------------------------------
# DB upsert
# ---------------------------------------------------------------------------

def upsert_tool(cur, tool: dict, server: dict, dry_run: bool) -> str:
    """
    Upsert a single tool into tool_registry.
    Returns 'inserted', 'updated', or 'dry-run'.
    """
    name = tool["name"]
    version = "1.0.0"
    description = tool.get("description") or f"{name} tool from {server['key']}"
    schema = tool.get("inputSchema") or {"type": "object", "properties": {}}
    upstream_url = server["internal_url"]
    injection_mode = server["injection_mode"]
    service_name = server["service_name"]
    inject_header = server["inject_header"]
    inject_prefix = server["inject_prefix"]
    risk_level = server["risk_level"]
    risk_score = server["risk_score"]
    tags = server["tags"] + [name]

    if dry_run:
        print(f"    [dry-run] would upsert: {name}@{version} → {upstream_url} "
              f"(injection_mode={injection_mode})")
        return "dry-run"

    # Check if already exists
    cur.execute(
        "SELECT tool_id FROM tool_registry WHERE name = %s AND version = %s AND deleted_at IS NULL",
        (name, version),
    )
    row = cur.fetchone()

    if row:
        cur.execute(
            """
            UPDATE tool_registry SET
                description    = %s,
                schema         = %s,
                upstream_url   = %s,
                injection_mode = %s,
                service_name   = %s,
                inject_header  = %s,
                inject_prefix  = %s,
                tags           = %s,
                updated_at     = NOW()
            WHERE tool_id = %s
            """,
            (
                description, json.dumps(schema), upstream_url,
                injection_mode, service_name, inject_header, inject_prefix,
                tags, row[0],
            ),
        )
        return "updated"
    else:
        cur.execute(
            """
            INSERT INTO tool_registry (
                tool_id, name, version, description, schema, upstream_url,
                status, risk_level, risk_score, risk_reasons,
                injection_mode, service_name, inject_header, inject_prefix,
                tags, metadata, registered_by, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s,
                'active', %s, %s, '[]'::jsonb,
                %s, %s, %s, %s,
                %s, '{}'::jsonb, 'discover-script', NOW(), NOW()
            )
            """,
            (
                str(uuid.uuid4()), name, version, description, json.dumps(schema), upstream_url,
                risk_level, risk_score,
                injection_mode, service_name, inject_header, inject_prefix,
                tags,
            ),
        )
        return "inserted"


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

    if not _HAS_PSYCOPG2 and not args.dry_run:
        print("ERROR: psycopg2 not installed. Run: pip install psycopg2-binary")
        sys.exit(1)

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

    total_inserted = total_updated = total_skipped = 0

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

    # Write to DB
    try:
        conn = psycopg2.connect(DB_DSN)
        conn.autocommit = False
    except Exception as exc:
        print(f"\nERROR: cannot connect to DB at 127.0.0.1:5434 — {exc}")
        print("Is the lab DB running? Check: docker ps | grep mcp-db")
        sys.exit(1)

    print("\n--- Upserting tools ---")
    try:
        with conn.cursor() as cur:
            for server, tools in discovered:
                print(f"\n{server['key']}:")
                for tool in tools:
                    try:
                        action = upsert_tool(cur, tool, server, dry_run=False)
                        if action == "inserted":
                            total_inserted += 1
                            print(f"  + {tool['name']}@1.0.0")
                        elif action == "updated":
                            total_updated += 1
                            print(f"  ~ {tool['name']}@1.0.0 (updated)")
                    except Exception as exc:
                        total_skipped += 1
                        print(f"  ! {tool['name']}: ERROR — {exc}")
                        conn.rollback()
                        conn.autocommit = False
        conn.commit()
    finally:
        conn.close()

    # Patch existing rows that still have injection_mode='none' because they were
    # inserted before V010 set the default — covers any rows tools.sql left behind.
    print("\n--- Patching pre-V010 rows with injection_mode='none' ───────────")
    try:
        conn2 = psycopg2.connect(DB_DSN)
        with conn2.cursor() as cur:
            cur.execute(
                """
                UPDATE tool_registry SET
                    injection_mode = CASE
                        WHEN service_name IS NOT NULL AND (credential_approach = 'B' OR inject_header IS NOT NULL)
                             THEN 'service'::injection_mode_enum
                        WHEN credential_approach = 'A'
                             THEN 'user'::injection_mode_enum
                        ELSE injection_mode
                    END,
                    updated_at = NOW()
                WHERE injection_mode = 'none'
                  AND deleted_at IS NULL
                  AND (service_name IS NOT NULL OR credential_approach IS NOT NULL)
                RETURNING name, injection_mode
                """
            )
            patched = cur.fetchall()
            conn2.commit()
        for name, mode in patched:
            print(f"  patched {name} → injection_mode={mode}")
        if not patched:
            print("  (no rows needed patching)")
    except Exception as exc:
        print(f"  patch query failed (non-fatal): {exc}")
    finally:
        conn2.close()

    print(f"\n{'='*50}")
    print(f"Done.  inserted={total_inserted}  updated={total_updated}  errors={total_skipped}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
