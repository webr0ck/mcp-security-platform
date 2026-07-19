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
#
# All per-server credential/entitlement/risk config now lives on the existing
# alias row in tool_registry and is INHERITED by per-tool rows via
# per_tool_upsert_sql — it is NOT duplicated here (see Task 3 migration).
# ---------------------------------------------------------------------------
SERVERS: list[dict[str, Any]] = [
    {"key": "lab-grafana", "host_port": 8100, "internal_url": "http://lab-mcp-grafana:8000/mcp"},
    {"key": "lab-netbox", "host_port": 8101, "internal_url": "http://mcp-netbox:8000/mcp"},
    {"key": "lab-gitea", "host_port": 8102, "internal_url": "http://lab-mcp-gitea:8000/mcp"},
    {"key": "lab-m365", "host_port": 8103, "internal_url": "http://lab-mcp-m365:8000/mcp"},
    {"key": "lab-rag-assistant", "host_port": 8104, "internal_url": "http://lab-rag-assistant:8000/mcp"},
    {"key": "lab-echo", "host_port": 8105, "internal_url": "http://lab-mcp-echo:8000/mcp"},
    {"key": "lab-notes", "host_port": 8106, "internal_url": "http://lab-mcp-notes:8000/mcp"},
    {"key": "lab-search", "host_port": 8107, "internal_url": "http://lab-mcp-search:8000/mcp"},
    {"key": "self-service", "host_port": 8108, "internal_url": "http://self-service:8000/mcp"},
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


def status_for_tool(activate: bool) -> str:
    """Routine syncs quarantine new tools (pending review); an operator who has
    reviewed the dry-run passes --activate-discovered to activate this run."""
    return "active" if activate else "quarantined"


def hide_alias_sql(upstream_url: str) -> str:
    """Hide the alias from tools/list WITHOUT changing status or soft-deleting it
    (stays invoke_tool-callable). Deferred: only hides once an ACTIVE per-tool row
    exists, so a server is never left with zero visible tools."""
    return f"""
UPDATE tool_registry
SET metadata = COALESCE(metadata, '{{}}'::jsonb) || jsonb_build_object('hidden', true),
    updated_at = NOW()
WHERE upstream_url = {_sql_str(upstream_url)}
  AND deleted_at IS NULL
  AND COALESCE(metadata->>'kind', '') <> 'per-tool'
  AND EXISTS (
      SELECT 1 FROM tool_registry pt
      WHERE pt.upstream_url = {_sql_str(upstream_url)}
        AND pt.status = 'active' AND pt.deleted_at IS NULL
        AND COALESCE(pt.metadata->>'kind', '') = 'per-tool'
  );"""


def assert_lab_optin() -> None:
    """This script sets status without the SBOM gate, so it is lab-only. Require
    an explicit opt-in env var; the DB target is hardcoded to the mcp-db container
    (run_sql), which is the lab Postgres."""
    import os
    if os.environ.get("LAB_MIGRATION_CONFIRM") != "1":
        sys.exit("REFUSING: set LAB_MIGRATION_CONFIRM=1 to run the lab-only per-tool migration.")


def per_tool_upsert_sql(tool: dict, upstream_url: str, new_tool_status: str) -> str:
    """One per-tool row. name/version/description/schema/status literal; ALL
    per-server config inherited from the alias row (matched by upstream_url) so
    credential/entitlement config never drifts. ON CONFLICT promotes
    quarantined->active on an activate run and never downgrades an active row."""
    name = tool["name"]
    version = "1.0.0"
    description = tool.get("description") or f"{name} ({upstream_url})"
    schema_json = json.dumps(tool.get("inputSchema") or {"type": "object", "properties": {}})
    return f"""
INSERT INTO tool_registry (
    tool_id, name, version, description, schema, status,
    upstream_url, server_id, risk_level, risk_score, risk_reasons,
    injection_mode, service_name, inject_header, inject_prefix,
    credential_id, credential_approach,
    kc_client_id, kc_token_audience, entra_tenant_id, entra_client_id, entra_scope,
    required_integrity, sensitivity_label,
    source_repo, source_commit, tags, metadata, registered_by, created_at, updated_at
)
SELECT
    gen_random_uuid(), {_sql_str(name)}, {_sql_str(version)},
    {_sql_str(description)}, {_sql_str(schema_json)}::jsonb, {_sql_str(new_tool_status)},
    alias.upstream_url, alias.server_id, alias.risk_level, alias.risk_score, '[]'::jsonb,
    alias.injection_mode, alias.service_name, alias.inject_header, alias.inject_prefix,
    alias.credential_id, alias.credential_approach,
    alias.kc_client_id, alias.kc_token_audience, alias.entra_tenant_id, alias.entra_client_id, alias.entra_scope,
    alias.required_integrity, alias.sensitivity_label,
    alias.source_repo, alias.source_commit,
    COALESCE(alias.tags, '{{}}'::text[]) || ARRAY[{_sql_str(name)}]::text[],
    jsonb_build_object('kind', 'per-tool', 'expanded_from', alias.name),
    'per-tool-migration', NOW(), NOW()
FROM tool_registry alias
WHERE alias.upstream_url = {_sql_str(upstream_url)}
  AND alias.deleted_at IS NULL
  AND COALESCE(alias.metadata->>'kind', '') <> 'per-tool'
ORDER BY alias.created_at
LIMIT 1
ON CONFLICT (name, version) DO UPDATE SET
    description    = EXCLUDED.description,
    schema         = EXCLUDED.schema,
    upstream_url   = EXCLUDED.upstream_url,
    server_id      = EXCLUDED.server_id,
    injection_mode = EXCLUDED.injection_mode,
    service_name   = EXCLUDED.service_name,
    inject_header  = EXCLUDED.inject_header,
    inject_prefix  = EXCLUDED.inject_prefix,
    credential_id  = EXCLUDED.credential_id,
    metadata       = EXCLUDED.metadata,
    status         = CASE WHEN EXCLUDED.status = 'active' AND tool_registry.status <> 'deprecated' THEN 'active' ELSE tool_registry.status END,
    updated_at     = NOW();
"""


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
    parser.add_argument("--activate-discovered", action="store_true",
                        help="Activate already-known/discovered tool names (new names otherwise start quarantined)")
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
                      f"(config inherited from alias row)")
        print(f"\nWould process {sum(len(t) for _, t in discovered)} tools across "
              f"{len(discovered)} server(s). Re-run without --dry-run to apply.")
        return

    assert_lab_optin()

    print("\n--- Upserting tools via docker exec mcp-db psql ---")
    for server, tools in discovered:
        url = server["internal_url"]
        # Routine runs insert per-tool rows as 'quarantined', so hide_alias_sql is a
        # no-op until an operator does an --activate-discovered run (which makes a
        # per-tool row 'active').
        st = status_for_tool(args.activate_discovered)
        print(f"\n{server['key']}:")
        for tool in tools:
            ok, output = run_sql(per_tool_upsert_sql(tool, url, st))
            print(f"  {'+' if ok else '!'} {tool['name']}@1.0.0 [{st}]"
                  + ("" if ok else f" ERROR {output[:120]}"))
            total_ok += int(ok); total_skipped += int(not ok)
        if tools:
            ok, output = run_sql(hide_alias_sql(url))   # no-op until an active per-tool row exists
            print(f"  · hide-alias {server['key']}: {'OK' if ok else 'ERROR ' + output[:120]}")
            total_skipped += int(not ok)   # a failed hide counts toward the error tally

    print(f"\n{'='*50}")
    print(f"Done.  ok={total_ok}  errors={total_skipped}")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()
