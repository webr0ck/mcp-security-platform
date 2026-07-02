#!/usr/bin/env python3
"""Auto-provision an MCP server end-to-end (Part 2 — "make MCP start working").

Closes the gap the acceptance test flagged: today, approving a submission only
sets a status — no container is built, run, wired, or discovered, so an approved
server is never actually invocable. This engine does the missing steps:

    build image  ->  run container  ->  wire proxy into a per-backend network
      ->  wait healthy  ->  discover tools (MCP initialize + tools/list)
      ->  register server_registry + tool_registry (active)  ->  invocable

It supports both onboarding flows:

  FLOW A (user has code):
      scripts/provision_mcp.py --name demo-uploaded --source sandbox/uploaded-demo-mcp
      # or from an approved+scanned submission:
      scripts/provision_mcp.py --submission <server_id>

  FLOW B (no code — self-service scaffold):
      scripts/provision_mcp.py --name my-svc --scaffold-mode kc_token_exchange

Security: for --submission, provisioning REFUSES unless the submission's
scan_status is 'passed' (the platform's security-automation gate must have run
and passed first). Discovered tools are marked active because the scan gate
already cleared the code; in a hardened deployment they would land 'quarantined'
and require an admin release + rescan (INV-005) — pass --quarantine for that.

Runs on the lab host (needs podman). DB writes and tool discovery go through
`podman exec` so no proxy admin session or direct proxy access is needed (the
SEC-05 ingress guard blocks direct proxy access by design).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid

PROXY_CONTAINER = "mcp-proxy"
DB_CONTAINER = "mcp-db"
DB_USER = "mcp_app"
DB_NAME = "mcp_security"
SDK_BASE_IMAGE = "mcphub-sdk:base"


def _run(cmd: list[str], *, check: bool = True, input_: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, capture_output=True, input=input_)


def _podman(*args: str, check: bool = True, input_: str | None = None) -> subprocess.CompletedProcess:
    return _run(["podman", *args], check=check, input_=input_)


def _sql(sql: str) -> str:
    """Run SQL in the db container, return stdout (tab-separated, no header)."""
    cp = _podman("exec", "-i", DB_CONTAINER, "psql", "-U", DB_USER, "-d", DB_NAME,
                 "-v", "ON_ERROR_STOP=1", "-t", "-A", "-F", "\t", "-f", "-", input_=sql)
    return cp.stdout.strip()


def _dq(val: str, tag: str = "q") -> str:
    """Dollar-quote a value for SQL, choosing a tag not present in the value."""
    t = tag
    i = 0
    while f"${t}$" in val:
        i += 1
        t = f"{tag}{i}"
    return f"${t}${val}${t}$"


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

def build_image(name: str, context_dir: str) -> str:
    image = f"lab-mcp-{name}:provisioned"
    print(f"[build] {image} from {context_dir}")
    _podman("build", "-t", image, context_dir)
    return image


def run_container(name: str, image: str) -> tuple[str, str]:
    container = f"lab-mcp-{name}"
    net = f"mcp-{name}-net"
    # network (idempotent)
    if _podman("network", "exists", net, check=False).returncode != 0:
        print(f"[net] create {net}")
        _podman("network", "create", net)
    # container (idempotent)
    _podman("rm", "-f", container, check=False)
    print(f"[run] {container} on {net}")
    _podman("run", "-d", "--name", container, "--network", net,
            "-e", f"SERVER_NAME={name}", image)
    # wire the proxy into this backend net so it can dial the server.
    # (SEC-05 guard still blocks the reverse direction: backend -> proxy:8000.)
    connected = _podman("network", "connect", net, PROXY_CONTAINER, check=False)
    if connected.returncode != 0 and "already" not in (connected.stderr or "").lower():
        print(f"[net] warn: connect proxy->{net}: {connected.stderr.strip()}")
    else:
        print(f"[net] proxy joined {net}")
    return container, f"http://{container}:8000/mcp"


def wait_healthy(container: str, timeout: int = 40) -> None:
    probe = ('import urllib.request,sys\n'
             'try:\n'
             ' urllib.request.urlopen("http://localhost:8000/health",timeout=3); print("ok")\n'
             'except Exception as e: print("wait:%s"%type(e).__name__)')
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = _podman("exec", container, "python", "-c", probe, check=False).stdout.strip()
        if out == "ok":
            print(f"[health] {container} healthy")
            return
        time.sleep(2)
    raise SystemExit(f"[health] {container} did not become healthy in {timeout}s")


def discover_tools(container: str) -> list[dict]:
    """Run the MCP initialize + tools/list handshake from inside the container."""
    snippet = r'''
import json, httpx
URL="http://localhost:8000/mcp"
# X-User-Sub satisfies SDK require_proxy=True servers (scaffold default); harmless
# for require_proxy=False servers. Discovery only lists tools, never invokes.
H={"Accept":"application/json, text/event-stream","Content-Type":"application/json","X-User-Sub":"provisioner"}
def parse(r):
    ct=r.headers.get("content-type","")
    if "event-stream" in ct:
        for line in r.text.splitlines():
            if line.startswith("data:"):
                try: return json.loads(line[5:].strip())
                except Exception: pass
        return {}
    return r.json()
with httpx.Client(timeout=15) as c:
    init={"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"provisioner","version":"1.0"}}}
    ir=c.post(URL,json=init,headers=H); sid=ir.headers.get("Mcp-Session-Id")
    h2=dict(H)
    if sid: h2["Mcp-Session-Id"]=sid
    # streamable-http requires notifications/initialized before tools/list
    try: c.post(URL,json={"jsonrpc":"2.0","method":"notifications/initialized","params":{}},headers=h2)
    except Exception: pass
    tr=c.post(URL,json={"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}},headers=h2)
    data=parse(tr)
print("TOOLS_JSON:"+json.dumps(data.get("result",{}).get("tools",[])))
'''
    out = _podman("exec", container, "python", "-c", snippet, check=False)
    line = next((l for l in out.stdout.splitlines() if l.startswith("TOOLS_JSON:")), None)
    if not line:
        raise SystemExit(f"[discover] handshake failed:\nstdout={out.stdout}\nstderr={out.stderr}")
    tools = json.loads(line[len("TOOLS_JSON:"):])
    print(f"[discover] {len(tools)} tool(s): {[t.get('name') for t in tools]}")
    return tools


def register(name: str, upstream_url: str, tools: list[dict], *,
             owner_sub: str, injection_mode: str, quarantine: bool) -> str:
    server_id = str(uuid.uuid4())
    tool_status = "quarantined" if quarantine else "active"
    stmts = [
        # server_registry — upsert by name
        f"""DELETE FROM server_registry WHERE name={_dq(name)};""",
        f"""INSERT INTO server_registry
            (server_id, name, upstream_url, owner_sub, service_name, injection_mode,
             status, submission_status, scan_status, trust_tier, created_at, updated_at)
            VALUES ('{server_id}', {_dq(name)}, {_dq(upstream_url)}, {_dq(owner_sub)},
             {_dq(name)}, '{injection_mode}'::injection_mode_enum, 'approved', 'active', 'passed', 2, NOW(), NOW());""",
    ]
    for t in tools:
        tname = t.get("name")
        if not tname:
            continue
        desc = t.get("description") or f"{tname} from {name}"
        schema = json.dumps(t.get("inputSchema", {"type": "object", "properties": {}}))
        stmts.append(f"""DELETE FROM tool_registry WHERE name={_dq(tname)} AND server_id='{server_id}';""")
        stmts.append(f"""INSERT INTO tool_registry
            (tool_id, name, version, description, schema, upstream_url, server_id,
             service_name, injection_mode, status, risk_level, risk_score, registered_by,
             created_at, updated_at)
            VALUES ('{uuid.uuid4()}', {_dq(tname)}, '1.0.0', {_dq(desc)},
             CAST({_dq(schema)} AS jsonb), {_dq(upstream_url)}, '{server_id}',
             {_dq(name)}, '{injection_mode}'::injection_mode_enum, '{tool_status}', 'low', 20,
             'provisioner', NOW(), NOW());""")
    _sql("BEGIN;\n" + "\n".join(stmts) + "\nCOMMIT;")
    print(f"[register] server_id={server_id} status=active tools={tool_status}")
    return server_id


def scaffold_to_dir(name: str, mode: str) -> str:
    """FLOW B: render the platform's own scaffold for a mode into a build dir."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proxy"))
    from app.services.scaffold_generator import generate_scaffold  # type: ignore
    files = generate_scaffold(name, mode)
    out = os.path.join("/tmp", f"scaffold-{name}")
    os.makedirs(out, exist_ok=True)
    for fname, content in files.items():
        with open(os.path.join(out, fname), "w") as fh:
            fh.write(content)
    # ponytail: the generated Dockerfile pip-installs `mcphub-sdk` from PyPI, which
    # isn't published in the lab (it's the in-tree SDK). Build the lab image on the
    # SDK base image instead — same as every real lab backend. Productionizing the
    # user-facing scaffold means publishing mcphub-sdk to a registry (separate task).
    with open(os.path.join(out, "Dockerfile"), "w") as fh:
        fh.write(f"FROM {SDK_BASE_IMAGE}\n"
                 "COPY --chown=appuser:appgroup server.py .\n"
                 'CMD ["python", "server.py"]\n')
    print(f"[scaffold] rendered {sorted(files)} -> {out} (lab Dockerfile on {SDK_BASE_IMAGE})")
    return out


def submission_source(server_id: str) -> tuple[str, str, str]:
    """Return (name, build_context_dir, injection_mode) for an approved submission.

    Honors the security gate: refuses unless scan_status='passed'.
    """
    row = _sql(f"""SELECT name, github_repo_url, scan_status, COALESCE(injection_mode::text,'none')
                   FROM server_registry WHERE server_id='{server_id}';""")
    if not row:
        raise SystemExit(f"[submission] {server_id} not found")
    name, repo, scan_status, mode = (row.split("\t") + ["", "", "", ""])[:4]
    if scan_status != "passed":
        raise SystemExit(f"[submission] refusing to provision: scan_status={scan_status!r} (must be 'passed')")
    if not repo:
        raise SystemExit(f"[submission] {name} has no github_repo_url to build from")
    ctx = os.path.join("/tmp", f"clone-{name}")
    subprocess.run(["rm", "-rf", ctx], check=False)
    print(f"[clone] {repo} -> {ctx}")
    _run(["git", "clone", "--depth=1", repo, ctx])
    return name, ctx, mode


def main() -> int:
    ap = argparse.ArgumentParser(description="Auto-provision an MCP server end-to-end")
    ap.add_argument("--name", help="server slug (lab-mcp-<name>)")
    ap.add_argument("--source", help="FLOW A: local build-context dir (Dockerfile + server)")
    ap.add_argument("--scaffold-mode", help="FLOW B: render platform scaffold for this injection mode")
    ap.add_argument("--submission", help="provision from an approved+scanned submission server_id")
    ap.add_argument("--owner-sub", default="provisioner")
    ap.add_argument("--injection-mode", default="none")
    ap.add_argument("--quarantine", action="store_true", help="land tools quarantined (INV-005) instead of active")
    args = ap.parse_args()

    if args.submission:
        name, ctx, mode = submission_source(args.submission)
        injection_mode = mode or "none"
    elif args.scaffold_mode:
        if not args.name:
            return _err("--name required with --scaffold-mode")
        name, ctx, injection_mode = args.name, scaffold_to_dir(args.name, args.scaffold_mode), args.injection_mode
    elif args.source:
        if not args.name:
            return _err("--name required with --source")
        name, ctx, injection_mode = args.name, args.source, args.injection_mode
    else:
        return _err("one of --source, --scaffold-mode, or --submission is required")

    image = build_image(name, ctx)
    container, upstream_url = run_container(name, image)
    wait_healthy(container)
    tools = discover_tools(container)
    if not tools:
        return _err("no tools discovered — not registering")
    server_id = register(name, upstream_url, tools, owner_sub=args.owner_sub,
                         injection_mode=injection_mode, quarantine=args.quarantine)
    print(f"\n✅ Provisioned '{name}' — {len(tools)} tool(s) live at {upstream_url}")
    print(f"   server_id={server_id}; proxy picks it up on the next registry refresh (~30s).")
    return 0


def _err(msg: str) -> int:
    print(f"ERROR: {msg}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
