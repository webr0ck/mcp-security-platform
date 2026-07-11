"""
Shared fixtures/helpers for the acceptance-test layer (lab/tests/acceptance/).

Unlike proxy/tests/{unit,integration,...}, these tests drive the REAL running
lab stack over the network (gateway HTTPS + direct backend URLs), never in-process
ASGI. Reuses the auth/invoke helpers from lab/tests/functional_test.py rather
than reimplementing OIDC token logic.

Network note (SEC-05): the proxy container now rejects any inbound peer that
isn't the gateway or its own loopback (see proxy/app/middleware/ingress.py).
That means the REST tool registry (/api/v1/tools, /api/v1/tools/{id}) is only
reachable two ways: (a) an mTLS client cert through the gateway (the real,
production-shaped path — see lab/tests/mtls_agent_identity.sh), or (b) from
inside the proxy container's own network namespace. This suite uses (b) via
`podman exec mcp-proxy curl ...` for registry lookups — it's a test-harness
convenience for finding tool_ids/health, not a claim about the security
boundary, which AT1's negative cases exercise directly through the gateway.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # lab/tests/
from functional_test import (  # noqa: E402
    _get_user_token as _kc_user_token,
    _get_service_token as _kc_service_token,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# ── Config ───────────────────────────────────────────────────────────────────
BASE_URL = os.environ.get("ACCEPT_BASE_URL", "https://100.119.138.35:8443")
KC_URL = os.environ.get("KC_URL", "http://localhost:8082")
KC_REALM = os.environ.get("KC_REALM", "mcp")
KC_TEST_CLIENT = os.environ.get("KC_TEST_CLIENT", "lab-test")
KC_TEST_SECRET = os.environ.get("KC_TEST_SECRET", "lab-test-secret")
KC_SVC_CLIENT = os.environ.get("KC_SVC_CLIENT", "svc-mcp-agent")
KC_SVC_SECRET = os.environ.get("KC_SVC_SECRET", "svc-mcp-agent-secret")
PROXY_CONTAINER = os.environ.get("PROXY_CONTAINER", "mcp-proxy")
DB_CONTAINER = os.environ.get("DB_CONTAINER", "mcp-db")

RESULTS_DIR = Path(os.environ.get("ACCEPT_RESULTS_DIR", "/tmp/mcp-acceptance-results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("acceptance")
_log_path = RESULTS_DIR / "acceptance.log"
_handler = logging.FileHandler(_log_path)
_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)


def _env_lab(key: str, default: str = "") -> str:
    """Read a single value out of .env.lab without ever echoing it anywhere."""
    path = REPO_ROOT / ".env.lab"
    if not path.is_file():
        return default
    prefix = f"{key}="
    for line in path.read_text().splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    return default


# ── podman exec helpers (container-loopback access, see module docstring) ────

def proxy_exec_json(path: str, token: str | None = None, timeout: int = 20) -> tuple[int, Any]:
    """curl a proxy-local path from inside mcp-proxy's own network namespace."""
    headers = f"-H 'Authorization: Bearer {token}'" if token else ""
    cmd = (
        f"curl -s -o /tmp/_at_resp -w '%{{http_code}}' {headers} "
        f"http://localhost:8000{path}"
    )
    r = subprocess.run(["podman", "exec", PROXY_CONTAINER, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    status = int(r.stdout.strip() or "0")
    body_r = subprocess.run(["podman", "exec", PROXY_CONTAINER, "cat", "/tmp/_at_resp"],
                            capture_output=True, text=True, timeout=timeout)
    try:
        body = json.loads(body_r.stdout) if body_r.stdout.strip() else {}
    except json.JSONDecodeError:
        body = {"_raw": body_r.stdout}
    return status, body


def db_query(sql: str, timeout: int = 20) -> str:
    """Run a SQL statement against the lab DB and return raw stdout (-tAc)."""
    r = subprocess.run(
        ["podman", "exec", "-i", DB_CONTAINER, "psql", "-U", "mcp_app", "-d", "mcp_security", "-tAc", sql],
        capture_output=True, text=True, timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError(f"db_query failed: {r.stderr.strip()}")
    return r.stdout.strip()


def podman_exec(container: str, cmd: list[str], timeout: int = 60, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["podman", "exec", container, *cmd], capture_output=True, text=True,
                          timeout=timeout, **kw)


def container_curl_json(container: str, url: str, headers: dict | None = None,
                        timeout: int = 20) -> tuple[int, Any]:
    """GET a URL from inside `container`'s network namespace (real, direct
    backend network access — used for NetBox/Grafana, whose URLs in .env.lab
    are internal-only container hostnames not reachable from the host)."""
    hdr_args = ""
    for k, v in (headers or {}).items():
        hdr_args += f" -H '{k}: {v}'"
    cmd = f"curl -s -o /tmp/_at_backend_resp -w '%{{http_code}}'{hdr_args} '{url}'"
    r = subprocess.run(["podman", "exec", container, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    status = int(r.stdout.strip() or "0")
    body_r = subprocess.run(["podman", "exec", container, "cat", "/tmp/_at_backend_resp"],
                            capture_output=True, text=True, timeout=timeout)
    try:
        body = json.loads(body_r.stdout) if body_r.stdout.strip() else {}
    except json.JSONDecodeError:
        body = {"_raw": body_r.stdout}
    return status, body


# ── MCP invoke helpers (gateway HTTPS, real network) ─────────────────────────

def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"}


def mcp_session_headers(token: str, timeout: float = 20) -> dict:
    headers = _auth_headers(token)
    init = httpx.post(f"{BASE_URL}/mcp", headers=headers, timeout=timeout, verify=False,
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                         "clientInfo": {"name": "acceptance-test", "version": "1.0"}}})
    sid = init.headers.get("mcp-session-id") or init.headers.get("MCP-Session-Id", "")
    return {**headers, "MCP-Session-Id": sid} if sid else headers


def invoke_upstream(token: str, server_tool_name: str, upstream_method: str, upstream_args: dict,
                    timeout: float = 30) -> dict:
    """Invoke a specific upstream method on a multi-method server tool
    (grafana-query/netbox-query/m365-graph/lab-tickets-query) via the
    invoke_tool platform tool, e.g. upstream_method='tools/call',
    upstream_args={'name': 'query_dashboards', 'arguments': {'search': 'x'}}.
    """
    headers = mcp_session_headers(token, timeout)
    r = httpx.post(f"{BASE_URL}/mcp", headers=headers, timeout=timeout, verify=False,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/call",
              "params": {"name": "invoke_tool",
                         "arguments": {"tool_name": server_tool_name, "method": upstream_method,
                                      "arguments": upstream_args}}})
    return {"status_code": r.status_code, "body": r.json() if r.text else {}}


def invoke_upstream_loopback(token: str, server_tool_name: str, upstream_method: str,
                             upstream_args: dict, timeout: int = 30) -> dict:
    """Same as invoke_upstream but via the proxy container's own loopback
    (see module docstring on SEC-05). Use when the payload itself trips the
    gateway WAF for benign reasons — e.g. an upstream tool literally named
    'whoami' matches the CRS Unix-RCE wordlist (rule 932260) and nginx 403s
    before the proxy ever sees it. Every proxy-side gate (auth, entitlement,
    OPA, credential injection, DNS-rebind) is still fully exercised."""
    body = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "invoke_tool",
                       "arguments": {"tool_name": server_tool_name, "method": upstream_method,
                                     "arguments": upstream_args}}}
    hdrs = (f"-H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' "
            f"-H 'Accept: application/json, text/event-stream'")
    init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                  "clientInfo": {"name": "acceptance-test", "version": "1.0"}}})
    sid_cmd = (f"curl -s -D - -o /dev/null -X POST http://localhost:8000/mcp {hdrs} "
               f"-d '{init}' | grep -i '^mcp-session-id' | tr -d '\\r' | cut -d' ' -f2")
    sid_r = subprocess.run(["podman", "exec", PROXY_CONTAINER, "sh", "-c", sid_cmd],
                           capture_output=True, text=True, timeout=timeout)
    sid = sid_r.stdout.strip()
    sid_hdr = f" -H 'MCP-Session-Id: {sid}'" if sid else ""
    cmd = (f"curl -s -o /tmp/_at_loop_resp -w '%{{http_code}}' -X POST "
           f"http://localhost:8000/mcp {hdrs}{sid_hdr} -d '{json.dumps(body)}'")
    r = subprocess.run(["podman", "exec", PROXY_CONTAINER, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    status = int(r.stdout.strip() or "0")
    body_r = subprocess.run(["podman", "exec", PROXY_CONTAINER, "cat", "/tmp/_at_loop_resp"],
                            capture_output=True, text=True, timeout=timeout)
    try:
        parsed = json.loads(body_r.stdout) if body_r.stdout.strip() else {}
    except json.JSONDecodeError:
        parsed = {"_raw": body_r.stdout}
    return {"status_code": status, "body": parsed}


# Gate-chain failures that still come back as HTTP 200 (see
# lab/tests/functional_test.py's _INVOKE_FAILURE_SENTINELS for the full
# rationale/history) — a bare status/JSON-RPC-error check is blind to these.
_INVOKE_FAILURE_SENTINELS = (
    "tool invocation failed",
    "dns resolution failed",
    "dns-rebind",
    "upstream_revalidation_failed",
    "not entitled",
    "access denied",
    "internal error",
    "unknown tool",
    "unauthorized",
    "downstream authorization required",
    "credential_injection_failed",
    # Enrollment prompts (dispatcher CredentialEnrollmentRequiredError) come back
    # as a friendly HTTP-200 "log in first" message — that is still a failed
    # invocation for acceptance purposes, never a pass.
    "login required",
    "isn't connected yet",
    "\"error\"",
)


def call_upstream_tool(token: str, server_tool_name: str, upstream_tool: str, upstream_args: dict,
                       timeout: float = 30, loopback: bool = False) -> dict:
    """Invoke a named upstream tool (e.g. 'query_dashboards') with arguments
    and return its parsed text content dict. Asserts real end-to-end success —
    inspects the text content for gate-chain failure sentinels rather than
    trusting a bare HTTP 200 / absence of a top-level JSON-RPC error, both of
    which this platform's invoke_tool wrapper returns even when the call
    failed deep in the credential/DNS-rebind/upstream chain.

    loopback=True routes via the proxy container's loopback instead of the
    gateway — see invoke_upstream_loopback for when that is legitimate."""
    invoker = invoke_upstream_loopback if loopback else invoke_upstream
    r = invoker(token, server_tool_name, "tools/call",
                {"name": upstream_tool, "arguments": upstream_args}, timeout)
    assert r["status_code"] == 200, f"{server_tool_name}.{upstream_tool}: HTTP {r['status_code']} {r}"
    body = r["body"]
    assert "error" not in body, f"{server_tool_name}.{upstream_tool}: {body.get('error')}"
    content = (body.get("result") or {}).get("content") or []
    text_blobs = [c.get("text", "") for c in content if c.get("type") == "text"]
    joined = "\n".join(text_blobs)
    lowered = joined.lower()
    for sentinel in _INVOKE_FAILURE_SENTINELS:
        assert sentinel not in lowered, (
            f"{server_tool_name}.{upstream_tool}: gate-chain failure leaked through HTTP 200 "
            f"— matched {sentinel!r} in: {joined[:300]}"
        )
    return _unwrap_mcp_envelope(joined)


def _unwrap_mcp_envelope(text: str, _depth: int = 0) -> Any:
    """The upstream MCP server's own tool-call result usually comes back as
    another {"content": [{"type": "text", "text": "<json-or-plain-text>"}]}
    envelope nested inside invoke_tool's envelope (and, for servers that
    themselves speak JSON-RPC, that can nest a further {"jsonrpc","result"}
    layer). Peel every layer until something that isn't one of those two
    wrapper shapes is left."""
    if _depth > 5:
        return {"_raw_text": text}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"_raw_text": text}
    if isinstance(parsed, dict) and isinstance(parsed.get("content"), list):
        blobs = [c.get("text", "") for c in parsed["content"] if c.get("type") == "text"]
        return _unwrap_mcp_envelope("\n".join(blobs), _depth + 1)
    if isinstance(parsed, dict) and "jsonrpc" in parsed and "result" in parsed:
        inner = parsed["result"]
        if isinstance(inner, dict) and isinstance(inner.get("content"), list):
            blobs = [c.get("text", "") for c in inner["content"] if c.get("type") == "text"]
            return _unwrap_mcp_envelope("\n".join(blobs), _depth + 1)
        return inner
    return parsed


# ── Token fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def alice_password() -> str:
    return _env_lab("DEX_ALICE_PASSWORD", "labpassword")


@pytest.fixture(scope="session")
def bob_password() -> str:
    return _env_lab("DEX_BOB_PASSWORD", "labpassword")


@pytest.fixture(scope="session")
def carol_password() -> str:
    return "labpassword"


@pytest.fixture(scope="session")
def alice_token(alice_password) -> str:
    return _kc_user_token("alice", alice_password)


@pytest.fixture(scope="session")
def bob_token(bob_password) -> str:
    return _kc_user_token("bob", bob_password)


@pytest.fixture(scope="session")
def carol_token(carol_password) -> str:
    return _kc_user_token("carol", carol_password)


@pytest.fixture(scope="session")
def service_token() -> str:
    return _kc_service_token()


@pytest.fixture(autouse=True, scope="module")
def _reset_anomaly_limits(alice_token):
    """This suite invokes the same handful of tools many times in a short
    window, which trips the platform's own anomaly_threshold_exceeded OPA
    policy (a real, working control: 'rapid invocations' is >10 calls in a
    30s sliding window, tracked by anomaly:window:{client_id} in Redis) and
    self-denies the very calls we're trying to test.

    Module-scoped, not function-scoped: the reset endpoint itself is rate
    limited to 10 resets per client per 5 minutes (admin_limits.py's
    `_RESET_RL`) specifically to prevent reset-flooding — calling it before
    every individual test (~24 in this suite) trips THAT limiter instead,
    which fails silently because httpx doesn't raise on a non-2xx status
    unless you ask it to. Once per test file keeps each module's own call
    volume (well under 10) from carrying into the next. Best-effort; never
    fails the suite."""
    for client_id in ("alice@corp", "bob@corp", "carol@corp"):
        try:
            httpx.post(f"{BASE_URL}/api/v1/admin/limits/{client_id}/reset",
                      headers=_auth_headers(alice_token), json={"target": "both"},
                      verify=False, timeout=15)
        except httpx.HTTPError:
            pass
    yield


# ── Results collection (per-test outcomes -> results.json) ──────────────────

_results: list[dict] = []


def pytest_configure(config):
    logger.info("=== acceptance run starting: %s ===", time.strftime("%Y-%m-%dT%H:%M:%SZ"))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        _results.append({
            "nodeid": item.nodeid,
            "outcome": rep.outcome,
            "duration": round(rep.duration, 3),
            "when": rep.when,
        })
        logger.info("TEST %s -> %s (%.3fs)", item.nodeid, rep.outcome, rep.duration)


def pytest_sessionfinish(session, exitstatus):
    out_path = RESULTS_DIR / "results.json"
    out_path.write_text(json.dumps({
        "exit_status": exitstatus,
        "tests": _results,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }, indent=2))
    logger.info("=== acceptance run finished: exit=%s tests=%d ===", exitstatus, len(_results))
