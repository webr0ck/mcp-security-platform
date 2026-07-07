"""
CR-06 (WP-B3 phase 6) — machine-testable subset of the MCP server
compatibility contract.

Validates the SHAPE of a live server's `initialize` and `tools/list`
JSON-RPC responses against docs/reference/mcp-server-contract.schema.json
(a direct transcription of the compatibility contract doc sec 2 — nothing
invented beyond what that doc already specifies), plus a plain `GET
/health` reachability check.

This is deliberately narrow: it validates response SHAPE, not runtime
correctness. A safe representative `tools/call` smoke-invocation remains
roadmap (contract doc sec 8) — this module does not attempt one.

Called from both deploy_verifier.verify_server (Task 5) and
submission.py's shared _run_verification_probes-equivalent path (Task 6)
so both the platform-managed and self-hosted flows get the identical
contract check.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urljoin

import httpx
import jsonschema

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "docs" / "reference" / "mcp-server-contract.schema.json"
_PROBE_TIMEOUT_SECONDS = 10

_schema_cache: dict | None = None


def _load_schema() -> dict:
    global _schema_cache
    if _schema_cache is None:
        with open(_SCHEMA_PATH) as f:
            _schema_cache = json.load(f)
    return _schema_cache


def _extract_jsonrpc_result(resp: httpx.Response) -> dict:
    """Handle the same dual JSON/SSE response format
    app.routers.tools._run_tool_discovery already accounts for — an MCP
    streamable-HTTP server may answer as a plain JSON body or as a single
    SSE 'data:' frame."""
    if "text/event-stream" in resp.headers.get("content-type", ""):
        for line in resp.text.splitlines():
            if line.startswith("data:"):
                body = json.loads(line[5:].strip())
                break
        else:
            raise ValueError("SSE response contained no data frame")
    else:
        body = resp.json()
    if "error" in body:
        raise ValueError(f"JSON-RPC error: {body['error']}")
    return body.get("result", body)


async def run_contract_check(runtime_url: str) -> dict:
    """
    Returns {"initialize_ok": bool, "tools_list_ok": bool, "health_ok": bool,
    "violations": list[str]} — never raises; every failure mode is recorded
    as a violation string instead of propagating, since a contract-check
    failure is diagnostic information for the caller's verification_report,
    not a crash.
    """
    schema = _load_schema()
    violations: list[str] = []
    health_ok = False
    initialize_ok = False
    tools_list_ok = False

    health_url = urljoin(runtime_url, "/health")
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(health_url, timeout=_PROBE_TIMEOUT_SECONDS)
            health_ok = 200 <= resp.status_code < 300
            if not health_ok:
                violations.append(f"GET /health returned {resp.status_code}, expected 2xx")
    except httpx.HTTPError as exc:
        violations.append(f"GET /health failed: {exc}")

    headers = {"Accept": "application/json, text/event-stream"}
    init_payload = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                  "clientInfo": {"name": "mcp-security-platform-contract-check", "version": "1.0.0"}},
    }
    session_id: str | None = None
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(runtime_url, json=init_payload, headers=headers, timeout=_PROBE_TIMEOUT_SECONDS)
            resp.raise_for_status()
            session_id = resp.headers.get("Mcp-Session-Id")
            result = _extract_jsonrpc_result(resp)
            jsonschema.validate(instance=result, schema=schema["definitions"]["initializeResult"])
            initialize_ok = True
    except jsonschema.ValidationError as exc:
        violations.append(f"initialize response violates contract schema: {exc.message}")
    except (httpx.HTTPError, ValueError) as exc:
        violations.append(f"initialize probe failed: {exc}")

    tools_headers = dict(headers)
    if session_id:
        tools_headers["Mcp-Session-Id"] = session_id
    tools_payload = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(runtime_url, json=tools_payload, headers=tools_headers, timeout=_PROBE_TIMEOUT_SECONDS)
            resp.raise_for_status()
            result = _extract_jsonrpc_result(resp)
            jsonschema.validate(instance=result, schema=schema["definitions"]["toolsListResult"])
            tools_list_ok = True
    except jsonschema.ValidationError as exc:
        violations.append(f"tools/list response violates contract schema: {exc.message}")
    except (httpx.HTTPError, ValueError) as exc:
        violations.append(f"tools/list probe failed: {exc}")

    return {
        "initialize_ok": initialize_ok,
        "tools_list_ok": tools_list_ok,
        "health_ok": health_ok,
        "violations": violations,
    }
