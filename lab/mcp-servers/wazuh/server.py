"""
Wazuh MCP Server — security event and agent management via Wazuh REST API v4.

Designed to run behind mcp-security-platform proxy.
Auth: Wazuh API JWT — credentials (admin user + password) injected by
      the credential broker (service mode, approach B) as an Authorization
      header on each incoming MCP HTTP request.  The ASGI middleware
      (AuthHeaderMiddleware) reads that header and stores it in
      _request_auth before each tool dispatch.  _get_jwt() checks
      _request_auth first; if empty it falls back to WAZUH_API_PASSWORD
      (must be non-empty or RuntimeError is raised — fail-closed).

Tools:
  wazuh_cluster_health    — cluster status, node list, node health
  wazuh_list_agents       — list monitored agents with OS, version, status
  wazuh_get_agent_detail  — detailed view of one agent including last scan time
  wazuh_list_alerts       — recent manager daemon logs (ossec.log entries by severity)
  wazuh_search_alerts     — free-text search of the manager log buffer
  wazuh_get_rules         — list active detection rules with level filter
  wazuh_list_decoders     — list loaded decoders
  wazuh_run_active_response — trigger an active response on an agent (env-flag gated)

Security design:
  - Wazuh API creds are injected by the broker as the Authorization header
    on the incoming MCP request; captured by AuthHeaderMiddleware → _request_auth.
    WAZUH_API_PASSWORD env fallback is provided for local dev only; the compose
    default is empty string, forcing use of the broker path in production-like runs.
  - agent_id is validated as a numeric string before URL construction (HIGH-2 fix).
  - Active-response arguments are character-allowlisted before forwarding (MEDIUM-1 fix).
  - All Wazuh API calls use VERIFY_SSL env flag (off by default in lab).
  - Active-response tool is guarded by ALLOW_ACTIVE_RESPONSE=false by default;
    returns an error dict rather than raising so INV-001 audit path is preserved.
  - Sensitive fields (passwords, hashes) are stripped from all responses.
"""
from __future__ import annotations

import logging
import os
import re
import time
from contextvars import ContextVar
from typing import Any

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.types import ASGIApp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wazuh-mcp")

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8000"))

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
VERIFY_SSL = os.environ.get("VERIFY_SSL", "false").lower() not in ("0", "false", "no")
ALLOW_ACTIVE_RESPONSE = os.environ.get("ALLOW_ACTIVE_RESPONSE", "false").lower() in (
    "1", "true", "yes", "on",
)
DEFAULT_LIMIT = 25
MAX_LIMIT = 100

if not VERIFY_SSL:
    logger.warning(
        "TLS certificate verification is DISABLED (VERIFY_SSL=false) — lab use only"
    )

# Context var: carries the per-request Authorization header value set by
# AuthHeaderMiddleware. Populated before every tool dispatch; reset after.
_request_auth: ContextVar[str | None] = ContextVar("_request_auth", default=None)

# JWT token cache — reused across requests until near expiry.
_jwt_token: str | None = None
_jwt_expires_at: float = 0.0
_JWT_LIFETIME_SECS = 840  # 900s Wazuh default minus 60s safety margin

# Wazuh agent IDs are zero-padded integers, e.g. "001", "042", "000".
# Reject anything that doesn't match to prevent path traversal (HIGH-2).
_AGENT_ID_RE = re.compile(r"^\d{1,10}$")

# Active-response argument allowlist — alphanumeric plus common safe separators.
_ARG_SAFE_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,128}$")
_MAX_AR_ARGS = 10


# ---------------------------------------------------------------------------
# ASGI middleware — populates _request_auth from incoming Authorization header
# ---------------------------------------------------------------------------

class AuthHeaderMiddleware(BaseHTTPMiddleware):
    """Extract Authorization header from each MCP HTTP request into _request_auth."""

    async def dispatch(self, request: Request, call_next):
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        token = _request_auth.set(auth)
        try:
            response = await call_next(request)
        finally:
            _request_auth.reset(token)
        return response


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_client() -> httpx.Client:
    return httpx.Client(verify=VERIFY_SSL, timeout=15.0)


def _get_jwt(client: httpx.Client) -> str:
    """Return a cached Wazuh JWT, refreshing if near expiry.

    Priority:
    1. Authorization header injected by the credential broker (via _request_auth).
    2. Cached JWT (refreshed from WAZUH_API_PASSWORD on expiry).
    3. Fresh token from WAZUH_API_PASSWORD — raises RuntimeError if empty.
    """
    global _jwt_token, _jwt_expires_at

    injected = _request_auth.get()
    if injected and injected.startswith("Bearer "):
        return injected[len("Bearer "):]

    if _jwt_token and time.monotonic() < _jwt_expires_at:
        return _jwt_token

    password = WAZUH_API_PASSWORD
    if not password:
        raise RuntimeError(
            "WAZUH_API_PASSWORD is empty and no Authorization header was injected. "
            "Configure the credential broker (service mode) or set WAZUH_API_PASSWORD."
        )

    resp = client.get(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, password),
    )
    resp.raise_for_status()
    token = resp.json()["data"]["token"]
    _jwt_token = token
    _jwt_expires_at = time.monotonic() + _JWT_LIFETIME_SECS
    return token


def _api(method: str, path: str, **kwargs: Any) -> Any:
    """Execute one Wazuh API call, returning the parsed JSON body."""
    with _http_client() as client:
        token = _get_jwt(client)
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{WAZUH_API_URL}{path}"
        resp = client.request(method, url, headers=headers, **kwargs)
        resp.raise_for_status()
        return resp.json()


def _validate_agent_id(agent_id: str) -> str | None:
    """Return agent_id if valid numeric string, else None (for caller to reject)."""
    if not _AGENT_ID_RE.match(str(agent_id)):
        return None
    return agent_id


def _strip_sensitive(obj: Any, keys: set[str]) -> Any:
    """Recursively remove sensitive keys from dicts."""
    if isinstance(obj, dict):
        return {k: _strip_sensitive(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [_strip_sensitive(item, keys) for item in obj]
    return obj


_SENSITIVE_KEYS = {"password", "passwd", "secret", "token", "hash", "md5", "sha1", "sha256"}


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP("wazuh-mcp")


@mcp.tool()
def wazuh_cluster_health() -> dict:
    """
    Return Wazuh cluster status, manager version, and node list.

    Returns dict with keys: cluster_enabled, cluster_name, nodes, manager_version, status.
    """
    try:
        cluster = _api("GET", "/cluster/status")
        info = _api("GET", "/manager/info")
        nodes: list[dict] = []
        if cluster.get("data", {}).get("enabled") == "yes":
            node_resp = _api("GET", "/cluster/nodes")
            nodes = node_resp.get("data", {}).get("affected_items", [])
        return {
            "cluster_enabled": cluster.get("data", {}).get("enabled") == "yes",
            "cluster_name": cluster.get("data", {}).get("name", ""),
            "nodes": nodes,
            "manager_version": info.get("data", {}).get("version", ""),
            "status": info.get("data", {}).get("openssl_support", ""),
        }
    except Exception as exc:
        logger.error("wazuh_cluster_health failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_list_agents(
    status: str = "active",
    os_platform: str = "",
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """
    List monitored Wazuh agents.

    Args:
        status: Filter by status — 'active', 'disconnected', 'never_connected', or 'all'.
        os_platform: Optional OS platform filter (e.g. 'linux', 'windows').
        limit: Maximum number of agents to return (1–100).

    Returns dict with keys: total, agents (list of agent summaries).
    """
    limit = max(1, min(limit, MAX_LIMIT))
    params: dict[str, Any] = {"limit": limit}
    if status != "all":
        params["status"] = status
    if os_platform:
        params["os.platform"] = os_platform

    try:
        resp = _api("GET", "/agents", params=params)
        items = resp.get("data", {}).get("affected_items", [])
        safe = _strip_sensitive(items, _SENSITIVE_KEYS)
        return {
            "total": resp.get("data", {}).get("total_affected_items", len(safe)),
            "agents": safe,
        }
    except Exception as exc:
        logger.error("wazuh_list_agents failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_get_agent_detail(agent_id: str) -> dict:
    """
    Return detailed information about a specific Wazuh agent.

    Args:
        agent_id: Wazuh agent ID — numeric string e.g. '001', '042'.

    Returns dict with agent fields: id, name, ip, os, version, status, lastKeepAlive.
    """
    if not _validate_agent_id(agent_id):
        return {"error": f"invalid agent_id {agent_id!r} — must be a numeric string (e.g. '001')"}
    try:
        resp = _api("GET", f"/agents/{agent_id}")
        items = resp.get("data", {}).get("affected_items", [])
        if not items:
            return {"error": f"agent {agent_id!r} not found"}
        return _strip_sensitive(items[0], _SENSITIVE_KEYS)
    except Exception as exc:
        logger.error("wazuh_get_agent_detail failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_list_alerts(
    log_type: str = "all",
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """
    Return recent Wazuh manager daemon log entries (ossec.log).

    Note: this tool returns operational daemon logs from /manager/logs, NOT
    security alert events. Security alerts require the Wazuh indexer (OpenSearch).
    Use wazuh_search_alerts for free-text search of the same log buffer.

    Args:
        log_type: Severity filter — 'all', 'error', 'warning', 'info', 'critical'.
        limit: Maximum number of log entries to return (1–100).

    Returns dict with keys: total, logs (list of manager log entries).
    """
    limit = max(1, min(limit, MAX_LIMIT))
    valid_types = {"all", "error", "warning", "info", "critical"}
    if log_type not in valid_types:
        log_type = "all"
    params: dict[str, Any] = {"type_log": log_type, "limit": limit}

    try:
        resp = _api("GET", "/manager/logs", params=params)
        logs = resp.get("data", {}).get("affected_items", [])
        return {
            "total": resp.get("data", {}).get("total_affected_items", len(logs)),
            "logs": _strip_sensitive(logs, _SENSITIVE_KEYS),
        }
    except Exception as exc:
        logger.error("wazuh_list_alerts failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_search_alerts(
    query: str,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """
    Search the Wazuh manager log buffer using a filter expression.

    Note: this searches manager daemon logs (ossec.log) via the Wazuh q= filter
    language. Full security-event search across all agents requires the Wazuh
    indexer (OpenSearch). Time-window filtering is not available in manager-only
    deployments — this returns the most recent buffer matching the query.

    Args:
        query: Filter expression forwarded as the Wazuh API q= parameter
               (e.g. 'description=SSH'). Max 256 characters.
        limit: Maximum number of matching log entries to return (1–100).

    Returns dict with keys: query, total, logs, note.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    if len(query) > 256:
        return {"error": "query exceeds 256-character limit"}

    try:
        resp = _api(
            "GET", "/manager/logs",
            params={"limit": min(limit * 4, MAX_LIMIT), "q": query},
        )
        logs = resp.get("data", {}).get("affected_items", [])
        safe = _strip_sensitive(logs[:limit], _SENSITIVE_KEYS)
        return {
            "query": query,
            "total": len(safe),
            "logs": safe,
            "note": "searching manager log buffer only; indexer required for full alert history",
        }
    except Exception as exc:
        logger.error("wazuh_search_alerts failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_get_rules(
    level_gte: int = 0,
    group: str = "",
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """
    List active Wazuh detection rules.

    Args:
        level_gte: Minimum rule level (0–15). 0 returns all.
        group: Filter by rule group (e.g. 'web', 'syslog', 'authentication').
        limit: Maximum number of rules to return (1–100).

    Returns dict with keys: total, rules (list with id, level, description, groups).
    """
    limit = max(1, min(limit, MAX_LIMIT))
    params: dict[str, Any] = {"limit": limit, "status": "enabled"}
    if level_gte > 0:
        params["level"] = f"{level_gte}-15"
    if group:
        params["group"] = group

    try:
        resp = _api("GET", "/rules", params=params)
        items = resp.get("data", {}).get("affected_items", [])
        return {
            "total": resp.get("data", {}).get("total_affected_items", len(items)),
            "rules": _strip_sensitive(items, _SENSITIVE_KEYS),
        }
    except Exception as exc:
        logger.error("wazuh_get_rules failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_list_decoders(filename: str = "", limit: int = DEFAULT_LIMIT) -> dict:
    """
    List loaded Wazuh decoders.

    Args:
        filename: Optional decoder filename filter (e.g. 'apache').
        limit: Maximum number of decoders to return (1–100).

    Returns dict with keys: total, decoders (list with name, file, position).
    """
    limit = max(1, min(limit, MAX_LIMIT))
    params: dict[str, Any] = {"limit": limit, "status": "enabled"}
    if filename:
        params["filename"] = f"*{filename}*"

    try:
        resp = _api("GET", "/decoders", params=params)
        items = resp.get("data", {}).get("affected_items", [])
        return {
            "total": resp.get("data", {}).get("total_affected_items", len(items)),
            "decoders": _strip_sensitive(items, _SENSITIVE_KEYS),
        }
    except Exception as exc:
        logger.error("wazuh_list_decoders failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_run_active_response(
    agent_id: str,
    command: str,
    custom: bool = False,
    arguments: list[str] | None = None,
) -> dict:
    """
    Trigger a Wazuh active response on a specific agent.

    Requires ALLOW_ACTIVE_RESPONSE=true in the server environment (off by default).
    Callers should be restricted to the 'admin' role at the proxy/OPA layer;
    this server does not re-enforce RBAC — configure the OPA grant accordingly.

    Args:
        agent_id: Target agent ID — numeric string e.g. '001'.
        command: Active response command name — alphanumeric, hyphens and underscores
                 only (e.g. 'restart-ossec', 'firewall-drop').
        custom: Whether this is a custom command (not in the default set).
        arguments: Optional list of arguments; each must match [a-zA-Z0-9._-]{1,128}.

    Returns dict with keys: agent_id, command, status, response.
    """
    if not ALLOW_ACTIVE_RESPONSE:
        return {
            "error": "active response disabled",
            "detail": "Set ALLOW_ACTIVE_RESPONSE=true to enable this tool.",
        }

    # Validate agent_id (HIGH-2: prevent path traversal on Wazuh API)
    if not _validate_agent_id(agent_id):
        return {"error": f"invalid agent_id {agent_id!r} — must be a numeric string (e.g. '001')"}

    # Validate command name
    if not command or not command.replace("-", "").replace("_", "").isalnum():
        return {"error": "invalid command name — alphanumeric, hyphens and underscores only"}

    # Validate each argument element (MEDIUM-1: prevent injection via argument list)
    args_list = arguments or []
    if len(args_list) > _MAX_AR_ARGS:
        return {"error": f"too many arguments — maximum is {_MAX_AR_ARGS}"}
    for arg in args_list:
        if not _ARG_SAFE_RE.match(str(arg)):
            return {
                "error": f"invalid argument {arg!r} — must match [a-zA-Z0-9._-]{{1,128}}"
            }

    payload: dict[str, Any] = {
        "command": command,
        "custom": custom,
        "arguments": args_list,
    }

    try:
        resp = _api("PUT", f"/active-response/{agent_id}", json=payload)
        return {
            "agent_id": agent_id,
            "command": command,
            "status": "triggered",
            "response": resp.get("message", ""),
        }
    except Exception as exc:
        logger.error("wazuh_run_active_response failed: %s", exc)
        return {"error": str(exc)}


@mcp.tool()
def wazuh_list_ai_alerts(limit: int = DEFAULT_LIMIT) -> dict:
    """
    List recent Wazuh alerts fired by MCP AI attack detection rules.

    Returns events from rules 100510–100523 which detect:
    - AI agent policy probe bursts (jailbreak attempts)
    - Agent invocations with high behavioural anomaly scores
    - SIEM data exfiltration patterns (agent reading security events at scale)
    - Active response invocations via MCP (any principal, especially agents)
    - Agent invocation bursts (loop detection)

    Also returns the set of AI detection rules currently loaded in Wazuh,
    confirming the ruleset is active.

    Args:
        limit: Maximum number of recent log entries to return (1–100).

    Returns dict with keys: active_ai_rules, rule_count, recent_events,
            event_count, note.
    """
    limit = max(1, min(limit, MAX_LIMIT))
    try:
        # Query AI detection rules (100510–100529) to confirm they are loaded
        rules_resp = _api("GET", "/rules", params={
            "rule_ids": ",".join(str(i) for i in range(100510, 100530)),
            "limit": 20,
        })
        active_rules = [
            {
                "id": r.get("id"),
                "level": r.get("level"),
                "description": r.get("description", ""),
                "groups": r.get("groups", []),
            }
            for r in rules_resp.get("data", {}).get("affected_items", [])
        ]

        # Search manager log buffer for any MCP audit events (syslog path)
        logs_resp = _api("GET", "/manager/logs", params={
            "limit": limit,
            "q": "mcp_audit",
        })
        logs = logs_resp.get("data", {}).get("affected_items", [])
        safe_logs = _strip_sensitive(logs, _SENSITIVE_KEYS)

        return {
            "active_ai_rules": active_rules,
            "rule_count": len(active_rules),
            "recent_events": safe_logs,
            "event_count": len(safe_logs),
            "note": (
                "AI attack rules: 100510-100523 in 0960-mcp-ai-attacks.xml. "
                "Detects: jailbreak probes, anomaly-scored agent invocations, "
                "SIEM exfiltration, active-response abuse, invocation bursts. "
                "Full alert history requires the Wazuh indexer."
            ),
        }
    except Exception as exc:
        logger.error("wazuh_list_ai_alerts failed: %s", exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# ASGI app — wrap FastMCP with AuthHeaderMiddleware
# ---------------------------------------------------------------------------

def _build_app() -> ASGIApp:
    base = mcp.streamable_http_app()
    return AuthHeaderMiddleware(base)


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        _build_app(),
        host=HOST,
        port=PORT,
        log_level="info",
    )
