#!/usr/bin/env python3
"""
Wazuh Active Response: quarantine-mcp-tool.py

Triggered by Wazuh when an AI attack pattern is detected (rules 100511, 100513,
100515, 100517). Calls the MCP proxy admin API to quarantine the offending tool,
preventing further invocations (INV-005 enforcement).

Wazuh active-response contract:
  - Must be placed at: /var/ossec/active-response/bin/quarantine-mcp-tool.py
  - Must be executable (chmod 750, owner root:wazuh)
  - Input: JSON alert on stdin (Wazuh AR format v1)
  - Must complete in < 30s (Wazuh default AR timeout)
  - Exit 0 on success, non-zero on failure (Wazuh logs non-zero exits)

Required environment variables (set in wazuh-manager container):
  MCP_PROXY_URL        — proxy base URL, e.g. http://proxy:8000
  MCP_ADMIN_API_KEY    — admin-role API key for the proxy

Optional:
  MCP_AR_TIMEOUT       — HTTP timeout in seconds (default: 15)
  MCP_AR_DRY_RUN       — if 'true', log the action but do not call the API

Usage in ossec.conf:
  <command>
    <name>quarantine-mcp-tool</name>
    <executable>quarantine-mcp-tool.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>quarantine-mcp-tool</command>
    <location>server</location>
    <rules_id>100511,100513,100515,100517</rules_id>
  </active-response>
"""
from __future__ import annotations

import json
import logging
import os
import sys
import urllib.error
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s quarantine-mcp-tool %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("quarantine-mcp-tool")

MCP_PROXY_URL = os.environ.get("MCP_PROXY_URL", "").rstrip("/")
MCP_ADMIN_API_KEY = os.environ.get("MCP_ADMIN_API_KEY", "")
MCP_AR_TIMEOUT = int(os.environ.get("MCP_AR_TIMEOUT", "15"))
MCP_AR_DRY_RUN = os.environ.get("MCP_AR_DRY_RUN", "false").lower() == "true"


def _parse_alert() -> dict:
    """Read and parse the Wazuh AR alert JSON from stdin."""
    raw = sys.stdin.read()
    return json.loads(raw)


def _extract_tool_name(alert: dict) -> str | None:
    """Pull tool_name from the alert data (filebeat JSON path or syslog path)."""
    # Filebeat path: alert.data.json.tool_name
    tool_name = (
        alert.get("parameters", {})
             .get("alert", {})
             .get("data", {})
             .get("json.tool_name")
    )
    if tool_name:
        return tool_name

    # Syslog decoder path: alert.data.id (mapped to tool_name by mcp-audit decoder)
    tool_name = (
        alert.get("parameters", {})
             .get("alert", {})
             .get("data", {})
             .get("id")
    )
    return tool_name or None


def _extract_client_id(alert: dict) -> str:
    return (
        alert.get("parameters", {})
             .get("alert", {})
             .get("data", {})
             .get("json.client_id")
        or alert.get("parameters", {})
                .get("alert", {})
                .get("data", {})
                .get("srcuser", "unknown")
    )


def _extract_rule_id(alert: dict) -> str:
    return str(
        alert.get("parameters", {})
             .get("alert", {})
             .get("rule", {})
             .get("id", "unknown")
    )


def _quarantine_tool(tool_name: str, rule_id: str, client_id: str) -> bool:
    """Call proxy PATCH /api/v1/tools/{tool_name} to quarantine the tool.

    Returns True on success (2xx), False on error.
    """
    if not MCP_PROXY_URL:
        logger.error("MCP_PROXY_URL not set — cannot quarantine tool '%s'", tool_name)
        return False
    if not MCP_ADMIN_API_KEY:
        logger.error("MCP_ADMIN_API_KEY not set — cannot quarantine tool '%s'", tool_name)
        return False

    # Sanitize tool_name — it comes from the alert, must only contain safe chars
    import re
    if not re.match(r'^[a-zA-Z0-9_\-]{1,128}$', tool_name):
        logger.error("Refusing to quarantine tool with unsafe name: %r", tool_name)
        return False

    url = f"{MCP_PROXY_URL}/api/v1/tools/{tool_name}"
    payload = json.dumps({
        "status": "quarantined",
        "_wazuh_ar_reason": f"auto-quarantine by Wazuh rule {rule_id} (client: {client_id})",
    }).encode("utf-8")

    if MCP_AR_DRY_RUN:
        logger.info(
            "DRY RUN: would PATCH %s status=quarantined (rule=%s client=%s)",
            url, rule_id, client_id,
        )
        return True

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": MCP_ADMIN_API_KEY,
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=MCP_AR_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            logger.info(
                "Quarantined tool '%s' via proxy (status=%d rule=%s client=%s): %s",
                tool_name, resp.status, rule_id, client_id, body[:200],
            )
            return True
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        logger.error(
            "Proxy returned HTTP %d quarantining '%s': %s",
            exc.code, tool_name, body[:200],
        )
        return False
    except Exception as exc:
        logger.error("Failed to quarantine tool '%s': %s", tool_name, exc)
        return False


def main() -> int:
    try:
        alert = _parse_alert()
    except Exception as exc:
        logger.error("Failed to parse Wazuh AR alert from stdin: %s", exc)
        return 1

    tool_name = _extract_tool_name(alert)
    client_id = _extract_client_id(alert)
    rule_id = _extract_rule_id(alert)

    logger.info(
        "Active response triggered: rule=%s client=%s tool=%s",
        rule_id, client_id, tool_name or "unknown",
    )

    if not tool_name:
        logger.warning(
            "Could not extract tool_name from alert (rule=%s client=%s) — skipping quarantine",
            rule_id, client_id,
        )
        return 0  # not an error — some rules (burst by client) don't name a specific tool

    success = _quarantine_tool(tool_name, rule_id, client_id)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
