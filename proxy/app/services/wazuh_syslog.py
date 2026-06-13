"""
MCP Security Platform — Wazuh syslog UDP emitter.

Sends structured MCP audit events to the Wazuh manager via UDP syslog on every
tool invocation. This is a SECONDARY, best-effort path alongside the primary
audit (PostgreSQL + mcp-audit-logger). Failures here are logged at WARNING and
swallowed — they must never affect INV-001.

Transport: UDP (fire-and-forget). Works with both Docker and Podman without
requiring a container log socket or Filebeat sidecar.

Wire format (RFC 3164 syslog):
  <priority>TIMESTAMP MCP-PROXY mcp_audit: {JSON}

JSON payload fields:
  client_id      string  — caller identity
  tool_name      string  — tool being invoked
  outcome        string  — "allow" | "deny"
  anomaly_score  float   — 0.0–1.0 from behavioural analyser
  risk_level     string  — "low" | "medium" | "high" | "critical"
  request_id     string  — correlation ID
  principal_type string? — "human" | "agent" | "service" (omitted if None)
  deny_reasons   list?   — OPA deny reason codes (omitted if empty/None)

Wazuh syslog priority mapping:
  outcome=deny          → user.err    (priority 11)
  anomaly_score >= 0.7  → user.warning (priority 12)
  otherwise             → user.info   (priority 14)

Decoded by: deployments/poc/wazuh/decoders/mcp-audit-decoder.xml
Detected by: deployments/poc/wazuh/rules/0960-mcp-ai-attacks.xml (100521–100523)
"""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Module-level UDP socket — created once, reused across requests.
_udp_socket: socket.socket | None = None
_MAX_DATAGRAM = 1024  # safe syslog UDP max


def _socket() -> socket.socket:
    global _udp_socket
    if _udp_socket is None:
        _udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return _udp_socket


def emit(
    host: str,
    port: int,
    *,
    client_id: str,
    tool_name: str,
    outcome: str,
    anomaly_score: float,
    risk_level: str,
    request_id: str,
    principal_type: str | None = None,
    deny_reasons: list[str] | None = None,
) -> None:
    """Emit one MCP audit event as a UDP syslog datagram.

    Never raises — any exception is logged at WARNING and swallowed.
    Must not affect INV-001 (synchronous audit to PostgreSQL).
    """
    try:
        # RFC 3164 priority: facility=user(1), severity varies
        if outcome == "deny":
            priority = 8 * 1 + 3   # user.err    = 11
        elif anomaly_score >= 0.7:
            priority = 8 * 1 + 4   # user.warning = 12
        else:
            priority = 8 * 1 + 6   # user.info   = 14

        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

        payload: dict[str, Any] = {
            "client_id": client_id,
            "tool_name": tool_name,
            "outcome": outcome,
            "anomaly_score": round(anomaly_score, 4),
            "risk_level": risk_level,
            "request_id": request_id,
        }
        if principal_type:
            payload["principal_type"] = principal_type
        if deny_reasons:
            payload["deny_reasons"] = deny_reasons

        msg = f"<{priority}>{ts} MCP-PROXY mcp_audit: {json.dumps(payload, separators=(',', ':'))}"
        data = msg.encode("utf-8")[:_MAX_DATAGRAM]
        _socket().sendto(data, (host, port))
    except Exception as exc:
        logger.warning("wazuh_syslog emit failed (non-critical): %s", exc)
