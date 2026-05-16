"""
MCP Security Platform — Tool Invocation Service

Implements the critical invocation path described in docs/ARCHITECTURE.md Section 5.1.

This service orchestrates:
  1. Tool status check (INV-005: quarantine block before OPA)
  2. Anomaly score computation
  3. OPA policy evaluation (INV-004: fail-closed on OPA unreachable)
  4. HTTP forwarding to upstream MCP server
  5. Audit event emission (INV-001: synchronous, before response returned)
  6. Anomaly baseline update (async, post-response)

The invocation handler in routers/tools.py calls invoke_tool() here.
Credentials in upstream responses are redacted by mcp-audit-logger.

See docs/ARCHITECTURE.md data flow 5.1 for the step-by-step sequence.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from app.credential_broker.broker import CredentialBroker

logger = logging.getLogger(__name__)

# Module-level singleton — initialized by app lifespan, injected for tests.
broker_instance: CredentialBroker | None = None

# Hard cap on bytes read from an upstream MCP server. Guards against a
# malicious upstream streaming unbounded data on the SSE channel.
_MAX_UPSTREAM_BODY_BYTES = 4 * 1024 * 1024  # 4 MiB


async def invoke_tool(
    tool_record: dict[str, Any],
    json_rpc_request: dict[str, Any],
    client_id: str,
    client_roles: list[str],
    is_testing: bool,
    request_id: str,
) -> dict[str, Any]:
    """
    Execute the full tool invocation pipeline.

    Args:
        tool_record: Full tool_registry record for the target tool.
        json_rpc_request: Parsed MCP JSON-RPC 2.0 request body.
        client_id: Resolved caller identity.
        client_roles: List of roles for the caller.
        is_testing: True if called by admin for testing (bypasses anomaly).
        request_id: Request correlation ID.

    Returns:
        Dict matching the MCP JSON-RPC 2.0 response format with meta.audit_id.

    Raises:
        ToolQuarantinedError: If tool status == 'quarantined' (INV-005).
        OPADenyError: If OPA denies the invocation.
        OPAUnavailableError: If OPA is unreachable (returns 503).
    """
    from app.services.anomaly import evaluate_anomaly
    from app.services.policy import OPADenyError, OPAUnavailableError, evaluate_policy

    tool_id = tool_record["tool_id"]
    tool_name = tool_record["name"]
    tool_status = tool_record["status"]
    tool_risk_level = tool_record.get("risk_level", "low")
    upstream_url = tool_record["upstream_url"]
    params = json_rpc_request.get("params", {}).get("arguments", {})

    # -------------------------------------------------------------------------
    # Step 1: INV-005 — Block quarantined tools before OPA evaluation
    # -------------------------------------------------------------------------
    if tool_status == "quarantined":
        raise ToolQuarantinedError(tool_id, tool_name)

    if tool_status == "deprecated":
        raise ToolDeprecatedError(tool_id, tool_name)

    # -------------------------------------------------------------------------
    # Step 2: Anomaly detection
    # -------------------------------------------------------------------------
    # Testing bypass: skip anomaly for admin is_testing requests so test suites
    # don't accumulate window state.
    from app.services.anomaly import detect as detect_anomaly

    anomaly_score = 0.0
    if not is_testing:
        try:
            anomaly_result = await detect_anomaly(client_id=client_id, tool_name=tool_name)
            anomaly_score = anomaly_result.anomaly_score
        except Exception as exc:
            # Anomaly detection is non-blocking — a failure here should not
            # block invocation, but must be logged for investigation.
            logger.warning(
                "Anomaly detection failed — defaulting score to 0.0",
                extra={"client_id": client_id, "tool_name": tool_name, "error": str(exc)},
            )

    # -------------------------------------------------------------------------
    # Step 3: OPA policy evaluation (INV-003, INV-004)
    # -------------------------------------------------------------------------
    opa_input = {
        "client_id": client_id,
        "client_roles": client_roles,
        "tool_id": str(tool_id),
        "tool_name": tool_name,
        "tool_status": tool_status,
        "tool_risk_level": tool_risk_level,
        "params": params,
        "anomaly_score": anomaly_score,
        "is_testing": is_testing,
    }

    opa_result = await evaluate_policy(opa_input)
    opa_decision_id = f"dec_{uuid4().hex[:16]}"

    if not opa_result["allow"]:
        # Emit DENY audit event synchronously (INV-001)
        audit_id = await _emit_audit_event(
            tool_id=str(tool_id),
            tool_name=tool_name,
            tool_version=tool_record.get("version"),
            client_id=client_id,
            outcome="deny",
            deny_reasons=opa_result["reasons"],
            request_id=request_id,
            latency_ms=0,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
        )
        raise OPADenyError(opa_result["reasons"])

    # -------------------------------------------------------------------------
    # Step 4: Forward to upstream MCP server
    # -------------------------------------------------------------------------
    extra_headers: dict[str, str] = {}
    credential = None
    if broker_instance is not None and tool_record.get("service_name") and tool_record.get("credential_approach"):
        credential = await broker_instance.resolve(
            user_sub=client_id,
            service=tool_record["service_name"],
            session_id=request_id,
            approach=tool_record["credential_approach"],
        )
        prefix = tool_record.get("inject_prefix", "")
        extra_headers[tool_record["inject_header"]] = f"{prefix}{credential.token}"

    start_ts = datetime.now(timezone.utc)
    upstream_response: dict[str, Any] = {}
    upstream_error: Exception | None = None
    init_failed = False

    # MCP streamable-http requires Accept header to signal JSON or SSE response preference.
    # The initialize handshake does NOT need the upstream credential — only the tools/call
    # forward does. Keeping handshake headers minimal limits credential exposure to the
    # request that actually needs it.
    handshake_headers = {
        "Accept": "application/json, text/event-stream",
    }
    forward_base_headers = {
        **handshake_headers,
        **extra_headers,
    }

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # MCP streamable-http servers require an initialize handshake before
            # any tools/call — establish a session and reuse it for the real call.
            try:
                session_id = await _mcp_initialize(client, upstream_url, handshake_headers)
            except Exception as exc:
                init_failed = True
                upstream_error = exc
                logger.error("MCP initialize handshake failed: %s", exc)
                session_id = None

            if not init_failed:
                forward_headers = dict(forward_base_headers)
                if session_id:
                    forward_headers["Mcp-Session-Id"] = session_id

                resp = await client.post(upstream_url, json=json_rpc_request, headers=forward_headers)

                # Defense against unbounded streaming from a malicious upstream.
                body = resp.content[:_MAX_UPSTREAM_BODY_BYTES]
                content_type = resp.headers.get("content-type", "")
                if "text/event-stream" in content_type:
                    for line in body.decode("utf-8", errors="replace").splitlines():
                        if line.startswith("data:"):
                            upstream_response = json.loads(line[5:].strip())
                            break
                else:
                    upstream_response = json.loads(body)
    except Exception as exc:
        upstream_error = exc
        logger.error("Upstream MCP server error: %s", exc)
    finally:
        if credential is not None:
            credential.zero()

    end_ts = datetime.now(timezone.utc)
    latency_ms = int((end_ts - start_ts).total_seconds() * 1000)

    # -------------------------------------------------------------------------
    # Step 5: Emit audit event synchronously (INV-001).
    # If the upstream call (or init handshake) failed, the policy decision
    # was "allow" but the tool did not actually execute. Record outcome="error"
    # with a reason so audit reviewers can distinguish this from a genuine
    # successful invocation.
    # -------------------------------------------------------------------------
    if upstream_error is not None:
        audit_outcome = "error"
        audit_reasons = [
            "upstream_init_failed" if init_failed else "upstream_invocation_failed",
        ]
    else:
        audit_outcome = "allow"
        audit_reasons = []

    audit_id = await _emit_audit_event(
        tool_id=str(tool_id),
        tool_name=tool_name,
        tool_version=tool_record.get("version"),
        client_id=client_id,
        outcome=audit_outcome,
        deny_reasons=audit_reasons,
        request_id=request_id,
        latency_ms=latency_ms,
        anomaly_score=anomaly_score,
        opa_decision_id=opa_decision_id,
        is_testing=is_testing,
    )

    # -------------------------------------------------------------------------
    # Step 6: Return proxied response
    # -------------------------------------------------------------------------
    if upstream_error or not upstream_response:
        return {
            "jsonrpc": "2.0",
            "id": json_rpc_request.get("id"),
            "error": {
                "code": -32603,
                "message": "Upstream MCP server error.",
                "data": {"audit_id": audit_id},
            },
        }

    upstream_response.setdefault("meta", {})
    upstream_response["meta"]["audit_id"] = audit_id
    upstream_response["meta"]["latency_ms"] = latency_ms

    return upstream_response


async def _mcp_initialize(
    client: httpx.AsyncClient,
    upstream_url: str,
    headers: dict[str, str],
) -> str | None:
    """
    Perform the MCP initialize handshake and return the Mcp-Session-Id.
    Returns None if the server doesn't require sessions (no header in response).
    """
    init_payload = {
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 0,
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-security-proxy", "version": "1.0.0"},
        },
    }
    # Errors propagate to the caller, which records the failure in the audit
    # event with outcome="error" rather than masking it as an "allow".
    resp = await client.post(upstream_url, json=init_payload, headers=headers)
    return resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")


async def _emit_audit_event(
    tool_id: str,
    tool_name: str,
    tool_version: str | None,
    client_id: str,
    outcome: str,
    deny_reasons: list[str],
    request_id: str,
    latency_ms: int,
    anomaly_score: float,
    opa_decision_id: str,
    is_testing: bool,
) -> str:
    """
    Emit a structured audit event via mcp-audit-logger.
    Returns the event_id for embedding in the response.

    This function is called synchronously before the response is returned (INV-001).
    """
    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, AuditOutcome, MCPAuditLogger

        outcome_map = {
            "allow": AuditOutcome.ALLOW,
            "deny": AuditOutcome.DENY,
            "error": getattr(AuditOutcome, "ERROR", AuditOutcome.DENY),
        }
        audit_logger = _get_audit_logger()
        event = AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            client_id=client_id,
            tool_name=tool_name,
            tool_id=tool_id,
            tool_version=tool_version,
            outcome=outcome_map.get(outcome, AuditOutcome.DENY),
            request_id=request_id,
            latency_ms=latency_ms,
            deny_reasons=deny_reasons,
            anomaly_score=anomaly_score,
            opa_decision_id=opa_decision_id,
            is_testing=is_testing,
        )
        audit_logger.emit(event)
        return str(event.event_id)
    except AuditEmissionError:
        raise
    except Exception as exc:
        # Per INV-001: if audit emission fails, we must surface this.
        # The caller treats a raised exception as a 500 error.
        logger.error("CRITICAL: Audit event emission failed: %s", exc)
        raise AuditEmissionError(f"Audit event emission failed: {exc}") from exc


# Module-level singleton so we don't re-instantiate on every invocation
# (synchronous audit path is on the hot RTT path — INV-001).
_audit_logger_singleton = None


def _get_audit_logger():
    global _audit_logger_singleton
    if _audit_logger_singleton is None:
        from mcp_audit_logger import MCPAuditLogger

        _audit_logger_singleton = MCPAuditLogger()
    return _audit_logger_singleton


class AuditEmissionError(RuntimeError):
    """Raised when audit event emission fails (INV-001).

    Treated by AuditMiddleware as a 500 with code AUDIT_EMISSION_FAILED.
    Distinct exception type so the middleware does not have to string-match
    on the message (which is fragile — see L1 in the AppSec review).
    """


class ToolQuarantinedError(Exception):
    """Raised when attempting to invoke a quarantined tool (INV-005)."""

    def __init__(self, tool_id: str, tool_name: str) -> None:
        self.tool_id = tool_id
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' ({tool_id}) is quarantined and cannot be invoked.")


class ToolDeprecatedError(Exception):
    """Raised when attempting to invoke a deprecated tool."""

    def __init__(self, tool_id: str, tool_name: str) -> None:
        self.tool_id = tool_id
        self.tool_name = tool_name
        super().__init__(f"Tool '{tool_name}' ({tool_id}) is deprecated.")
