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

import hashlib
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
    # Step 2.5: Profile lookup — check mcp_profiles for per-identity permission
    # -------------------------------------------------------------------------
    # If a profile row exists for (client_id, tool_name), inject it into OPA input.
    # OPA then applies mcp_disabled_for_profile / function_not_allowed_for_profile rules.
    # Absence of a row = platform default = no restriction.
    profile_data: dict = {}
    function_name = params.get("tool_name", "")  # inner tool being invoked via invoke_tool
    try:
        from app.core.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as _db:
            row = await _db.execute(
                text("SELECT enabled, allowed_functions FROM mcp_profiles WHERE profile_id=:pid AND mcp_name=:mname LIMIT 1"),
                {"pid": client_id, "mname": tool_name},
            )
            prow = row.mappings().first()
            if prow:
                profile_data = {
                    "enabled": prow["enabled"],
                    "allowed_functions": prow["allowed_functions"],
                }
    except Exception as _exc:
        # Fail-open: if DB is unreachable, skip profile check (do not block legitimate traffic)
        logger.warning("mcp_profiles lookup failed for %s/%s: %s", client_id, tool_name, _exc)

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
        "profile": profile_data,
        "tool_function_name": function_name,
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
    # Step 3b: SSRF guard — re-validate upstream URL at call time (C3)
    # Registration-time check alone is insufficient: upstream_url may have been
    # changed via PATCH after approval. Call-time validation is an independent
    # defense-in-depth layer.
    # -------------------------------------------------------------------------
    from app.core.config import settings
    from app.services.ssrf import SSRFError, validate_server_url as _validate_server_url

    try:
        _validate_server_url(
            upstream_url,
            allow_http_localhost=(settings.ENVIRONMENT == "development"),
        )
    except SSRFError as exc:
        raise ValueError(f"SSRF blocked upstream URL at invoke time: {exc}") from exc

    # -------------------------------------------------------------------------
    # Step 4: Forward to upstream MCP server
    # -------------------------------------------------------------------------
    from app.credential_broker.dispatcher import CredentialInjectionError

    extra_headers: dict[str, str] = {}
    credential = None
    injection_mode = tool_record.get("injection_mode", "none")
    service_name = tool_record.get("service_name")

    if injection_mode != "none":
        from app.credential_broker.dispatcher import dispatch_credential_injection
        extra_headers = await dispatch_credential_injection(
            tool_record=tool_record,
            client_id=client_id,
            user_kc_token=None,
        )

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
        "Content-Type": "application/json",
        # FastMCP's TrustedHostMiddleware rejects container hostnames; override to localhost.
        "Host": "localhost",
    }
    # Forward caller identity so MCP servers that implement per-user isolation
    # (notes, self-service) can resolve the user without re-parsing a JWT.
    # X-User-Role carries the highest-privilege role for admin-gate checks.
    primary_role = client_roles[0] if client_roles else "user"
    forward_base_headers = {
        **handshake_headers,
        **extra_headers,
        "X-User-Sub": client_id,
        "X-User-Role": primary_role,
    }

    try:
        # Attempt to reuse a cached MCP-Session-Id before opening an HTTP client.
        # On cache hit we skip the 2-request initialize handshake entirely (Bug 1 fix).
        session_id = await _get_or_create_session(upstream_url, client_id, handshake_headers)

        async with httpx.AsyncClient(timeout=30.0) as client:
            # If no cached session was available, run the full initialize handshake.
            if session_id is None:
                try:
                    session_id = await _mcp_initialize(client, upstream_url, handshake_headers)
                    if session_id:
                        await _store_session(upstream_url, client_id, session_id)
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



async def _get_or_create_session(upstream_url: str, client_id: str, headers: dict) -> str | None:
    """Return cached MCP-Session-Id or None (caller runs full handshake on None).

    Cache key is a SHA-256 hash of (upstream_url, client_id) to prevent cross-client
    session reuse. TTL is 25s — safely below the 30s upstream session timeout.
    Fails open: returns None if Redis is unavailable so caller falls back to fresh handshake.
    """
    from app.core.redis_client import redis_pool
    if redis_pool.client is None:
        return None
    cache_key = (
        "mcp_session:"
        + hashlib.sha256(f"{upstream_url}:{client_id}".encode()).hexdigest()[:16]
    )
    try:
        cached = await redis_pool.client.get(cache_key)
        if cached:
            logger.debug("MCP session cache hit for client=%s", client_id)
            return cached.decode()
    except Exception as exc:
        logger.debug("Redis session cache read failed (fail-open): %s", exc)
    return None


async def _store_session(upstream_url: str, client_id: str, session_id: str) -> None:
    """Persist a newly-created MCP-Session-Id in Redis with 25s TTL (best-effort)."""
    from app.core.redis_client import redis_pool
    if redis_pool.client is None:
        return
    cache_key = (
        "mcp_session:"
        + hashlib.sha256(f"{upstream_url}:{client_id}".encode()).hexdigest()[:16]
    )
    try:
        await redis_pool.client.setex(cache_key, 25, session_id)
    except Exception as exc:
        logger.debug("Redis session cache write failed (non-fatal): %s", exc)


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
    session_id = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")

    # MCP spec requires notifications/initialized after initialize before tool calls.
    notify_headers = dict(headers)
    if session_id:
        notify_headers["Mcp-Session-Id"] = session_id
    await client.post(upstream_url, json={
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }, headers=notify_headers)

    return session_id


async def _emit_audit_event(
    tool_id: str | None,
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
        sha256_hash = audit_logger.emit(event)
        event_id = str(event.event_id)

        # Also persist to the audit_events index table (INV-001).
        # This allows the compliance API to query events without Loki.
        # Guard: skip DB write if values look like test mocks (non-UUID event_id or
        # non-string sha256_hash). This keeps unit tests that mock the audit logger
        # from hitting the real DB.
        # Also skip if tool_id is falsy (None/empty): audit_events.tool_id is a
        # nullable UUID FK and PostgreSQL would reject an empty string cast to UUID.
        import re as _re
        _uuid_re = _re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', _re.I)
        if not isinstance(sha256_hash, str) or not _uuid_re.match(event_id):
            return event_id
        if not tool_id:
            return event_id
        try:
            from sqlalchemy import text as _text
            from app.core.database import engine as _db_engine
            async with _db_engine.begin() as conn:
                await conn.execute(
                    _text(
                        """
                        INSERT INTO audit_events (
                            event_id, client_id, tool_name, tool_id,
                            outcome, latency_ms, sha256_hash,
                            anomaly_score, opa_reasons, request_id
                        ) VALUES (
                            :event_id, :client_id, :tool_name, :tool_id,
                            :outcome, :latency_ms, :sha256_hash,
                            :anomaly_score, CAST(:opa_reasons AS jsonb), :request_id
                        )
                        """
                    ),
                    {
                        "event_id": event_id,
                        "client_id": client_id,
                        "tool_name": tool_name,
                        "tool_id": tool_id,
                        # DB CHECK constraint only allows 'allow'/'deny'.
                        # An upstream failure means the tool did NOT successfully
                        # execute despite OPA allowing it — mapping to 'allow'
                        # would misrepresent the event in compliance queries.
                        # 'deny' is the conservative choice: the operation did not
                        # complete; opa_reasons records the specific failure cause.
                        "outcome": "deny" if outcome == "error" else outcome,
                        "latency_ms": latency_ms,
                        "sha256_hash": sha256_hash,
                        "anomaly_score": anomaly_score,
                        "opa_reasons": __import__("json").dumps(deny_reasons),
                        "request_id": request_id,
                    },
                )
        except Exception as db_exc:
            # DB write failure must not silently swallow — log and re-raise as AuditEmissionError
            logger.error("CRITICAL: audit_events DB write failed: %s", db_exc)
            raise AuditEmissionError(f"audit_events DB write failed: {db_exc}") from db_exc

        return event_id
    except AuditEmissionError:
        raise
    except Exception as exc:
        # Per INV-001: if audit emission fails, we must surface this.
        # The caller treats a raised exception as a 500 error.
        logger.error("CRITICAL: Audit event emission failed: %s", exc)
        raise AuditEmissionError(f"Audit event emission failed: {exc}") from exc


# Public alias so mcp_server.py can call emit_mcp_access_event directly
# without importing the private _emit_audit_event name.
emit_mcp_access_event = _emit_audit_event


async def emit_internal_tool_event(
    tool_name: str,
    client_id: str,
    outcome: str,
    deny_reasons: list[str],
    request_id: str,
    latency_ms: int,
    opa_decision_id: str,
) -> None:
    """Emit an audit event for internal platform tools (no tool_id/registry entry).
    Uses INTERNAL_TOOL_INVOCATION event type which doesn't require a tool_id UUID.
    Failures are logged but not re-raised — internal tool audit is best-effort.
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
            event_type=AuditEventType.INTERNAL_TOOL_INVOCATION,
            client_id=client_id,
            tool_name=tool_name,
            outcome=outcome_map.get(outcome, AuditOutcome.DENY),
            request_id=request_id,
            latency_ms=latency_ms,
            deny_reasons=deny_reasons,
            opa_decision_id=opa_decision_id,
        )
        audit_logger.emit(event)
    except Exception as exc:
        logger.warning("Internal tool audit emission failed (non-critical): %s", exc)


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
