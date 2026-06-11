"""
MCP Audit Logger — Mandatory Field Schema

Defines the required fields for every audit event emitted by the platform.
All fields are validated at construction time. Missing required fields
raise AuditSchemaError to prevent partial audit records (INV-001).

See docs/ARCHITECTURE.md Section 5.1 for data flow context.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4


class AuditOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    # Policy allowed but the upstream invocation could not complete
    # (handshake failure, network error, malformed response, etc.).
    # Distinguished from ALLOW so audit reviewers don't conflate "tool
    # actually executed" with "tool would have been allowed to execute".
    ERROR = "error"


class AuditEventType(str, Enum):
    TOOL_INVOCATION = "TOOL_INVOCATION"
    TOOL_REGISTERED = "TOOL_REGISTERED"
    TOOL_STATUS_CHANGED = "TOOL_STATUS_CHANGED"
    TOOL_DELETED = "TOOL_DELETED"
    AUDIT_RERUN_TRIGGERED = "AUDIT_RERUN_TRIGGERED"
    COMPLIANCE_RUN_TRIGGERED = "COMPLIANCE_RUN_TRIGGERED"
    ANOMALY_ALERT_RESOLVED = "ANOMALY_ALERT_RESOLVED"
    POLICY_EVAL_MANUAL = "POLICY_EVAL_MANUAL"
    INTERNAL_TOOL_INVOCATION = "INTERNAL_TOOL_INVOCATION"
    API_KEY_CREATED = "API_KEY_CREATED"
    API_KEY_REVOKED = "API_KEY_REVOKED"
    CREDENTIAL_UPLOADED = "CREDENTIAL_UPLOADED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    CREDENTIAL_MODE_CHANGED = "CREDENTIAL_MODE_CHANGED"


class AuditSchemaError(ValueError):
    """Raised when a required audit field is missing or invalid."""


@dataclass
class AuditEvent:
    """
    Mandatory schema for all audit events.

    Required fields must be set at construction time.
    The sha256_hash field is computed automatically over canonical fields.
    """

    # Required
    event_id: UUID = field(default_factory=uuid4)
    event_type: AuditEventType = field(default=AuditEventType.TOOL_INVOCATION)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    client_id: str = ""
    platform_version: str = "1.0.0"

    # Required for TOOL_INVOCATION events
    tool_name: str = ""
    tool_id: str = ""
    outcome: AuditOutcome | None = None
    request_id: str = ""

    # Optional
    tool_version: str | None = None
    latency_ms: int | None = None
    deny_reasons: list[str] = field(default_factory=list)
    anomaly_score: float | None = None
    opa_decision_id: str | None = None
    is_testing: bool = False

    # Optional — originating client IP address (from X-Forwarded-For or REMOTE_ADDR).
    # Stored as a plain string (v4 or v6). Never populated for internal synthetic events.
    # INV-002 redaction applies: if this value matches a secret pattern it will be
    # replaced with [REDACTED] in the emitted log (source_ip patterns are unlikely,
    # but the redaction pass runs unconditionally over all string fields).
    source_ip: str | None = None

    # Task 1.2 — "who" enrichment fields (LOG-F04).
    # Populated by the proxy from request.state at invocation time.
    # Never populated for internal synthetic events or auth-failure (401/403) rows
    # where the identity has not been fully resolved.
    #
    # principal_type: 'human' | 'agent' | 'service' — the category of the caller.
    #   Derived from request.state.principal_type (set by auth middleware).
    #   None for unauthenticated / auth-failure events.
    principal_type: str | None = None

    # roles: copy of the caller's roles list at invocation time.
    #   Snapshot of request.state.client_roles (list[str]) for the audit record.
    #   Stored as a list so the audit consumer can filter without parsing JSON.
    #   INV-002: roles values must not carry bearer-token payloads; they are
    #   role-name strings (e.g. ['agent', 'auditor']).
    roles: list[str] = field(default_factory=list)

    # session_jti: OIDC session JWT ID from request.state.session_jti.
    #   Present only for session-JWT callers (OIDC browser flow); None for
    #   mTLS / API-key callers that have no OIDC session.
    #   Used to correlate audit events with session revocation records (INV-014).
    session_jti: str | None = None

    # NOTE: prev_hash was deleted in Task 1.2 (plan decision: delete, not wire).
    # Hash-chain / sequence tamper evidence is P5 scope; per-event HMAC (Task 0.2)
    # is the tamper-evidence mechanism for this build. Callers that previously
    # passed prev_hash= will see a TypeError — update call sites to remove the
    # argument.

    # Computed — set automatically in __post_init__
    sha256_hash: str = field(default="", init=False)

    def __post_init__(self) -> None:
        self._validate()
        self.sha256_hash = self._compute_hash()

    def _validate(self) -> None:
        if not self.client_id:
            raise AuditSchemaError("AuditEvent.client_id is required")
        if self.event_type == AuditEventType.TOOL_INVOCATION:
            if not self.tool_name:
                raise AuditSchemaError("AuditEvent.tool_name is required for TOOL_INVOCATION")
            if not self.tool_id:
                raise AuditSchemaError("AuditEvent.tool_id is required for TOOL_INVOCATION")
            if self.outcome is None:
                raise AuditSchemaError("AuditEvent.outcome is required for TOOL_INVOCATION")

    def _compute_hash(self) -> str:
        """SHA-256 over canonical fields for log integrity (INV-001, INV-007)."""
        canonical = json.dumps({
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "client_id": self.client_id,
            "tool_name": self.tool_name,
            "tool_id": self.tool_id,
            "outcome": self.outcome.value if self.outcome else None,
            "request_id": self.request_id,
        }, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "client_id": self.client_id,
            "tool_name": self.tool_name,
            "tool_id": self.tool_id,
            "tool_version": self.tool_version,
            "outcome": self.outcome.value if self.outcome else None,
            "request_id": self.request_id,
            "latency_ms": self.latency_ms,
            "deny_reasons": self.deny_reasons,
            "anomaly_score": self.anomaly_score,
            "opa_decision_id": self.opa_decision_id,
            "is_testing": self.is_testing,
            "platform_version": self.platform_version,
            "sha256_hash": self.sha256_hash,
            # Task 1.2 — "who" enrichment fields (LOG-F04).
            "source_ip": self.source_ip,
            "principal_type": self.principal_type,
            "roles": self.roles,
            "session_jti": self.session_jti,
        }
