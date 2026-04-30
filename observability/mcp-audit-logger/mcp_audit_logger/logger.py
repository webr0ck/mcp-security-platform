"""
MCP Audit Logger — MCPAuditLogger

Primary logger class. Accepts an AuditEvent, applies redaction to all string
fields (INV-002), computes the SHA-256 integrity hash, and writes a single
structured JSON line to stdout via the stdlib logging module.

INV-001 compliance: this module is the ONLY path through which audit events
are emitted. Any failure here must propagate to the caller (no silent swallow).

Usage:
    from mcp_audit_logger.logger import MCPAuditLogger
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    logger = MCPAuditLogger()
    event = AuditEvent(
        client_id="agent-001",
        tool_name="file_reader",
        tool_id="550e8400-...",
        outcome=AuditOutcome.ALLOW,
        request_id="req_01HZ...",
    )
    logger.emit(event)
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any

from mcp_audit_logger.hasher import hash_audit_entry
from mcp_audit_logger.redaction import redact_dict
from mcp_audit_logger.schema import AuditEvent

# Configure root audit logger to emit JSON to stdout
# Consumers (Promtail) scrape stdout for structured log lines.
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))

_audit_logger = logging.getLogger("mcp.audit")
_audit_logger.setLevel(logging.INFO)
_audit_logger.addHandler(_handler)
_audit_logger.propagate = False  # Don't double-emit to root logger


class MCPAuditLogger:
    """
    Structured audit event emitter.

    Pipeline per emit() call:
      1. Serialize AuditEvent to dict (pre-redaction — used for hash)
      2. Compute SHA-256 integrity hash over core identity fields
      3. Apply redaction to all string fields (INV-002)
      4. Write single JSON line to stdout via stdlib logging

    Raises AuditEmitError if the JSON serialization or write fails.
    This keeps INV-001 enforcement in the caller's hands.
    """

    def emit(self, event: AuditEvent) -> str:
        """
        Emit an audit event as a structured JSON log line.

        Returns the sha256_hash of the pre-redaction event for storage
        in the audit_events table (used by compliance checker for integrity).

        Raises:
            AuditEmitError: if log emission fails for any reason.
        """
        try:
            raw_dict = event.to_dict()

            # Compute hash over RAW (pre-redaction) data for integrity verification
            integrity_hash = hash_audit_entry(raw_dict)

            # Apply redaction to all string fields (INV-002)
            redacted_dict = redact_dict(raw_dict)

            # Build the final log record
            log_record: dict[str, Any] = {
                "log_type": "mcp_audit_event",
                **redacted_dict,
                "sha256_hash": integrity_hash,  # Always the pre-redaction hash
            }

            # Emit as a single JSON line to stdout
            _audit_logger.info(json.dumps(log_record, default=str))

            return integrity_hash

        except Exception as exc:
            raise AuditEmitError(f"Failed to emit audit event: {exc}") from exc

    def emit_admin_event(
        self,
        event: AuditEvent,
        extra_fields: dict[str, Any] | None = None,
    ) -> str:
        """
        Emit an administrative audit event (non-invocation: tool registration,
        status changes, compliance runs, etc.).

        extra_fields is merged into the log record after redaction.
        """
        try:
            raw_dict = event.to_dict()
            integrity_hash = hash_audit_entry(raw_dict)
            redacted_dict = redact_dict(raw_dict)

            log_record: dict[str, Any] = {
                "log_type": "mcp_audit_event",
                **redacted_dict,
                "sha256_hash": integrity_hash,
            }

            if extra_fields:
                safe_extra = redact_dict(extra_fields)
                log_record.update(safe_extra)

            _audit_logger.info(json.dumps(log_record, default=str))
            return integrity_hash

        except Exception as exc:
            raise AuditEmitError(f"Failed to emit admin audit event: {exc}") from exc


class AuditEmitError(RuntimeError):
    """Raised when audit event emission fails. Caller must treat this as a 500."""
