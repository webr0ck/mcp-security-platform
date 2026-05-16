"""
MCP Security Platform — Audit Event Pydantic Models

Matches API.md Section 2.8 response shapes for GET /audit/events.
Also provides AuditEventCreate used internally to persist index records.

Note: full event content lives in Loki; this table stores metadata only.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AuditOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"


class AuditEventCreate(BaseModel):
    """Internal DTO used to write a row to audit_events table."""

    client_id: str
    tool_id: UUID | None = None
    tool_name: str
    tool_version: str | None = None
    outcome: AuditOutcome
    deny_reason: str | None = None
    latency_ms: int | None = None
    anomaly_score: float | None = Field(None, ge=0.0, le=1.0)
    sha256_hash: str  # Pre-redaction hash from mcp-audit-logger
    is_testing: bool = False
    opa_decision_id: str | None = None
    request_id: str | None = None


class AuditEvent(BaseModel):
    """
    Audit event record returned by GET /audit/events.
    Matches API.md §2.8 response shape exactly.
    """

    event_id: UUID
    timestamp: datetime
    client_id: str
    tool_name: str
    tool_id: UUID | None = None
    outcome: AuditOutcome
    latency_ms: int | None = None
    sha256_hash: str
    anomaly_score: float | None = None


class AuditEventListResponse(BaseModel):
    """Paginated response for GET /audit/events."""

    data: list[AuditEvent]
    pagination: dict[str, Any]


class AuditEventFilters(BaseModel):
    """Query parameter model for GET /audit/events."""

    client_id: str | None = None
    tool_name: str | None = None
    outcome: AuditOutcome | None = None
    from_: datetime | None = Field(None, alias="from")
    to: datetime | None = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=200)
