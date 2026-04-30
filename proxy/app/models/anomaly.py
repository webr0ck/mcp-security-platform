"""
MCP Security Platform — Anomaly Detection Pydantic Models

Matches API.md Section 2.7 response shapes for:
  GET /anomaly/baselines
  GET /anomaly/alerts
  PATCH /anomaly/alerts/{alert_id}
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AnomalyBaseline(BaseModel):
    """Per-client behavioral baseline. Matches API.md §2.7 GET /anomaly/baselines item."""

    client_id: str
    baseline_version: int
    tools_in_baseline: list[str] = Field(default_factory=list)
    sequence_patterns: int
    last_updated: datetime
    anomaly_score_threshold: float = Field(0.85, ge=0.0, le=1.0)


class AnomalyBaselineListResponse(BaseModel):
    """Paginated response for GET /anomaly/baselines."""

    data: list[AnomalyBaseline]
    pagination: dict[str, Any]


class AnomalyAlert(BaseModel):
    """
    Anomaly alert record. Matches API.md §2.7 GET /anomaly/alerts item.
    Created when anomaly_score >= 0.85.
    """

    alert_id: UUID
    client_id: str
    detected_at: datetime
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    pattern: str
    description: str
    invocation_ids: list[str] = Field(default_factory=list)
    resolved: bool = False
    resolved_at: datetime | None = None
    resolved_by: str | None = None
    resolution_note: str | None = None


class AnomalyAlertListResponse(BaseModel):
    """Paginated response for GET /anomaly/alerts."""

    data: list[AnomalyAlert]
    pagination: dict[str, Any]


class AnomalyAlertUpdate(BaseModel):
    """Request body for PATCH /anomaly/alerts/{alert_id}."""

    resolved: bool | None = None
    resolution_note: str | None = Field(None, max_length=2000)


class AnomalyDetectionResult(BaseModel):
    """Internal result from the AnomalyDetector service."""

    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    pattern_matched: str | None = None
    description: str | None = None
    alert_triggered: bool = False
