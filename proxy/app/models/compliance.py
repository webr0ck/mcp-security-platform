"""
MCP Security Platform — Compliance Report Pydantic Models

Matches API.md Section 2.6 response shapes for:
  GET /compliance/reports
  GET /compliance/reports/{report_id}
  POST /compliance/reports/run
"""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ComplianceCategory(BaseModel):
    """Per-category compliance check result. Matches API.md §2.6 nested shape."""

    category: str
    description: str
    events_checked: int
    violations_found: int
    status: str  # "pass" | "fail"


class HashIntegrityResult(BaseModel):
    """SHA-256 hash integrity check results."""

    events_checked: int
    hash_mismatches: int
    status: str  # "pass" | "fail"


class ComplianceReport(BaseModel):
    """Full compliance report. Matches API.md §2.6 GET /compliance/reports/{id}."""

    report_id: UUID
    run_at: datetime
    status: str  # "pass" | "fail" | "in_progress" | "error"
    sample_size: int
    period_start: datetime
    period_end: datetime
    categories: list[ComplianceCategory] = Field(default_factory=list)
    hash_integrity: HashIntegrityResult | None = None
    archive_url: str | None = None


class ComplianceReportListItem(BaseModel):
    """Abbreviated compliance report for list view. Matches API.md §2.6."""

    report_id: UUID
    run_at: datetime
    status: str
    sample_size: int
    categories_checked: int
    categories_failed: int
    archive_url: str | None = None


class ComplianceReportListResponse(BaseModel):
    """Paginated response for GET /compliance/reports."""

    data: list[ComplianceReportListItem]
    pagination: dict[str, Any]


class ComplianceReportCreate(BaseModel):
    """Request body for POST /compliance/reports/run."""

    sample_size: int = Field(500, ge=1, le=10000)
    period_hours: int = Field(24, ge=1, le=8760)


class ComplianceRunResponse(BaseModel):
    """Response for POST /compliance/reports/run."""

    job_id: str
    status: str
    estimated_seconds: int
