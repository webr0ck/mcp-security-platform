"""
MCP Security Platform — Tool Registry Pydantic Models

All models match the API.md Section 2.2 response shapes exactly.
These are the source of truth for request validation and response serialization.

Field constraints follow the database schema in V001__initial_schema.sql.
"""
from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, Field, field_validator, model_config


class ToolStatus(str, Enum):
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    DEPRECATED = "deprecated"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Semver pattern: major.minor.patch with optional pre-release
_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))"
    r"?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

# Tool name: lowercase, hyphen-separated, max 64 chars
_TOOL_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,62}[a-z0-9]$|^[a-z0-9]$")


class ToolCreate(BaseModel):
    """Request body for POST /tools/register. Matches API.md §2.2."""

    model_config = model_config(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=64, description="Tool identifier")
    version: str = Field(..., min_length=1, max_length=32, description="Semver version")
    description: str = Field(..., min_length=1, description="Human-readable description")
    schema: dict[str, Any] = Field(..., description="JSON Schema defining tool parameters")
    upstream_url: AnyHttpUrl = Field(..., description="URL the proxy forwards tool calls to")
    source_repo: str | None = Field(None, description="Source repository URL")
    source_commit: str | None = Field(
        None, min_length=7, max_length=40, description="Git commit SHA"
    )
    tags: list[str] = Field(default_factory=list, description="Taxonomy tags")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _TOOL_NAME_PATTERN.match(v):
            raise ValueError(
                "Tool name must be lowercase alphanumeric with hyphens/underscores, max 64 chars"
            )
        return v

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if not _SEMVER_PATTERN.match(v):
            raise ValueError("version must be a valid semver string (e.g., '1.2.0')")
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        for tag in v:
            if not tag or len(tag) > 64:
                raise ValueError("Each tag must be 1–64 characters")
        return [t.lower() for t in v]


class ToolUpdate(BaseModel):
    """Request body for PATCH /tools/{tool_id}. Matches API.md §2.2."""

    model_config = model_config(str_strip_whitespace=True)

    status: ToolStatus | None = Field(None, description="New tool status")
    metadata: dict[str, Any] | None = Field(None, description="Metadata to merge (not replace)")


class AuditFinding(BaseModel):
    """A single finding from the Tool Manifest Auditor."""

    finding_id: str
    category: str
    severity: str
    description: str
    parameter_name: str | None = None
    evidence: str | None = None
    recommendation: str | None = None


class LLMAnalysis(BaseModel):
    """LLM risk scoring result from Ollama."""

    model: str
    prompt_injection_detected: bool
    excessive_scope_detected: bool
    suspicious_parameter_names: list[str] = Field(default_factory=list)
    summary: str


class StaticAnalysis(BaseModel):
    """Static pattern-matching result."""

    injection_patterns_matched: list[str] = Field(default_factory=list)
    excessive_permissions_patterns_matched: list[str] = Field(default_factory=list)
    suspicious_name_patterns_matched: list[str] = Field(default_factory=list)


class ToolResponse(BaseModel):
    """Full tool record returned by POST /tools/register and GET /tools/{tool_id}."""

    tool_id: UUID
    name: str
    version: str
    description: str
    schema: dict[str, Any]
    status: ToolStatus
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    risk_reasons: list[str] = Field(default_factory=list)
    source_repo: str | None = None
    source_commit: str | None = None
    upstream_url: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    sbom_ref: str | None = None
    sbom_signature: str | None = None
    registered_at: datetime
    registered_by: str
    updated_at: datetime | None = None


class ToolListItem(BaseModel):
    """Abbreviated tool record for GET /tools list responses."""

    tool_id: UUID
    name: str
    version: str
    status: ToolStatus
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    tags: list[str] = Field(default_factory=list)
    registered_at: datetime


class ToolListResponse(BaseModel):
    """Paginated list response for GET /tools."""

    data: list[ToolListItem]
    pagination: dict[str, Any]


class ToolAuditResponse(BaseModel):
    """Full auditor result for GET /tools/{tool_id}/audit."""

    tool_id: UUID
    audit_id: str
    audited_at: datetime
    auditor_version: str
    risk_score: int
    risk_level: RiskLevel
    findings: list[AuditFinding]
    llm_analysis: LLMAnalysis | None = None
    static_analysis: StaticAnalysis | None = None


class AuditRerunResponse(BaseModel):
    """Response for POST /tools/{tool_id}/audit/rerun."""

    audit_job_id: str
    status: str
    estimated_seconds: int


class ToolRegisterResponse(BaseModel):
    """Response body for POST /tools/register. Matches API.md §2.2."""

    tool_id: UUID
    name: str
    version: str
    status: ToolStatus
    risk_score: int | None = None
    risk_level: RiskLevel | None = None
    risk_reasons: list[str] = Field(default_factory=list)
    sbom_ref: str | None = None
    sbom_signature: str | None = None
    registered_at: datetime
    registered_by: str
