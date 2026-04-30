"""
MCP Security Platform — Compliance Checker Pattern Registry

Canonical list of the 10 PII/credential categories checked during compliance runs.
Must stay synchronized with observability/mcp-audit-logger/mcp_audit_logger/redaction.py.
Any new pattern added to redaction.py must also appear here (and vice versa).
"""
from __future__ import annotations

import re
from typing import NamedTuple


class CompliancePattern(NamedTuple):
    category: str
    description: str
    pattern: re.Pattern


COMPLIANCE_PATTERNS: list[CompliancePattern] = [
    CompliancePattern(
        category="aws_access_key",
        description="AWS access key ID (AKIA...)",
        pattern=re.compile(r"AKIA[A-Z0-9]{16}", re.ASCII),
    ),
    CompliancePattern(
        category="aws_secret_key",
        description="AWS secret access key (40-char base64)",
        pattern=re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    ),
    CompliancePattern(
        category="github_token",
        description="GitHub personal access token (ghp_... or github_pat_...)",
        pattern=re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"),
    ),
    CompliancePattern(
        category="private_key",
        description="PEM private key material",
        pattern=re.compile(r"-----BEGIN\s[\w\s]+PRIVATE KEY-----", re.DOTALL),
    ),
    CompliancePattern(
        category="url_password",
        description="Password in URL query string or JSON field",
        pattern=re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
    ),
    CompliancePattern(
        category="jwt_token",
        description="JWT token (eyJ...)",
        pattern=re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*"),
    ),
    CompliancePattern(
        category="db_connection_string",
        description="Database connection string with embedded credentials",
        pattern=re.compile(r"(?i)(postgres|mysql|mongodb|redis):\/\/[^:]+:[^@]+@"),
    ),
    CompliancePattern(
        category="email_address",
        description="Email address (GDPR PII)",
        pattern=re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
    ),
    CompliancePattern(
        category="ip_address",
        description="IPv4 address in parameter values",
        pattern=re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ),
    CompliancePattern(
        category="api_key",
        description="API key pattern in field value",
        pattern=re.compile(r"(?i)(api[_\-]?key|apikey|x-api-key)\s*[=:]\s*\S+"),
    ),
]

# Verify exactly 10 patterns (per INV-002 specification)
assert len(COMPLIANCE_PATTERNS) == 10, (
    f"Expected exactly 10 compliance patterns per INV-002, got {len(COMPLIANCE_PATTERNS)}"
)

CATEGORY_NAMES: list[str] = [p.category for p in COMPLIANCE_PATTERNS]
