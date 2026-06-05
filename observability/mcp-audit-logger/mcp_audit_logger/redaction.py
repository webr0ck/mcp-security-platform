"""
MCP Audit Logger — Credential and PII Auto-Redaction

Implements INV-002: Raw payloads and credentials must never appear in logs.
All 10 mandatory redaction categories are implemented here.

Every field passed through redact_value() or redact_dict() is scanned
against all patterns before any log emission.
"""
from __future__ import annotations

import re
from typing import Any

# =============================================================================
# REDACTION PATTERNS
# 10 mandatory categories per INV-002.
# Pattern order does not affect correctness; all are applied.
# =============================================================================
REDACTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # 1. AWS Access Key ID
    ("aws_access_key", re.compile(r"AKIA[A-Z0-9]{16}", re.ASCII)),
    # 2. AWS Secret Access Key (40-char base64-ish)
    ("aws_secret_key", re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")),
    # 3. GitHub tokens
    ("github_token", re.compile(r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})")),
    # 4. Private key material
    ("private_key", re.compile(r"-----BEGIN\s[\w\s]+PRIVATE KEY-----", re.DOTALL)),
    # 5. Passwords in query strings or JSON fields
    ("url_password", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+")),
    # 6. JWT tokens
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*")),
    # 7. Database connection strings with credentials
    ("db_connection_string", re.compile(
        r"(?i)(postgres(?:ql)?|mysql|mongodb|redis):\/\/[^:]+:[^@]+@"
    )),
    # 8. Email addresses (GDPR)
    ("email_address", re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    # 9. IP addresses in parameter values
    ("ip_address", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    # 10. API key patterns in field values
    ("api_key", re.compile(r"(?i)(api[_\-]?key|apikey|x-api-key)\s*[=:]\s*\S+")),
]


def redact_string(value: str) -> str:
    """Apply all redaction patterns to a string value."""
    for category, pattern in REDACTION_PATTERNS:
        value = pattern.sub(f"[REDACTED:{category}]", value)
    return value


def redact_value(value: Any) -> Any:
    """Recursively redact a value of any type."""
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, dict):
        return redact_dict(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return value


def redact_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Redact all string values in a dictionary, recursively."""
    return {key: redact_value(val) for key, val in data.items()}
