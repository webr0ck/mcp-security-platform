"""
Unit Test — Redaction (proxy-side, INV-002 CI Gate)

Tests the same 10 redaction categories via the mcp-audit-logger library
as consumed by the proxy. This is the version run by `make security-check`.

See also: observability/mcp-audit-logger/tests/test_redaction.py for the
library-level tests. These tests verify the integration from the proxy's
import path.
"""
from __future__ import annotations

import pytest

from mcp_audit_logger.redaction import redact_string, redact_dict


@pytest.mark.unit
def test_aws_access_key_redacted():
    assert "[REDACTED:aws_access_key]" in redact_string("key: AKIAIOSFODNN7EXAMPLE done")


@pytest.mark.unit
def test_github_token_redacted():
    token = "ghp_" + "x" * 36
    assert "[REDACTED:github_token]" in redact_string(f"Bearer {token}")


@pytest.mark.unit
def test_private_key_redacted():
    assert "[REDACTED:private_key]" in redact_string(
        "-----BEGIN RSA PRIVATE KEY----- abc"
    )


@pytest.mark.unit
def test_url_password_redacted():
    assert "[REDACTED:url_password]" in redact_string("password=mysecret")


@pytest.mark.unit
def test_jwt_token_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc"
    assert "[REDACTED:jwt_token]" in redact_string(jwt)


@pytest.mark.unit
def test_db_connection_string_redacted():
    assert "[REDACTED:db_connection_string]" in redact_string(
        "postgresql://user:password@localhost/db"
    )


@pytest.mark.unit
def test_email_redacted():
    assert "[REDACTED:email_address]" in redact_string("contact: user@example.com")


@pytest.mark.unit
def test_ip_address_redacted():
    assert "[REDACTED:ip_address]" in redact_string("from 10.0.0.1 to server")


@pytest.mark.unit
def test_api_key_redacted():
    assert "[REDACTED:api_key]" in redact_string("api_key=mysecretkey123")


@pytest.mark.unit
def test_safe_strings_unchanged():
    safe = "Normal tool call output: file content here"
    assert redact_string(safe) == safe


@pytest.mark.unit
def test_all_10_categories_covered():
    """Verify redaction.py defines all 10 required categories per INV-002."""
    from mcp_audit_logger.redaction import REDACTION_PATTERNS
    assert len(REDACTION_PATTERNS) == 10, (
        f"INV-002 requires exactly 10 redaction categories, found {len(REDACTION_PATTERNS)}"
    )
    category_names = [name for name, _ in REDACTION_PATTERNS]
    required_categories = [
        "aws_access_key",
        "aws_secret_key",
        "github_token",
        "private_key",
        "url_password",
        "jwt_token",
        "db_connection_string",
        "email_address",
        "ip_address",
        "api_key",
    ]
    for cat in required_categories:
        assert cat in category_names, f"Missing required redaction category: {cat}"
