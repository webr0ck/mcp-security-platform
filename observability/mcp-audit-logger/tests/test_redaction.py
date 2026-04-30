"""
MCP Audit Logger — Redaction Tests (INV-002 CI Gate)

Tests all 10 mandatory PII/credential redaction categories.
This test file MUST be in the CI gate (make security-check runs it).

Per INV-002: raw request bodies, response bodies, and parameter values
must NEVER appear in any log output. Each of the 10 categories is tested
with at least one positive case (should be redacted) and one negative case
(should pass through unchanged).
"""
from __future__ import annotations

import pytest

from mcp_audit_logger.redaction import redact_string, redact_value, redact_dict


class TestCategory1AWSAccessKey:
    def test_aws_access_key_redacted(self):
        value = "Here is AKIAIOSFODNN7EXAMPLE in a string"
        result = redact_string(value)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED:aws_access_key]" in result

    def test_normal_string_unchanged(self):
        value = "This is a safe description with no credentials"
        result = redact_string(value)
        assert result == value


class TestCategory2AWSSecretKey:
    def test_aws_secret_key_redacted(self):
        # 40-char base64 string surrounded by non-base64 chars
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        value = f"secret_key: {secret} done"
        result = redact_string(value)
        assert "[REDACTED:aws_secret_key]" in result

    def test_short_base64_not_redacted(self):
        value = "abc123 short"
        result = redact_string(value)
        # Short base64 should NOT match
        assert "[REDACTED:aws_secret_key]" not in result


class TestCategory3GitHubToken:
    def test_github_token_ghp_redacted(self):
        token = "ghp_" + "a" * 36
        result = redact_string(f"token={token}")
        assert token not in result
        assert "[REDACTED:github_token]" in result

    def test_plain_text_unchanged(self):
        result = redact_string("no github token here")
        assert "[REDACTED:github_token]" not in result


class TestCategory4PrivateKey:
    def test_private_key_redacted(self):
        value = "-----BEGIN RSA PRIVATE KEY----- MIIEowIBAAKCAQEA..."
        result = redact_string(value)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "[REDACTED:private_key]" in result

    def test_public_key_not_redacted(self):
        value = "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG..."
        result = redact_string(value)
        assert "[REDACTED:private_key]" not in result


class TestCategory5URLPassword:
    def test_password_field_redacted(self):
        value = "password=super_secret_123"
        result = redact_string(value)
        assert "super_secret_123" not in result
        assert "[REDACTED:url_password]" in result

    def test_passwd_field_redacted(self):
        value = "passwd=s3cr3t"
        result = redact_string(value)
        assert "[REDACTED:url_password]" in result

    def test_username_field_not_redacted(self):
        value = "username=john"
        result = redact_string(value)
        assert result == value


class TestCategory6JWTToken:
    def test_jwt_token_redacted(self):
        # Valid JWT format: header.payload.signature
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redact_string(f"Authorization: Bearer {jwt}")
        assert jwt not in result
        assert "[REDACTED:jwt_token]" in result

    def test_plain_text_unchanged(self):
        result = redact_string("some plain text value here")
        assert "[REDACTED:jwt_token]" not in result


class TestCategory7DBConnectionString:
    def test_postgres_connection_string_redacted(self):
        value = "postgresql://user:password@localhost:5432/mydb"
        result = redact_string(value)
        assert "password" not in result
        assert "[REDACTED:db_connection_string]" in result

    def test_postgres_url_without_password_unchanged(self):
        value = "postgresql://localhost:5432/mydb"
        result = redact_string(value)
        assert "[REDACTED:db_connection_string]" not in result


class TestCategory8EmailAddress:
    def test_email_redacted(self):
        value = "Contact john.doe@example.com for support"
        result = redact_string(value)
        assert "john.doe@example.com" not in result
        assert "[REDACTED:email_address]" in result

    def test_non_email_unchanged(self):
        value = "This has no email address in it"
        result = redact_string(value)
        assert "[REDACTED:email_address]" not in result


class TestCategory9IPAddress:
    def test_ip_address_redacted(self):
        value = "Client connected from 192.168.1.100"
        result = redact_string(value)
        assert "192.168.1.100" not in result
        assert "[REDACTED:ip_address]" in result

    def test_version_number_not_redacted(self):
        # Version numbers like 1.2.3 should not match (only 3 octets)
        value = "version 1.2.3 installed"
        result = redact_string(value)
        # Note: 1.2.3 only has 3 dots pattern — 3 octets, not 4 — should not match
        assert "[REDACTED:ip_address]" not in result


class TestCategory10APIKey:
    def test_api_key_field_redacted(self):
        value = "api_key=sk-proj-abcdef1234567890"
        result = redact_string(value)
        assert "sk-proj-abcdef1234567890" not in result
        assert "[REDACTED:api_key]" in result

    def test_normal_param_unchanged(self):
        value = "tool_name=file_reader"
        result = redact_string(value)
        assert result == value


class TestRedactDict:
    def test_nested_dict_redacted(self):
        data = {
            "client_id": "agent-001",
            "params": {
                "api_key": "apikey=abc123secret",
                "query": "normal query",
            },
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc",
        }
        result = redact_dict(data)
        assert result["client_id"] == "agent-001"
        assert "apikey=abc123secret" not in str(result)
        assert "[REDACTED:api_key]" in result["params"]["api_key"]

    def test_list_values_redacted(self):
        data = {"emails": ["user@example.com", "admin@test.org"]}
        result = redact_dict(data)
        assert "user@example.com" not in str(result)
        assert "admin@test.org" not in str(result)

    def test_non_string_values_unchanged(self):
        data = {"count": 42, "active": True, "score": 0.95}
        result = redact_dict(data)
        assert result["count"] == 42
        assert result["active"] is True
        assert result["score"] == 0.95
