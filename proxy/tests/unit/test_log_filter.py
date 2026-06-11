"""
Unit Test — RedactingFilter (INV-002 root-logger coverage)

Verifies that the RedactingFilter applied to the root logger scrubs
token-shaped strings from log records before they reach any handler,
ensuring INV-002 holds for the entire Loki-shipped log surface.
"""
from __future__ import annotations

import logging

import pytest

from app.core.log_filter import RedactingFilter, _redact_message


# ---------------------------------------------------------------------------
# _redact_message() unit tests
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_bearer_token_redacted() -> None:
    """Bearer token in a log message must be replaced with [REDACTED:token]."""
    msg = "Upstream responded with 401, Authorization: Bearer eyJnot-a-jwt-but-long-enough-token"
    result = _redact_message(msg)
    assert "REDACTED:token" in result
    # The literal token value must not appear in the output
    assert "eyJnot-a-jwt-but-long-enough-token" not in result


@pytest.mark.unit
def test_jwt_redacted() -> None:
    """A raw JWT (three base64url segments) in a log message must be redacted."""
    # Construct a plausible-looking JWT (not a real token)
    header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    payload = "eyJzdWIiOiJ1c2VyLTAwMSIsInJvbGUiOiJhZG1pbiJ9"
    signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt = f"{header}.{payload}.{signature}"
    msg = f"Token validation failed for {jwt}"
    result = _redact_message(msg)
    assert "[REDACTED:jwt]" in result
    assert jwt not in result


@pytest.mark.unit
def test_api_key_redacted() -> None:
    """api_key= pattern in a log message must be redacted."""
    msg = "Request failed: api_key=supersecretapikey1234567890abcdef"
    result = _redact_message(msg)
    assert "REDACTED:token" in result
    assert "supersecretapikey1234567890abcdef" not in result


@pytest.mark.unit
def test_normal_message_passes_through_unchanged() -> None:
    """Plain log messages without token patterns must not be modified."""
    msg = "Tool invocation completed successfully for tool_id=abc123 client_id=agent-001"
    result = _redact_message(msg)
    assert result == msg


@pytest.mark.unit
def test_uuid_not_redacted() -> None:
    """UUIDs must not be treated as tokens (they lack the required prefix)."""
    msg = "scan_id=550e8400-e29b-41d4-a716-446655440000 completed"
    result = _redact_message(msg)
    assert result == msg


@pytest.mark.unit
def test_short_token_not_redacted() -> None:
    """Strings shorter than 20 chars after the token prefix are not redacted."""
    msg = "token=short"
    result = _redact_message(msg)
    # 'short' is < 20 chars, should not match
    assert result == msg


# ---------------------------------------------------------------------------
# RedactingFilter integration tests (logging.LogRecord level)
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_filter_redacts_bearer_in_record_msg() -> None:
    """RedactingFilter.filter() must redact a Bearer token in record.msg."""
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="",
        lineno=0,
        msg="httpx error: Authorization: Bearer eyJteXRva2VuLXZhbHVlLXRoYXQtaXMtbG9uZ2Vub3VnaA==",
        args=None,
        exc_info=None,
    )
    result = filt.filter(record)
    assert result is True  # filter must not drop the record
    assert "REDACTED:token" in record.msg
    assert "eyJteXRva2VuLXZhbHVlLXRoYXQtaXMtbG9uZ2Vub3VnaA==" not in record.msg


@pytest.mark.unit
def test_filter_redacts_jwt_in_record_msg() -> None:
    """RedactingFilter.filter() must redact a raw JWT in record.msg."""
    filt = RedactingFilter()
    header = "eyJhbGciOiJSUzI1NiJ9"
    payload = "eyJzdWIiOiJ1c2VyLTAwMSIsImlhdCI6MTYwMDAwMDAwMH0"
    sig = "abc123signaturevalue_that_is_long_enough"
    jwt = f"{header}.{payload}.{sig}"
    record = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname="",
        lineno=0,
        msg=f"Token rejected: {jwt}",
        args=None,
        exc_info=None,
    )
    filt.filter(record)
    assert "[REDACTED:jwt]" in record.msg
    assert jwt not in record.msg


@pytest.mark.unit
def test_filter_passes_plain_record_unchanged() -> None:
    """RedactingFilter.filter() must not modify records without token patterns."""
    filt = RedactingFilter()
    original_msg = "Database pool initialized with 20 connections"
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=original_msg,
        args=None,
        exc_info=None,
    )
    filt.filter(record)
    assert record.msg == original_msg


@pytest.mark.unit
def test_filter_always_returns_true() -> None:
    """RedactingFilter must never drop records (always return True)."""
    filt = RedactingFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.CRITICAL,
        pathname="",
        lineno=0,
        msg="Critical error with token=averylongtokenvalueherethatexceeds20chars",
        args=None,
        exc_info=None,
    )
    assert filt.filter(record) is True


@pytest.mark.unit
def test_filter_redacts_string_args() -> None:
    """RedactingFilter must also scrub token patterns in record.args tuple."""
    filt = RedactingFilter()
    long_token = "averylongtokenvaluehere1234567890"
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname="",
        lineno=0,
        msg="Error calling %s with token=%s",
        args=("upstream-service", f"Bearer {long_token}"),
        exc_info=None,
    )
    filt.filter(record)
    assert isinstance(record.args, tuple)
    # The second arg contained the token; it must now be redacted
    assert long_token not in str(record.args)
