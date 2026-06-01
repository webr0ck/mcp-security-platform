"""
Unit tests for proxy/app/services/consent.py — owner-consent tokens.
"""
from __future__ import annotations

import json
import time

import pytest

from app.services.consent import (
    ConsentPayload,
    ConsentTokenError,
    ConsentTokenExpiredError,
    ConsentTokenMismatchError,
    issue_consent_token,
    verify_consent_token,
)


def test_issue_and_verify_roundtrip():
    """Issuing and immediately verifying a token should return a ConsentPayload."""
    token, jti = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload = verify_consent_token(
        token=token,
        expected_server_id="srv-001",
        expected_new_mode="service",
        expected_owner_sub="user:sub123",
    )
    assert isinstance(payload, ConsentPayload)
    assert payload.server_id == "srv-001"
    assert payload.new_mode == "service"
    assert payload.jti == jti


def test_expired_token_raises():
    """A token issued with ttl_seconds=0 should be expired immediately."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
        ttl_seconds=0,
    )
    # Even without sleeping, exp = iat+0 will be <= now at verify time
    with pytest.raises(ConsentTokenExpiredError):
        verify_consent_token(
            token=token,
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_wrong_server_id_raises_mismatch():
    """Verifying with the wrong server_id must raise ConsentTokenMismatchError."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    with pytest.raises(ConsentTokenMismatchError, match="server_id"):
        verify_consent_token(
            token=token,
            expected_server_id="srv-WRONG",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_wrong_new_mode_raises_mismatch():
    """Verifying with the wrong new_mode must raise ConsentTokenMismatchError."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    with pytest.raises(ConsentTokenMismatchError, match="new_mode"):
        verify_consent_token(
            token=token,
            expected_server_id="srv-001",
            expected_new_mode="user",
            expected_owner_sub="user:sub123",
        )


def test_tampered_payload_raises_mismatch():
    """Modifying the payload portion (before the dot) should fail signature check."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload_json, sig = token.rsplit(".", 1)
    # Change server_id in the payload
    payload = json.loads(payload_json)
    payload["server_id"] = "srv-EVIL"
    tampered_payload = json.dumps(payload, sort_keys=True)
    tampered_token = f"{tampered_payload}.{sig}"
    with pytest.raises(ConsentTokenMismatchError, match="signature"):
        verify_consent_token(
            token=tampered_token,
            expected_server_id="srv-EVIL",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_tampered_signature_raises_mismatch():
    """A correct payload with a forged signature should fail."""
    token, _ = issue_consent_token(
        server_id="srv-001",
        old_mode="none",
        new_mode="service",
        owner_sub="user:sub123",
    )
    payload_json, _ = token.rsplit(".", 1)
    forged_token = f"{payload_json}.{'a' * 64}"
    with pytest.raises(ConsentTokenMismatchError, match="signature"):
        verify_consent_token(
            token=forged_token,
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_malformed_token_raises():
    """A garbage string should raise ConsentTokenError (no dot separator)."""
    with pytest.raises(ConsentTokenError):
        verify_consent_token(
            token="this-is-not-a-valid-token",
            expected_server_id="srv-001",
            expected_new_mode="service",
            expected_owner_sub="user:sub123",
        )


def test_payload_hash_in_issued_token():
    """The token should contain a parseable JSON payload (not an opaque blob)."""
    token, jti = issue_consent_token(
        server_id="srv-007",
        old_mode="none",
        new_mode="user",
        owner_sub="human:keycloak:alice",
    )
    payload_json, sig = token.rsplit(".", 1)
    payload = json.loads(payload_json)
    assert payload["server_id"] == "srv-007"
    assert payload["jti"] == jti
    assert "exp" in payload
    assert "iat" in payload
