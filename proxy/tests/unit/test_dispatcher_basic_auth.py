"""
Unit tests — basic_auth injection mode (Codex review CR-05, RFC 7617).

Covers:
  - dispatch with a stored shared basic_auth credential yields the EXACT
    Authorization: Basic <b64> header
  - a per-user credential row wins over the shared service row
  - fail-closed when no credential row exists (ServiceCredentialMissingError)
  - fail-closed when service_name is unset (CRITICAL-1 parity)
  - inject_header override is respected; the "Basic" scheme is not overridable
  - malformed (non-structured) stored payload fails closed
  - REDACTION: neither the raw username:secret pair, the secret alone, nor the
    base64 form ever appears in log records or exception messages
"""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    InjectionMode,
    ServiceCredentialMissingError,
    dispatch_credential_injection,
)

# base64.b64encode(b"labuser:s3cr3t!") — asserted as a literal on purpose.
_SHARED_JSON = '{"username": "labuser", "secret": "s3cr3t!"}'
_SHARED_B64 = "bGFidXNlcjpzM2NyM3Qh"
# base64.b64encode(b"alice:alice-pw")
_USER_JSON = '{"username": "alice", "secret": "alice-pw"}'
_USER_B64 = "YWxpY2U6YWxpY2UtcHc="

_DECRYPT = "app.credential_broker.approaches.approach_a.decrypt_credential"


def _tool(**over) -> dict:
    base = {
        "tool_id": "t-basic",
        "name": "echo-basic",
        "service_name": "lab-basic",
        "injection_mode": "basic_auth",
        "inject_header": "Authorization",
        "inject_prefix": "Basic",
    }
    base.update(over)
    return base


def _mock_broker():
    return patch("app.services.invocation.broker_instance", MagicMock())


def _decrypt_returning(user_value: str | None, service_value: str | None) -> AsyncMock:
    """decrypt_credential mock: owner_type routes to the right canned value."""
    async def _impl(user_sub, service, tool_id=None, owner_type="user"):
        return user_value if owner_type == "user" else service_value
    return AsyncMock(side_effect=_impl)


@pytest.mark.unit
def test_basic_auth_is_in_injection_mode_enum():
    assert InjectionMode.BASIC_AUTH.value == "basic_auth"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_shared_credential_yields_exact_b64_header():
    """Shared (owner_type=service) row: header must be exactly Basic <b64>."""
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, _SHARED_JSON)):
        result = await dispatch_credential_injection(_tool(), client_id="alice@corp")
    assert result == {"Authorization": f"Basic {_SHARED_B64}"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_per_user_credential_wins_over_shared():
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(_USER_JSON, _SHARED_JSON)):
        result = await dispatch_credential_injection(_tool(), client_id="alice@corp")
    assert result == {"Authorization": f"Basic {_USER_B64}"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_missing_credential_fails_closed():
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, None)):
        with pytest.raises(ServiceCredentialMissingError) as ei:
            await dispatch_credential_injection(_tool(), client_id="alice@corp")
    # Actionable, but never leaks anything secret-shaped
    assert "lab-basic" in str(ei.value)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_missing_service_name_fails_closed():
    """CRITICAL-1 parity: no approval-set service_name → refuse before lookup."""
    with _mock_broker():
        with pytest.raises(CredentialInjectionError, match="service_name"):
            await dispatch_credential_injection(
                _tool(service_name=None), client_id="alice@corp"
            )


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_respects_inject_header_override():
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, _SHARED_JSON)):
        result = await dispatch_credential_injection(
            _tool(inject_header="X-Upstream-Auth", inject_prefix="Bearer"),
            client_id="alice@corp",
        )
    # Header NAME is overridable; the RFC 7617 "Basic" scheme is not.
    assert result == {"X-Upstream-Auth": f"Basic {_SHARED_B64}"}


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_malformed_payload_fails_closed():
    """A non-structured stored secret (e.g. a legacy prebuilt header) must be
    rejected, and the error must not echo the payload back."""
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, "Basic hunter2-prebuilt")):
        with pytest.raises(CredentialInjectionError) as ei:
            await dispatch_credential_injection(_tool(), client_id="alice@corp")
    assert "hunter2" not in str(ei.value)
    assert "structured" in str(ei.value)


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_colon_in_username_fails_closed():
    bad = '{"username": "lab:user", "secret": "s3cr3t!"}'
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, bad)):
        with pytest.raises(CredentialInjectionError, match="colon"):
            await dispatch_credential_injection(_tool(), client_id="alice@corp")


# ---------------------------------------------------------------------------
# REDACTION (non-negotiable): neither username:secret nor its base64 form may
# appear in logs, audit rows, or error messages.
# ---------------------------------------------------------------------------

def _all_log_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records) + "\n".join(
        str(r.args) for r in caplog.records
    )


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_redaction_success_path(caplog):
    """Happy-path dispatch must not log the raw pair, the secret, or the b64."""
    caplog.set_level(logging.DEBUG)
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(_USER_JSON, _SHARED_JSON)):
        result = await dispatch_credential_injection(_tool(), client_id="alice@corp")
    assert result["Authorization"] == f"Basic {_USER_B64}"
    logged = _all_log_text(caplog)
    for needle in ("alice:alice-pw", "alice-pw", _USER_B64,
                   "labuser:s3cr3t!", "s3cr3t!", _SHARED_B64):
        assert needle not in logged, f"credential material leaked to logs: {needle!r}"


@pytest.mark.asyncio
@pytest.mark.unit
async def test_basic_auth_redaction_error_paths(caplog):
    """Every failure path (missing, malformed, decrypt crash) must keep the
    credential material out of logs AND out of the raised exception text —
    invocation.py forwards these messages to callers and audit deny_reasons."""
    caplog.set_level(logging.DEBUG)
    secrets = ("labuser:s3cr3t!", "s3cr3t!", _SHARED_B64)

    # malformed structured payload
    with _mock_broker(), patch(_DECRYPT, _decrypt_returning(None, '{"user": "labuser", "pass": "s3cr3t!"}')):
        with pytest.raises(CredentialInjectionError) as ei:
            await dispatch_credential_injection(_tool(), client_id="alice@corp")
    for needle in secrets:
        assert needle not in str(ei.value)

    # decrypt raises with the plaintext embedded in the exception (worst case:
    # a lower layer misbehaves) — the dispatcher must not propagate that text.
    boom = AsyncMock(side_effect=RuntimeError("plaintext was labuser:s3cr3t!"))
    with _mock_broker(), patch(_DECRYPT, boom):
        with pytest.raises(CredentialInjectionError) as ei2:
            await dispatch_credential_injection(_tool(), client_id="alice@corp")
    for needle in secrets:
        assert needle not in str(ei2.value), f"decrypt-crash path leaked {needle!r}"

    logged = _all_log_text(caplog)
    for needle in secrets:
        assert needle not in logged, f"credential material leaked to logs: {needle!r}"
