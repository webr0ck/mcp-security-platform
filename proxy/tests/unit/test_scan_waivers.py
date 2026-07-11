"""
Unit tests — CR-12 (WP-B2) waiver validation guards (scan_waivers.py).

These only exercise create_waiver's fail-closed input validation, which must
raise BEFORE touching the database — a `_UnusableSession` stub (raises on
any attribute access) proves that. Full round-trip (insert + audit event)
requires a real DB session and is covered by the acceptance-test fixtures,
not here.

Run: pytest proxy/tests/unit/test_scan_waivers.py -v
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.services.scan_waivers import InvalidWaiverRequest, create_waiver


class _UnusableSession:
    """Any use of this object should fail the test — proves validation short-circuits before DB access."""

    def __getattr__(self, name):
        raise AssertionError(f"validation must reject before touching the session (accessed .{name})")


def _future(days=7):
    return datetime.now(timezone.utc) + timedelta(days=days)


def _call(**overrides):
    kwargs = dict(
        server_id="00000000-0000-0000-0000-000000000001",
        package="requests", version="2.25.0", vuln_id="GHSA-xxxx", ecosystem="PyPI",
        reason="accepted by security team pending upstream patch",
        expires_at=_future(), principal_id="human:kc-realm:alice", principal_type="human",
        principal_issuer="kc-realm",
    )
    kwargs.update(overrides)
    return asyncio.run(create_waiver(_UnusableSession(), **kwargs))


def test_missing_package_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(package="")


def test_missing_version_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(version="")


def test_missing_vuln_id_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(vuln_id="")


def test_empty_reason_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(reason="   ")


def test_invalid_principal_type_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(principal_type="wildcard")


def test_missing_principal_id_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(principal_id="")


def test_expired_expires_at_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(expires_at=datetime.now(timezone.utc) - timedelta(days=1))


def test_expires_at_exactly_now_rejected():
    with pytest.raises(InvalidWaiverRequest):
        _call(expires_at=datetime.now(timezone.utc))
