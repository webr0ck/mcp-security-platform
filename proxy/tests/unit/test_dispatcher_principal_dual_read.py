"""
Unit tests — CR-10 (WP-A1) typed-principal dual-read wired through
dispatch_credential_injection (InjectionMode.USER), the end-to-end path a
real invoke_tool() call exercises.

These are the three required WP-A1 acceptance tests, exercised at the
dispatcher boundary (test_principal_resolution.py covers the same three at
the resolver-unit boundary):

  - Collision: 3 principals (OIDC human, API-key human, mTLS agent) sharing
    an IDENTICAL bare subject resolve to 3 DISTINCT injected credentials.
  - Dual-read: a pre-CR-10 bare-sub-only enrollment still resolves for a
    same-type caller.
  - Cross-type-fallback-denied: a different-type caller against an existing
    bare-sub row raises CredentialInjectionError (never a silent match).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.credential_broker.dispatcher import (
    CredentialInjectionError,
    CrossTypePrincipalFallbackDenied,
    dispatch_credential_injection,
)

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


@dataclass
class _Row:
    user_sub: str
    service: str
    principal_type: str | None = None


class _FakeResult:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _FakeSession:
    """Same fake credential_store simulation as test_principal_resolution.py,
    reused here to drive dispatch_credential_injection end-to-end."""

    def __init__(self, rows: list[_Row]):
        self._rows = rows

    async def execute(self, stmt, params):
        text = str(stmt)
        match = next(
            (r for r in self._rows if r.user_sub == params["sub"] and r.service == params["svc"]),
            None,
        )
        if match is None:
            return _FakeResult(None)
        if "SELECT 1" in text:
            return _FakeResult(SimpleNamespace())
        return _FakeResult(SimpleNamespace(principal_type=match.principal_type))


def _session_local_returning(rows: list[_Row]):
    """Patch target for app.core.database.AsyncSessionLocal used inside
    _resolve_owner_key_or_none (dispatcher.py)."""
    session = _FakeSession(rows)

    @asynccontextmanager
    async def _factory():
        yield session

    return patch("app.core.database.AsyncSessionLocal", _factory)


def _tool(**over) -> dict:
    base = {
        "tool_id": "t-user",
        "name": "notes-mcp",
        "service_name": "notes",
        "injection_mode": "user",
        "inject_header": "Authorization",
        "inject_prefix": "Bearer",
    }
    base.update(over)
    return base


def _mock_broker():
    return patch("app.services.invocation.broker_instance", MagicMock())


def _decrypt_keyed_by_owner(table: dict[str, str]):
    """decrypt_credential mock: returns table[user_sub] for owner_type='user'."""
    async def _impl(user_sub, service, tool_id=None, owner_type="user"):
        if owner_type != "user":
            return None
        return table.get(user_sub)
    return _impl


_DECRYPT = "app.credential_broker.approaches.approach_a.decrypt_credential"


async def test_collision_three_principal_types_inject_distinct_credentials():
    """CORE ACCEPTANCE TEST: same bare sub, three principal types → three
    distinct injected tokens (never the same upstream credential)."""
    bare_sub = "shared-subject-123"
    service = "notes"
    rows = [
        _Row(user_sub=f"human:kc-realm:{bare_sub}", service=service, principal_type="human"),
        _Row(user_sub=f"human:apikey:{bare_sub}", service=service, principal_type="human"),
        _Row(user_sub=f"agent:lab-ca:{bare_sub}", service=service, principal_type="agent"),
    ]
    tokens = {
        f"human:kc-realm:{bare_sub}": "oidc-secret-token",
        f"human:apikey:{bare_sub}": "apikey-secret-token",
        f"agent:lab-ca:{bare_sub}": "agent-secret-token",
    }

    with _mock_broker(), _session_local_returning(rows), patch(_DECRYPT, _decrypt_keyed_by_owner(tokens)):
        oidc_headers = await dispatch_credential_injection(
            _tool(), client_id=bare_sub,
            principal_id=f"human:kc-realm:{bare_sub}", principal_type="human",
        )
        apikey_headers = await dispatch_credential_injection(
            _tool(), client_id=bare_sub,
            principal_id=f"human:apikey:{bare_sub}", principal_type="human",
        )
        agent_headers = await dispatch_credential_injection(
            _tool(), client_id=bare_sub,
            principal_id=f"agent:lab-ca:{bare_sub}", principal_type="agent",
        )

    injected = {
        oidc_headers["Authorization"],
        apikey_headers["Authorization"],
        agent_headers["Authorization"],
    }
    assert injected == {
        "Bearer oidc-secret-token",
        "Bearer apikey-secret-token",
        "Bearer agent-secret-token",
    }


async def test_dual_read_legacy_bare_sub_enrollment_still_resolves():
    """A pre-CR-10 enrollment (bare-sub row, principal_type=NULL) resolves for
    a same-type (human) caller — the migration must not break existing
    enrollments."""
    rows = [_Row(user_sub="alice@corp", service="notes", principal_type=None)]
    with _mock_broker(), _session_local_returning(rows), patch(
        _DECRYPT, _decrypt_keyed_by_owner({"alice@corp": "legacy-token"})
    ):
        headers = await dispatch_credential_injection(
            _tool(), client_id="alice@corp",
            principal_id="human:kc-realm:alice@corp",  # typed miss — no such row yet
            principal_type="human",
        )
    assert headers == {"Authorization": "Bearer legacy-token"}


async def test_cross_type_fallback_is_denied_as_credential_injection_error():
    """CORE ACCEPTANCE TEST: an mTLS agent sharing a bare subject with an
    existing (legacy) human enrollment must be DENIED, not silently matched
    onto the human's credential."""
    rows = [_Row(user_sub="shared-subject-123", service="notes", principal_type=None)]
    with _mock_broker(), _session_local_returning(rows), patch(_DECRYPT, _decrypt_keyed_by_owner({})):
        with pytest.raises(CredentialInjectionError) as exc_info:
            await dispatch_credential_injection(
                _tool(), client_id="shared-subject-123",
                principal_id="agent:lab-ca:shared-subject-123",
                principal_type="agent",
            )
    assert isinstance(exc_info.value, CrossTypePrincipalFallbackDenied)
