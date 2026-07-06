"""
Unit tests — CR-10 (WP-A1) typed-principal credential dual-read.

Covers the three required WP-A1 acceptance tests plus the resolver's edge
cases in isolation (no real DB — a fake async session simulates
credential_store rows):

  - Collision: three principal types with an IDENTICAL bare subject resolve
    to three DISTINCT credential owners.
  - Dual-read: a pre-CR-10 (bare-sub, principal_type=NULL) row still resolves
    for a SAME-type caller (inferred-legacy = 'human').
  - Cross-type-fallback-denied: a caller of a DIFFERENT principal_type than
    an existing bare-sub row must NOT match it — raises
    CrossTypePrincipalMismatch (never a silent match).
"""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from app.credential_broker.principal_resolution import (
    CrossTypePrincipalMismatch,
    ResolvedCredentialOwner,
    resolve_credential_owner,
)


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
    """
    Simulates credential_store with an in-memory table (list of _Row).
    Understands only the two query shapes resolve_credential_owner issues:
      - "SELECT 1 FROM credential_store WHERE user_sub = :sub AND service = :svc ..."
      - "SELECT principal_type FROM credential_store WHERE user_sub = :sub AND service = :svc ..."
    """

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
        # "SELECT principal_type ..."
        return _FakeResult(SimpleNamespace(principal_type=match.principal_type))


pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


async def test_typed_lookup_hit_matches_typed_row():
    """A row keyed by the exact typed principal_id resolves via the typed path."""
    session = _FakeSession([_Row(user_sub="human:kc-realm:alice", service="m365", principal_type="human")])
    resolved = await resolve_credential_owner(
        session,
        principal_id="human:kc-realm:alice",
        principal_type="human",
        bare_sub="alice",
        service="m365",
    )
    assert resolved == ResolvedCredentialOwner(owner_key="human:kc-realm:alice", matched_typed=True)


async def test_not_enrolled_returns_none():
    session = _FakeSession([])
    resolved = await resolve_credential_owner(
        session,
        principal_id="human:kc-realm:alice",
        principal_type="human",
        bare_sub="alice",
        service="m365",
    )
    assert resolved is None


async def test_dual_read_legacy_bare_sub_row_same_type_resolves():
    """
    Pre-CR-10 row: keyed by bare sub, principal_type=NULL (never recorded).
    A HUMAN caller (matching the inferred-legacy default) must still resolve.
    """
    session = _FakeSession([_Row(user_sub="alice", service="m365", principal_type=None)])
    resolved = await resolve_credential_owner(
        session,
        principal_id="human:kc-realm:alice",  # typed miss (no such row)
        principal_type="human",
        bare_sub="alice",
        service="m365",
    )
    assert resolved == ResolvedCredentialOwner(owner_key="alice", matched_typed=False)


async def test_dual_read_legacy_row_with_recorded_type_resolves_same_type():
    """A post-V062 bare-sub row (principal_type explicitly recorded) also dual-reads."""
    session = _FakeSession([_Row(user_sub="cn-agent-1", service="netbox", principal_type="agent")])
    resolved = await resolve_credential_owner(
        session,
        principal_id="agent:lab-ca:cn-agent-1",
        principal_type="agent",
        bare_sub="cn-agent-1",
        service="netbox",
    )
    assert resolved == ResolvedCredentialOwner(owner_key="cn-agent-1", matched_typed=False)


async def test_cross_type_fallback_is_denied_not_matched():
    """
    CORE ACCEPTANCE TEST: a bare-sub row exists (inferred-legacy 'human'), but
    the caller is an mTLS AGENT with the same bare subject. This must be
    DENIED — never silently matched — the exact collision CR-10 exists to fix.
    """
    session = _FakeSession([_Row(user_sub="shared-subject-123", service="netbox", principal_type=None)])
    with pytest.raises(CrossTypePrincipalMismatch) as exc_info:
        await resolve_credential_owner(
            session,
            principal_id="agent:lab-ca:shared-subject-123",
            principal_type="agent",
            bare_sub="shared-subject-123",
            service="netbox",
        )
    assert exc_info.value.caller_type == "agent"
    assert exc_info.value.row_type == "human"  # inferred-legacy default


async def test_cross_type_fallback_denied_recorded_type_mismatch():
    """Same denial, but the row's principal_type was explicitly recorded (not inferred)."""
    session = _FakeSession([_Row(user_sub="shared-subject-123", service="netbox", principal_type="human")])
    with pytest.raises(CrossTypePrincipalMismatch) as exc_info:
        await resolve_credential_owner(
            session,
            principal_id="agent:lab-ca:shared-subject-123",
            principal_type="agent",
            bare_sub="shared-subject-123",
            service="netbox",
        )
    assert exc_info.value.caller_type == "agent"
    assert exc_info.value.row_type == "human"


async def test_collision_three_principal_types_same_bare_sub_resolve_distinctly():
    """
    CR-10 CORE ACCEPTANCE TEST: an OIDC human, an API-key human, and an mTLS
    agent share the IDENTICAL bare subject string. Each has enrolled its OWN
    typed-keyed row (the "writes are always typed" behaviour). The dual-read
    must resolve each caller to its OWN distinct row — never collide onto a
    shared credential.
    """
    bare_sub = "shared-subject-123"
    service = "m365"
    session = _FakeSession([
        _Row(user_sub=f"human:kc-realm:{bare_sub}", service=service, principal_type="human"),
        _Row(user_sub=f"human:apikey:{bare_sub}", service=service, principal_type="human"),
        _Row(user_sub=f"agent:lab-ca:{bare_sub}", service=service, principal_type="agent"),
    ])

    oidc = await resolve_credential_owner(
        session, principal_id=f"human:kc-realm:{bare_sub}", principal_type="human",
        bare_sub=bare_sub, service=service,
    )
    apikey = await resolve_credential_owner(
        session, principal_id=f"human:apikey:{bare_sub}", principal_type="human",
        bare_sub=bare_sub, service=service,
    )
    agent = await resolve_credential_owner(
        session, principal_id=f"agent:lab-ca:{bare_sub}", principal_type="agent",
        bare_sub=bare_sub, service=service,
    )

    owner_keys = {oidc.owner_key, apikey.owner_key, agent.owner_key}
    assert len(owner_keys) == 3, f"credential owners collided: {owner_keys}"
    assert all(r.matched_typed for r in (oidc, apikey, agent))
