"""GAP-1 regression: the audit event can carry session taint state.

RFC-0001 §8.1 / PRD-0001 W2.4 require that a tainted-session ALLOW of a low-floor
sink is never silently unrecorded — so the audit record carries `tainted` on the
ALLOW path, not only on the taint-floor DENY. This pins the schema contract:
`tainted` round-trips through to_dict() and does NOT change the integrity hash
(it is advisory enrichment, not a canonical field).
"""
import pytest

from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome


def _event(tainted):
    return AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="alice@corp",
        tool_name="search-kb",
        tool_id="11111111-1111-1111-1111-111111111111",
        outcome=AuditOutcome.ALLOW,
        request_id="req-1",
        tainted=tainted,
    )


@pytest.mark.unit
def test_tainted_roundtrips_in_to_dict():
    assert _event(True).to_dict()["tainted"] is True
    assert _event(False).to_dict()["tainted"] is False
    assert _event(None).to_dict()["tainted"] is None


@pytest.mark.unit
def test_tainted_does_not_affect_integrity_hash():
    # Same core fields → same hash regardless of taint enrichment (hash-safe).
    a, b, c = _event(True), _event(False), _event(None)
    # event_id/timestamp differ per instance, so compare the canonicalizer directly.
    from mcp_audit_logger.hasher import canonical_audit_json
    base = {"event_id": "x", "event_type": "TOOL_INVOCATION", "timestamp": "t",
            "client_id": "alice@corp", "tool_name": "search-kb",
            "tool_id": "11111111-1111-1111-1111-111111111111",
            "outcome": "ALLOW", "request_id": "req-1", "platform_version": "1.0.0"}
    h = canonical_audit_json({**base, "tainted": True})
    assert h == canonical_audit_json({**base, "tainted": False})
    assert h == canonical_audit_json({**base})  # tainted absent → identical
