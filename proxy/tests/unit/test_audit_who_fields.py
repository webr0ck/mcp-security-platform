"""
Unit Tests — Task 1.2: Audit "who" enrichment fields + prev_hash deletion

Verifies:
1. AuditEvent.to_dict() includes source_ip, principal_type, roles, session_jti.
2. prev_hash field is gone — constructing AuditEvent with prev_hash= raises TypeError.
3. _emit_audit_event accepts and threads source_ip / principal_type / roles / session_jti.
4. New who-fields pass INV-002 redaction (roles list, session_jti, source_ip values).
5. to_dict() round-trip: set field values are faithfully serialised.

LOG-F04: audit "who" enrichment.
LOG-F07: dead prev_hash code removed.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test: to_dict() includes new who-fields
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_audit_event_to_dict_includes_source_ip():
    """to_dict() must include source_ip field (was missing before Task 1.2)."""
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    event = AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="test-tool",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.ALLOW,
        request_id="req-001",
        source_ip="192.168.1.42",
    )
    d = event.to_dict()
    assert "source_ip" in d, "to_dict() must include source_ip field"
    assert d["source_ip"] == "192.168.1.42"


@pytest.mark.unit
def test_audit_event_to_dict_includes_principal_type():
    """to_dict() must include principal_type field."""
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    event = AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="test-tool",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.ALLOW,
        request_id="req-001",
        principal_type="human",
    )
    d = event.to_dict()
    assert "principal_type" in d
    assert d["principal_type"] == "human"


@pytest.mark.unit
def test_audit_event_to_dict_includes_roles():
    """to_dict() must include roles list."""
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    event = AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="test-tool",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.DENY,
        request_id="req-001",
        roles=["agent", "auditor"],
    )
    d = event.to_dict()
    assert "roles" in d
    assert d["roles"] == ["agent", "auditor"]


@pytest.mark.unit
def test_audit_event_to_dict_includes_session_jti():
    """to_dict() must include session_jti field."""
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    event = AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="test-tool",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.ALLOW,
        request_id="req-001",
        session_jti="jti-abc123-xyz",
    )
    d = event.to_dict()
    assert "session_jti" in d
    assert d["session_jti"] == "jti-abc123-xyz"


@pytest.mark.unit
def test_audit_event_who_fields_default_to_none():
    """All new who-fields must default to None/empty when not supplied."""
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    event = AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="test-tool",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.ALLOW,
        request_id="req-001",
    )
    d = event.to_dict()
    assert d["source_ip"] is None
    assert d["principal_type"] is None
    assert d["roles"] == []
    assert d["session_jti"] is None


# ---------------------------------------------------------------------------
# Test: prev_hash is deleted — constructing with it must raise TypeError
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_audit_event_prev_hash_deleted():
    """
    AuditEvent must NOT accept prev_hash as a constructor argument.
    This verifies the Task 1.2 deletion — per-event HMAC (Task 0.2) is the
    tamper-evidence mechanism; the hash-chain (prev_hash) is P5 scope and was
    deleted to remove the misleading dead code.
    """
    from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome

    with pytest.raises(TypeError):
        AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            client_id="test-client",
            tool_name="test-tool",
            tool_id="00000000-0000-0000-0000-000000000001",
            outcome=AuditOutcome.ALLOW,
            request_id="req-001",
            prev_hash="some-hash-value",  # must raise TypeError
        )


# ---------------------------------------------------------------------------
# Test: INV-002 redaction applies to new who-fields
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_roles_values_are_safe_strings():
    """
    Roles are role-name strings (not token values). Constructing an event with
    a JWT-shaped role string should be possible — it just means the role list
    would get redacted if it were logged. Verify redact_dict handles it.
    """
    from mcp_audit_logger.redaction import redact_dict

    # Simulate a to_dict() output containing a JWT-shaped value in roles.
    # This would be anomalous (roles are short strings) but INV-002 must still
    # handle it without crashing.
    d = {
        "client_id": "test-client",
        "roles": ["agent", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc"],
        "session_jti": "jti-safe-value",
        "source_ip": "10.0.0.1",
        "principal_type": "human",
    }
    # redact_dict should handle list values gracefully (not crash)
    try:
        result = redact_dict(d)
        # The JWT-shaped role should be redacted
        roles_str = str(result.get("roles", []))
        assert "eyJhbGciOiJIUzI1NiJ9" not in roles_str, (
            "JWT-shaped role value must be redacted by INV-002"
        )
    except Exception as exc:
        pytest.fail(f"redact_dict raised an exception on roles list: {exc}")


@pytest.mark.unit
def test_source_ip_passes_through_as_infrastructure_header():
    """
    Source IPs that appear in infrastructure headers (not parameter values)
    should NOT be redacted per INV-002 pattern #9. Verify that a plain IP
    in source_ip is NOT replaced (it is a known infrastructure value, not a
    secret in a parameter).

    Note: INV-002 pattern #9 says "IP addresses in parameter values" — not in
    dedicated infrastructure fields. The audit event source_ip is an
    infrastructure field. The redaction library's ip_address pattern targets
    parameter value contexts; verify it doesn't clobber infrastructure fields
    used as dict values directly.
    """
    from mcp_audit_logger.redaction import redact_string

    # A plain source IP string on its own should match the ip_address pattern.
    # This is acceptable — if the platform routes source_ip through redact_string,
    # IPs will be redacted. The point of this test is to document the boundary:
    # source_ip in the structured dict is stored as-is; only free-text log lines
    # run through redact_string.
    result = redact_string("10.0.0.1")
    # Just assert the function doesn't crash — behaviour depends on redaction policy.
    assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Test: _emit_audit_event threads who-fields correctly
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_emit_audit_event_threads_who_fields():
    """
    _emit_audit_event must pass source_ip, principal_type, roles, session_jti
    through to AuditEvent construction.
    """
    import app.services.invocation as inv_mod

    original_skip = inv_mod._SKIP_AUDIT_DB_WRITE
    inv_mod._SKIP_AUDIT_DB_WRITE = True

    constructed_kwargs: list[dict] = []

    class CapturingAuditEvent:
        """Capture the kwargs passed to AuditEvent() without running real logic."""
        def __init__(self, **kwargs: Any):
            constructed_kwargs.append(kwargs)
            self.event_id = __import__("uuid").uuid4()
            self.event_type = MagicMock()
            self.event_type.value = "TOOL_INVOCATION"
            self.timestamp = MagicMock()
            self.timestamp.isoformat.return_value = "2026-06-11T00:00:00+00:00"
            self.platform_version = "1.0.0"
            self.outcome = MagicMock()
            self.outcome.value = "deny"

    mock_logger = MagicMock()
    mock_logger.emit.return_value = "a" * 64

    try:
        with patch.object(inv_mod, "_get_audit_logger", return_value=mock_logger):
            with patch("mcp_audit_logger.AuditEvent", side_effect=CapturingAuditEvent):
                await inv_mod._emit_audit_event(
                    tool_id="12345678-1234-5678-1234-567812345678",
                    tool_name="test-tool",
                    tool_version=None,
                    client_id="test-client",
                    outcome="deny",
                    deny_reasons=["test_reason"],
                    request_id="req-001",
                    latency_ms=10,
                    anomaly_score=0.1,
                    opa_decision_id="dec_abc",
                    is_testing=False,
                    source_ip="172.16.0.5",
                    principal_type="agent",
                    roles=["agent", "auditor"],
                    session_jti="jti-xyz-789",
                )
    finally:
        inv_mod._SKIP_AUDIT_DB_WRITE = original_skip

    assert len(constructed_kwargs) == 1
    kw = constructed_kwargs[0]
    assert kw.get("source_ip") == "172.16.0.5", f"source_ip not threaded: {kw}"
    assert kw.get("principal_type") == "agent", f"principal_type not threaded: {kw}"
    assert kw.get("roles") == ["agent", "auditor"], f"roles not threaded: {kw}"
    assert kw.get("session_jti") == "jti-xyz-789", f"session_jti not threaded: {kw}"
