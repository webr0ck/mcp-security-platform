"""
The shared deny table (services/deny_map.py).

Three renderers hand-copied the exception -> client-error mapping and had already
drifted: ToolDisabled/Quarantined/Deprecated existed only in the REST renderer, so
the two /mcp paths fell through to a generic error that ALSO interpolated the
exception text into a client-facing message.
"""
import pytest

from app.services.deny_map import classify_deny
from app.services.entitlement import NotEntitledError
from app.services.invocation import (
    ScanFreshnessError,
    ServerInMaintenanceError,
    TaintFloorDenyError,
    ToolDeprecatedError,
    ToolDisabledError,
    ToolQuarantinedError,
)
from app.services.policy import OPADenyError, OPAUnavailableError


# Constructed explicitly rather than by a guess-the-signature helper: a helper that
# falls back through TypeErrors can silently build the wrong thing and make a leakage
# assertion vacuous.
DENY_INSTANCES = [
    NotEntitledError("srv-abc123", "no entitlement row"),
    ScanFreshnessError("t-1", "tool-x", "2020-01-01T00:00:00Z"),
    ServerInMaintenanceError("t-1", "tool-x", "srv-abc123"),
    TaintFloorDenyError("t-1", "tool-x", 3),
    ToolDisabledError("t-1", "tool-x"),
    ToolQuarantinedError("t-1", "tool-x"),
    ToolDeprecatedError("t-1", "tool-x"),
]
ALL_DENY_TYPES = [type(e) for e in DENY_INSTANCES]


def _ids(e):
    return type(e).__name__


class TestCoverage:
    @pytest.mark.parametrize("exc", DENY_INSTANCES, ids=_ids)
    def test_every_deny_exception_is_classified(self, exc):
        # The drift this prevents: a deny type mapped in one renderer and forgotten in
        # the other two, silently degrading to a generic internal error.
        info = classify_deny(exc)
        assert info is not None, f"{type(exc).__name__} is unmapped — renders as a 500"
        assert info.reason and info.message
        assert info.http_status in (403, 410, 503)
        assert info.jsonrpc_code == -32003

    def test_the_three_that_were_mcp_only_missing(self):
        for exc in (ToolDisabledError("t-1", "x"), ToolQuarantinedError("t-1", "x"),
                    ToolDeprecatedError("t-1", "x")):
            assert classify_deny(exc) is not None

    def test_unrelated_exception_is_not_a_deny(self):
        # Must stay None so genuine bugs render as 500 and are not disguised as denials.
        assert classify_deny(ValueError("boom")) is None
        assert classify_deny(RuntimeError("boom")) is None


class TestNoInternalLeakage:
    @pytest.mark.parametrize("exc", DENY_INSTANCES, ids=_ids)
    def test_message_never_contains_the_exception_text(self, exc):
        info = classify_deny(exc)
        raw = str(exc)
        if raw:
            assert raw not in info.message, (
                f"{type(exc).__name__}: exception text leaked into a client message"
            )

    @pytest.mark.parametrize("exc", DENY_INSTANCES, ids=_ids)
    def test_messages_do_not_leak_identifiers(self, exc):
        low = classify_deny(exc).message.lower()
        assert "t-1" not in low, f"{type(exc).__name__} leaked a tool_id"
        assert "srv-abc123" not in low, f"{type(exc).__name__} leaked a server_id"
        assert "traceback" not in low


class TestOpaDeny:
    def test_reasons_are_forwarded_and_remediation_attached(self):
        info = classify_deny(OPADenyError(["mcp_disabled_for_profile"]))
        assert info.reason == "opa_deny"
        assert info.data["reasons"] == ["mcp_disabled_for_profile"]
        assert "remediation" in info.data
        assert "get_my_profile" in info.message  # remediation inlined into the message

    def test_unknown_reason_gets_no_filler_remediation(self):
        info = classify_deny(OPADenyError(["some_future_rule"]))
        assert info.data["reasons"] == ["some_future_rule"]
        assert "remediation" not in info.data
        assert info.message == "Access denied by policy"

    def test_opa_unavailable_is_retryable_503_not_403(self):
        # A decision and an outage are different things: 403 says "no", 503 says
        # "ask again". Both deny, per INV-004.
        info = classify_deny(OPAUnavailableError("opa down"))
        assert info.http_status == 503
        assert info.reason == "opa_unavailable"


class TestStatusSemantics:
    def test_deprecated_is_410_not_403(self):
        assert classify_deny(ToolDeprecatedError("t-1", "x")).http_status == 410

    def test_decisions_are_403(self):
        for exc in (NotEntitledError("srv-abc123", "r"), ToolDisabledError("t-1", "x"),
                    ToolQuarantinedError("t-1", "x")):
            assert classify_deny(exc).http_status == 403
