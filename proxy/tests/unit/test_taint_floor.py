"""Unit tests for the B-coarse taint-floor decision core (PRD-0001 M2 / RFC-0001 §8.1).

Pure, services-free security logic:
  - binary integrity from a SEP-1913 trust_tier rank (fail-closed on NULL/unknown)
  - whether a result taints the session
  - effective injection mode resolution (server default overrides tool, V032)
  - injection-mode safety bump (a credential-injecting tool can never be a low sink)
  - the binary taint-floor decision (deny-on-unknown, deny-when-tainted)

These encode INV-003 (deny-by-default) and the RFC §4.1 binary mapping. No I/O here;
the Redis taint store and the invocation.py wiring are integration-tested separately.
"""

import pytest

from app.services.taint_floor import (
    binary_integrity,
    effective_injection_mode,
    effective_required_integrity,
    result_taints_session,
    taint_floor_decision,
)


# --- binary_integrity: SEP-1913 trust_tier (0..4) -> binary {0,1}, fail-closed ---

@pytest.mark.parametrize(
    "trust_tier,expected",
    [
        (None, 0),  # missing/unknown server trust_tier -> untrusted (fail-closed)
        (0, 0),     # untrustedPublic -> untrusted
        (1, 0),     # trustedPublic   -> untrusted (RFC §4.1 binary table)
        (2, 1),     # internal        -> trusted
        (3, 1),     # user            -> trusted
        (4, 1),     # system          -> trusted
    ],
)
def test_binary_integrity_maps_trust_tier_failclosed(trust_tier, expected):
    assert binary_integrity(trust_tier) == expected


def test_binary_integrity_out_of_range_is_failclosed():
    # A negative or absurd value must never be treated as trusted.
    assert binary_integrity(-1) == 0


# --- result_taints_session ---

def test_untrusted_result_taints_session():
    assert result_taints_session(trust_tier=0) is True
    assert result_taints_session(trust_tier=1) is True
    assert result_taints_session(trust_tier=None) is True  # unknown -> taints


def test_trusted_result_does_not_taint_session():
    assert result_taints_session(trust_tier=2) is False
    assert result_taints_session(trust_tier=4) is False


# --- effective_injection_mode: server default overrides tool (V032) ---

def test_effective_injection_mode_tool_level_when_server_default_null():
    assert effective_injection_mode(tool_mode="service", server_default=None) == "service"
    assert effective_injection_mode(tool_mode="none", server_default=None) == "none"


def test_effective_injection_mode_bumps_when_either_side_injects():
    # Conservative, fail-closed in BOTH directions (M-2): a credential-injecting tool
    # must never escape the bump regardless of which side carries the injecting mode.
    assert effective_injection_mode(tool_mode="none", server_default="service") == "service"
    assert effective_injection_mode(tool_mode="service", server_default="none") == "service"


def test_effective_injection_mode_double_none_is_none():
    assert effective_injection_mode(tool_mode=None, server_default=None) == "none"
    assert effective_injection_mode(tool_mode="none", server_default="none") == "none"


# --- effective_required_integrity: credential-injecting tools cannot be low sinks ---

def test_injection_mode_bumps_low_tool_to_high():
    # required_integrity=0 (low) + a real injection mode -> forced to >=1.
    assert effective_required_integrity(tool_required_integrity=0, injection="service") == 1
    assert effective_required_integrity(tool_required_integrity=0, injection="oauth_user_token") == 1


def test_no_injection_leaves_required_integrity_untouched():
    assert effective_required_integrity(tool_required_integrity=0, injection="none") == 0
    assert effective_required_integrity(tool_required_integrity=1, injection="none") == 1


def test_injection_never_lowers_an_already_high_floor():
    assert effective_required_integrity(tool_required_integrity=1, injection="service") == 1


# --- taint_floor_decision: the binary B-coarse rule ---

def test_tainted_session_denies_high_sink():
    assert taint_floor_decision(tainted=True, required_integrity=1) == "deny"


def test_tainted_session_allows_low_sink():
    assert taint_floor_decision(tainted=True, required_integrity=0) == "allow"


def test_clean_session_allows_high_sink():
    # D3/D8: a clean session is never blocked, even for a high (incl. default) floor.
    assert taint_floor_decision(tainted=False, required_integrity=1) == "allow"


def test_deny_on_unknown_default_floor_blocks_tainted_session():
    # Unclassified tool defaults to required_integrity=1; a tainted session is denied.
    default_floor = 1
    assert taint_floor_decision(tainted=True, required_integrity=default_floor) == "deny"
