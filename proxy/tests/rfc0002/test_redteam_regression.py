"""RFC-0002 red-team findings as tracked regression tests.

Each test asserts the VULNERABILITY IS PRESENT TODAY (passes while the bug exists).
Comments show the inverted assertion to swap in when the fix lands.

Run with: pytest tests/rfc0002 -m redteam -v
"""
from __future__ import annotations

import importlib.util
import inspect
from pathlib import Path

import pytest

pytestmark = pytest.mark.redteam


# ── F7: load_trust_list accepts unsigned rogue sub-CA entry ──────────────────
# Invert in Phase 4: when M-of-N governance sig verification is implemented,
# this load should raise (e.g. ValueError: "governance signature missing").

def test_f7_unsigned_rogue_entry_accepted():
    from app.services import trust_list as tl

    tl._LAST_ACCEPTED_SEQUENCE.pop("f7-rogue-test", None)
    result = tl.load_trust_list({
        "list_id": "f7-rogue-test",
        "sequence": 999,
        "issued_at": "2025-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "entries": [{
            "entry_id": "rogue-ca",
            "org_id": "evil-org",
            "gateway_id": "evil-gw",
            "sub_ca_spki_fp": "deadbeef",
            "valid_from": "2025-01-01T00:00:00Z",
            "valid_until": "2030-01-01T00:00:00Z",
            "trust_scope": {},
            # no transparency_log signature — accepted without verification
        }],
    })
    # Bug: accepted with no governance sig check.
    # Invert (Phase 4): assert raises ValueError / reject unsigned entry
    assert result is not None and len(result.entries) == 1


# ── F7c: rollback accepted after sequence state cleared ───────────────────────
# Invert in Phase 4: persist sequence to stable storage so clear() doesn't reset it.

def test_f7c_rollback_accepted_after_state_clear():
    from app.services import trust_list as tl

    list_id = "f7c-rollback-test"
    tl._LAST_ACCEPTED_SEQUENCE[list_id] = 50  # simulate prior accepted sequence

    # Adversarial: wipe in-memory state (simulates restart / cache eviction)
    tl._LAST_ACCEPTED_SEQUENCE.clear()

    # Sequence 10 < 50 — should be rollback-rejected, but state was lost
    result = tl.load_trust_list({
        "list_id": list_id,
        "sequence": 10,
        "issued_at": "2025-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "entries": [],
    })
    # Bug: sequence 10 accepted because last_accepted reset to -1 after clear.
    # Invert (Phase 4): assert raises ValueError / rollback rejected
    assert result.sequence == 10


# ── F4: no artifact_verifier module → tampered APE undetected ────────────────
# Invert in Phase 1: once app.services.artifact_verifier exists, flip the assert.

def test_f4_no_artifact_verifier_module():
    spec = importlib.util.find_spec("app.services.artifact_verifier")
    # Bug: nothing to reject a tampered APE.
    # Invert (Phase 1): assert spec is not None
    assert spec is None, (
        "app.services.artifact_verifier now exists — Phase 1 has landed. "
        "Remove this test and replace with a real tamper-detection assertion."
    )


# ── F2 (rewritten): parity file imports app.services ─────────────────────────
# Phase 0 fix: test_gateway_parity.py is the new parity home and DOES import app.services.
# This test ensures no one accidentally removes those imports (regression guard).

def test_f2_parity_file_imports_app_services():
    parity = Path(__file__).parent / "test_gateway_parity.py"
    src = parity.read_text()
    assert "from app.services" in src, (
        "test_gateway_parity.py must import app.services.* to exercise real impl, not just the oracle"
    )


# ── N3: labeler signs with structured_content=None; verifier reads structuredContent ──
# Invert in Phase 1: when structuredContent is threaded through build_envelope_result,
# change the assertion to: assert "structured_content=None" not in src.

def test_n3_labeler_signs_with_null_structured_content():
    from app.services import trust_labeler
    src = inspect.getsource(trust_labeler.build_envelope_result)
    # Bug: the call-site hardcodes structured_content=None so if a tool result carries
    # structuredContent the labeler signs an empty payload while the verifier hashes the real one.
    # Invert (Phase 1): assert "structured_content=None" not in src
    assert "structured_content=None" in src, (
        "N3 appears fixed — remove the xfail and verify verifier/labeler hash consistency"
    )
