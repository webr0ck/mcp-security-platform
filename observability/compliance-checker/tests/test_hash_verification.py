"""
Task 0.2 — Failing round-trip tests for audit-event hash integrity.

These tests verify that the compliance checker's verify_hash_integrity() correctly
validates events emitted by MCPAuditLogger using the shared canonicalizer from
mcp_audit_logger.hasher.

Four canonicalization breaks under test:
  Break 1: checker used json.dumps without separators=(",", ":") → different bytes
  Break 2: SELECT omitted event_type and timestamp → missing canonical inputs
  Break 3: AuditEvent._compute_hash() excluded platform_version (hash_audit_entry includes it)
  Break 4: invocation.py remaps outcome "error" → "deny" before INSERT → stored row
           has "deny" but hash was computed over "error"

All tests fail before the fix; all pass after.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

# Stub env vars required at module-level import of checker.py
_ENV_STUBS = {
    "DB_HOST": "localhost",
    "DB_PORT": "5432",
    "DB_NAME": "test",
    "COMPLIANCE_DB_USER": "test",
    "COMPLIANCE_DB_PASSWORD": "test",
    "MINIO_ROOT_USER": "test",
    "MINIO_ROOT_PASSWORD": "test",
}
for _k, _v in _ENV_STUBS.items():
    os.environ.setdefault(_k, _v)

# Add checker directory to sys.path so checker.py is importable directly.
_CHECKER_DIR = Path(__file__).resolve().parents[1]
if str(_CHECKER_DIR) not in sys.path:
    sys.path.insert(0, str(_CHECKER_DIR))

# Add mcp-audit-logger to sys.path so mcp_audit_logger is importable.
_AUDIT_LOGGER_DIR = (
    Path(__file__).resolve().parents[3]
    / "mcp-audit-logger"
)
if str(_AUDIT_LOGGER_DIR) not in sys.path:
    sys.path.insert(0, str(_AUDIT_LOGGER_DIR))

import checker  # noqa: E402
from mcp_audit_logger.hasher import hash_audit_entry  # noqa: E402
from mcp_audit_logger.schema import AuditEvent, AuditEventType, AuditOutcome  # noqa: E402
from mcp_audit_logger.logger import MCPAuditLogger  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_allow_event() -> AuditEvent:
    """Create a minimal TOOL_INVOCATION event with outcome=ALLOW."""
    return AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="read_file",
        tool_id="00000000-0000-0000-0000-000000000001",
        outcome=AuditOutcome.ALLOW,
        request_id="req-allow-001",
    )


def _make_error_event() -> AuditEvent:
    """Create a minimal TOOL_INVOCATION event with outcome=ERROR (fourth break)."""
    return AuditEvent(
        event_type=AuditEventType.TOOL_INVOCATION,
        client_id="test-client",
        tool_name="write_file",
        tool_id="00000000-0000-0000-0000-000000000002",
        outcome=AuditOutcome.ERROR,
        request_id="req-error-001",
    )


def _emit_and_build_db_row(event: AuditEvent, remap_error_to_deny: bool = False) -> dict[str, Any]:
    """
    Simulate the full emit + DB INSERT path:
    1. Emit via MCPAuditLogger (returns integrity_hash)
    2. Build the dict that the compliance checker SELECT would return,
       including or excluding canonical columns depending on whether the
       fix has landed.

    remap_error_to_deny=True simulates the pre-fix invocation.py:693 behaviour.
    """
    logger = MCPAuditLogger()
    integrity_hash = logger.emit(event)

    raw = event.to_dict()

    # The outcome stored in the DB (post-remap)
    stored_outcome = raw["outcome"]
    if remap_error_to_deny and stored_outcome == "error":
        stored_outcome = "deny"

    # Build the row dict matching the NEW SELECT (includes event_type, timestamp,
    # platform_version, original_outcome)
    return {
        "event_id": raw["event_id"],
        "client_id": raw["client_id"],
        "tool_name": raw["tool_name"],
        "tool_id": raw["tool_id"],
        "outcome": stored_outcome,
        "sha256_hash": integrity_hash,
        "request_id": raw["request_id"],
        # New canonical columns (added by V028 + fix)
        "event_type": raw["event_type"],
        "timestamp": raw["timestamp"],
        "platform_version": raw["platform_version"],
        "original_outcome": raw["outcome"],  # pre-remap
    }


# ---------------------------------------------------------------------------
# Break 1: separator mismatch
# ---------------------------------------------------------------------------

class TestBreak1SeparatorMismatch:
    """
    checker.py pre-fix uses json.dumps without separators=(",", ":").
    This produces " " spacing around ":" which differs from the canonical
    form that hash_audit_entry uses, causing hash mismatches.
    """

    def test_canonical_json_matches_hasher_output(self):
        """
        The hash stored by the emitter (hash_audit_entry) must equal the hash
        recomputed by checker.verify_hash_integrity() using the same canonicalizer.
        """
        event = _make_allow_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)

        # Simulate a minimal DB row with all canonical fields present
        row = {
            "event_id": raw["event_id"],
            "event_type": raw["event_type"],
            "timestamp": raw["timestamp"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": raw["outcome"],
            "request_id": raw["request_id"],
            "platform_version": raw["platform_version"],
            "original_outcome": raw["outcome"],
            "sha256_hash": stored_hash,
        }

        assert checker.verify_hash_integrity(row), (
            "verify_hash_integrity must return True for a freshly emitted event. "
            "FAIL = Break 1 (separator mismatch) not yet fixed."
        )


# ---------------------------------------------------------------------------
# Break 2: missing event_type and timestamp from SELECT
# ---------------------------------------------------------------------------

class TestBreak2MissingSelectColumns:
    """
    Pre-fix SELECT omitted event_type and timestamp; both are required by the
    canonical form.  A row without these columns will fail verification even
    if the rest is correct.
    """

    def test_verify_fails_without_event_type(self):
        """Without event_type the recomputed hash cannot match."""
        event = _make_allow_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)

        row_missing_event_type = {
            "event_id": raw["event_id"],
            # event_type intentionally omitted (pre-fix SELECT)
            "timestamp": raw["timestamp"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": raw["outcome"],
            "request_id": raw["request_id"],
            "platform_version": raw["platform_version"],
            "original_outcome": raw["outcome"],
            "sha256_hash": stored_hash,
        }

        # Without event_type, canonical "event_type" field defaults to "" → hash mismatch
        assert not checker.verify_hash_integrity(row_missing_event_type), (
            "A row missing event_type should FAIL verification (empty string ≠ 'TOOL_INVOCATION')."
        )

    def test_verify_fails_without_timestamp(self):
        """Without timestamp the recomputed hash cannot match.

        After appsec 0.2-F1 the checker treats a NULL/missing timestamp as
        "legacy" (unverifiable) rather than a hard mismatch False — because the
        event_ts_iso column being NULL is now the marker for the V028–V030
        migration window.  Either False or "legacy" is acceptable; the key
        invariant is that the result is NOT True (i.e. verification does not pass).
        """
        event = _make_allow_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)

        row_missing_ts = {
            "event_id": raw["event_id"],
            "event_type": raw["event_type"],
            # timestamp intentionally omitted (simulates event_ts_iso IS NULL)
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": raw["outcome"],
            "request_id": raw["request_id"],
            "platform_version": raw["platform_version"],
            "original_outcome": raw["outcome"],
            "sha256_hash": stored_hash,
        }

        result = checker.verify_hash_integrity(row_missing_ts)
        assert result is not True, (
            f"A row missing timestamp must NOT pass verification (got {result!r}). "
            "Result may be False (mismatch) or 'legacy' (unverifiable) — both are correct. "
            "appsec 0.2-F1: NULL timestamp is now treated as 'legacy' (V028–V030 window)."
        )

    def test_verify_passes_with_all_canonical_columns(self):
        """With all canonical columns present, verification must pass."""
        event = _make_allow_event()
        row = _emit_and_build_db_row(event, remap_error_to_deny=False)
        assert checker.verify_hash_integrity(row), (
            "Verification must pass when all canonical columns are present. "
            "FAIL = Break 2 not yet fixed."
        )


# ---------------------------------------------------------------------------
# Break 3: platform_version missing from AuditEvent._compute_hash
# ---------------------------------------------------------------------------

class TestBreak3PlatformVersionInHash:
    """
    hash_audit_entry (used by logger.emit) includes platform_version.
    AuditEvent._compute_hash() does NOT — it is used only internally
    and is superseded by the emit() call.

    The test confirms that the stored hash (from hash_audit_entry) includes
    platform_version in its canonical form, so removing platform_version
    from the row causes recomputation to fail.
    """

    def test_verify_fails_without_platform_version(self):
        """platform_version is a required canonical field; omitting it breaks the hash."""
        event = _make_allow_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)

        row_no_pv = {
            "event_id": raw["event_id"],
            "event_type": raw["event_type"],
            "timestamp": raw["timestamp"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": raw["outcome"],
            "request_id": raw["request_id"],
            # platform_version intentionally omitted
            "original_outcome": raw["outcome"],
            "sha256_hash": stored_hash,
        }

        assert not checker.verify_hash_integrity(row_no_pv), (
            "Row without platform_version should FAIL — platform_version is canonical."
        )


# ---------------------------------------------------------------------------
# Break 4: error→deny remap in invocation.py:693
# ---------------------------------------------------------------------------

class TestBreak4ErrorToDenyRemap:
    """
    invocation.py remaps outcome "error" → "deny" before the DB INSERT.
    The SHA-256 hash was computed with "error"; the stored row has "deny".
    Recomputing from the stored row yields a different hash → mismatch.

    Fix: store the original outcome in an `original_outcome` column and
    use it (not the remapped `outcome`) when recomputing the hash.
    """

    def test_remap_causes_mismatch_without_original_outcome_column(self):
        """
        Simulates pre-fix: the row only has the remapped outcome='deny'
        (no original_outcome column).  Recomputing against 'deny' will not
        match the hash computed over 'error'.
        """
        event = _make_error_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)  # hash over outcome="error"

        # Pre-fix row: outcome remapped to "deny", no original_outcome column
        row_remapped_no_original = {
            "event_id": raw["event_id"],
            "event_type": raw["event_type"],
            "timestamp": raw["timestamp"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": "deny",  # remapped
            "request_id": raw["request_id"],
            "platform_version": raw["platform_version"],
            # no original_outcome
            "sha256_hash": stored_hash,
        }

        assert not checker.verify_hash_integrity(row_remapped_no_original), (
            "Row with remapped outcome 'deny' (no original_outcome) must FAIL verification — "
            "hash was computed over 'error'. FAIL = Break 4 not yet fixed."
        )

    def test_original_outcome_column_allows_verification(self):
        """
        Post-fix: original_outcome column carries the pre-remap value.
        Verification uses original_outcome for hash recomputation → passes.
        """
        event = _make_error_event()
        # remap_error_to_deny=True simulates the DB row having outcome="deny"
        # but original_outcome="error"
        row = _emit_and_build_db_row(event, remap_error_to_deny=True)

        assert checker.verify_hash_integrity(row), (
            "Row with original_outcome='error' must pass even when outcome='deny'. "
            "FAIL = Break 4 fix not yet landed."
        )


# ---------------------------------------------------------------------------
# HMAC keyed signature test
# ---------------------------------------------------------------------------

class TestHMACKeyedSignature:
    """
    Step 3: verify_hash_integrity must also verify the HMAC signature
    stored in hmac_signature when present.  Mutating the row's content
    while leaving the plain hash intact must be caught by the HMAC check.
    """

    def test_hmac_signature_present_and_valid(self, monkeypatch):
        """A freshly emitted row with hmac_signature must pass HMAC verification."""
        from mcp_audit_logger.hasher import canonical_audit_json
        import hmac as _hmac
        import hashlib as _hashlib

        _TEST_KEY = "test-key-for-unit-tests-minimum32bytes!!"
        monkeypatch.setenv("AUDIT_LOG_HMAC_KEY", _TEST_KEY)

        event = _make_allow_event()
        row = _emit_and_build_db_row(event, remap_error_to_deny=False)

        # Compute HMAC and add it to the row (simulating the fixed INSERT)
        canonical = canonical_audit_json(row)
        sig = _hmac.new(_TEST_KEY.encode(), canonical.encode(), _hashlib.sha256).hexdigest()
        row["hmac_signature"] = sig
        row["hmac_key_id"] = "default"

        assert checker.verify_hash_integrity(row), (
            "Row with valid hmac_signature must pass HMAC verification."
        )

    def test_mutated_row_caught_by_hmac(self, monkeypatch):
        """
        Mutating outcome after signing: plain SHA-256 can be re-forged by a
        DB-writer, but HMAC cannot.  Mutating the row while recalculating
        only the plain sha256_hash must still be caught.
        """
        from mcp_audit_logger.hasher import hash_audit_entry, canonical_audit_json
        import hmac as _hmac
        import hashlib as _hashlib

        _TEST_KEY = "test-key-for-unit-tests-minimum32bytes!!"
        monkeypatch.setenv("AUDIT_LOG_HMAC_KEY", _TEST_KEY)

        event = _make_allow_event()
        row = _emit_and_build_db_row(event, remap_error_to_deny=False)

        canonical = canonical_audit_json(row)
        sig = _hmac.new(_TEST_KEY.encode(), canonical.encode(), _hashlib.sha256).hexdigest()
        row["hmac_signature"] = sig
        row["hmac_key_id"] = "default"

        # Simulate an attacker mutating the outcome and reforging only the plain hash.
        # The attacker changes original_outcome from "allow" to a different value.
        original_before_tamper = row["original_outcome"]
        row["original_outcome"] = "deny"  # tampered — was "allow"

        # Attacker recomputes plain hash over the tampered values
        tampered_hash = hash_audit_entry({
            "event_id": row["event_id"],
            "event_type": row["event_type"],
            "timestamp": row["timestamp"],
            "client_id": row["client_id"],
            "tool_name": row["tool_name"],
            "tool_id": row["tool_id"],
            "outcome": row["original_outcome"],  # tampered value
            "request_id": row["request_id"],
            "platform_version": row["platform_version"],
        })
        row["sha256_hash"] = tampered_hash  # plain hash re-forged

        # Sanity check: the tampered value differs from the original
        assert original_before_tamper != row["original_outcome"]

        # HMAC must still catch the tampering because the HMAC was over the original
        assert not checker.verify_hash_integrity(row), (
            "HMAC must catch tampering even when the plain sha256_hash is re-forged."
        )


# ---------------------------------------------------------------------------
# Historical-row cutoff (Step 4)
# ---------------------------------------------------------------------------

class TestLegacyRowCutoff:
    """
    Pre-migration rows lack the new canonical columns.  The verifier must
    skip them (not count as mismatches) and report them as unverifiable_legacy.
    """

    def test_legacy_row_not_counted_as_mismatch(self):
        """
        A row where event_type, timestamp, platform_version, and original_outcome
        are all NULL must NOT be counted as a mismatch — it is unverifiable_legacy.
        """
        legacy_row = {
            "event_id": "aaaaaaaa-0000-0000-0000-000000000001",
            "client_id": "old-client",
            "tool_name": "old_tool",
            "tool_id": "bbbbbbbb-0000-0000-0000-000000000002",
            "outcome": "allow",
            "sha256_hash": "deadbeef" * 8,  # 64 hex chars but wrong value
            "request_id": "req-legacy",
            # New canonical columns are NULL/absent
            "event_type": None,
            "timestamp": None,
            "platform_version": None,
            "original_outcome": None,
        }

        # verify_hash_integrity must signal "legacy" not "mismatch"
        result = checker.verify_hash_integrity(legacy_row)
        # A legacy row should return a sentinel that is NOT True (fails) but
        # is distinguishable.  The implementation returns the string "legacy"
        # to allow callers to separate unverifiable_legacy from mismatches.
        assert result == "legacy", (
            f"Legacy row (NULL canonical columns) must return 'legacy', got {result!r}. "
            "FAIL = legacy-cutoff not yet implemented."
        )

    def test_run_passes_with_unverifiable_legacy_row(self):
        """
        The compliance run logic: a legacy row must increment unverifiable_legacy,
        not hash_mismatches, so overall_status remains 'pass'.
        """
        # This tests the checker's run() loop logic via verify_hash_integrity
        # returning "legacy" being handled correctly by the caller.
        # We use a fresh good event + a legacy event to ensure the good one passes
        # and the legacy one does not increment the mismatch counter.
        event = _make_allow_event()
        good_row = _emit_and_build_db_row(event, remap_error_to_deny=False)

        legacy_row = {
            "event_id": "cccccccc-0000-0000-0000-000000000003",
            "client_id": "old-client",
            "tool_name": "old_tool",
            "tool_id": "dddddddd-0000-0000-0000-000000000004",
            "outcome": "deny",
            "sha256_hash": "00" * 32,
            "request_id": "req-legacy-2",
            "event_type": None,
            "timestamp": None,
            "platform_version": None,
            "original_outcome": None,
        }

        # Simulate the run() loop logic
        mismatches = 0
        unverifiable_legacy = 0
        for row in [good_row, legacy_row]:
            result = checker.verify_hash_integrity(row)
            if result == "legacy":
                unverifiable_legacy += 1
            elif result is not True:
                mismatches += 1

        assert mismatches == 0, f"Expected 0 mismatches, got {mismatches}"
        assert unverifiable_legacy == 1, f"Expected 1 legacy row, got {unverifiable_legacy}"


# ---------------------------------------------------------------------------
# appsec 0.2-F1: event_ts_iso round-trip tests
# ---------------------------------------------------------------------------

class TestEventTsIsoRoundTrip:
    """
    appsec finding 0.2-F1 (CRITICAL, blocking).

    The TIMESTAMPTZ column event_ts, when read back via event_ts::text, renders
    as "2026-06-11 00:10:36.123456+00" (space separator, shortened "+00" offset)
    rather than the Python isoformat() string "2026-06-11T00:10:36.123456+00:00".
    This byte-level divergence causes every post-V028 row to fail both SHA-256
    and HMAC verification.

    Fix: persist event.timestamp.isoformat() verbatim into event_ts_iso (TEXT),
    and SELECT event_ts_iso AS timestamp in the compliance checker.

    These unit tests simulate the Postgres round-trip without a live database by
    asserting that the writer-side isoformat() string and the checker-side
    canonical_audit_json() call receive byte-identical timestamp bytes.

    asyncpg text rendering rule (documented for future reference):
      asyncpg renders TIMESTAMPTZ as ISO 8601 with a space separator and
      shortened UTC offset ("+00" not "+00:00").  Python's isoformat() uses
      "T" separator and "+00:00".  These are two different strings for the
      same instant — storing the verbatim isoformat() text is the only way
      to guarantee round-trip identity.
    """

    def _make_db_row_with_event_ts_iso(
        self,
        event: AuditEvent,
        remap_error_to_deny: bool = False,
    ) -> dict[str, Any]:
        """
        Build a simulated DB row that includes event_ts_iso (the V030 column).
        The timestamp field in the returned dict is set to event.timestamp.isoformat()
        verbatim — exactly what the V030 INSERT stores and the updated SELECT reads.
        """
        logger_inst = MCPAuditLogger()
        integrity_hash = logger_inst.emit(event)

        raw = event.to_dict()
        stored_outcome = raw["outcome"]
        if remap_error_to_deny and stored_outcome == "error":
            stored_outcome = "deny"

        # Verbatim isoformat() string — what the writer stores in event_ts_iso.
        event_ts_iso = event.timestamp.isoformat()

        return {
            "event_id": raw["event_id"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": stored_outcome,
            "sha256_hash": integrity_hash,
            "request_id": raw["request_id"],
            "event_type": raw["event_type"],
            # V030: event_ts_iso is read back as "timestamp" by the updated SELECT.
            # This is the byte-identical string that was fed into canonical_audit_json
            # by hash_audit_entry at write time.
            "timestamp": event_ts_iso,
            "platform_version": raw["platform_version"],
            "original_outcome": raw["outcome"],  # pre-remap value
        }

    def test_isoformat_with_microseconds_verifies(self):
        """
        Timestamp with microseconds (most rows): isoformat() produces
        "2026-06-11T00:10:36.123456+00:00".  The checker must verify True.
        """
        from datetime import datetime, timezone, timedelta

        # Force a specific timestamp with microseconds to make the test deterministic.
        ts = datetime(2026, 6, 11, 0, 10, 36, 123456, tzinfo=timezone.utc)
        event = AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            client_id="test-client-ts-micro",
            tool_name="tool_with_microseconds",
            tool_id="00000000-0000-0000-0000-000000000010",
            outcome=AuditOutcome.ALLOW,
            request_id="req-ts-micro-001",
        )
        # Override the auto-generated timestamp with our deterministic one.
        object.__setattr__(event, "timestamp", ts)
        # Re-run __post_init__ to recompute sha256_hash with the new timestamp.
        # (sha256_hash is computed in __post_init__; reassigning timestamp after
        # construction requires recomputing it explicitly.)
        object.__setattr__(event, "sha256_hash", event._compute_hash())

        row = self._make_db_row_with_event_ts_iso(event)

        assert row["timestamp"] == "2026-06-11T00:10:36.123456+00:00", (
            f"Writer must produce 'T' separator + '+00:00' suffix, "
            f"got {row['timestamp']!r}"
        )
        assert checker.verify_hash_integrity(row) is True, (
            "verify_hash_integrity must return True for a row with event_ts_iso. "
            "FAIL = appsec 0.2-F1 not yet fixed (timestamp byte mismatch)."
        )

    def test_isoformat_without_microseconds_verifies(self):
        """
        Timestamp without microseconds: isoformat() produces
        "2026-06-11T00:10:36+00:00".  Verification must still pass.
        """
        from datetime import datetime, timezone

        ts = datetime(2026, 6, 11, 0, 10, 36, 0, tzinfo=timezone.utc)
        event = AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            client_id="test-client-ts-zero",
            tool_name="tool_no_microseconds",
            tool_id="00000000-0000-0000-0000-000000000011",
            outcome=AuditOutcome.ALLOW,
            request_id="req-ts-zero-001",
        )
        object.__setattr__(event, "timestamp", ts)
        object.__setattr__(event, "sha256_hash", event._compute_hash())

        row = self._make_db_row_with_event_ts_iso(event)

        assert row["timestamp"] == "2026-06-11T00:10:36+00:00", (
            f"Writer must produce 'T' separator + '+00:00' suffix (no fractional seconds), "
            f"got {row['timestamp']!r}"
        )
        assert checker.verify_hash_integrity(row) is True, (
            "verify_hash_integrity must return True for a zero-microseconds timestamp."
        )

    def test_postgres_cast_format_causes_mismatch(self):
        """
        Demonstrates the original bug: if the checker received the Postgres
        TIMESTAMPTZ::text rendering ("2026-06-11 00:10:36.123456+00") instead of
        the verbatim isoformat() string, verification MUST fail — confirming that
        the fix (event_ts_iso) is load-bearing.
        """
        from datetime import datetime, timezone

        ts = datetime(2026, 6, 11, 0, 10, 36, 123456, tzinfo=timezone.utc)
        event = AuditEvent(
            event_type=AuditEventType.TOOL_INVOCATION,
            client_id="test-client-ts-cast",
            tool_name="tool_cast_regression",
            tool_id="00000000-0000-0000-0000-000000000012",
            outcome=AuditOutcome.ALLOW,
            request_id="req-ts-cast-001",
        )
        object.__setattr__(event, "timestamp", ts)
        object.__setattr__(event, "sha256_hash", event._compute_hash())

        row = self._make_db_row_with_event_ts_iso(event)

        # Simulate the pre-fix checker receiving the Postgres cast rendering.
        postgres_cast_rendering = "2026-06-11 00:10:36.123456+00"
        row_with_cast_ts = dict(row)
        row_with_cast_ts["timestamp"] = postgres_cast_rendering

        assert checker.verify_hash_integrity(row_with_cast_ts) is not True, (
            "A row with the Postgres TIMESTAMPTZ::text rendering must FAIL verification "
            "— confirming the T-separator / +00:00 divergence is real and that the "
            "event_ts_iso fix is load-bearing."
        )

    def test_v028_to_v030_window_row_treated_as_legacy(self):
        """
        A row written between V028 and V030 has event_ts_iso IS NULL (aliased as
        timestamp=None in the SELECT) but the other V028 columns present.
        It must be treated as unverifiable_legacy, NOT as a mismatch.
        """
        event = _make_allow_event()
        raw = event.to_dict()
        stored_hash = hash_audit_entry(raw)

        # V028–V030 window: V028 columns present, event_ts_iso (timestamp) is NULL.
        window_row = {
            "event_id": raw["event_id"],
            "client_id": raw["client_id"],
            "tool_name": raw["tool_name"],
            "tool_id": raw["tool_id"],
            "outcome": raw["outcome"],
            "sha256_hash": stored_hash,
            "request_id": raw["request_id"],
            "event_type": raw["event_type"],        # V028 column — present
            "timestamp": None,                       # event_ts_iso — NULL (pre-V030)
            "platform_version": raw["platform_version"],  # V028 column — present
            "original_outcome": raw["outcome"],      # V028 column — present
        }

        result = checker.verify_hash_integrity(window_row)
        assert result == "legacy", (
            f"V028–V030 window row (event_ts_iso IS NULL) must return 'legacy', "
            f"got {result!r}. appsec 0.2-F1: these rows cannot be verified "
            f"without the verbatim isoformat() string."
        )
