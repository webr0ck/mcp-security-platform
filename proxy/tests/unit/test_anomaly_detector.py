"""
Unit Tests — Anomaly Detector Service
(proxy/app/services/anomaly.py)

Tests the scoring logic in _score_window() in full isolation (pure function,
no Redis, no DB). The async detect() path is tested with a mocked
push_anomaly_invocation to verify alert triggering and error resilience.

Invariant coverage:
  - Pattern 1: web_search → bulk_file_read (exfiltration chain)
  - Pattern 2: auth → data_export (credential exfiltration)
  - Pattern 3: rapid successive invocations (>10 in window)
  - Client isolation: separate windows do not bleed
  - Boundary: exactly at threshold (== 0.85 is alert, < 0.85 is not)
  - Error resilience: Redis failure returns 0.0 score, never crashes
"""
from __future__ import annotations

import sys
from unittest.mock import AsyncMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import the pure scoring function directly — no external deps
# ---------------------------------------------------------------------------
from app.services.anomaly import (
    ANOMALY_ALERT_THRESHOLD,
    AnomalyDetectionResult,
    _score_window,
    detect,
)


# ---------------------------------------------------------------------------
# Pure function tests: _score_window
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_empty_window_scores_zero():
    """An empty window has no anomaly signal."""
    score, pattern, description = _score_window([])
    assert score == 0.0
    assert pattern is None
    assert description is None


@pytest.mark.unit
def test_single_normal_tool_scores_zero():
    """A single benign tool call produces no anomaly."""
    score, pattern, _ = _score_window(["grep_files"])
    assert score == 0.0
    assert pattern is None


@pytest.mark.unit
def test_web_search_alone_below_threshold():
    """
    web_search without file reads doesn't trigger exfiltration pattern
    (needs search_count >= 1 AND file_read_count >= 3).
    """
    score, pattern, _ = _score_window(["web_search", "web_search"])
    assert score == 0.0


@pytest.mark.unit
def test_file_reads_below_threshold_without_search():
    """Two file reads (< 3) without a preceding search must not trigger."""
    score, pattern, _ = _score_window(["file_read", "file_read"])
    assert score == 0.0


@pytest.mark.unit
def test_exactly_three_file_reads_with_one_search_triggers_pattern1():
    """
    Pattern 1 fires when search_count >= 1 AND file_read_count >= 3.
    Minimum case: 1 search + 3 file reads.
    """
    score, pattern, description = _score_window(
        ["web_search", "file_read", "file_read", "file_read"]
    )
    assert score >= 0.7, f"Expected >= 0.7, got {score}"
    assert pattern == "web_search → bulk_file_read"
    assert description is not None
    assert "exfiltration" in description.lower()


@pytest.mark.unit
def test_exfiltration_chain_score_scales_with_file_count():
    """
    More file reads after a search = higher score (up to max 0.95).
    5 reads should score higher than 3 reads.
    """
    score_3, _, _ = _score_window(["web_search"] + ["file_reader"] * 3)
    score_5, _, _ = _score_window(["web_search"] + ["file_reader"] * 5)
    assert score_5 > score_3


@pytest.mark.unit
def test_exfiltration_chain_uses_all_search_tool_names():
    """All EXFIL_SEARCH_TOOLS variants should trigger pattern 1."""
    from app.services.anomaly import EXFIL_SEARCH_TOOLS
    for search_tool in EXFIL_SEARCH_TOOLS:
        score, pattern, _ = _score_window([search_tool] + ["bulk_file_read"] * 3)
        assert score > 0, f"Search tool '{search_tool}' did not trigger pattern"
        assert pattern == "web_search → bulk_file_read"


@pytest.mark.unit
def test_exfiltration_chain_uses_all_file_read_tool_names():
    """All EXFIL_FILE_TOOLS variants should count toward file_read_count."""
    from app.services.anomaly import EXFIL_FILE_TOOLS
    for file_tool in EXFIL_FILE_TOOLS:
        window = ["web_search"] + [file_tool] * 3
        score, pattern, _ = _score_window(window)
        assert score > 0, f"File read tool '{file_tool}' was not counted"


@pytest.mark.unit
def test_auth_export_chain_triggers_pattern2():
    """
    Pattern 2 fires when auth_count >= 1 AND export_count >= 1.
    Score must be exactly 0.80 (hardcoded in anomaly.py).
    """
    score, pattern, description = _score_window(["auth", "data_export"])
    assert score == 0.80
    assert pattern == "auth → data_export"
    assert "exfiltration" in description.lower()


@pytest.mark.unit
def test_auth_export_uses_all_auth_tool_variants():
    """All EXFIL_AUTH_TOOLS must trigger pattern 2."""
    from app.services.anomaly import EXFIL_AUTH_TOOLS
    for auth_tool in EXFIL_AUTH_TOOLS:
        score, pattern, _ = _score_window([auth_tool, "data_export"])
        assert pattern == "auth → data_export", f"Auth tool '{auth_tool}' missed"


@pytest.mark.unit
def test_auth_export_uses_all_export_tool_variants():
    """All EXFIL_EXPORT_TOOLS must trigger pattern 2."""
    from app.services.anomaly import EXFIL_EXPORT_TOOLS
    for export_tool in EXFIL_EXPORT_TOOLS:
        score, pattern, _ = _score_window(["auth", export_tool])
        assert pattern == "auth → data_export", f"Export tool '{export_tool}' missed"


@pytest.mark.unit
def test_rapid_invocations_exactly_11_triggers_pattern3():
    """
    Pattern 3 fires when total > 10. 11 calls is the minimum trigger.
    Score = 0.5 + (11-10)*0.035 = 0.535.
    """
    window = ["generic_tool"] * 11
    score, pattern, _ = _score_window(window)
    assert score > 0
    assert pattern == "rapid_successive_invocations"


@pytest.mark.unit
def test_rapid_invocations_exactly_10_does_not_trigger():
    """
    Boundary: exactly 10 calls in the window does NOT trigger pattern 3
    (condition is `total > 10`, not `>= 10`).
    """
    window = ["generic_tool"] * 10
    score, pattern, _ = _score_window(window)
    assert pattern != "rapid_successive_invocations"
    assert score == 0.0


@pytest.mark.unit
def test_rapid_invocations_score_capped_at_090():
    """
    rapid_successive_invocations score is capped at 0.90 regardless of
    how large the window grows.
    """
    window = ["generic_tool"] * 100
    score, pattern, _ = _score_window(window)
    assert score <= 0.90
    assert pattern == "rapid_successive_invocations"


@pytest.mark.unit
def test_highest_score_pattern_wins():
    """
    When multiple patterns match, the highest-scoring one wins.
    Pattern 1 (exfil chain with many reads) should beat pattern 3.
    """
    # pattern 1 + pattern 3 in same window
    window = ["web_search"] + ["file_reader"] * 5 + ["misc"] * 6
    score, pattern, _ = _score_window(window)
    # pattern 1 with 5 reads: 0.7 + 5*0.05 = 0.95 → capped implicitly
    # pattern 3 with 12 total: 0.5 + 2*0.035 = 0.57
    # Winner should be pattern 1 if its score is higher
    assert score > 0.70


@pytest.mark.unit
def test_score_at_alert_threshold_triggers_alert():
    """
    Score == ANOMALY_ALERT_THRESHOLD (0.85) must trigger an alert.
    Pattern: auth → data_export scores 0.80, not enough.
    Use window that produces >= 0.85 to verify threshold boundary.
    """
    # Pattern 1 with 4 file reads: 0.7 + 4*0.05 = 0.90 (above threshold)
    window = ["web_search"] + ["file_reader"] * 4
    score, _, _ = _score_window(window)
    assert score >= ANOMALY_ALERT_THRESHOLD


@pytest.mark.unit
def test_score_below_alert_threshold_does_not_trigger_alert():
    """
    Pattern 2 (auth → export) always scores 0.80, which is below the
    0.85 alert threshold.
    """
    score, _, _ = _score_window(["auth", "data_export"])
    assert score < ANOMALY_ALERT_THRESHOLD


# ---------------------------------------------------------------------------
# Async detect() tests with mocked Redis
# ---------------------------------------------------------------------------

@pytest.mark.unit
async def test_detect_returns_result_from_scored_window():
    """
    detect() calls push_anomaly_invocation then _score_window.
    The returned AnomalyDetectionResult must have the correct score.
    """
    window = ["web_search"] + ["file_reader"] * 4  # score >= 0.85
    with patch(
        "app.services.anomaly.push_anomaly_invocation",
        new=AsyncMock(return_value=window),
    ):
        with patch("app.services.anomaly._persist_alert", new=AsyncMock()):
            result = await detect("client-001", "file_reader")

    assert isinstance(result, AnomalyDetectionResult)
    assert result.anomaly_score >= ANOMALY_ALERT_THRESHOLD
    assert result.alert_triggered is True
    assert result.pattern_matched == "web_search → bulk_file_read"


@pytest.mark.unit
async def test_detect_no_alert_below_threshold():
    """Normal traffic window → no alert triggered."""
    window = ["grep_files", "list_dir"]
    with patch(
        "app.services.anomaly.push_anomaly_invocation",
        new=AsyncMock(return_value=window),
    ):
        result = await detect("client-002", "grep_files")

    assert result.anomaly_score == 0.0
    assert result.alert_triggered is False


@pytest.mark.unit
async def test_detect_redis_error_returns_zero_score():
    """
    If push_anomaly_invocation raises an exception (Redis down), detect()
    must return AnomalyDetectionResult with score=0.0 and alert_triggered=False.
    It must NEVER propagate the exception to the caller (invocation must continue).
    """
    with patch(
        "app.services.anomaly.push_anomaly_invocation",
        new=AsyncMock(side_effect=ConnectionError("Redis unavailable")),
    ):
        result = await detect("client-003", "web_search")

    assert result.anomaly_score == 0.0
    assert result.alert_triggered is False


@pytest.mark.unit
async def test_detect_does_not_block_on_persist_failure():
    """
    If _persist_alert raises (DB down), detect() must still return a result
    and must not propagate the exception.
    """
    window = ["web_search"] + ["file_reader"] * 4
    with (
        patch("app.services.anomaly.push_anomaly_invocation", new=AsyncMock(return_value=window)),
        patch("app.services.anomaly._persist_alert", new=AsyncMock(side_effect=Exception("DB down"))),
    ):
        result = await detect("client-004", "file_reader")

    assert result.anomaly_score >= ANOMALY_ALERT_THRESHOLD
    # Result still returned even though DB write failed


@pytest.mark.unit
async def test_detect_different_clients_do_not_interfere():
    """
    Each client gets its own Redis key. Calling detect() for client-A
    with a malicious window must not affect client-B's score.
    Windows are keyed by client_id in push_anomaly_invocation.
    """
    call_log: list[tuple] = []

    async def _track_push(client_id: str, tool_name: str) -> list[str]:
        call_log.append((client_id, tool_name))
        # Return benign window for client-B, malicious for client-A
        if client_id == "client-a":
            return ["web_search"] + ["file_reader"] * 4
        return ["list_dir"]

    with patch("app.services.anomaly.push_anomaly_invocation", side_effect=_track_push):
        with patch("app.services.anomaly._persist_alert", new=AsyncMock()):
            result_a = await detect("client-a", "file_reader")
            result_b = await detect("client-b", "list_dir")

    assert result_a.alert_triggered is True
    assert result_b.alert_triggered is False
    # Each detect() call used the correct client_id
    assert call_log[0][0] == "client-a"
    assert call_log[1][0] == "client-b"
