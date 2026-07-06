"""
Unit tests — scan evaluator policy logic (CR-14 / WP-B1).

_decide_status is the ONLY place that turns raw scanner findings into an
adjudication verdict. These tests pin down that the policy is unchanged
from the pre-CR-14 in-proxy pipeline (submission_scanner._set_status):
  - any finding with block=True            -> 'blocked'
  - worker_error set, or missing_tool=True -> 'error' (fail closed)
  - otherwise                              -> 'passed'

Run: pytest proxy/tests/unit/test_scan_evaluator.py -v
"""
from __future__ import annotations

from app.services.scan_evaluator import _decide_status


def test_no_findings_passes():
    assert _decide_status([], None) == "passed"


def test_blocking_finding_blocks():
    findings = [{"scanner": "trufflehog", "block": True, "severity": "critical"}]
    assert _decide_status(findings, None) == "blocked"


def test_missing_tool_is_error_not_pass():
    findings = [{"scanner": "pip-audit", "missing_tool": True, "block": False}]
    assert _decide_status(findings, None) == "error"


def test_missing_tool_never_silently_overridden_by_non_blocking_findings():
    findings = [
        {"scanner": "custom", "block": False, "severity": "warning"},
        {"scanner": "mcp_checker", "missing_tool": True, "block": False},
    ]
    assert _decide_status(findings, None) == "error"


def test_block_takes_precedence_over_missing_tool():
    findings = [
        {"scanner": "trufflehog", "block": True},
        {"scanner": "pip-audit", "missing_tool": True, "block": False},
    ]
    assert _decide_status(findings, None) == "blocked"


def test_worker_error_is_error_even_with_clean_findings():
    """A worker crash/clone-failure must never present as a pass."""
    assert _decide_status([], "clone_failed: private repo, no access") == "error"


def test_worker_error_does_not_override_block():
    findings = [{"scanner": "trufflehog", "block": True}]
    assert _decide_status(findings, "crashed: OOMKilled") == "blocked"


def test_skipped_findings_do_not_block_or_error():
    """A 'skipped' finding (e.g. pip-audit with no requirements.txt) is neither."""
    findings = [{"scanner": "pip-audit", "skipped": True, "block": False, "severity": "info"}]
    assert _decide_status(findings, None) == "passed"
