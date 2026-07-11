"""
Unit tests — build evaluator policy logic (CR-01 / WP-B3 phase 2c).

_decide_build_status is the ONLY place that turns a build_results row into
a deployment_status verdict. Pure function tests, no DB — same style as
test_scan_evaluator.py.

Run: pytest proxy/tests/unit/test_build_evaluator.py -v
"""
from __future__ import annotations

from app.services.build_evaluator import _decide_build_status


def test_worker_error_is_failed_never_built():
    assert _decide_build_status(None, "digest mismatch: refusing to build") == "failed"
    assert _decide_build_status("sha256:stub-abc123", "crashed: OOMKilled") == "failed"


def test_digest_present_is_built():
    assert _decide_build_status("sha256:stub-abc123", None) == "built"


def test_no_digest_and_no_error_is_still_failed():
    """A build worker that produced neither a digest nor an explicit error
    must still fail closed — success is NEVER inferred from the absence of
    an error alone."""
    assert _decide_build_status(None, None) == "failed"


def test_empty_string_digest_is_failed():
    assert _decide_build_status("", None) == "failed"
