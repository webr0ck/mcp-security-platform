"""
6.4 — eliminate the write-only anomaly-baseline dead code (drift guard).

The scorer (_score_window / detect) uses static keyword/window heuristics only.
A separate update_baseline_async() wrote an anomaly_baselines row that NOTHING
ever read — write-only dead code that misrepresented the platform as having a
learned baseline. We removed it (roadmap decision B: an honest heuristic beats
dead code that implies a model that does not exist).

These tests lock that decision in so the dead writer cannot creep back, and
confirm the advisory heuristic scorer remains the supported entry point.
"""
from __future__ import annotations

import pytest

from app.services import anomaly


@pytest.mark.unit
def test_write_only_baseline_writer_is_removed():
    """The unreferenced update_baseline_async must not exist — its presence
    implied a learned baseline the scorer never consulted."""
    assert not hasattr(anomaly, "update_baseline_async")


@pytest.mark.unit
def test_advisory_heuristic_scorer_is_the_entry_point():
    """detect() (aliased evaluate_anomaly) remains the supported scorer."""
    assert hasattr(anomaly, "detect")
    assert anomaly.evaluate_anomaly is anomaly.detect


@pytest.mark.unit
def test_module_docstring_does_not_claim_a_learned_baseline():
    """Drift guard: the module must not reference the removed write-only baseline
    or imply a learned/statistical model it does not have."""
    doc = (anomaly.__doc__ or "").lower()
    assert "update_baseline_async" not in doc
