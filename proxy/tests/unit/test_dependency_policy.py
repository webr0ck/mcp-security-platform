"""
Unit tests — CR-12 (WP-B2) dependency-CVE policy engine (alias collapse,
severity policy, waiver matching). This module is the trusted, verdict-
computing side of the multi-ecosystem CVE gate — it never touches
attacker-controlled repo content, only structured findings the scanner-
worker already produced.

Run: pytest proxy/tests/unit/test_dependency_policy.py -v
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.services.dependency_policy import collapse_aliases, evaluate_dependency_findings


def _finding(**kw):
    base = {
        "scanner": "osv-scanner", "ecosystem": "PyPI", "package": "requests",
        "version": "2.25.0", "vuln_id": "GHSA-xxxx", "aliases": ["CVE-2023-0001"],
        "severity": "critical", "cvss_score": 9.8, "fix_versions": ["2.31.0"],
        "source": "requirements.txt", "reachable": None, "direct_dependency": None,
        "block": False, "waiver_id": None, "message": "bad",
    }
    base.update(kw)
    return base


def _waiver(**kw):
    now = datetime.now(timezone.utc)
    base = {
        "waiver_id": "w-1", "package": "requests", "version": "2.25.0",
        "vuln_id": "GHSA-xxxx", "expires_at": now + timedelta(days=1), "revoked_at": None,
    }
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
# Fixture 1: Python-critical -> blocks
# ---------------------------------------------------------------------------

def test_python_critical_blocks():
    findings = [_finding()]
    result = evaluate_dependency_findings(findings, block_on="high")
    assert result["block"] is True
    assert result["review_required"] is False


# ---------------------------------------------------------------------------
# Alias collapse
# ---------------------------------------------------------------------------

def test_alias_collapse_pip_audit_and_osv_same_cve_one_group():
    """A vuln reported by both OSV-Scanner (severity known) and pip-audit
    (severity unknown, only a bare CVE id) must collapse to ONE group, and
    the group must inherit the known severity — not stay 'unknown'."""
    osv = _finding(scanner="osv-scanner", vuln_id="GHSA-xxxx", aliases=["CVE-2023-0001"],
                   severity="critical")
    pip = _finding(scanner="pip-audit", vuln_id="CVE-2023-0001", aliases=[],
                   severity="unknown", cvss_score=None)
    groups = collapse_aliases([osv, pip])
    assert len(groups) == 1
    assert groups[0]["severity"] == "critical"
    assert set(groups[0]["vuln_ids"]) == {"GHSA-xxxx", "CVE-2023-0001"}


def test_alias_collapse_unrelated_cves_stay_separate():
    a = _finding(vuln_id="GHSA-aaaa", aliases=["CVE-2023-0001"])
    b = _finding(vuln_id="GHSA-bbbb", aliases=["CVE-2023-0002"], package="flask")
    groups = collapse_aliases([a, b])
    assert len(groups) == 2


def test_pip_audit_alone_no_severity_forces_review_required():
    """pip-audit alone (no OSV-Scanner coverage, e.g. binary missing) never
    carries severity — the CR-12 hardening rule is: never infer, and
    'unknown' forces review, never a silent pass."""
    pip_only = _finding(scanner="pip-audit", vuln_id="CVE-2023-9999", aliases=[],
                        severity="unknown", cvss_score=None)
    result = evaluate_dependency_findings([pip_only], block_on="high")
    assert result["block"] is False
    assert result["review_required"] is True


# ---------------------------------------------------------------------------
# Severity threshold policy
# ---------------------------------------------------------------------------

def test_medium_severity_does_not_block_at_high_threshold():
    findings = [_finding(severity="medium", cvss_score=5.0)]
    result = evaluate_dependency_findings(findings, block_on="high")
    assert result["block"] is False
    assert result["review_required"] is False


def test_unknown_severity_never_inferred_from_fix_version_presence():
    """A finding with fix_versions present but no real severity data must
    still be 'unknown' -> review_required, never silently treated as safe or
    as automatically severe just because a fix exists."""
    findings = [_finding(severity="unknown", cvss_score=None, fix_versions=["9.9.9"])]
    result = evaluate_dependency_findings(findings, block_on="high")
    assert result["review_required"] is True
    assert result["block"] is False


# ---------------------------------------------------------------------------
# Go-native incomplete signal (no package/vuln_id — a structural marker)
# ---------------------------------------------------------------------------

def test_govulncheck_incomplete_signal_forces_review_required():
    signal = {
        "scanner": "govulncheck", "package": None, "vuln_id": None,
        "severity": "unknown", "review_required": True, "block": False,
        "message": "module load failure",
    }
    result = evaluate_dependency_findings([signal], block_on="high")
    assert result["review_required"] is True
    assert result["block"] is False


def test_govulncheck_incomplete_signal_survives_alongside_clean_osv_go_coverage():
    """Even if OSV-Scanner's manifest-only Go coverage found nothing, an
    incomplete govulncheck run must still force review — a clean OTHER
    scanner must never silently override the incomplete signal."""
    signal = {
        "scanner": "govulncheck", "package": None, "vuln_id": None,
        "severity": "unknown", "review_required": True, "block": False,
        "message": "module load failure",
    }
    result = evaluate_dependency_findings([signal], block_on="high")
    assert result["review_required"] is True


# ---------------------------------------------------------------------------
# Waivers — exact package+version+vuln_id match only
# ---------------------------------------------------------------------------

def test_valid_waiver_suppresses_block():
    findings = [_finding()]
    waivers = [_waiver()]
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert result["block"] is False
    assert result["review_required"] is False
    assert result["groups"][0]["waived"] is True
    assert result["groups"][0]["waiver_id"] == "w-1"


def test_waiver_does_not_suppress_different_version():
    findings = [_finding(version="2.31.0")]
    waivers = [_waiver(version="2.25.0")]  # waiver for a DIFFERENT version
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert result["block"] is True
    assert result["groups"][0]["waived"] is False


def test_waiver_does_not_suppress_different_package():
    findings = [_finding(package="urllib3")]
    waivers = [_waiver(package="requests")]
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert result["block"] is True


def test_expired_waiver_does_not_suppress():
    findings = [_finding()]
    waivers = [_waiver(expires_at=datetime.now(timezone.utc) - timedelta(days=1))]
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert result["block"] is True


def test_revoked_waiver_does_not_suppress():
    findings = [_finding()]
    waivers = [_waiver(revoked_at=datetime.now(timezone.utc))]
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert result["block"] is True


def test_waived_finding_stays_in_groups_visible_not_deleted():
    """Waived findings must remain visible (with waiver_id set), never
    silently dropped from the result."""
    findings = [_finding()]
    waivers = [_waiver()]
    result = evaluate_dependency_findings(findings, waivers, block_on="high")
    assert len(result["groups"]) == 1
    assert result["groups"][0]["package"] == "requests"
