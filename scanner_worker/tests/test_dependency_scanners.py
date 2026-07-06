"""
Unit tests — CR-12 (WP-B2) multi-ecosystem dependency scanner layers.

Each scanner function takes an injected `run` callable (matching
scan_engine._run's `(cmd, cwd=None, timeout=..., env=None) -> (rc, stdout,
stderr)` signature) so these tests never spawn a real subprocess or require
osv-scanner/npm/go/govulncheck to be installed.

Run: python -m pytest scanner_worker/tests/test_dependency_scanners.py -v
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

from scanner_worker import dependency_scanners as ds

_CFG = {"scanners": {
    "osv_scanner": {"enabled": True},
    "npm_audit": {"enabled": True},
    "govulncheck": {"enabled": True},
}}


def _run_returning(rc: int, stdout: str, stderr: str = ""):
    async def _fake(cmd, cwd=None, timeout=120, env=None):
        return rc, stdout, stderr
    return _fake


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# OSV-Scanner
# ---------------------------------------------------------------------------

def test_osv_scanner_missing_binary_is_missing_tool():
    with patch("shutil.which", return_value=None):
        findings = _run(ds.run_osv_scanner(_run_returning(0, ""), "/repo", _CFG))
    assert len(findings) == 1
    assert findings[0]["missing_tool"] is True
    assert findings[0]["block"] is False


def test_osv_scanner_disabled_returns_nothing():
    cfg = {"scanners": {"osv_scanner": {"enabled": False}}}
    findings = _run(ds.run_osv_scanner(_run_returning(0, ""), "/repo", cfg))
    assert findings == []


def test_osv_scanner_parses_severity_from_database_specific():
    report = {"results": [{
        "source": {"path": "requirements.txt"},
        "packages": [{
            "package": {"name": "flask", "version": "1.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{
                "id": "GHSA-xxxx", "aliases": ["CVE-2023-0001"],
                "summary": "bad thing",
                "database_specific": {"severity": "CRITICAL"},
            }],
            "groups": [{"ids": ["GHSA-xxxx", "CVE-2023-0001"], "fixedVersions": ["1.1"]}],
        }],
    }]}
    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        findings = _run(ds.run_osv_scanner(
            _run_returning(1, json.dumps(report)), "/repo", _CFG))
    assert len(findings) == 1
    f = findings[0]
    assert f["severity"] == "critical"
    assert f["vuln_id"] == "GHSA-xxxx"
    assert "CVE-2023-0001" in f["aliases"]
    assert f["fix_versions"] == ["1.1"]
    assert f["block"] is False  # worker never decides block for dependency findings


def test_osv_scanner_cvss_numeric_score_bucketed():
    vuln = {"id": "GHSA-y", "severity": [{"type": "CVSS_V3", "score": "8.1"}]}
    sev, score = ds._osv_severity(vuln)
    assert sev == "high"
    assert score == 8.1


def test_osv_scanner_unparseable_json_forces_review_required():
    with patch("shutil.which", return_value="/usr/bin/osv-scanner"):
        findings = _run(ds.run_osv_scanner(_run_returning(0, "not json"), "/repo", _CFG))
    assert len(findings) == 1
    assert findings[0]["review_required"] is True
    assert findings[0]["block"] is False


# ---------------------------------------------------------------------------
# npm audit
# ---------------------------------------------------------------------------

def test_npm_audit_no_package_json_is_noop(tmp_path):
    findings = _run(ds.run_npm_audit(_run_returning(0, "{}"), str(tmp_path), _CFG))
    assert findings == []


def test_npm_audit_missing_lockfile_is_review_required(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    findings = _run(ds.run_npm_audit(_run_returning(0, "{}"), str(tmp_path), _CFG))
    assert len(findings) == 1
    assert findings[0]["review_required"] is True
    assert findings[0]["block"] is False
    assert findings[0]["missing_tool"] is False


def test_npm_audit_missing_binary_is_missing_tool(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    with patch("shutil.which", return_value=None):
        findings = _run(ds.run_npm_audit(_run_returning(0, "{}"), str(tmp_path), _CFG))
    assert len(findings) == 1
    assert findings[0]["missing_tool"] is True


def test_npm_audit_parses_vulnerabilities(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    report = {"vulnerabilities": {
        "lodash": {
            "severity": "high", "range": "<4.17.21", "isDirect": True,
            "fixAvailable": {"name": "lodash", "version": "4.17.21"},
            "via": [{"source": 1234, "title": "Prototype Pollution", "url": "https://x/GHSA-abc"}],
        }
    }}
    with patch("shutil.which", return_value="/usr/bin/npm"):
        findings = _run(ds.run_npm_audit(_run_returning(0, json.dumps(report)), str(tmp_path), _CFG))
    assert len(findings) == 1
    f = findings[0]
    assert f["package"] == "lodash"
    assert f["severity"] == "high"
    assert f["fix_versions"] == ["4.17.21"]
    assert f["block"] is False


def test_npm_audit_never_runs_install(tmp_path):
    """Hardening: npm audit must use --package-lock-only, NEVER `npm install`
    (which would execute the submitted package's own install scripts)."""
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "package-lock.json").write_text("{}")
    captured = {}

    async def _fake(cmd, cwd=None, timeout=120, env=None):
        captured["cmd"] = cmd
        return 0, "{}", ""

    with patch("shutil.which", return_value="/usr/bin/npm"):
        _run(ds.run_npm_audit(_fake, str(tmp_path), _CFG))
    assert "install" not in captured["cmd"]
    assert "--package-lock-only" in captured["cmd"]


# ---------------------------------------------------------------------------
# govulncheck
# ---------------------------------------------------------------------------

def test_govulncheck_no_go_mod_is_noop(tmp_path):
    findings = _run(ds.run_govulncheck(_run_returning(0, ""), str(tmp_path), _CFG))
    assert findings == []


def test_govulncheck_missing_binary_is_missing_tool(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    with patch("shutil.which", return_value=None):
        findings = _run(ds.run_govulncheck(_run_returning(0, ""), str(tmp_path), _CFG))
    assert len(findings) == 1
    assert findings[0]["missing_tool"] is True


def test_govulncheck_module_load_failure_forces_review_required_never_pass(tmp_path):
    """Core security property (CR-12): a submitter can break their own go.mod
    to make govulncheck fail to load. That must NEVER present as a clean
    pass — it must be a distinct, forced review_required outcome."""
    (tmp_path / "go.mod").write_text("module x\n")
    with patch("shutil.which", return_value="/usr/bin/go"):
        findings = _run(ds.run_govulncheck(
            _run_returning(1, "", "go: updates to go.mod needed"), str(tmp_path), _CFG))
    assert len(findings) == 1
    f = findings[0]
    assert f["review_required"] is True
    assert f["block"] is False
    assert f["missing_tool"] is False
    assert "INCOMPLETE" in f["message"]


def test_govulncheck_reachable_finding_is_surfaced_not_blocked_by_worker(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    stream = "\n".join([
        json.dumps({"osv": {
            "id": "GO-2023-0001", "aliases": ["CVE-2023-9999"],
            "summary": "bad Go thing",
            "database_specific": {"severity": "CRITICAL"},
            "affected": [{"package": {"name": "golang.org/x/text"},
                         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.4.0"}]}]}],
        }}),
        json.dumps({"finding": {"osv": "GO-2023-0001", "trace": [{"function": "main"}]}}),
    ])
    with patch("shutil.which", return_value="/usr/bin/govulncheck"):
        findings = _run(ds.run_govulncheck(_run_returning(3, stream, ""), str(tmp_path), _CFG))
    assert len(findings) == 1
    f = findings[0]
    assert f["vuln_id"] == "GO-2023-0001"
    assert f["severity"] == "critical"
    assert f["reachable"] is True
    assert f["fix_versions"] == ["0.4.0"]
    assert f["block"] is False  # evaluator decides block, not the worker
    assert f["review_required"] is False


def test_govulncheck_clean_run_no_findings(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    with patch("shutil.which", return_value="/usr/bin/govulncheck"):
        findings = _run(ds.run_govulncheck(_run_returning(0, "", ""), str(tmp_path), _CFG))
    assert findings == []
