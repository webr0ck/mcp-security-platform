"""
Multi-ecosystem dependency CVE scanner layers (CR-12 / WP-B2).

Adds OSV-Scanner (broad, multi-ecosystem), npm audit (Node), and govulncheck
(Go, reachability-aware) alongside the existing pip-audit layer in
scan_engine.py. Same execution/adjudication split as the rest of this
package (see scanner_worker/README.md): every function here returns RAW
findings only. In particular `block` is ALWAYS False from this module —
dependency-CVE block/review-required policy is decided centrally by the
evaluator (proxy/app/services/dependency_policy.py) AFTER alias-collapsing
findings across every scanner layer. A single layer here does not have the
full picture: e.g. pip-audit's own JSON output carries no severity/CVSS at
all, only a vuln_id — the evaluator only learns the real severity once that
finding is alias-collapsed with an OSV-Scanner finding for the same CVE (or
is left "unknown" -> forced review-required if no other layer covers it).

Normalized finding schema (verbatim from
Codex_review/___issue-12-multi-ecosystem-dependency-gate.md):
    scanner, ecosystem, package, version, vuln_id, aliases, severity,
    cvss_score, fix_versions, source, reachable, direct_dependency, block,
    waiver_id, message
Plus two worker-only signal fields (consistent with the existing
trufflehog/mcp_checker/pip-audit pattern in scan_engine.py):
    missing_tool  - this scanner's binary was not available; the evaluator
                    maps ANY missing_tool=True finding to scan_status='error'
                    (fail closed, never a silent pass).
    review_required - this scanner's own analysis is structurally incomplete
                    or ambiguous (e.g. Go module load failure, npm project
                    with no lockfile, unparseable output). Distinct from
                    missing_tool: the binary ran, but its answer cannot be
                    trusted as a clean pass.
Plus file/line for the existing review-UI renderer's `f.get("file","")`/
`f.get("line",0)` calls (proxy/app/routers/portal.py) — dependency findings
have no line number, so line is always 0 and file is the manifest path.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITIES = ("critical", "high", "medium", "low")
# CVSS v3/v4 base score -> bucket, used only when an advisory gives a numeric
# score but no explicit severity label (OSV's database_specific.severity is
# preferred whenever present — this is the fallback).
_CVSS_BUCKETS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low"))


def _dep_finding(
    *,
    scanner: str,
    ecosystem: str | None,
    package: str | None,
    version: str | None,
    vuln_id: str | None,
    aliases: list[str] | None = None,
    severity: str = "unknown",
    cvss_score: float | None = None,
    fix_versions: list[str] | None = None,
    source: str = "",
    reachable: bool | None = None,
    direct_dependency: bool | None = None,
    message: str = "",
    missing_tool: bool = False,
    review_required: bool = False,
) -> dict[str, Any]:
    return {
        "scanner": scanner,
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "vuln_id": vuln_id,
        "aliases": aliases or [],
        "severity": severity,
        "cvss_score": cvss_score,
        "fix_versions": fix_versions or [],
        "source": source,
        "reachable": reachable,
        "direct_dependency": direct_dependency,
        # Always False — see module docstring. The evaluator computes the
        # real verdict after alias-collapse; this field is never trusted by
        # scan_evaluator._decide_status for scanners that set vuln_id.
        "block": False,
        "waiver_id": None,
        "message": message,
        "missing_tool": missing_tool,
        "review_required": review_required,
        "file": source,
        "line": 0,
    }


def _bucket_from_score(score: float) -> str:
    for threshold, label in _CVSS_BUCKETS:
        if score >= threshold:
            return label
    return "low"


def _osv_severity(vuln: dict) -> tuple[str, float | None]:
    """Extract (severity_bucket, cvss_score) from an OSV vulnerability object.

    Never infers severity from fix-version presence (CR-12 hardening
    requirement) — only from database_specific.severity or a parseable CVSS
    numeric score. Falls back to 'unknown' (never a guess) so the evaluator
    forces review-required rather than silently treating it as low risk.
    """
    db_spec = vuln.get("database_specific") or {}
    raw = db_spec.get("severity")
    if isinstance(raw, str) and raw.strip().lower() in _SEVERITIES:
        return raw.strip().lower(), None
    for sev in vuln.get("severity", []) or []:
        score_str = sev.get("score", "")
        try:
            score = float(score_str)
        except (TypeError, ValueError):
            continue
        return _bucket_from_score(score), score
    return "unknown", None


def _osv_fix_versions(pkg: dict, vuln_id: str) -> list[str]:
    out: list[str] = []
    for group in pkg.get("groups", []) or []:
        if vuln_id in (group.get("ids") or []):
            out.extend(group.get("fixedVersions") or [])
    return sorted(set(out))


async def run_osv_scanner(run, repo_path: str, config: dict) -> list[dict]:
    """Broad multi-ecosystem scan via OSV-Scanner (Go, npm, PyPI, and more).

    `run` is scan_engine._run (subprocess helper), passed in rather than
    imported to keep this module independently unit-testable without
    spinning up real subprocesses.
    """
    cfg = config.get("scanners", {}).get("osv_scanner", {})
    if not cfg.get("enabled", True):
        return []
    if not shutil.which("osv-scanner"):
        logger.error("osv-scanner not found; broad multi-ecosystem CVE scan did not run")
        return [_dep_finding(
            scanner="osv-scanner", ecosystem=None, package=None, version=None, vuln_id=None,
            severity="critical", source="", missing_tool=True,
            message="osv-scanner binary not found in scanner-worker environment; broad "
                    "multi-ecosystem dependency CVE scan did not run",
        )]

    timeout = int(cfg.get("timeout_seconds", 180))
    rc, stdout, stderr = await run(
        ["osv-scanner", "--format=json", "--recursive", repo_path], timeout=timeout,
    )
    # osv-scanner exits 1 when it found vulnerabilities (not a tool error) and
    # 0 when clean; anything else plus empty stdout is a genuine failure —
    # EXCEPT "no package sources found", which is osv-scanner's own way of
    # saying the repo has zero manifests it recognizes across ANY ecosystem
    # (e.g. a bare single-file Python script with no requirements.txt/
    # package.json/go.mod at all). That is not incomplete coverage, it is
    # correctly-complete coverage of an empty dependency surface — the same
    # repo that pip-audit already reports as a benign "skipped" info finding
    # for the Python-specific case. Treating it as review-required would
    # force every dependency-less repo into manual review forever.
    if rc not in (0, 1) and not stdout.strip():
        if "no package sources found" in stderr.lower():
            logger.info("osv-scanner found no manifests of any ecosystem in %s; nothing to scan", repo_path)
            return []
        logger.warning("osv-scanner exited %s with no output (stderr=%s)", rc, stderr[-300:])
        return [_dep_finding(
            scanner="osv-scanner", ecosystem=None, package=None, version=None, vuln_id=None,
            severity="unknown", source="", review_required=True,
            message=f"osv-scanner exited {rc} with no output; broad dependency CVE scan is incomplete",
        )]
    if not stdout.strip():
        return []
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("osv-scanner output not valid JSON: %s", exc)
        return [_dep_finding(
            scanner="osv-scanner", ecosystem=None, package=None, version=None, vuln_id=None,
            severity="unknown", source="", review_required=True,
            message=f"osv-scanner produced unparseable output; broad dependency CVE scan result "
                    f"is unreliable: {exc}",
        )]

    findings: list[dict] = []
    for result in report.get("results", []) or []:
        source_path = (result.get("source") or {}).get("path", "")
        for pkg in result.get("packages", []) or []:
            p = pkg.get("package", {}) or {}
            name, version, ecosystem = p.get("name", ""), p.get("version", ""), p.get("ecosystem", "")
            for vuln in pkg.get("vulnerabilities", []) or []:
                vuln_id = vuln.get("id", "")
                sev, cvss = _osv_severity(vuln)
                findings.append(_dep_finding(
                    scanner="osv-scanner", ecosystem=ecosystem, package=name, version=version,
                    vuln_id=vuln_id, aliases=vuln.get("aliases", []) or [], severity=sev,
                    cvss_score=cvss, fix_versions=_osv_fix_versions(pkg, vuln_id),
                    source=source_path,
                    message=vuln.get("summary") or f"{name}@{version}: {vuln_id}",
                ))
    return findings


async def run_npm_audit(run, repo_path: str, config: dict) -> list[dict]:
    """npm-native lockfile audit. Requires package-lock.json/npm-shrinkwrap.json.

    A Node project WITHOUT a lockfile cannot be scanned deterministically —
    per CR-12 hardening this is review-required, never a silent pass and
    never a block (the submitter's dependency graph genuinely can't be
    pinned down, that's not the same as a known vulnerability).
    """
    cfg = config.get("scanners", {}).get("npm_audit", {})
    if not cfg.get("enabled", True):
        return []
    if not (Path(repo_path) / "package.json").is_file():
        return []  # not a Node project

    lockfile = None
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        candidate = Path(repo_path) / name
        if candidate.is_file():
            lockfile = candidate
            break
    if lockfile is None:
        return [_dep_finding(
            scanner="npm-audit", ecosystem="npm", package=None, version=None, vuln_id=None,
            severity="unknown", source="package.json", review_required=True,
            message="Node project has no package-lock.json/npm-shrinkwrap.json — dependency "
                    "versions are not pinned, so npm audit cannot run a deterministic scan. "
                    "Flagged for manual review rather than a silent pass.",
        )]
    if not shutil.which("npm"):
        logger.error("npm not found; Node dependency CVE scan did not run")
        return [_dep_finding(
            scanner="npm-audit", ecosystem="npm", package=None, version=None, vuln_id=None,
            severity="critical", source=lockfile.name, missing_tool=True,
            message="npm binary not found in scanner-worker environment; Node dependency CVE "
                    "scan did not run",
        )]

    timeout = int(cfg.get("timeout_seconds", 120))
    # --package-lock-only: audit the lockfile as committed, WITHOUT running
    # `npm install`. Deliberate: `npm install` executes the submitted
    # package's own preinstall/postinstall scripts (arbitrary attacker code)
    # inside this container — exactly the class of execution CR-14's
    # scanner-worker isolation exists to contain. Never install submitted
    # packages here.
    rc, stdout, stderr = await run(
        ["npm", "audit", "--json", "--package-lock-only"], cwd=repo_path, timeout=timeout,
    )
    if not stdout.strip():
        logger.warning("npm audit produced no output (rc=%s stderr=%s)", rc, stderr[-300:])
        return [_dep_finding(
            scanner="npm-audit", ecosystem="npm", package=None, version=None, vuln_id=None,
            severity="unknown", source=lockfile.name, review_required=True,
            message=f"npm audit produced no output (exit {rc}); Node dependency CVE scan did "
                    "not complete",
        )]
    try:
        report = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("npm audit output not valid JSON: %s", exc)
        return [_dep_finding(
            scanner="npm-audit", ecosystem="npm", package=None, version=None, vuln_id=None,
            severity="unknown", source=lockfile.name, review_required=True,
            message=f"npm audit output was unparseable: {exc}",
        )]

    findings: list[dict] = []
    for pkg_name, entry in (report.get("vulnerabilities") or {}).items():
        sev = str(entry.get("severity") or "unknown").lower()
        if sev not in _SEVERITIES:
            sev = "unknown"
        fix = entry.get("fixAvailable")
        fix_versions = [fix["version"]] if isinstance(fix, dict) and fix.get("version") else []
        via = [v for v in (entry.get("via") or []) if isinstance(v, dict)]
        if not via:
            findings.append(_dep_finding(
                scanner="npm-audit", ecosystem="npm", package=pkg_name,
                version=entry.get("range", ""), vuln_id=f"npm-{pkg_name}", severity=sev,
                fix_versions=fix_versions, source=lockfile.name,
                direct_dependency=entry.get("isDirect"),
                message=f"{pkg_name}: {sev} severity advisory",
            ))
            continue
        for v in via:
            vuln_id = v.get("source") and f"GHSA-{v['source']}" or v.get("url", "").rsplit("/", 1)[-1]
            findings.append(_dep_finding(
                scanner="npm-audit", ecosystem="npm", package=pkg_name,
                version=entry.get("range", ""), vuln_id=v.get("title") or vuln_id or f"npm-{pkg_name}",
                aliases=[str(v["source"])] if v.get("source") else [],
                severity=sev, fix_versions=fix_versions, source=lockfile.name,
                direct_dependency=entry.get("isDirect"),
                message=v.get("title") or f"{pkg_name}: {sev} severity advisory",
            ))
    return findings


async def run_govulncheck(run, repo_path: str, config: dict) -> list[dict]:
    """Go reachability-aware vulnerability check via govulncheck.

    Core security property (CR-12): if the module fails to load/build, or
    output is otherwise incomplete, this MUST return a distinct
    review_required finding — NEVER treat "incomplete" as a clean pass. A
    submitter can deliberately break their own go.mod to force this exact
    downgrade path, so "incomplete but passing" would be an
    attacker-controlled fail-open. OSV-Scanner's independent go.mod-manifest
    parse (run in parallel, ecosystem-agnostic) remains the coverage floor
    for this repo's Go dependencies when govulncheck itself can't run.
    """
    cfg = config.get("scanners", {}).get("govulncheck", {})
    if not cfg.get("enabled", True):
        return []
    if not (Path(repo_path) / "go.mod").is_file():
        return []  # not a Go project

    if not shutil.which("govulncheck") or not shutil.which("go"):
        logger.error("govulncheck/go not found; Go dependency CVE scan did not run")
        return [_dep_finding(
            scanner="govulncheck", ecosystem="Go", package=None, version=None, vuln_id=None,
            severity="critical", source="go.mod", missing_tool=True,
            message="govulncheck/go binary not found in scanner-worker environment; Go "
                    "dependency CVE scan did not run",
        )]

    timeout = int(cfg.get("timeout_seconds", 240))
    env = os.environ.copy()
    env.setdefault("GOFLAGS", "-mod=mod")
    env.setdefault("GOPROXY", "https://proxy.golang.org,direct")
    env.setdefault("GOSUMDB", "sum.golang.org")
    env.setdefault("GOPATH", os.path.join(repo_path, ".gocache-gopath"))
    env.setdefault("GOCACHE", os.path.join(repo_path, ".gocache-build"))
    rc, stdout, stderr = await run(
        ["govulncheck", "-json", "./..."], cwd=repo_path, timeout=timeout, env=env,
    )

    osv_by_id: dict[str, dict] = {}
    trace_by_osv: dict[str, list] = {}
    saw_any_stream_object = False
    for raw_line in stdout.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        saw_any_stream_object = True
        if "osv" in obj:
            osv = obj["osv"]
            osv_by_id[osv.get("id", "")] = osv
        elif "finding" in obj:
            f = obj["finding"]
            trace_by_osv.setdefault(f.get("osv", ""), []).append(f.get("trace"))

    # rc 0 = no vulns found, module loaded cleanly. rc 3 = govulncheck's own
    # "vulnerabilities found" exit code. Anything else, OR a run that
    # produced no parseable stream objects at all despite non-zero stderr,
    # means the module failed to load/build — incomplete, not clean.
    module_load_failed = rc not in (0, 3) and not saw_any_stream_object

    if module_load_failed:
        detail = stderr.strip()[-500:] if stderr.strip() else "(no stderr captured)"
        return [_dep_finding(
            scanner="govulncheck", ecosystem="Go", package=None, version=None, vuln_id=None,
            severity="unknown", source="go.mod", review_required=True,
            message="govulncheck could not load the Go module (build/module-load failure) — "
                    "Go reachability analysis is INCOMPLETE, not clean. Falling back to "
                    "OSV-Scanner's manifest-only coverage for this repo's Go dependencies; a "
                    f"reviewer must confirm no reachable vulnerability was missed. detail: {detail}",
        )]

    findings: list[dict] = []
    for osv_id, osv in osv_by_id.items():
        reachable = any(trace_by_osv.get(osv_id) or [])
        sev, cvss = _osv_severity(osv)
        pkg_name, fix_versions = None, []
        affected = osv.get("affected", []) or []
        if affected:
            pkg_name = (affected[0].get("package") or {}).get("name")
            for rng in affected[0].get("ranges", []) or []:
                for ev in rng.get("events", []) or []:
                    if "fixed" in ev:
                        fix_versions.append(ev["fixed"])
        findings.append(_dep_finding(
            scanner="govulncheck", ecosystem="Go", package=pkg_name, version=None,
            vuln_id=osv_id, aliases=osv.get("aliases", []) or [], severity=sev, cvss_score=cvss,
            fix_versions=sorted(set(fix_versions)), source="go.mod", reachable=reachable,
            message=osv.get("summary") or f"{osv_id}: Go module vulnerability",
        ))
    return findings
