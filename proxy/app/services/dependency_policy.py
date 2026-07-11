"""
Dependency-CVE policy engine (CR-12 / WP-B2) — the evaluator-side half of the
multi-ecosystem dependency gate. Lives entirely on the trusted (proxy_app)
side of the CR-14 execution/adjudication split: this module only ever reads
structured JSON the scanner-worker already wrote to scan_raw_results, never
attacker-controlled repo content.

Responsibilities:
  1. Alias-collapse: a vulnerability reported under different identifier
     namespaces by different scanner layers (CVE-xxxx from pip-audit,
     GHSA-xxxx from OSV-Scanner, GO-xxxx from govulncheck, RUSTSEC-xxxx,
     ...) must count as ONE finding group, not double/triple-count.
  2. Severity policy: block on severity >= configured threshold. Severity is
     NEVER inferred from fix-version presence (CR-12 hardening) — only from
     advisory data (OSV database_specific.severity / CVSS score). "unknown"
     severity forces review-required, never a silent pass.
  3. Waiver application: an active (non-expired, non-revoked) waiver
     matching a finding's EXACT package + version + vuln_id (or one of its
     aliases — same underlying vuln, not fuzzy matching) suppresses
     block/review-required for that finding group, but the finding stays
     visible with waiver_id set (see scan_waivers.py — waived findings are
     never deleted or hidden from the SBOM/review UI).

`_decide_status` in scan_evaluator.py calls `evaluate_dependency_findings`
and folds its block/review_required flags into the existing
blocked > error > review_required > passed precedence.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_SCAN_CONFIG_PATH = Path(__file__).resolve().parents[2] / "scan-config.yaml"
_SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_DEFAULT_BLOCK_ON = "high"

# Scanner names that participate in the CR-12 dependency-CVE pipeline.
# Non-CVE scanners (trufflehog, custom_rules, mcp_checker) are untouched by
# this module and keep computing their own `block` as before (see
# scan_evaluator._decide_status).
_DEPENDENCY_SCANNERS = {"pip-audit", "osv-scanner", "npm-audit", "govulncheck"}


def _load_block_on() -> str:
    try:
        with open(_SCAN_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        block_on = cfg.get("scanners", {}).get("dependency_audit", {}).get("block_on", _DEFAULT_BLOCK_ON)
        if block_on not in _SEVERITY_RANK:
            logger.warning("dependency_audit.block_on=%r not a known severity; defaulting to %r",
                           block_on, _DEFAULT_BLOCK_ON)
            return _DEFAULT_BLOCK_ON
        return block_on
    except FileNotFoundError:
        logger.warning("scan-config.yaml not found; defaulting dependency block_on=%r", _DEFAULT_BLOCK_ON)
        return _DEFAULT_BLOCK_ON
    except Exception as exc:
        logger.error("failed to load scan-config.yaml dependency_audit.block_on: %s", exc)
        return _DEFAULT_BLOCK_ON


def _is_dependency_finding(f: dict) -> bool:
    """A real (package, vuln) finding — not an infra signal (missing_tool /
    no-lockfile / incomplete-module) marker, which carries no package/vuln_id."""
    return bool(f.get("scanner") in _DEPENDENCY_SCANNERS and (f.get("vuln_id") or f.get("package")))


class _UnionFind:
    def __init__(self) -> None:
        self._parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self._parent.setdefault(x, x)
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def collapse_aliases(dep_findings: list[dict]) -> list[dict]:
    """Group findings whose vuln_id/aliases identifier sets overlap into one
    group. Real-world advisory identifiers (CVE/GHSA/GO/RUSTSEC) are globally
    unique to a single underlying vulnerability, so grouping purely on
    identifier-string overlap (ignoring package-name spelling differences
    across scanners) is safe and avoids inventing fuzzy package-matching.
    """
    uf = _UnionFind()
    ids_per_finding: list[list[str]] = []
    for f in dep_findings:
        ids = [str(f["vuln_id"])] if f.get("vuln_id") else []
        ids += [str(a) for a in (f.get("aliases") or [])]
        ids_per_finding.append(ids)
        for a, b in zip(ids, ids[1:]):
            uf.union(a, b)

    # Findings with NO identifier at all (should not normally happen for a
    # dependency finding, but fail safe) get their own singleton group keyed
    # by object identity so they are never silently dropped.
    groups: dict[str, list[dict]] = {}
    for f, ids in zip(dep_findings, ids_per_finding):
        key = uf.find(ids[0]) if ids else f"__no_id__:{id(f)}"
        groups.setdefault(key, []).append(f)

    out = []
    for members in groups.values():
        all_ids: set[str] = set()
        for m in members:
            if m.get("vuln_id"):
                all_ids.add(str(m["vuln_id"]))
            all_ids.update(str(a) for a in (m.get("aliases") or []))

        severities = [m.get("severity", "unknown") for m in members if m.get("severity")]
        concrete = [s for s in severities if s != "unknown" and s in _SEVERITY_RANK]
        severity = max(concrete, key=lambda s: _SEVERITY_RANK[s]) if concrete else "unknown"
        cvss_scores = [m["cvss_score"] for m in members if m.get("cvss_score") is not None]

        fix_versions: set[str] = set()
        for m in members:
            fix_versions.update(m.get("fix_versions") or [])

        package = next((m.get("package") for m in members if m.get("package")), None)
        version = next((m.get("version") for m in members if m.get("version")), None)
        ecosystem = next((m.get("ecosystem") for m in members if m.get("ecosystem")), None)
        reachable_values = [m.get("reachable") for m in members if m.get("reachable") is not None]
        reachable = True if any(reachable_values) else (False if reachable_values else None)
        direct_dependency = next((m.get("direct_dependency") for m in members
                                  if m.get("direct_dependency") is not None), None)
        scanners = sorted({m.get("scanner", "") for m in members})
        message = next((m.get("message") for m in members if m.get("message")), "")

        out.append({
            "vuln_ids": sorted(all_ids),
            "primary_vuln_id": members[0].get("vuln_id") or (sorted(all_ids)[0] if all_ids else None),
            "package": package,
            "version": version,
            "ecosystem": ecosystem,
            "severity": severity,
            "cvss_score": max(cvss_scores) if cvss_scores else None,
            "fix_versions": sorted(fix_versions),
            "reachable": reachable,
            "direct_dependency": direct_dependency,
            "scanners": scanners,
            "message": message,
            "members": members,
        })
    return out


def _waiver_active(waiver: dict, now: datetime) -> bool:
    if waiver.get("revoked_at") is not None:
        return False
    expires_at = waiver.get("expires_at")
    return expires_at is not None and expires_at > now


def _waiver_matches_group(waiver: dict, group: dict) -> bool:
    """EXACT package + version + vuln_id match (issue-12 requirement: not
    fuzzy/prefix). "vuln_id" membership is checked against the group's full
    alias-collapsed identifier set — that is still an exact-identity match
    (same underlying vuln under a different namespace), not fuzzy matching.
    A waiver for version X must NEVER suppress a finding for version Y of the
    same package."""
    w_package = (waiver.get("package") or "").strip().lower()
    w_version = (waiver.get("version") or "").strip()
    w_vuln_id = waiver.get("vuln_id")
    if not w_package or not w_version or not w_vuln_id:
        return False
    if (group.get("package") or "").strip().lower() != w_package:
        return False
    if (group.get("version") or "").strip() != w_version:
        return False
    return w_vuln_id in (group.get("vuln_ids") or [])


def _find_matching_waiver(group: dict, active_waivers: list[dict]) -> dict | None:
    for w in active_waivers:
        if _waiver_matches_group(w, group):
            return w
    return None


def _decide_group(group: dict, active_waivers: list[dict], block_on: str) -> dict:
    waiver = _find_matching_waiver(group, active_waivers)
    if waiver is not None:
        return {"block": False, "review_required": False, "waived": True,
                "waiver_id": waiver.get("waiver_id")}
    if group["severity"] == "unknown":
        # CR-12 hardening: unknown severity is NEVER a silent pass.
        return {"block": False, "review_required": True, "waived": False, "waiver_id": None}
    rank = _SEVERITY_RANK[group["severity"]]
    threshold = _SEVERITY_RANK.get(block_on, _SEVERITY_RANK[_DEFAULT_BLOCK_ON])
    return {"block": rank >= threshold, "review_required": False, "waived": False, "waiver_id": None}


def evaluate_dependency_findings(raw_findings: list[dict], waivers: list[dict] | None = None,
                                 *, block_on: str | None = None) -> dict[str, Any]:
    """Returns {"block": bool, "review_required": bool, "groups": [...]}.

    `groups` carries the fully alias-collapsed, waiver-applied decision per
    vulnerability group — callers that want to persist a normalized,
    de-duplicated dependency report (e.g. for the SBOM/review UI) can use
    this directly instead of the raw per-scanner findings list.
    """
    waivers = waivers or []
    now = datetime.now(timezone.utc)
    active_waivers = [w for w in waivers if _waiver_active(w, now)]
    threshold = block_on or _load_block_on()

    dep_findings = [f for f in raw_findings if _is_dependency_finding(f)]
    # Infra-level "review required" signals with no package/vuln_id at all —
    # e.g. govulncheck module-load failure, npm project with no lockfile.
    # These always propagate: they are not a specific vulnerability, they are
    # a structural gap in coverage that a human must clear.
    signal_review_required = any(
        f.get("review_required") and not (f.get("vuln_id") or f.get("package"))
        for f in raw_findings
    )

    groups = collapse_aliases(dep_findings)
    block = False
    review_required = signal_review_required
    decided = []
    for group in groups:
        decision = _decide_group(group, active_waivers, threshold)
        decided.append({**group, **decision})
        block = block or decision["block"]
        review_required = review_required or decision["review_required"]

    return {"block": block, "review_required": review_required, "groups": decided}
