"""
scanner-worker's scan engine — executes scanners and returns RAW findings.

Ported from proxy/app/services/submission_scanner.py, trimmed of every DB
write and every pass/fail decision (CR-14 execution/adjudication split: this
module NEVER decides block/scan_status — see scanner_worker/README.md and
proxy/app/services/scan_evaluator.py, which is the only place that verdict
is computed, from the raw_findings this module returns).

This intentionally duplicates (does not import) submission_scanner.py's
clone/trufflehog/pip-audit/mcp_checker logic: this process must not import
proxy application code.

WP-B1 scope: only the EXISTING pip-audit/clone/trufflehog/custom-rules/
mcp_checker pipeline is wired up here — no new scanner layers (OSV-Scanner,
npm audit, govulncheck). That is WP-B2.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import yaml

from . import dependency_scanners, git_clone

logger = logging.getLogger(__name__)

_SCAN_CONFIG_PATH = Path(__file__).parent / "scan-config.yaml"
_MCP_CHECKER_DIR = Path(__file__).parent / "vendor" / "mcp_checker"
_MCP_CHECKER_PY = _MCP_CHECKER_DIR / "mcp_checker.py"

_SBOM_MAX_FILE_BYTES = 2 * 1024 * 1024
_SBOM_MAX_COMPONENTS = 500
_REQ_LINE_RE = re.compile(
    r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9._*+!-]*)'
)
_GO_REQUIRE_LINE_RE = re.compile(r'^([^\s]+)\s+(v[^\s]+)')


def _load_scan_config() -> dict[str, Any]:
    try:
        with open(_SCAN_CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("scan-config.yaml not found; using defaults")
        return {"scanners": {"trufflehog": {"enabled": True, "block_on": "verified"},
                             "dependency_audit": {"enabled": True, "block_on": "critical"}}}
    except Exception as exc:
        logger.error("Failed to load scan-config.yaml: %s", exc)
        return {}


async def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120,
               env: dict | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd, env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 1, "", "timed out"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _clone_repo(pool, repo_url: str, dest: str) -> tuple[bool, str]:
    provider = await git_clone.match_provider(pool, repo_url)
    if provider is None:
        return False, ("Repository URL does not match any enabled git provider. "
                        "Allowed: an enabled host in Admin -> Git Providers.")
    if not shutil.which("git"):
        return False, "git not available in the scanner worker environment"

    try:
        git_clone.validate_host(provider.host, provider.allow_private)
    except git_clone.GitHostError as exc:
        return False, f"clone blocked: {exc}"

    token = git_clone.provider_token(provider.provider)
    clone_url = git_clone.build_clone_url(repo_url, provider.clone_account, token)
    rc, _, stderr = await _run(
        [
            "git",
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "protocol.ext.allow=never",
            "-c", "protocol.file.allow=never",
            "clone", "--depth=1", "--quiet",
            "--",
            clone_url, dest,
        ],
        timeout=120,
    )
    if rc != 0:
        safe_err = stderr.replace(token, "***") if token else stderr
        return False, safe_err.strip() or "clone failed"
    return True, ""


async def _run_trufflehog(repo_path: str, config: dict) -> list[dict]:
    th_cfg = config.get("scanners", {}).get("trufflehog", {})
    if not th_cfg.get("enabled", True):
        return []
    if not shutil.which("trufflehog"):
        logger.error("trufflehog not found; scan cannot certify this submission")
        return [{
            "scanner": "trufflehog", "severity": "critical", "block": False,
            "missing_tool": True, "file": "", "line": 0,
            "message": "trufflehog binary not found in scanner-worker environment; secret scan did not run",
        }]

    only_verified = th_cfg.get("block_on", "verified") == "verified"
    cmd = ["trufflehog", "filesystem", repo_path, "--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")
    skip_paths = th_cfg.get("skip_paths", [])

    rc, stdout, stderr = await _run(cmd, timeout=180)
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue
        source_meta = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file_path = source_meta.get("file", "")
        if any(pat.replace("*", "") in file_path for pat in skip_paths):
            continue
        findings.append({
            "scanner": "trufflehog", "severity": "critical", "block": True,
            "detector": finding.get("DetectorName", "unknown"),
            "file": file_path, "line": source_meta.get("line", 0),
            "verified": finding.get("Verified", False),
            "message": f"Secret detected: {finding.get('DetectorName', 'unknown')}",
        })
    return findings


async def _run_custom_rules(repo_path: str, config: dict) -> list[dict]:
    rules = config.get("scanners", {}).get("custom_rules", [])
    findings = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        if not pattern:
            continue
        try:
            rx = re.compile(pattern)
        except re.error:
            continue
        file_globs = rule.get("files", ["*.py"])
        for root, _dirs, files in os.walk(repo_path):
            if ".git" in root:
                continue
            for fname in files:
                if not any(fname.endswith(g.lstrip("*")) or g == "*" for g in file_globs):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    content = Path(fpath).read_text(errors="replace")
                except OSError:
                    continue
                for i, line in enumerate(content.splitlines(), 1):
                    if rx.search(line):
                        rel = os.path.relpath(fpath, repo_path)
                        findings.append({
                            "scanner": "custom", "rule_id": rule.get("id", "unknown"),
                            "severity": "warning" if not rule.get("block") else "critical",
                            "block": bool(rule.get("block", False)),
                            "file": rel, "line": i,
                            "message": rule.get("description", f"Rule {rule.get('id')} matched"),
                        })
                        break
    return findings


def _rel_to_repo(path: str, repo_path: str) -> str:
    if not path:
        return ""
    try:
        p = str(path)
        if "/repo/" in p:
            return p.split("/repo/", 1)[1]
        return os.path.basename(p)
    except Exception:
        return path


def _mcp_checker_hits(details: dict) -> list[dict]:
    out: list[dict] = []
    for f in details.get("findings", []) or []:
        file = f.get("file", "")
        inner = f.get("hits", [])
        if inner:
            for h in inner:
                out.append({"file": file, "line": h.get("line", 0),
                            "detail": h.get("sig") or h.get("message", ""),
                            "message": f.get("message") or h.get("message", "")})
        else:
            out.append({"file": file, "line": f.get("line", 0),
                        "detail": f.get("message", ""), "message": f.get("message", "")})
    for v in details.get("violations", []) or []:
        out.append({"file": v.get("file", ""), "line": v.get("line", 0),
                    "detail": v.get("type", ""),
                    "message": f"{v.get('type','violation')}: tool {v.get('tool','?')}"
                               f"{' param ' + v['parameter'] if v.get('parameter') else ''}"})
    if not out:
        out.append({"file": "", "line": 0, "detail": "", "message": ""})
    return out


async def _run_mcp_checker(repo_path: str, config: dict) -> list[dict]:
    cfg = config.get("scanners", {}).get("mcp_checker", {})
    if not cfg.get("enabled", True):
        return []
    if not _MCP_CHECKER_PY.is_file():
        logger.error("mcp_checker not vendored at %s; MCP scan did not run", _MCP_CHECKER_PY)
        return [{
            "scanner": "mcp_checker", "severity": "critical", "block": False,
            "missing_tool": True, "file": "", "line": 0,
            "message": "mcp_checker engine not found in scanner-worker environment; MCP security scan did not run",
        }]

    checks = cfg.get("checks", "code_static,tool_schema,semgrep")
    block_checks = set(cfg.get("block_checks", []))

    with tempfile.TemporaryDirectory(prefix="mcp_checker_") as proj_dir:
        env = os.environ.copy()
        env["HOME"] = proj_dir
        env["SEMGREP_SETTINGS_FILE"] = os.path.join(proj_dir, "semgrep_settings.yml")
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        env["SEMGREP_SEND_METRICS"] = "off"
        rc, stdout, stderr = await _run(
            ["python3", str(_MCP_CHECKER_PY), "-u", repo_path,
             "--project-name", "submission", "--projects-dir", proj_dir, "--checks", checks],
            cwd=str(_MCP_CHECKER_DIR), timeout=300, env=env,
        )
        report_path = Path(proj_dir) / "submission" / "artifacts" / "mcp-checker-report.json"
        if not report_path.is_file():
            logger.error("mcp_checker produced no report (rc=%s): %s", rc, (stderr or stdout)[-500:])
            return [{
                "scanner": "mcp_checker", "severity": "critical", "block": False,
                "missing_tool": True, "file": "", "line": 0,
                "message": f"mcp_checker did not produce a report (exit {rc}); MCP security scan did not complete",
            }]
        try:
            report = json.loads(report_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("mcp_checker report unreadable: %s", exc)
            return [{
                "scanner": "mcp_checker", "severity": "critical", "block": False,
                "missing_tool": True, "file": "", "line": 0,
                "message": "mcp_checker report was unreadable; MCP security scan did not complete",
            }]

    findings: list[dict] = []
    _infra = {"clone", "checkout", "lint", "rego", "trivy"}
    for res in report.get("results", []):
        if res.get("status") != "FAIL" or res.get("name") in _infra:
            continue
        name = res.get("name", "unknown")
        hits = _mcp_checker_hits(res.get("details", {}))
        blocks = name in block_checks
        for h in hits[:20]:
            findings.append({
                "scanner": "mcp_checker", "check": name,
                "severity": "critical" if blocks else "warning", "block": blocks,
                "file": _rel_to_repo(h.get("file", ""), repo_path), "line": h.get("line", 0),
                "message": h.get("message") or f"{name}: {h.get('detail', 'MCP security check failed')}",
            })
    return findings


async def _run_pip_audit(repo_path: str, config: dict) -> list[dict]:
    dep_cfg = config.get("scanners", {}).get("dependency_audit", {})
    if not dep_cfg.get("enabled", True):
        return []
    if "pip" not in dep_cfg.get("ecosystems", ["pip"]):
        return []
    req_files = list(Path(repo_path).glob("requirements*.txt")) + list(Path(repo_path).glob("pyproject.toml"))
    if not req_files:
        return [{
            "scanner": "pip-audit", "severity": "info", "block": False, "skipped": True,
            "file": "", "line": 0,
            "message": "No requirements.txt/pyproject.toml found — dependency-CVE scan did not run "
                       "(this repo may use a different ecosystem, e.g. npm, which is not CVE-audited here)",
        }]
    if not shutil.which("pip-audit"):
        logger.error("pip-audit not found; scan cannot certify this submission")
        return [{
            "scanner": "pip-audit", "severity": "critical", "block": False, "missing_tool": True,
            "file": "", "line": 0,
            "message": "pip-audit binary not found in scanner-worker environment; dependency scan did not run",
        }]

    rc, stdout, stderr = await _run(["pip-audit", "--format=json", "-r", str(req_files[0])], timeout=120)
    findings = []
    try:
        result = json.loads(stdout) if stdout else []
        for dep in result:
            for vuln in dep.get("vulns", []):
                # pip-audit's own JSON output carries NO severity/CVSS field
                # at all — only an advisory id. CR-12 hardening: never infer
                # severity from fix-version presence (that was this
                # function's pre-WP-B2 behavior and is exactly the heuristic
                # the issue file calls out to remove). Severity is always
                # "unknown" here; the evaluator (dependency_policy.py)
                # recovers the real severity by alias-collapsing this
                # finding's vuln_id/aliases against OSV-Scanner's finding for
                # the same CVE, which does carry CVSS/severity. If no other
                # layer covers this package, "unknown" forces
                # review-required rather than a silent pass. `block` is
                # always False from this worker — see dependency_scanners.py
                # module docstring for the full policy split rationale.
                findings.append({
                    "scanner": "pip-audit", "ecosystem": "PyPI", "severity": "unknown",
                    "cvss_score": None, "block": False, "waiver_id": None,
                    "package": dep.get("name", ""), "version": dep.get("version", ""),
                    "vuln_id": vuln.get("id", ""),
                    "aliases": vuln.get("aliases", []) or [],
                    "fix_versions": vuln.get("fix_versions", []) or [],
                    "reachable": None, "direct_dependency": None,
                    "file": str(req_files[0].relative_to(repo_path)), "line": 0,
                    "source": str(req_files[0].relative_to(repo_path)),
                    "message": f"{dep.get('name')}=={dep.get('version')}: {vuln.get('id', '')}",
                })
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("pip-audit parse error: %s", exc)
    return findings


def _parse_requirements_txt(text_content: str) -> list[dict]:
    out = []
    for raw in text_content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-e", "--", "git+", "http://", "https://")):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name, _op, version = m.groups()
        version = version.strip() or "*"
        out.append({"name": name, "version": version,
                    "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}"})
    return out


def _parse_pyproject_toml(text_content: str) -> list[dict]:
    try:
        import tomllib
    except ImportError:
        return []
    try:
        data = tomllib.loads(text_content)
    except Exception:
        return []
    out = []
    for dep in data.get("project", {}).get("dependencies", []) or []:
        m = _REQ_LINE_RE.match(str(dep).strip())
        if not m:
            continue
        name, _op, version = m.groups()
        version = version.strip() or "*"
        out.append({"name": name, "version": version,
                    "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}"})
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            version = str(spec.get("version", "*")).lstrip("^~>=< ") or "*"
        else:
            version = str(spec).lstrip("^~>=< ") or "*"
        out.append({"name": name, "version": version,
                    "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}"})
    return out


def _parse_package_json(text_content: str) -> list[dict]:
    try:
        data = json.loads(text_content)
    except Exception:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, version in (data.get(section) or {}).items():
            version = str(version).lstrip("^~>=< ") or "*"
            out.append({"name": name, "version": version,
                        "purl": f"pkg:npm/{name}@{version}" if version != "*" else f"pkg:npm/{name}"})
    return out


def _parse_go_mod(text_content: str) -> list[dict]:
    out = []
    in_block = False
    for raw in text_content.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line == "require (":
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if in_block:
            m = _GO_REQUIRE_LINE_RE.match(line)
        elif line.startswith("require "):
            m = _GO_REQUIRE_LINE_RE.match(line[len("require "):].strip())
        else:
            m = None
        if not m:
            continue
        name, version = m.groups()
        out.append({"name": name, "version": version, "purl": f"pkg:golang/{name}@{version}"})
    return out


async def _generate_cyclonedx_sbom(repo_path: str) -> dict | None:
    if not shutil.which("syft"):
        logger.info("syft not present; skipping CycloneDX SBOM")
        return None
    env = os.environ.copy()
    env.setdefault("SYFT_CHECK_FOR_APP_UPDATE", "false")
    rc, stdout, stderr = await _run(["syft", f"dir:{repo_path}", "-o", "cyclonedx-json", "-q"],
                                    timeout=180, env=env)
    if rc != 0 or not stdout.strip():
        logger.warning("syft SBOM generation failed (rc=%s): %s", rc, (stderr or "")[-300:])
        return None
    try:
        doc = json.loads(stdout)
        if len(stdout) > 4 * 1024 * 1024:
            return {"bomFormat": doc.get("bomFormat"), "specVersion": doc.get("specVersion"),
                    "components": (doc.get("components") or [])[:_SBOM_MAX_COMPONENTS], "_truncated": True}
        return doc
    except json.JSONDecodeError as exc:
        logger.warning("syft SBOM output not valid JSON: %s", exc)
        return None


def _parse_sbom_components(repo_path: str) -> list[dict]:
    components: list[dict] = []
    manifests = [
        ("requirements.txt", _parse_requirements_txt),
        ("pyproject.toml", _parse_pyproject_toml),
        ("package.json", _parse_package_json),
        ("go.mod", _parse_go_mod),
    ]
    for filename, parser in manifests:
        fpath = Path(repo_path) / filename
        try:
            if not fpath.is_file() or fpath.stat().st_size > _SBOM_MAX_FILE_BYTES:
                continue
            content = fpath.read_text(errors="replace")
            components.extend(parser(content))
        except OSError:
            continue
        except Exception as exc:
            logger.warning("SBOM manifest parse error for %s: %s", filename, exc)
        if len(components) >= _SBOM_MAX_COMPONENTS:
            break
    seen = set()
    deduped = []
    for c in components:
        key = (c["name"].lower(), c["version"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    return deduped[:_SBOM_MAX_COMPONENTS]


async def run_scan(pool, github_url: str) -> dict[str, Any]:
    """
    Execute the full scanner pipeline against github_url and return RAW
    results only:
        {
          "raw_findings": [...],        # never a block/pass/fail decision
          "scan_commit": "<sha>"|None,
          "sbom_components": [...],
          "sbom_cyclonedx": {...}|None,
          "worker_error": None | "clone failed: ..." | "crashed: ..."
        }
    This function makes NO policy decision. The evaluator (proxy side)
    decides scan_status/block from raw_findings + worker_error.
    """
    config = _load_scan_config()

    if await git_clone.match_provider(pool, github_url) is None:
        return {
            "raw_findings": [{
                "scanner": "url_validation", "severity": "critical", "block": True,
                "file": "", "line": 0,
                "message": "Repository URL rejected: host must match an enabled git provider "
                           "(Admin -> Git Providers).",
            }],
            "scan_commit": None, "sbom_components": [], "sbom_cyclonedx": None,
            "worker_error": "clone_rejected: no matching git provider",
        }

    tmpdir = tempfile.mkdtemp(prefix="mcp_scan_")
    try:
        repo_path = os.path.join(tmpdir, "repo")
        cloned, clone_err = await _clone_repo(pool, github_url, repo_path)
        if not cloned:
            return {
                "raw_findings": [{
                    "scanner": "clone", "severity": "critical", "block": True,
                    "file": "", "line": 0,
                    "message": f"Could not clone repository: {clone_err}.",
                }],
                "scan_commit": None, "sbom_components": [], "sbom_cyclonedx": None,
                "worker_error": f"clone_failed: {clone_err}",
            }

        scan_commit = ""
        try:
            rc_c, out_c, _ = await _run(["git", "-C", repo_path, "rev-parse", "HEAD"], timeout=15)
            if rc_c == 0:
                scan_commit = out_c.strip()[:64]
        except Exception:
            scan_commit = ""

        try:
            sbom_components = _parse_sbom_components(repo_path)
        except Exception as exc:
            logger.warning("SBOM component parse failed for %s: %s", github_url, exc)
            sbom_components = []
        try:
            sbom_cyclonedx = await _generate_cyclonedx_sbom(repo_path)
        except Exception as exc:
            logger.warning("CycloneDX SBOM generation failed for %s: %s", github_url, exc)
            sbom_cyclonedx = None

        th, custom, pip_f, mcp_f, osv_f, npm_f, go_f = await asyncio.gather(
            _run_trufflehog(repo_path, config),
            _run_custom_rules(repo_path, config),
            _run_pip_audit(repo_path, config),
            _run_mcp_checker(repo_path, config),
            dependency_scanners.run_osv_scanner(_run, repo_path, config),
            dependency_scanners.run_npm_audit(_run, repo_path, config),
            dependency_scanners.run_govulncheck(_run, repo_path, config),
        )
        findings = th + custom + pip_f + mcp_f + osv_f + npm_f + go_f
        return {
            "raw_findings": findings,
            "scan_commit": scan_commit or None,
            "sbom_components": sbom_components,
            "sbom_cyclonedx": sbom_cyclonedx,
            "worker_error": None,
        }
    except Exception as exc:
        logger.exception("scanner-worker crashed scanning %s: %s", github_url, exc)
        return {
            "raw_findings": [{
                "scanner": "system", "severity": "critical", "block": False,
                "file": "", "line": 0,
                "message": f"Scanner worker crashed unexpectedly: {exc}",
            }],
            "scan_commit": None, "sbom_components": [], "sbom_cyclonedx": None,
            "worker_error": f"crashed: {exc}",
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
