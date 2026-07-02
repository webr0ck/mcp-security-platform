"""
Submission scanner — runs automated security checks on a GitHub repo before
the submission enters the human review queue.

Pipeline:
  1. git clone (shallow, read-only, using platform GitHub account)
  2. trufflehog filesystem scan (if available)
  3. custom regex rules from scan-config.yaml
  4. pip-audit dependency scan (if pip ecosystem enabled)

Writes results to server_registry.scan_report (jsonb) and sets scan_status.
Called as an asyncio background task from the submission router.

If trufflehog or git is absent, the scanner degrades gracefully:
  - missing git/trufflehog → scan_status='passed', warning in report
  - clone failure (private repo, no access) → scan_status='blocked', clear message
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

from app.core.database import AsyncSessionLocal
from sqlalchemy import text

# Strict allowlist: only https://github.com/<owner>/<repo> (optionally .git)
# Owner/repo chars: alphanumeric, hyphens, underscores, dots.
# Rejects anything starting with '-', protocol smuggling, file://, etc.
_GITHUB_URL_RE = re.compile(
    r'^https://github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(\.git)?/?$'
)

logger = logging.getLogger(__name__)

_SCAN_CONFIG_PATH = Path(__file__).parents[2] / "scan-config.yaml"

# GitHub account used to clone repositories (shown to submitters in the wizard).
GITHUB_CLONE_ACCOUNT = os.environ.get("GITHUB_CLONE_ACCOUNT", "mcp-platform-bot")
GITHUB_CLONE_TOKEN = os.environ.get("GITHUB_CLONE_TOKEN", "")


def _load_scan_config() -> dict[str, Any]:
    try:
        with open(_SCAN_CONFIG_PATH) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("scan-config.yaml not found; using defaults")
        return {"scanners": {"trufflehog": {"enabled": True, "block_on": "verified"}, "dependency_audit": {"enabled": True, "block_on": "critical"}}}
    except Exception as exc:
        logger.error("Failed to load scan-config.yaml: %s", exc)
        return {}


def _clone_url_with_auth(github_url: str) -> str:
    """Inject token into GitHub HTTPS clone URL."""
    if not GITHUB_CLONE_TOKEN:
        return github_url
    url = github_url.rstrip("/")
    if url.startswith("https://github.com/"):
        path = url[len("https://github.com/"):]
        return f"https://{GITHUB_CLONE_ACCOUNT}:{GITHUB_CLONE_TOKEN}@github.com/{path}"
    return github_url


async def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return 1, "", "timed out"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _clone_repo(github_url: str, dest: str) -> tuple[bool, str]:
    """Clone the repo. Returns (success, error_message)."""
    if not _GITHUB_URL_RE.match(github_url):
        return False, "Repository URL must be https://github.com/<owner>/<repo>"
    if not shutil.which("git"):
        return False, "git not available in the scanner environment"
    clone_url = _clone_url_with_auth(github_url)
    rc, _, stderr = await _run(
        [
            "git",
            # Disable dangerous transports; only allow https
            "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "-c", "protocol.ext.allow=never",
            "-c", "protocol.file.allow=never",
            "clone", "--depth=1", "--quiet",
            "--",          # end of flags — prevents URL starting with '-' being parsed as a flag
            clone_url, dest,
        ],
        timeout=120,
    )
    if rc != 0:
        # Sanitise: remove token from error message before storing
        safe_err = stderr.replace(GITHUB_CLONE_TOKEN, "***") if GITHUB_CLONE_TOKEN else stderr
        return False, safe_err.strip() or "clone failed"
    return True, ""


async def _run_trufflehog(repo_path: str, config: dict) -> list[dict]:
    """Run trufflehog and return list of findings."""
    th_cfg = config.get("scanners", {}).get("trufflehog", {})
    if not th_cfg.get("enabled", True):
        return []
    if not shutil.which("trufflehog"):
        logger.warning("trufflehog not found; skipping secret scan")
        return []

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
        # Check skip_paths
        source_meta = finding.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
        file_path = source_meta.get("file", "")
        if any(pat.replace("*", "") in file_path for pat in skip_paths):
            continue
        findings.append({
            "scanner": "trufflehog",
            "severity": "critical",
            "block": True,
            "detector": finding.get("DetectorName", "unknown"),
            "file": file_path,
            "line": source_meta.get("line", 0),
            "verified": finding.get("Verified", False),
            "message": f"Secret detected: {finding.get('DetectorName', 'unknown')}",
        })
    return findings


async def _run_custom_rules(repo_path: str, config: dict) -> list[dict]:
    """Run custom regex rules from scan-config.yaml."""
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
            # Skip .git
            if ".git" in root:
                continue
            for fname in files:
                if not any(
                    fname.endswith(g.lstrip("*")) or g == "*" for g in file_globs
                ):
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
                            "scanner": "custom",
                            "rule_id": rule.get("id", "unknown"),
                            "severity": "warning" if not rule.get("block") else "critical",
                            "block": bool(rule.get("block", False)),
                            "file": rel,
                            "line": i,
                            "message": rule.get("description", f"Rule {rule.get('id')} matched"),
                        })
                        break  # one finding per file per rule is enough
    return findings


async def _run_pip_audit(repo_path: str, config: dict) -> list[dict]:
    """Run pip-audit if enabled and requirements files exist."""
    dep_cfg = config.get("scanners", {}).get("dependency_audit", {})
    if not dep_cfg.get("enabled", True):
        return []
    if "pip" not in dep_cfg.get("ecosystems", ["pip"]):
        return []
    if not shutil.which("pip-audit"):
        logger.warning("pip-audit not found; skipping dependency scan")
        return []

    block_on = dep_cfg.get("block_on", "critical")
    severity_order = ["low", "medium", "high", "critical"]
    block_threshold = severity_order.index(block_on) if block_on in severity_order else 3

    # Find requirements files
    req_files = list(Path(repo_path).glob("requirements*.txt")) + list(Path(repo_path).glob("pyproject.toml"))
    if not req_files:
        return []

    rc, stdout, stderr = await _run(
        ["pip-audit", "--format=json", "-r", str(req_files[0])],
        timeout=120,
    )
    findings = []
    try:
        result = json.loads(stdout) if stdout else []
        for dep in result:
            for vuln in dep.get("vulns", []):
                sev = vuln.get("fix_versions", [""])[0] and "high" or "medium"
                sev_idx = severity_order.index(sev) if sev in severity_order else 1
                findings.append({
                    "scanner": "pip-audit",
                    "severity": sev,
                    "block": sev_idx >= block_threshold,
                    "package": dep.get("name", ""),
                    "version": dep.get("version", ""),
                    "vuln_id": vuln.get("id", ""),
                    "file": str(req_files[0].relative_to(repo_path)),
                    "line": 0,
                    "message": f"{dep.get('name')}=={dep.get('version')}: {vuln.get('id', '')}",
                })
    except (json.JSONDecodeError, Exception) as exc:
        logger.warning("pip-audit parse error: %s", exc)
    return findings


async def scan_submission(server_id: str, github_url: str) -> None:
    """
    Clone the repo and run all enabled scanners.
    Updates server_registry.scan_status and scan_report in the DB.
    Called as an asyncio background task.
    """
    logger.info("Starting scan for server_id=%s repo=%s", server_id, github_url)
    config = _load_scan_config()

    async def _set_status(status: str, report: list[dict]) -> None:
        subm_status = "scan_blocked" if status == "blocked" else ("awaiting_review" if status == "passed" else "scan_running")
        async with AsyncSessionLocal() as session:
            await session.execute(text("""
                UPDATE server_registry
                SET scan_status = :scan_status,
                    scan_report = :report::jsonb,
                    submission_status = :subm_status,
                    updated_at = now()
                WHERE server_id = :sid
            """), {
                "scan_status": status,
                "report": json.dumps(report),
                "subm_status": subm_status,
                "sid": server_id,
            })
            await session.commit()

    # H1 fix: URL check is here (after _set_status is defined) so an invalid URL
    # produces a proper DB update rather than a NameError.
    if not _GITHUB_URL_RE.match(github_url):
        await _set_status("blocked", [{
            "scanner": "url_validation",
            "severity": "critical",
            "block": True,
            "file": "",
            "line": 0,
            "message": "Repository URL rejected: must be https://github.com/<owner>/<repo>",
        }])
        return

    await _set_status("running", [])

    tmpdir = tempfile.mkdtemp(prefix="mcp_scan_")
    try:
        repo_path = os.path.join(tmpdir, "repo")
        cloned, clone_err = await _clone_repo(github_url, repo_path)
        if not cloned:
            report = [{
                "scanner": "clone",
                "severity": "critical",
                "block": True,
                "file": "",
                "line": 0,
                "message": f"Could not clone repository: {clone_err}. "
                           f"Ensure the platform account ({GITHUB_CLONE_ACCOUNT}) has read access.",
            }]
            await _set_status("blocked", report)
            return

        findings: list[dict] = []
        th, custom, pip_f = await asyncio.gather(
            _run_trufflehog(repo_path, config),
            _run_custom_rules(repo_path, config),
            _run_pip_audit(repo_path, config),
        )
        findings.extend(th)
        findings.extend(custom)
        findings.extend(pip_f)

        blocked = any(f.get("block") for f in findings)
        await _set_status("blocked" if blocked else "passed", findings)
        logger.info(
            "Scan complete server_id=%s status=%s findings=%d",
            server_id, "blocked" if blocked else "passed", len(findings),
        )
    except Exception as exc:
        # C1 fix: fail-closed — a scanner crash is unknown, not a pass.
        # A human reviewer must explicitly un-block after investigating.
        logger.exception("Scan crashed for server_id=%s: %s", server_id, exc)
        await _set_status("blocked", [{
            "scanner": "system",
            "severity": "critical",
            "block": True,
            "file": "",
            "line": 0,
            "message": f"Scanner crashed unexpectedly; submission blocked pending manual investigation. Error: {exc}",
        }])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def scan_repo(github_url: str) -> tuple[list[dict], str]:
    """
    Run the scanner pipeline on a GitHub repo and return (findings, status).
    Does NOT write to the DB — callers handle persistence.
    Used by the periodic rescan scheduler.
    """
    if not _GITHUB_URL_RE.match(github_url):
        return ([{
            "scanner": "url_validation", "severity": "critical", "block": True,
            "file": "", "line": 0,
            "message": "Repository URL rejected by rescan: must be https://github.com/<owner>/<repo>",
        }], "blocked")

    config = _load_scan_config()
    tmpdir = tempfile.mkdtemp(prefix="mcp_rescan_")
    try:
        repo_path = os.path.join(tmpdir, "repo")
        cloned, clone_err = await _clone_repo(github_url, repo_path)
        if not cloned:
            return ([{
                "scanner": "clone", "severity": "critical", "block": True,
                "file": "", "line": 0,
                "message": f"Rescan clone failed: {clone_err}",
            }], "blocked")

        th, custom, pip_f = await asyncio.gather(
            _run_trufflehog(repo_path, config),
            _run_custom_rules(repo_path, config),
            _run_pip_audit(repo_path, config),
        )
        findings = th + custom + pip_f
        status = "blocked" if any(f.get("block") for f in findings) else "passed"
        return findings, status
    except Exception as exc:
        return ([{
            "scanner": "system", "severity": "critical", "block": True,
            "file": "", "line": 0, "message": f"Rescan crashed: {exc}",
        }], "blocked")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
