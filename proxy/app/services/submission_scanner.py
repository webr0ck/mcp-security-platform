"""
DEPRECATED execution path (CR-14 / WP-B1) — kept only for its still-used
helpers (parse_sbom_components / GITHUB_CLONE_ACCOUNT / GITHUB_CLONE_TOKEN)
and to avoid a disruptive mass-delete mid-program. The clone + scanner
functions below (`_clone_repo`, `_run_trufflehog`, `_run_custom_rules`,
`_run_pip_audit`, `_run_mcp_checker`, `scan_submission`, `scan_repo`) are NOT
called from any live code path anymore — no router or scheduler imports
them. Do not add new callers.

Untrusted clone + scanner execution now runs in the isolated, unprivileged
`scanner-worker` service (see scanner_worker/scan_engine.py, which is an
intentional standalone re-implementation of the pipeline described below —
not an import of this module, so the worker never depends on proxy
application code). The proxy only enqueues (app/services/scan_queue.py) and
evaluates raw results (app/services/scan_evaluator.py); it does not clone or
exec scanners in-process, and its own container/image no longer bundles
git/trufflehog/pip-audit/syft/semgrep (see proxy/Dockerfile).

Original docstring, describing the now-dead-code pipeline below, preserved
for context:

Submission scanner — runs automated security checks on a GitHub repo before
the submission enters the human review queue.

Pipeline:
  1. git clone (shallow, read-only, using platform GitHub account)
  2. trufflehog filesystem scan (if available)
  3. custom regex rules from scan-config.yaml
  4. pip-audit dependency scan (if pip ecosystem enabled)

Writes results to server_registry.scan_report (jsonb) and sets scan_status.

If a scanner binary is absent, the scan fails closed:
  - missing git → scan_status='blocked' (cannot even clone)
  - missing trufflehog/pip-audit → scan_status='error' (never 'passed'); the
    submission cannot be approved until scanner tooling is available
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

logger = logging.getLogger(__name__)

_SCAN_CONFIG_PATH = Path(__file__).parents[2] / "scan-config.yaml"

# GitHub account used to clone repositories (shown to submitters in the wizard).
# R-2: the authoritative per-provider allowlist + clone now lives in
# app/services/git_providers.py; these env vars remain the github fallback
# (account display + token via git_providers.provider_token) for back-compat.
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


async def _run(cmd: list[str], cwd: str | None = None, timeout: int = 120,
               env: dict | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        env=env,
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


async def _clone_repo(repo_url: str, dest: str) -> tuple[bool, str]:
    """Clone the repo from a configured git provider. Returns (success, error).

    R-2: the provider (github/bitbucket/…) is inferred from the URL host and must
    match an enabled git_providers row. The host is SSRF-validated (loopback/
    link-local/metadata always rejected; RFC1918 only with allow_private) right
    before the clone. Transport hardening (https-only, option-injection guard,
    shallow, sandbox cwd) is unchanged.
    """
    from app.services import git_providers

    provider = await git_providers.match_provider(repo_url)
    if provider is None:
        return False, ("Repository URL does not match any enabled git provider. "
                       "Allowed: an enabled host in Admin → Git Providers.")
    if not shutil.which("git"):
        return False, "git not available in the scanner environment"

    # SSRF: resolve + validate the host immediately before cloning.
    try:
        git_providers.validate_host(provider.host, provider.allow_private)
    except git_providers.GitHostError as exc:
        return False, f"clone blocked: {exc}"

    try:
        token = await git_providers.provider_token(provider.provider)
    except git_providers.GitHostError as exc:
        return False, str(exc)

    clone_url = git_providers.build_clone_url(repo_url, provider.clone_account, token)
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
        safe_err = stderr.replace(token, "***") if token else stderr
        return False, safe_err.strip() or "clone failed"
    return True, ""


async def _run_trufflehog(repo_path: str, config: dict) -> list[dict]:
    """Run trufflehog and return list of findings."""
    th_cfg = config.get("scanners", {}).get("trufflehog", {})
    if not th_cfg.get("enabled", True):
        return []
    if not shutil.which("trufflehog"):
        logger.error("trufflehog not found; scan cannot certify this submission")
        return [{
            "scanner": "trufflehog",
            "severity": "critical",
            "block": False,
            "missing_tool": True,
            "file": "",
            "line": 0,
            "message": "trufflehog binary not found in scanner environment; secret scan did not run",
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


# Vendored mcp_checker engine (proxy/vendor/mcp_checker). Runs MCP-specific
# static checks the secret/CVE/regex scanners structurally cannot see:
# malicious code patterns, tool poisoning, SSRF/IMDS, crypto stealers, and
# MCP-aware semgrep SAST. See VENDORED.md for provenance.
_MCP_CHECKER_DIR = Path(__file__).parents[2] / "vendor" / "mcp_checker"
_MCP_CHECKER_PY = _MCP_CHECKER_DIR / "mcp_checker.py"


async def _run_mcp_checker(repo_path: str, config: dict) -> list[dict]:
    """Run the vendored mcp_checker static pass against an already-cloned repo."""
    cfg = config.get("scanners", {}).get("mcp_checker", {})
    if not cfg.get("enabled", True):
        return []
    if not _MCP_CHECKER_PY.is_file():
        logger.error("mcp_checker not vendored at %s; MCP scan did not run", _MCP_CHECKER_PY)
        return [{
            "scanner": "mcp_checker", "severity": "critical", "block": False,
            "missing_tool": True, "file": "", "line": 0,
            "message": "mcp_checker engine not found in scanner environment; MCP security scan did not run",
        }]

    checks = cfg.get("checks", "code_static,tool_schema,semgrep")
    block_checks = set(cfg.get("block_checks", []))

    # mcp_checker writes its report under <projects-dir>/<project>/artifacts/.
    # Point it at a throwaway dir and scan the local clone (no re-clone).
    with tempfile.TemporaryDirectory(prefix="mcp_checker_") as proj_dir:
        # semgrep (spawned by mcp_checker) writes a settings file under $HOME and
        # phones home for version/metrics by default. The proxy runs as a
        # read-only-home non-root user, so give it a writable HOME and force it
        # fully offline — the scanner must not leak submitted-repo metadata.
        env = os.environ.copy()
        env["HOME"] = proj_dir
        env["SEMGREP_SETTINGS_FILE"] = os.path.join(proj_dir, "semgrep_settings.yml")
        env["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        env["SEMGREP_SEND_METRICS"] = "off"
        rc, stdout, stderr = await _run(
            [
                "python3", str(_MCP_CHECKER_PY),
                "-u", repo_path,
                "--project-name", "submission",
                "--projects-dir", proj_dir,
                "--checks", checks,
            ],
            cwd=str(_MCP_CHECKER_DIR),
            timeout=300,
            env=env,
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
    # Infra checks that FAIL for reasons unrelated to the repo's security posture.
    _infra = {"clone", "checkout", "lint", "rego", "trivy"}
    for res in report.get("results", []):
        if res.get("status") != "FAIL" or res.get("name") in _infra:
            continue
        name = res.get("name", "unknown")
        hits = _mcp_checker_hits(res.get("details", {}))
        blocks = name in block_checks
        for h in hits[:20]:  # cap per-check to keep the report bounded
            findings.append({
                "scanner": "mcp_checker",
                "check": name,
                "severity": "critical" if blocks else "warning",
                "block": blocks,
                "file": _rel_to_repo(h.get("file", ""), repo_path),
                "line": h.get("line", 0),
                "message": h.get("message") or f"{name}: {h.get('detail', 'MCP security check failed')}",
            })
    return findings


def _rel_to_repo(path: str, repo_path: str) -> str:
    """mcp_checker emits absolute paths inside its own clone dir; relativise."""
    if not path:
        return ""
    try:
        # mcp_checker clones into <projects-dir>/submission/repo/... — strip to
        # the basename-ward portion after 'repo/' when present, else basename.
        p = str(path)
        if "/repo/" in p:
            return p.split("/repo/", 1)[1]
        return os.path.basename(p)
    except Exception:
        return path


def _mcp_checker_hits(details: dict) -> list[dict]:
    """Normalise the varied per-check detail shapes into {file,line,detail,message}."""
    out: list[dict] = []
    # code_static / semgrep style: findings -> [{file, hits:[{line,sig}]}]
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
    # tool_schema style: violations -> [{tool, type, parameter, line, file}]
    for v in details.get("violations", []) or []:
        out.append({"file": v.get("file", ""), "line": v.get("line", 0),
                    "detail": v.get("type", ""),
                    "message": f"{v.get('type','violation')}: tool {v.get('tool','?')}"
                               f"{' param ' + v['parameter'] if v.get('parameter') else ''}"})
    # attack-pattern / doc-ast style: hits -> [{file, type, line, match/snippet/...}]
    # (malicious_doc_ast, windows/linux/macos_attack_patterns, network_exposure,
    # ssrf_patterns, memory_poisoning, oauth_abuse, crypto_stealer, ide_config_scan,
    # obfuscation_scan all share this shape via detect_*/​_detect_platform_patterns).
    # Previously unhandled — any FAIL from these checks silently fell through to the
    # blank-message fallback below, discarding the actual file/line/evidence a
    # reviewer needs to assess or waive the finding.
    for h in details.get("hits", []) or []:
        kind = h.get("type", "finding")
        evidence = (
            h.get("match") or h.get("snippet") or h.get("path_literal")
            or h.get("chain") or ""
        )
        out.append({
            "file": h.get("file", ""),
            "line": h.get("line", 0),
            "detail": evidence,
            "message": f"{kind}: {evidence}" if evidence else kind,
        })
    if not out:  # a FAIL with an unrecognised shape still counts — don't drop it
        out.append({"file": "", "line": 0, "detail": "", "message": ""})
    return out


async def _run_pip_audit(repo_path: str, config: dict) -> list[dict]:
    """Run pip-audit if enabled and requirements files exist."""
    dep_cfg = config.get("scanners", {}).get("dependency_audit", {})
    if not dep_cfg.get("enabled", True):
        return []
    if "pip" not in dep_cfg.get("ecosystems", ["pip"]):
        return []
    # Find requirements files
    req_files = list(Path(repo_path).glob("requirements*.txt")) + list(Path(repo_path).glob("pyproject.toml"))
    if not req_files:
        return [{
            "scanner": "pip-audit",
            "severity": "info",
            "block": False,
            "skipped": True,
            "file": "",
            "line": 0,
            "message": "No requirements.txt/pyproject.toml found — dependency-CVE scan did not run "
                       "(this repo may use a different ecosystem, e.g. npm, which is not CVE-audited here)",
        }]

    if not shutil.which("pip-audit"):
        logger.error("pip-audit not found; scan cannot certify this submission")
        return [{
            "scanner": "pip-audit",
            "severity": "critical",
            "block": False,
            "missing_tool": True,
            "file": "",
            "line": 0,
            "message": "pip-audit binary not found in scanner environment; dependency scan did not run",
        }]

    block_on = dep_cfg.get("block_on", "critical")
    severity_order = ["low", "medium", "high", "critical"]
    block_threshold = severity_order.index(block_on) if block_on in severity_order else 3

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


# ---------------------------------------------------------------------------
# R-9: textual-only SBOM manifest parsing (declared, unresolved dependencies)
#
# No `pip install`/`npm install`, no code execution — regex/stdlib line
# parsing only, run in the same trust boundary R-0 already accepts for
# trufflehog/pip-audit (attacker-controlled repo content, bounded I/O).
# ---------------------------------------------------------------------------

_SBOM_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB — malformed/huge manifest guard
_SBOM_MAX_COMPONENTS = 500

# name[extras]specifier, e.g. "requests[security]==2.31.0" / "flask>=2.0" / "click"
_REQ_LINE_RE = re.compile(
    r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9._*+!-]*)'
)


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
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}",
        })
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
    # PEP 621: [project.dependencies] = ["name>=1.0", ...]
    for dep in data.get("project", {}).get("dependencies", []) or []:
        m = _REQ_LINE_RE.match(str(dep).strip())
        if not m:
            continue
        name, _op, version = m.groups()
        version = version.strip() or "*"
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}",
        })
    # Poetry: [tool.poetry.dependencies] name = "^1.0" (table of name -> spec)
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for name, spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            version = str(spec.get("version", "*")).lstrip("^~>=< ") or "*"
        else:
            version = str(spec).lstrip("^~>=< ") or "*"
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}" if version != "*" else f"pkg:pypi/{name.lower()}",
        })
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
            out.append({
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}" if version != "*" else f"pkg:npm/{name}",
            })
    return out


_GO_REQUIRE_LINE_RE = re.compile(r'^([^\s]+)\s+(v[^\s]+)')


def _parse_go_mod(text_content: str) -> list[dict]:
    """
    Parse `require` module/version pairs from a go.mod file — both the
    single-line form (`require module v1.2.3`) and the grouped block form
    (`require (\n  module v1.2.3\n)`). Comments (`// indirect` etc.) and
    blank lines are ignored; malformed lines are skipped, not fatal.
    """
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
        out.append({
            "name": name,
            "version": version,
            "purl": f"pkg:golang/{name}@{version}",
        })
    return out


async def generate_cyclonedx_sbom(repo_path: str) -> dict | None:
    """R-5 step 2: generate a CycloneDX SBOM with syft. Soft-fail (returns None).

    Static, offline (`syft dir:` — no install/build, no network). A missing binary
    or any failure returns None; the caller keeps the declared-dependency inventory
    (parse_sbom_components) as the always-available fallback. Never a scan gate.
    """
    if not shutil.which("syft"):
        logger.info("syft not present; skipping CycloneDX SBOM (declared-deps inventory still collected)")
        return None
    env = os.environ.copy()
    env.setdefault("SYFT_CHECK_FOR_APP_UPDATE", "false")
    rc, stdout, stderr = await _run(
        ["syft", f"dir:{repo_path}", "-o", "cyclonedx-json", "-q"],
        timeout=180, env=env,
    )
    if rc != 0 or not stdout.strip():
        logger.warning("syft SBOM generation failed (rc=%s): %s", rc, (stderr or "")[-300:])
        return None
    try:
        doc = json.loads(stdout)
        # Bound the stored size — a pathological repo shouldn't bloat the row.
        if len(stdout) > 4 * 1024 * 1024:
            logger.warning("syft SBOM > 4MB; storing components summary only")
            return {"bomFormat": doc.get("bomFormat"), "specVersion": doc.get("specVersion"),
                    "components": (doc.get("components") or [])[:_SBOM_MAX_COMPONENTS],
                    "_truncated": True}
        return doc
    except json.JSONDecodeError as exc:
        logger.warning("syft SBOM output not valid JSON: %s", exc)
        return None


def parse_sbom_components(repo_path: str) -> list[dict]:
    """
    Best-effort, bounded parse of declared (unresolved) dependencies from
    common manifest files at the repo root. Never raises — a malformed or
    oversized manifest degrades to "nothing parsed from that file", never a
    scan failure (this is inventory metadata, not a security gate; unlike
    trufflehog/pip-audit above, a parse miss here is silent, not `error`).
    """
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
    # De-dupe by (name, version); cap regardless of source file mix.
    seen = set()
    deduped = []
    for c in components:
        key = (c["name"].lower(), c["version"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    return deduped[:_SBOM_MAX_COMPONENTS]


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
                    scan_report = CAST(:report AS jsonb),
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
    # R-2: accept any URL matching an enabled git provider (github/bitbucket/…).
    from app.services import git_providers
    if await git_providers.match_provider(github_url) is None:
        await _set_status("blocked", [{
            "scanner": "url_validation",
            "severity": "critical",
            "block": True,
            "file": "",
            "line": 0,
            "message": "Repository URL rejected: host must match an enabled git provider "
                       "(Admin → Git Providers).",
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

        # PRD-0006 R-1: record the scanned commit so a later re-audit can detect
        # a stale code-scan floor. Best-effort (shallow clone still has HEAD).
        scan_commit = ""
        try:
            rc_c, out_c, _ = await _run(["git", "-C", repo_path, "rev-parse", "HEAD"], timeout=15)
            if rc_c == 0:
                scan_commit = out_c.strip()[:64]
        except Exception:
            scan_commit = ""

        # R-9: best-effort manifest parse, independent of scan pass/fail —
        # inventory metadata, not a security gate (FM: never blocks approval).
        try:
            sbom_components = parse_sbom_components(repo_path)
        except Exception as exc:
            logger.warning("SBOM component parse failed for server_id=%s: %s", server_id, exc)
            sbom_components = []
        # R-5 step 2: full CycloneDX SBOM via syft (soft-fail — None if syft
        # absent/fails; the declared-deps inventory above is the fallback).
        try:
            sbom_cyclonedx = await generate_cyclonedx_sbom(repo_path)
        except Exception as exc:
            logger.warning("CycloneDX SBOM generation failed for server_id=%s: %s", server_id, exc)
            sbom_cyclonedx = None
        async with AsyncSessionLocal() as session:
            await session.execute(text("""
                UPDATE server_registry
                SET sbom_components = CAST(:components AS jsonb),
                    sbom_cyclonedx = CAST(:cyclonedx AS jsonb),
                    scanned_at = now(),
                    scan_commit = :commit,
                    updated_at = now()
                WHERE server_id = :sid
            """), {"components": json.dumps(sbom_components),
                   "cyclonedx": json.dumps(sbom_cyclonedx) if sbom_cyclonedx is not None else None,
                   "commit": scan_commit or None,
                   "sid": server_id})
            await session.commit()

        findings: list[dict] = []
        th, custom, pip_f, mcp_f = await asyncio.gather(
            _run_trufflehog(repo_path, config),
            _run_custom_rules(repo_path, config),
            _run_pip_audit(repo_path, config),
            _run_mcp_checker(repo_path, config),
        )
        findings.extend(th)
        findings.extend(custom)
        findings.extend(pip_f)
        findings.extend(mcp_f)

        blocked = any(f.get("block") for f in findings)
        missing_tool = any(f.get("missing_tool") for f in findings)
        # R-0 fix: a scanner that couldn't run is not a pass — fail closed.
        status = "blocked" if blocked else ("error" if missing_tool else "passed")
        await _set_status(status, findings)
        logger.info(
            "Scan complete server_id=%s status=%s findings=%d",
            server_id, status, len(findings),
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
    from app.services import git_providers
    if await git_providers.match_provider(github_url) is None:
        return ([{
            "scanner": "url_validation", "severity": "critical", "block": True,
            "file": "", "line": 0,
            "message": "Repository URL rejected by rescan: host must match an enabled git provider.",
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

        th, custom, pip_f, mcp_f = await asyncio.gather(
            _run_trufflehog(repo_path, config),
            _run_custom_rules(repo_path, config),
            _run_pip_audit(repo_path, config),
            _run_mcp_checker(repo_path, config),
        )
        findings = th + custom + pip_f + mcp_f
        blocked = any(f.get("block") for f in findings)
        missing_tool = any(f.get("missing_tool") for f in findings)
        status = "blocked" if blocked else ("error" if missing_tool else "passed")
        return findings, status
    except Exception as exc:
        return ([{
            "scanner": "system", "severity": "critical", "block": True,
            "file": "", "line": 0, "message": f"Rescan crashed: {exc}",
        }], "blocked")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
