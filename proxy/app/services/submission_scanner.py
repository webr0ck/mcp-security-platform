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
from sqlalchemy import text

from app.core.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

_SCAN_CONFIG_PATH = Path(__file__).parents[2] / "scan-config.yaml"

# GitHub account used to clone repositories (shown to submitters in the wizard).
# R-2: the authoritative per-provider allowlist + clone now lives in
# app/services/git_providers.py; these env vars remain the github fallback
# (account display + token via git_providers.provider_token) for back-compat.
GITHUB_CLONE_ACCOUNT = os.environ.get("GITHUB_CLONE_ACCOUNT", "mcp-platform-bot")
GITHUB_CLONE_TOKEN = os.environ.get("GITHUB_CLONE_TOKEN", "")


# ── SBOM manifest-parser constants ─────────────────────────────────────────
# Retained after the 2026-07-25 removal of the in-proxy scan-execution path.
# _MCP_CHECKER_DIR/_MCP_CHECKER_PY went with it — they only fed the deleted
# in-proxy checker; scanning now runs in the isolated scanner-worker.
_SBOM_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB — malformed/huge manifest guard
_SBOM_MAX_COMPONENTS = 500
_REQ_LINE_RE = re.compile(
    r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|>|<)?\s*([A-Za-z0-9._*+!-]*)'
)


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
    except TimeoutError:
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


