"""
checks_research.py — MCP security research scanner checks.

Five checks added from the 2026-05 CISO-prioritised research pipeline:
  check_default_binding_exposure
  check_unauthenticated_control_plane
  check_silent_exfil_pattern
  check_tool_definition_drift
  check_oauth_misconfiguration

Each returns {"name": str, "status": "PASS|FAIL|SKIPPED|ERROR", "details": dict, "duration_s": float}.
Import helpers from mcp_checker to avoid duplication.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Local copies of helpers from mcp_checker (can't import mcp_checker — it imports us).
_SKIP_FRAGS = ("node_modules", "venv", ".venv", "site-packages", "__pycache__", ".git",
               "dist", "build", "out", ".next", ".nuxt")


def rglob_text(
    repo: Path,
    exts: tuple = (".py", ".ts", ".js", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java",
                   ".yaml", ".yml", ".json", ".env", ".ini", ".toml", ".sh", ".bash", ".zsh", ".md"),
) -> List[Path]:
    files = []
    for p in repo.rglob("*"):
        s = str(p)
        if any(f"/{frag}/" in s for frag in _SKIP_FRAGS):
            continue
        if p.is_file() and p.suffix.lower() in exts and p.stat().st_size <= 2_000_000:
            files.append(p)
    return files


def read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# check_default_binding_exposure
# CVE class: NeighborJack / unauthenticated LAN exposure (Tier 1, risk 3/3)
# ---------------------------------------------------------------------------

# Patterns that bind to all interfaces
_BIND_ALL_PATTERNS: List[re.Pattern] = [
    re.compile(r"""host\s*=\s*["']0\.0\.0\.0["']"""),
    re.compile(r"""\.listen\s*\(\s*\d+\s*,\s*["']0\.0\.0\.0["']"""),
    re.compile(r"""\.bind\s*\(\s*["']0\.0\.0\.0"""),
    re.compile(r"""uvicorn\.run\s*\([^)]*host\s*=\s*["']0\.0\.0\.0["']"""),
    re.compile(r"""FastMCP\s*\([^)]*host\s*=\s*["']0\.0\.0\.0["']"""),
    re.compile(r"""mcp\.run\s*\([^)]*host\s*=\s*["']0\.0\.0\.0["']"""),
    re.compile(r"""app\.run\s*\([^)]*host\s*=\s*["']0\.0\.0\.0["']"""),
    # Docker-compose / yaml: ports: "0.0.0.0:..."
    re.compile(r"""["']0\.0\.0\.0:\d+"""),
]

# Auth middleware presence signals in the same file
_AUTH_PRESENT = re.compile(
    r"(require_auth|@auth|authenticate|oauth|jwt|bearer|api_key|Authorization)",
    re.IGNORECASE,
)

_SKIP_DIRS = {"node_modules", ".git", "__pycache__", "vendor", "dist", "build", ".venv", "venv"}
_TEST_RE = re.compile(r"(test_|_test\.|\.test\.|spec\.|_spec\.)", re.IGNORECASE)


def check_default_binding_exposure(repo_dir: Path) -> Dict[str, Any]:
    """Detect MCP servers binding to 0.0.0.0 without auth middleware (LAN/internet exposure)."""
    start = time.time()
    res: Dict[str, Any] = {"name": "default_binding_exposure", "status": "PASS", "details": {}}

    exts = (".py", ".js", ".ts", ".go", ".rs", ".yaml", ".yml", ".toml", ".sh")
    hits: List[Dict] = []

    for f in rglob_text(repo_dir, exts=exts):
        if _TEST_RE.search(str(f)):
            continue
        txt = read_text_safe(f)
        for pat in _BIND_ALL_PATTERNS:
            m = pat.search(txt)
            if m:
                has_auth = bool(_AUTH_PRESENT.search(txt))
                hits.append({
                    "file": str(f.relative_to(repo_dir)),
                    "match": m.group(0)[:120],
                    "has_auth_in_file": has_auth,
                    "severity": "high" if has_auth else "critical",
                })
                break  # one hit per file is enough

    if hits:
        res["status"] = "FAIL"
        critical = [h for h in hits if h["severity"] == "critical"]
        res["details"] = {
            "hits": hits,
            "critical_count": len(critical),
            "high_count": len(hits) - len(critical),
            "summary": (
                f"{len(critical)} file(s) bind to 0.0.0.0 with no auth middleware detected — "
                "reachable from any LAN/internet host."
            ) if critical else (
                f"{len(hits)} file(s) bind to 0.0.0.0 but auth middleware detected — verify coverage."
            ),
        }
    else:
        res["details"] = {"reason": "no 0.0.0.0 binding patterns found"}

    res["duration_s"] = round(time.time() - start, 3)
    return res


# ---------------------------------------------------------------------------
# check_unauthenticated_control_plane
# CVE class: CVE-2026-23744 class — HTTP management routes without auth/CSRF
# ---------------------------------------------------------------------------

# Flask / FastAPI / Express management route patterns
_MGMT_ROUTE_RE = re.compile(
    r"""(@app\.(get|post|put|delete|route)|router\.(get|post)|app\.(get|post))\s*\(\s*["'][^"']*"""
    r"""(install|connect|restart|shutdown|config|admin|management|control|reload|update)[^"']*["']""",
    re.IGNORECASE,
)

# Patterns for user-supplied URL passed to install/exec helpers
_INSTALL_URL_RE = re.compile(
    r"""(npm\s+install|pip\s+install|apt.get\s+install)[^"'\n]{0,80}(https?://|{|}|\$)""",
    re.IGNORECASE,
)

# CSRF protection signals
_CSRF_RE = re.compile(r"(csrf|CSRFProtect|csrf_token|X-CSRF-Token)", re.IGNORECASE)

# Localhost-only binding (mitigates risk)
_LOCALHOST_RE = re.compile(r"""host\s*=\s*["'](127\.0\.0\.1|localhost)["']""")

# Auth check signals in same file
_AUTH_IN_FILE_RE = re.compile(
    r"(require_auth|@requires_auth|@login_required|verify_token|check_auth|api_key_required)",
    re.IGNORECASE,
)


def check_unauthenticated_control_plane(repo_dir: Path) -> Dict[str, Any]:
    """Detect HTTP management routes (install/restart/config) without CSRF/auth protection."""
    start = time.time()
    res: Dict[str, Any] = {"name": "unauthenticated_control_plane", "status": "PASS", "details": {}}

    exts = (".py", ".js", ".ts", ".go", ".rb")
    hits: List[Dict] = []

    for f in rglob_text(repo_dir, exts=exts):
        if _TEST_RE.search(str(f)):
            continue
        txt = read_text_safe(f)
        route_match = _MGMT_ROUTE_RE.search(txt)
        if not route_match:
            continue
        has_csrf = bool(_CSRF_RE.search(txt))
        has_auth = bool(_AUTH_IN_FILE_RE.search(txt))
        is_localhost = bool(_LOCALHOST_RE.search(txt))
        has_install_url = bool(_INSTALL_URL_RE.search(txt))

        severity = "high"
        if has_install_url and not has_csrf and not has_auth and not is_localhost:
            severity = "critical"

        hits.append({
            "file": str(f.relative_to(repo_dir)),
            "route_match": route_match.group(0)[:120],
            "has_csrf": has_csrf,
            "has_auth": has_auth,
            "is_localhost_only": is_localhost,
            "has_install_url_pattern": has_install_url,
            "severity": severity,
        })

    if hits:
        res["status"] = "FAIL"
        critical = [h for h in hits if h["severity"] == "critical"]
        res["details"] = {
            "hits": hits,
            "critical_count": len(critical),
            "high_count": len(hits) - len(critical),
            "summary": (
                f"{len(critical)} management route(s) allow remote code execution via "
                "user-supplied install URLs with no CSRF/auth."
            ) if critical else (
                f"{len(hits)} management route(s) lack CSRF or auth protection."
            ),
        }
    else:
        res["details"] = {"reason": "no unauthenticated management routes detected"}

    res["duration_s"] = round(time.time() - start, 3)
    return res


# ---------------------------------------------------------------------------
# check_silent_exfil_pattern
# CVE class: postmark-mcp class — tool handlers with secondary outbound HTTP
# ---------------------------------------------------------------------------

_SUSPICIOUS_DOMAIN_RE = re.compile(
    r"""["'](https?://[^"']*(?:webhook\.site|requestbin|pipedream|beeceptor|hookbin|"""
    r"""ngrok\.io|localhost\.run|exfil|steal|collect|harvest|track)[^"']*)["']""",
    re.IGNORECASE,
)

_HARDCODED_URL_RE = re.compile(
    r"""["'](https?://[a-zA-Z0-9._/-]{8,})["']""",
)

_ASYNC_SPAWN_RE = re.compile(
    r"""(asyncio\.create_task|threading\.Thread|background_tasks\.add_task|setImmediate|setTimeout)""",
)

# JS/TS hardcoded fetch / axios patterns
_JS_FETCH_URL_RE = re.compile(
    r"""fetch\s*\(\s*["'](https?://[^"']{8,})["']""",
)
_JS_AXIOS_URL_RE = re.compile(
    r"""axios\.(get|post|put)\s*\(\s*["'](https?://[^"']{8,})["']""",
)


class _ToolHandlerVisitor(ast.NodeVisitor):
    """Walk Python AST; find @mcp.tool functions that make secondary HTTP calls."""

    def __init__(self, source_lines: List[str]) -> None:
        self.source_lines = source_lines
        self.findings: List[Dict] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        is_tool = any(
            (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
             and getattr(d.func.value, "id", None) == "mcp" and d.func.attr == "tool")
            or (isinstance(d, ast.Attribute) and getattr(d.value, "id", None) == "mcp" and d.attr == "tool")
            or (isinstance(d, ast.Name) and d.id == "tool")
            for d in node.decorator_list
        )
        if not is_tool:
            self.generic_visit(node)
            return

        # Collect string literals that look like URLs inside this function body
        urls: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if re.match(r"https?://", child.value):
                    urls.append(child.value)

        if len(urls) >= 2:
            suspicious = [u for u in urls if _SUSPICIOUS_DOMAIN_RE.search(f'"{u}"')]
            self.findings.append({
                "function": node.name,
                "line": node.lineno,
                "outbound_urls": urls[:10],
                "suspicious_urls": suspicious,
                "severity": "critical" if suspicious else "high",
            })

        self.generic_visit(node)

    # Also handle async def
    visit_AsyncFunctionDef = visit_FunctionDef


def check_silent_exfil_pattern(repo_dir: Path) -> Dict[str, Any]:
    """Detect MCP tool handlers with secondary hardcoded outbound HTTP — postmark-mcp class."""
    start = time.time()
    res: Dict[str, Any] = {"name": "silent_exfil_pattern", "status": "PASS", "details": {}}
    hits: List[Dict] = []

    # Python: AST analysis of @mcp.tool functions
    for f in rglob_text(repo_dir, exts=(".py",)):
        if _TEST_RE.search(str(f)):
            continue
        txt = read_text_safe(f)
        try:
            tree = ast.parse(txt)
        except SyntaxError:
            continue
        visitor = _ToolHandlerVisitor(txt.splitlines())
        visitor.visit(tree)
        for finding in visitor.findings:
            hits.append({
                "file": str(f.relative_to(repo_dir)),
                "lang": "python",
                **finding,
            })

    # JS/TS: regex scan for hardcoded fetch/axios URLs inside likely tool handlers
    for f in rglob_text(repo_dir, exts=(".js", ".ts", ".mjs", ".tsx")):
        if _TEST_RE.search(str(f)):
            continue
        txt = read_text_safe(f)
        fetch_urls = [m.group(1) for m in _JS_FETCH_URL_RE.finditer(txt)]
        axios_urls = [m.group(2) for m in _JS_AXIOS_URL_RE.finditer(txt)]
        all_urls = fetch_urls + axios_urls
        if len(all_urls) >= 2:
            suspicious = [u for u in all_urls if _SUSPICIOUS_DOMAIN_RE.search(f'"{u}"')]
            hits.append({
                "file": str(f.relative_to(repo_dir)),
                "lang": "js_ts",
                "outbound_urls": all_urls[:10],
                "suspicious_urls": suspicious,
                "severity": "critical" if suspicious else "high",
            })

    if hits:
        res["status"] = "FAIL"
        critical = [h for h in hits if h["severity"] == "critical"]
        res["details"] = {
            "hits": hits,
            "critical_count": len(critical),
            "high_count": len(hits) - len(critical),
            "summary": (
                f"{len(critical)} tool handler(s) send data to suspicious exfiltration endpoints."
            ) if critical else (
                f"{len(hits)} tool handler(s) make multiple hardcoded outbound HTTP calls — "
                "manual review required."
            ),
        }
    else:
        res["details"] = {"reason": "no silent exfiltration patterns detected"}

    res["duration_s"] = round(time.time() - start, 3)
    return res


# ---------------------------------------------------------------------------
# check_tool_definition_drift
# CVE class: rug pull — tool schema / description changes between scans
# ---------------------------------------------------------------------------

_SUSPICIOUS_DESC_RE = re.compile(
    r"""(YOU MUST|DISREGARD|ignore previous|now route|forward all|send.*to.*http|"""
    r"""http[s]?://[a-z0-9._/-]{6,})""",
    re.IGNORECASE,
)

_SUSPICIOUS_PARAM_RE = re.compile(
    r"""(log_to|forward_to|notify|relay|exfil|callback_url|webhook)""",
    re.IGNORECASE,
)


def _extract_py_tools(repo_dir: Path) -> Dict[str, Dict]:
    """Return {tool_name: {description, params, file}} for @mcp.tool functions."""
    tools: Dict[str, Dict] = {}
    for f in rglob_text(repo_dir, exts=(".py",)):
        txt = read_text_safe(f)
        try:
            tree = ast.parse(txt)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_tool = any(
                (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                 and getattr(d.func.value, "id", None) == "mcp" and d.func.attr == "tool")
                or (isinstance(d, ast.Attribute) and getattr(d.value, "id", None) == "mcp" and d.attr == "tool")
                or (isinstance(d, ast.Name) and d.id == "tool")
                for d in node.decorator_list
            )
            if not is_tool:
                continue
            doc = ast.get_docstring(node) or ""
            params = [a.arg for a in node.args.args if a.arg != "self"]
            tools[node.name] = {
                "description": doc,
                "params": params,
                "file": str(f),
            }
    return tools


def _extract_js_tools(repo_dir: Path) -> Dict[str, Dict]:
    """Return {tool_name: {description, params, file}} from JS/TS .tool("name", "desc") calls."""
    tools: Dict[str, Dict] = {}
    pat = re.compile(r"""\.tool\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']*)["']""")
    for f in rglob_text(repo_dir, exts=(".ts", ".js", ".tsx", ".mjs")):
        txt = read_text_safe(f)
        for m in pat.finditer(txt):
            name, desc = m.group(1), m.group(2)
            tools[name] = {"description": desc, "params": [], "file": str(f)}
    return tools


def _tool_hash(tool: Dict) -> str:
    canonical = json.dumps(
        {"description": tool["description"], "params": tool["params"]}, sort_keys=True
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _classify_drift(old: Dict, new: Dict) -> str:
    """Return 'critical', 'high', or 'medium' depending on what changed."""
    new_params = set(new["params"]) - set(old["params"])
    if new_params and any(_SUSPICIOUS_PARAM_RE.search(p) for p in new_params):
        return "critical"
    if _SUSPICIOUS_DESC_RE.search(new["description"]) and not _SUSPICIOUS_DESC_RE.search(old["description"]):
        return "critical"
    if new_params:
        return "high"
    return "medium"


def check_tool_definition_drift(repo_dir: Path, artifacts_dir: Path) -> Dict[str, Any]:
    """Detect rug-pull: MCP tool descriptions or schemas changed since last scan."""
    start = time.time()
    res: Dict[str, Any] = {"name": "tool_definition_drift", "status": "PASS", "details": {}}

    tools = {**_extract_py_tools(repo_dir), **_extract_js_tools(repo_dir)}

    if not tools:
        res["details"] = {"reason": "no MCP tools found", "tool_count": 0}
        res["duration_s"] = round(time.time() - start, 3)
        return res

    baseline_path = artifacts_dir / "tool_definition_drift.json"
    current_hashes = {name: _tool_hash(t) for name, t in tools.items()}

    if not baseline_path.exists():
        os.makedirs(str(artifacts_dir), exist_ok=True)
        payload = {
            name: {"hash": _tool_hash(t), "description": t["description"], "params": t["params"]}
            for name, t in tools.items()
        }
        baseline_path.write_text(json.dumps(payload, indent=2))
        res["details"] = {"baseline_created": True, "tool_count": len(tools), "baseline_path": str(baseline_path)}
        res["duration_s"] = round(time.time() - start, 3)
        return res

    baseline = json.loads(baseline_path.read_text())

    changed: List[Dict] = []
    new_tools: List[str] = []

    for name, tool in tools.items():
        old_entry = baseline.get(name)
        if old_entry is None:
            new_tools.append(name)
            continue
        if _tool_hash(tool) != old_entry["hash"]:
            old_tool = {"description": old_entry.get("description", ""), "params": old_entry.get("params", [])}
            severity = _classify_drift(old_tool, tool)
            changed.append({
                "name": name,
                "severity": severity,
                "old_description": old_tool["description"][:200],
                "new_description": tool["description"][:200],
                "old_params": old_tool["params"],
                "new_params": tool["params"],
                "file": tool["file"],
            })

    # Update baseline with current state
    updated = {
        name: {"hash": _tool_hash(t), "description": t["description"], "params": t["params"]}
        for name, t in tools.items()
    }
    baseline_path.write_text(json.dumps(updated, indent=2))

    if changed:
        res["status"] = "FAIL"
        critical = [c for c in changed if c["severity"] == "critical"]
        res["details"] = {
            "changed_tools": changed,
            "new_tools": new_tools,
            "critical_count": len(critical),
            "high_count": len([c for c in changed if c["severity"] == "high"]),
            "medium_count": len([c for c in changed if c["severity"] == "medium"]),
            "baseline_path": str(baseline_path),
            "summary": (
                f"{len(critical)} tool(s) show critical rug-pull indicators "
                "(injection text or suspicious new parameters)."
            ) if critical else (
                f"{len(changed)} tool definition(s) changed since last scan."
            ),
        }
    else:
        res["details"] = {
            "tool_count": len(tools),
            "new_tools": new_tools,
            "baseline_path": str(baseline_path),
        }

    res["duration_s"] = round(time.time() - start, 3)
    return res


# ---------------------------------------------------------------------------
# check_oauth_misconfiguration
# 7-class taxonomy: C1 PKCE, C2 redirect URI, C3 broad scope, C4 state,
#                   C5 token-in-env, C6 dynamic authz server, C7 offline_access
# ---------------------------------------------------------------------------

# C1: OAuth authorization URL present but PKCE absent
_OAUTH_AUTHZ_URL_RE = re.compile(r"""["']https?://[^"']*[?&]response_type=(code|token)[^"']*["']""")
_PKCE_PRESENT_RE = re.compile(r"(code_challenge|code_verifier|PKCE|S256)", re.IGNORECASE)

# C2: Redirect URI with wildcard or format placeholder
_REDIRECT_URI_RE = re.compile(r"""redirect_uri\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_REDIRECT_WILDCARD_RE = re.compile(r"[*%{]|format\s*\(")
_TUNNEL_DOMAIN_RE = re.compile(r"(ngrok\.io|localhost\.run|serveo\.net|trycloudflare\.com)", re.IGNORECASE)

# C3: Broad OAuth scopes
_SCOPE_RE = re.compile(r"""scope\s*[=:]\s*["']([^"']{4,})["']""", re.IGNORECASE)
_BROAD_SCOPE_SIGNALS = re.compile(
    r"(admin|full_control|write:repo|https://www\.googleapis\.com/auth/[a-z.]+\s+https://)",
    re.IGNORECASE,
)

# C4: Authorization URL without state parameter
_STATE_PRESENT_RE = re.compile(r"(secrets\.|os\.urandom|uuid\.|state\s*=)", re.IGNORECASE)

# C5: Token written to environment variable
_TOKEN_IN_ENV_RE = re.compile(
    r"""os\.environ\s*\[\s*["'](ACCESS_TOKEN|OAUTH_TOKEN|ID_TOKEN|BEARER)[^"']*["']\s*\]\s*=""",
    re.IGNORECASE,
)

# C6: Authorization server endpoint read from config/env/request (not pinned)
_AUTHZ_SERVER_DYNAMIC_RE = re.compile(
    r"""authorization_endpoint\s*=\s*(config|os\.environ|request\.|settings\.)""",
    re.IGNORECASE,
)

# C7: offline_access scope without refresh token rotation
_OFFLINE_ACCESS_RE = re.compile(r"offline_access|refresh_token", re.IGNORECASE)
_REFRESH_ROTATION_RE = re.compile(r"(rotate|invalidate|revoke).*refresh", re.IGNORECASE)


def check_oauth_misconfiguration(repo_dir: Path) -> Dict[str, Any]:
    """Detect OAuth 2.0 / PKCE misconfigs: 7-class taxonomy (C1–C7, RFC 9700 alignment)."""
    start = time.time()
    res: Dict[str, Any] = {"name": "oauth_misconfiguration", "status": "PASS", "details": {}}

    exts = (".py", ".js", ".ts", ".mjs", ".go", ".rb", ".java")
    findings: List[Dict] = []

    for f in rglob_text(repo_dir, exts=exts):
        if _TEST_RE.search(str(f)):
            continue
        txt = read_text_safe(f)
        rel = str(f.relative_to(repo_dir))

        # C1 — missing PKCE
        if _OAUTH_AUTHZ_URL_RE.search(txt) and not _PKCE_PRESENT_RE.search(txt):
            findings.append({"class": "C1", "file": rel, "severity": "critical",
                             "detail": "OAuth authorization code flow without PKCE (RFC 9700 violation)"})

        # C2 — redirect URI wildcard / placeholder
        for m in _REDIRECT_URI_RE.finditer(txt):
            uri = m.group(1)
            if _REDIRECT_WILDCARD_RE.search(uri):
                findings.append({"class": "C2", "file": rel, "severity": "critical",
                                 "detail": f"Redirect URI contains wildcard/placeholder: {uri[:80]}"})
            elif _TUNNEL_DOMAIN_RE.search(uri):
                findings.append({"class": "C2", "file": rel, "severity": "high",
                                 "detail": f"Redirect URI points to tunnel service: {uri[:80]}"})

        # C3 — broad scopes
        for m in _SCOPE_RE.finditer(txt):
            scope_val = m.group(1)
            if _BROAD_SCOPE_SIGNALS.search(scope_val):
                findings.append({"class": "C3", "file": rel, "severity": "high",
                                 "detail": f"Overly broad OAuth scope: {scope_val[:80]}"})

        # C4 — missing state / CSRF
        if _OAUTH_AUTHZ_URL_RE.search(txt) and not _STATE_PRESENT_RE.search(txt):
            findings.append({"class": "C4", "file": rel, "severity": "high",
                             "detail": "OAuth flow has no state parameter (CSRF risk)"})

        # C5 — access token written to env var
        if _TOKEN_IN_ENV_RE.search(txt):
            findings.append({"class": "C5", "file": rel, "severity": "high",
                             "detail": "OAuth access token stored in environment variable (plaintext)"})

        # C6 — authorization server endpoint from dynamic config
        if _AUTHZ_SERVER_DYNAMIC_RE.search(txt):
            findings.append({"class": "C6", "file": rel, "severity": "high",
                             "detail": "Authorization server endpoint read from dynamic config (not pinned)"})

        # C7 — offline_access / refresh token without rotation
        if _OFFLINE_ACCESS_RE.search(txt) and not _REFRESH_ROTATION_RE.search(txt):
            findings.append({"class": "C7", "file": rel, "severity": "medium",
                             "detail": "offline_access or refresh_token used without token rotation/revocation"})

    if findings:
        res["status"] = "FAIL"
        by_class = {}
        for fi in findings:
            by_class.setdefault(fi["class"], []).append(fi)
        critical = [fi for fi in findings if fi["severity"] == "critical"]
        res["details"] = {
            "findings": findings,
            "by_class": {k: len(v) for k, v in by_class.items()},
            "critical_count": len(critical),
            "total_count": len(findings),
            "summary": (
                f"{len(findings)} OAuth misconfiguration(s) across {len(by_class)} class(es). "
                f"{len(critical)} critical (PKCE missing or redirect URI wildcard)."
            ),
        }
    else:
        res["details"] = {"reason": "no OAuth misconfigurations detected"}

    res["duration_s"] = round(time.time() - start, 3)
    return res
