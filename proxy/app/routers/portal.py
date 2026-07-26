"""
MCP Security Platform — Multi-Role Web Portal

Provides a unified portal UI for all platform roles:
  - agent / admin: Catalog tab (browsable tool cards)
  - agent / admin: My Access tab (personal grants, credential status, MCP config snippet)
  - admin only:    Admin tab (tools table, credentials management, grants editor)

Routes:
  GET /portal                              — full page shell
  (removed 2026-07-25: GET /portal/fragments/catalog — unfiltered inventory dump)
  GET /portal/fragments/my-access          — my-access tab fragment
  GET /portal/fragments/admin              — admin tab fragment (admin only)
  GET /portal/fragments/admin/tools        — admin > tools sub-tab
  GET /portal/fragments/admin/credentials  — admin > credentials sub-tab
  GET /portal/fragments/admin/grants       — admin > grants sub-tab
  POST /portal/actions/save-grants         — atomic write back to data.json
"""
from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.services.auth_modes import AUTH_MODES
from app.services.oauth_policy import HIGH_RISK_SCOPES, _is_wildcard_consent_scope


def _injection_mode_filter_options() -> str:
    """WP-A5 (CR-02 completion): the catalog filter's mode dropdown used to be
    a hardcoded literal list that had drifted (included a nonexistent
    'header' mode, omitted basic_auth/kc_token_exchange/entra_*/
    external_oauth_*) — sourced from the canonical AUTH_MODES matrix instead,
    labelled with each mode's human-facing label. Excludes the deprecated
    oauth_user_token alias (kc_token_exchange covers the same filter intent)."""
    from html import escape as _esc
    from app.services.auth_modes import AuthMode

    opts = ['<option value="">All injection modes</option>']
    for mode, info in AUTH_MODES.items():
        if mode is AuthMode.OAUTH_USER_TOKEN:
            continue
        opts.append(f'<option value="{_esc(mode.value)}">{_esc(info.label)}</option>')
    return "\n        ".join(opts)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/portal", tags=["Portal"])

# Path to OPA data file — resolved relative to this file's location so it works
# regardless of CWD at runtime.
_HERE = Path(__file__).resolve().parent
_DATA_JSON = (_HERE / "../../../../policies/rego/data.json").resolve()
_REGO_DIR = (_HERE / "../../../../policies/rego").resolve()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _roles(request: Request) -> list[str]:
    return list(getattr(request.state, "client_roles", []) or [])


def _client_id(request: Request) -> str:
    return str(getattr(request.state, "client_id", "") or "")


def _require_portal_access(request: Request) -> None:
    """Read access to the portal. agent/admin get full use; auditor is read-only
    (see _require_portal_write). RBAC.md lists auditor as a first-class read role."""
    roles = _roles(request)
    if not any(r in {"agent", "admin", "auditor"} for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "agent, admin or auditor role required to access the portal."},
        )


def _is_auditor_only(request: Request) -> bool:
    """True when the caller has auditor but neither agent nor admin (read-only view)."""
    roles = _roles(request)
    return "auditor" in roles and not any(r in {"agent", "admin"} for r in roles)


def _require_portal_write(request: Request) -> None:
    """Portal write actions (credential upload, profile enable/disable) require
    agent or admin. Auditor is read-only and must be rejected here."""
    roles = _roles(request)
    if not any(r in {"agent", "admin"} for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "agent or admin role required for this action."},
        )


def _require_admin(request: Request) -> None:
    if "admin" not in _roles(request):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "Admin role required for this section."},
        )


_REVIEWER_ROLES = {"admin", "platform_admin", "security_reviewer"}


def _is_reviewer(roles: list[str]) -> bool:
    """admin/platform_admin/security_reviewer can review+approve submissions —
    mirrors submission.py's _require_submission_reviewer. Plain 'auditor' is
    read-only by design and intentionally excluded."""
    return any(r in _REVIEWER_ROLES for r in roles)


def _require_submission_reviewer(request: Request) -> None:
    if not _is_reviewer(_roles(request)):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "admin, platform_admin, or security_reviewer role required."},
        )


# ---------------------------------------------------------------------------
# Shared head tags. The bulk of the shared CSS/JS (_JS_COMMON and every
# admin/agent-shell + fragment inline <script>) was extracted to
# proxy/app/static/{portal.css,portal.js} — see roadmap R1.1. Every
# full-page shell links/scripts them once; fragments swapped in via htmx
# must NOT re-include them.
#
# _CSS below stays as a Python constant (rather than also moving into
# portal.css) solely because the standalone /portal/submit wizard page's
# acceptance tests (ui/e2e/portal-acceptance.spec.ts AC-04) assert against
# the raw page HTML returned by page.content() — which only ever contains
# the *source text* of inline <script>/<style> tags, never the contents of
# an externally-linked file. The wizard's CSS/JS were therefore kept inline
# rather than extracted, and _CSS (shared with portal.css, which every
# other page/fragment uses) had to stay defined here for that one caller.
# ---------------------------------------------------------------------------

_HTMX_TAG = '<script src="/static/htmx.min.js"></script>'
_FAVICON_LINK = '<link rel="icon" type="image/png" href="/static/owl-icon.png">'

_FONTS_LINK = (
    # Non-blocking async font load: media="print" + onload swap prevents blocking
    # the window load event when fonts.googleapis.com is unreachable (lab network).
    '<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800'
    '&family=JetBrains+Mono:wght@400;500;600&display=swap"'
    # data-media-swap replaces an inline onload= handler: inline event handlers are
    # blocked by the portal CSP and cannot be nonce'd. portal.js does the swap.
    ' rel="stylesheet" media="print" data-media-swap>'
)


_CSS = """
  :root {
    --bg:      #0a0c11;
    --surface: #12161e;
    --border:  rgba(255,255,255,0.07);
    --text:    #e7eaf0;
    --muted:   #8a93a4;
    --primary: #4f9cf9;
    --primary-dark: #0284c7;
    --green:   #4ade80;
    --red:     #f87171;
    --amber:   #eab308;
    --cyan:    #67e8f9;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
  }

  /* ---- Header ---- */
  .header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0.75rem 1.5rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .header-title {
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--primary);
    letter-spacing: -0.01em;
    flex: 1;
  }
  .user-chip {
    background: #0f172a;
    border: 1px solid var(--border);
    border-radius: 9999px;
    padding: 0.25rem 0.75rem;
    font-size: 0.8rem;
    color: var(--muted);
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .user-chip .uid { color: var(--text); font-weight: 600; }
  .role-pill {
    display: inline-block;
    padding: 0.1rem 0.4rem;
    border-radius: 9999px;
    font-size: 0.65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .role-admin   { background: #4c1d95; color: #c4b5fd; }
  .role-agent   { background: #065f46; color: #6ee7b7; }
  .role-auditor { background: #1e3a5f; color: #7dd3fc; }
  .role-reviewer{ background: #7c2d12; color: #fdba74; }
  .role-other   { background: var(--border); color: var(--muted); }

  /* ---- Tab bar ---- */
  .tabs {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 1.5rem;
    display: flex;
    gap: 0;
  }
  .tab-btn {
    background: none;
    border: none;
    border-bottom: 3px solid transparent;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 500;
    padding: 0.75rem 1.25rem;
    transition: color 0.15s, border-color 0.15s;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }

  /* ---- Main content area ---- */
  .content { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }

  /* ---- Tool cards ---- */
  .card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 1rem;
  }
  .tool-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.1rem;
    transition: border-color 0.15s;
  }
  .tool-card:hover { border-color: var(--primary); }
  .tool-card-header { display: flex; align-items: flex-start; gap: 0.5rem; margin-bottom: 0.6rem; }
  .tool-name { font-weight: 700; color: #f1f5f9; font-size: 0.95rem; flex: 1; }
  .tool-version { font-size: 0.7rem; color: var(--muted); margin-top: 0.1rem; }
  .tool-desc { font-size: 0.82rem; color: var(--muted); margin-bottom: 0.75rem; line-height: 1.5; }
  .tool-tags { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.5rem; }
  .tag {
    background: #1e3a5f;
    color: #93c5fd;
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
    font-size: 0.7rem;
    font-weight: 500;
  }

  /* ---- Badges ---- */
  .badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 9999px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    white-space: nowrap;
  }
  .badge-active    { background: #166534; color: #86efac; }
  .badge-quarantined { background: #7f1d1d; color: #fca5a5; }
  .badge-disabled  { background: #374151; color: #9ca3af; }
  .badge-pending   { background: #374151; color: #9ca3af; }
  .badge-risk-low  { background: #0c4a6e; color: var(--cyan); }
  .badge-risk-medium { background: #713f12; color: var(--amber); }
  .badge-risk-high { background: #7c2d12; color: #fdba74; }
  .badge-risk-critical { background: #7f1d1d; color: #fca5a5; }
  .badge-mode-none    { background: #374151; color: #9ca3af; }
  .badge-mode-header  { background: #1e3a5f; color: #7dd3fc; }
  .badge-mode-user    { background: #1e3a5f; color: #93c5fd; }
  .badge-mode-service { background: #065f46; color: #6ee7b7; }
  .badge-mode-service_account { background: #4c1d95; color: #c4b5fd; }
  .badge-mode-oauth_user_token { background: #7c2d12; color: #fdba74; }
  .badge-enrolled   { background: #166534; color: #86efac; }
  .badge-not-enrolled { background: #374151; color: #9ca3af; }

  /* ---- Forms & inputs ---- */
  .cred-form { margin-top: 0.85rem; border-top: 1px solid var(--border); padding-top: 0.85rem; }
  label { display: block; font-size: 0.78rem; color: var(--muted); margin-bottom: 0.25rem; margin-top: 0.5rem; }
  input, select, textarea {
    width: 100%;
    padding: 0.4rem 0.6rem;
    border: 1px solid #475569;
    border-radius: 5px;
    background: var(--bg);
    color: var(--text);
    font-size: 0.85rem;
    font-family: inherit;
  }
  input:focus, select:focus, textarea:focus {
    outline: none;
    border-color: var(--primary);
  }
  textarea { resize: vertical; font-family: 'Menlo', 'Monaco', monospace; }
  button {
    padding: 0.4rem 1rem;
    border-radius: 5px;
    border: none;
    cursor: pointer;
    font-size: 0.85rem;
    font-weight: 500;
    transition: background 0.15s;
  }
  .btn-primary { background: var(--adm-blue); color: var(--adm-on-accent); font-weight: 700; }
  .btn-primary:hover { filter: brightness(1.08); }
  .btn-danger  { background: #dc2626; color: #fff; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-secondary { background: #334155; color: var(--text); }
  .btn-secondary:hover { background: #475569; }
  .btn-sm { padding: 0.25rem 0.6rem; font-size: 0.78rem; }
  .row { display: flex; gap: 0.5rem; align-items: flex-end; }
  .row > * { flex: 1; }

  /* ---- Feedback messages ---- */
  .msg { padding: 0.5rem 0.75rem; border-radius: 5px; margin-top: 0.5rem; font-size: 0.83rem; }
  .msg-ok  { background: #14532d; color: #86efac; }
  .msg-err { background: #7f1d1d; color: #fca5a5; }

  /* ---- Tables ---- */
  .tbl-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th {
    background: var(--bg);
    color: var(--muted);
    font-weight: 600;
    text-align: left;
    padding: 0.6rem 0.75rem;
    border-bottom: 2px solid var(--border);
    white-space: nowrap;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  td { padding: 0.6rem 0.75rem; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(56, 189, 248, 0.04); }

  /* ---- Admin inner tabs ---- */
  .inner-tabs { display: flex; gap: 0; margin-bottom: 1.25rem; border-bottom: 1px solid var(--border); }
  .inner-tab-btn {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--muted);
    cursor: pointer;
    font-size: 0.85rem;
    padding: 0.5rem 1rem;
    transition: color 0.15s, border-color 0.15s;
  }
  .inner-tab-btn:hover { color: var(--text); }
  .inner-tab-btn.active { color: var(--primary); border-bottom-color: var(--primary); }

  /* ---- My Access ---- */
  .access-row {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.9rem 1rem;
    margin-bottom: 0.6rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  .access-name { font-weight: 600; flex: 1; }
  .access-stats { font-size: 0.78rem; color: var(--muted); }

  /* ---- Code block ---- */
  .code-block {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Menlo', 'Monaco', 'Consolas', monospace;
    font-size: 0.8rem;
    line-height: 1.6;
    color: #93c5fd;
    overflow-x: auto;
    white-space: pre;
  }

  /* ---- Section headings ---- */
  .section-title {
    font-size: 1rem;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .section-title .count {
    background: var(--border);
    color: var(--muted);
    border-radius: 9999px;
    padding: 0.1rem 0.5rem;
    font-size: 0.7rem;
  }

  /* ---- Divider ---- */
  .divider { border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }

  /* ---- Grants editor ---- */
  .grant-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 0.75rem;
  }
  .grant-client { font-weight: 700; color: var(--primary); font-size: 0.9rem; margin-bottom: 0.5rem; }

  /* ---- Collapsible cred form ---- */
  details > summary {
    cursor: pointer;
    color: var(--primary);
    font-size: 0.82rem;
    margin-top: 0.5rem;
    user-select: none;
  }
  details[open] > summary { margin-bottom: 0.5rem; }

  /* ---- Spinner ---- */
  .spinner {
    display: inline-block;
    width: 1rem; height: 1rem;
    border: 2px solid var(--border);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .htmx-indicator { opacity: 0; transition: opacity 0.2s; }
  .htmx-request .htmx-indicator { opacity: 1; }
  .loading-state { text-align: center; padding: 3rem; color: var(--muted); }

  /* ---- Empty / error states ---- */
  .empty-state {
    text-align: center;
    padding: 3rem 1rem;
    color: var(--muted);
    font-size: 0.9rem;
  }
  .error-state {
    background: #7f1d1d22;
    border: 1px solid #7f1d1d;
    border-radius: 8px;
    padding: 1rem;
    color: #fca5a5;
    font-size: 0.87rem;
    margin: 1rem 0;
  }

  /* ---- Search / filter bar ---- */
  .filter-bar {
    display: flex;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
    align-items: center;
  }
  .filter-bar input { flex: 1; }
  .filter-bar select { width: auto; min-width: 140px; }

  /* ---- Attention banner ---- */
  .attention-banner {
    background: #1c1008;
    border: 1px solid #92400e;
    border-radius: 8px;
    padding: 0.85rem 1rem;
    margin-bottom: 1.25rem;
  }
  .attention-title {
    font-size: 0.85rem;
    font-weight: 700;
    color: var(--amber);
    margin-bottom: 0.6rem;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .attention-item {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.4rem 0;
    border-top: 1px solid #292007;
    font-size: 0.82rem;
  }
  .attention-item:first-of-type { border-top: none; }
  .attention-item-name { font-weight: 600; color: var(--text); min-width: 140px; }
  .attention-item-reason { color: var(--muted); flex: 1; }
  .btn-enroll {
    background: #92400e;
    color: var(--amber);
    border: 1px solid #b45309;
    border-radius: 5px;
    padding: 0.2rem 0.65rem;
    font-size: 0.75rem;
    font-weight: 600;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
  }
  .btn-enroll:hover { background: #b45309; }
  .badge-needs-auth { background: #78350f; color: var(--amber); }
  .badge-broken     { background: #7f1d1d; color: #fca5a5; }
  .badge-inactive   { background: #374151; color: #9ca3af; }

  /* ================================================================
     AEGIS DESIGN SYSTEM — Admin sidebar + User Portal cards
     ================================================================ */
  :root {
    /* PRD-0006 R-5: palette aligned to the MCP Console design
       (docs/design/mcp-console/MCP-Console.html). Surface stack: main bg is the
       darkest, sidebar sits slightly lighter, cards lighter still, inputs recess. */
    --adm-bg:      #0a0c11;
    --adm-sidebar: #0c0f15;
    --adm-surface: #12161e;   /* card */
    --adm-input:   #0f131b;   /* recessed inputs / inset sub-cards */
    --adm-border:  rgba(255,255,255,0.07);
    --adm-text:    #e7eaf0;
    --adm-muted:   #8a93a4;
    --adm-dim:     #5b6474;
    --adm-blue:    #4f9cf9;   /* primary accent */
    --adm-blue2:   #7c5cff;   /* violet — logo gradient end */
    --adm-green:   #35c88a;
    --adm-amber:   #eab308;
    --adm-red:     #ef5350;
    --adm-purple:  #c084fc;
    --adm-on-accent: #04122b; /* ink on blue buttons */
    --adm-btn-secondary: #1a2233; /* neutral/secondary button + toast bg */
    --ff-sans: 'Hanken Grotesk', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    --ff-mono: 'JetBrains Mono', ui-monospace, 'SF Mono', 'Menlo', monospace;
  }

  /* ---- Admin full-page layout ---- */
  .adm-layout {
    display: flex; height: 100vh; overflow: hidden;
    font-family: var(--ff-sans); background: var(--adm-bg); color: var(--adm-text);
  }
  .adm-sidebar {
    width: 218px; flex: none; background: var(--adm-sidebar);
    border-right: 1px solid var(--adm-border);
    display: flex; flex-direction: column; padding: 18px 14px;
  }
  .adm-logo-row {
    display: flex; align-items: center; gap: 10px; padding: 4px 8px 18px;
  }
  .adm-logo-mark {
    position: relative; width: 26px; height: 26px; border-radius: 7px; flex: none;
    background: linear-gradient(135deg, var(--adm-blue), var(--adm-blue2));
    box-shadow: 0 3px 12px rgba(124,92,255,0.40);
    display: flex; align-items: center; justify-content: center;
  }
  .adm-logo-mark::before {
    content: ''; width: 10px; height: 10px; border: 2px solid #fff;
    border-radius: 2px; transform: rotate(45deg);
  }
  .adm-logo-name { font-size: 15px; font-weight: 800; color: var(--adm-text); letter-spacing: -0.01em; }
  .adm-logo-sub  { font: 500 9px var(--ff-mono); letter-spacing: 0.16em; color: #7d838d; }
  .adm-nav-group {
    font: 600 10px var(--ff-mono); letter-spacing: 0.14em; color: #4f565f;
    padding: 14px 10px 6px;
  }
  .adm-nav-group:first-of-type { padding-top: 0; }
  .adm-nav-item {
    position: relative; display: flex; align-items: center; gap: 10px;
    padding: 8px 10px; border-radius: 8px;
    color: var(--adm-muted); font-size: 13px; font-weight: 500;
    cursor: pointer; text-decoration: none; border: none; background: none;
    width: 100%; text-align: left; font-family: var(--ff-sans);
  }
  .adm-nav-item:hover { color: var(--adm-text); background: rgba(255,255,255,0.04); }
  .adm-nav-item.active {
    background: rgba(79,156,249,0.12); color: #fff; font-weight: 600;
    box-shadow: inset 2px 0 0 var(--adm-blue);
  }
  .adm-nav-dot {
    width: 7px; height: 7px; border-radius: 2px; background: #454c55; flex: none;
    opacity: 0.55;
  }
  .adm-nav-dot.active { background: var(--adm-blue); opacity: 1; box-shadow: 0 0 8px rgba(79,156,249,0.7); }
  .adm-nav-badge {
    /* WCAG AA: --adm-blue (#4f9cf9) on this badge's tinted background measured
       4.49:1 — just under the 4.5 minimum for the 10px bold text, flagged by the
       axe check in AC-10. Lightened to #6bb0fc (5.57:1) here only; the global
       --adm-blue token is unchanged because it passes at its other, larger sizes. */
    margin-left: auto; font: 700 10px var(--ff-sans); color: #6bb0fc;
    background: rgba(79,156,249,0.16); padding: 1px 7px; border-radius: 10px;
  }
  .adm-user-panel {
    margin-top: auto; display: flex; align-items: center; gap: 10px;
    padding: 10px; border-radius: 10px;
    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  }
  .adm-avatar {
    width: 30px; height: 30px; border-radius: 8px;
    background: #2b3550;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 13px; color: #cdd6ea; flex: none;
  }
  .adm-user-name { font-size: 12.5px; font-weight: 600; color: var(--adm-text); }
  .adm-user-role { font: 500 10px var(--ff-mono); color: var(--adm-dim); }

  /* ---- Admin main area ---- */
  .adm-main { flex: 1; min-width: 0; display: flex; flex-direction: column; overflow: hidden; }
  .adm-topbar {
    height: 56px; flex: none; border-bottom: 1px solid var(--adm-border);
    display: flex; align-items: center; justify-content: space-between; padding: 0 22px;
  }
  .adm-breadcrumb { font-size: 13px; color: var(--adm-dim); }
  .adm-breadcrumb-sep { color: #3a4048; margin: 0 4px; }
  .adm-breadcrumb-page { color: var(--adm-text); font-weight: 600; font-size: 14px; }
  .adm-search-bar {
    display: flex; align-items: center; gap: 9px; width: 290px;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 9px; padding: 8px 11px;
  }
  .adm-search-orb {
    width: 13px; height: 13px; border-radius: 50%; border: 2px solid var(--adm-blue); flex: none;
  }
  .adm-search-text { font-size: 12.5px; color: #868c96; flex: 1; }
  .adm-search-kbd {
    font: 500 10px var(--ff-mono); color: #7d838d;
    background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 5px;
  }
  .adm-tabs-bar {
    height: 46px; flex: none; border-bottom: 1px solid var(--adm-border);
    display: flex; align-items: center; gap: 26px; padding: 0 22px;
  }
  .adm-tab {
    font-size: 13px; color: var(--adm-muted); font-weight: 500; cursor: pointer;
    background: none; border: none; height: 46px; display: flex; align-items: center;
    position: relative; padding: 0; font-family: var(--ff-sans);
  }
  .adm-tab:hover { color: var(--adm-text); }
  .adm-tab.active { color: var(--adm-text); font-weight: 600; }
  .adm-tab.active::after {
    content: ''; position: absolute; left: 0; right: 0; bottom: 0;
    height: 2px; background: var(--adm-blue); border-radius: 2px;
  }
  .ss-tabs-bar {
    display: flex; align-items: center; gap: 26px; margin: 4px 0 18px;
    border-bottom: 1px solid var(--border);
  }
  .ss-home-tiles {
    display: grid; grid-template-columns: repeat(auto-fit,minmax(180px,1fr));
    gap: 14px; margin: 16px 0;
  }
  .ss-home-tile {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px 18px; cursor: pointer;
  }
  .ss-home-tile-val { font-size: 26px; font-weight: 800; }
  .ss-home-tile-label { font-size: 12px; color: var(--muted); margin-top: 3px; }
  .adm-body {
    overflow-y: auto; padding: 18px 22px; display: block;
    height: calc(100vh - 56px); box-sizing: border-box;
  }
  .adm-body > * + * { margin-top: 16px; }

  /* ---- Attention band ---- */
  .adm-attention {
    display: flex; align-items: center; gap: 14px; padding: 13px 15px;
    background: rgba(59,130,246,0.07); border: 1px solid rgba(59,130,246,0.22);
    border-radius: 12px;
  }
  .adm-attention-icon {
    width: 30px; height: 30px; flex: none; border-radius: 8px;
    background: rgba(59,130,246,0.16);
    display: flex; align-items: center; justify-content: center;
  }
  .adm-attention-diamond {
    width: 11px; height: 11px; background: #7aa7ff; border-radius: 3px; transform: rotate(45deg);
  }
  .adm-attention-title { font-size: 13px; font-weight: 700; color: var(--adm-text); }
  .adm-attention-body  { font-size: 12px; color: var(--adm-muted); }
  .adm-attention-btn {
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.12);
    color: #cbd0d7; font-size: 12px; font-weight: 600; padding: 7px 14px;
    border-radius: 8px; cursor: pointer; white-space: nowrap; font-family: var(--ff-sans);
  }
  .adm-migration-banner {
    display: flex; align-items: flex-start; gap: 14px; padding: 13px 15px;
    background: rgba(192,132,252,0.07); border: 1px solid rgba(192,132,252,0.22);
    border-radius: 12px; margin: 0 22px 12px;
  }

  /* ---- Server registry toolbar ---- */
  .srv-toolbar {
    display: flex; align-items: center; gap: 12px;
  }
  .srv-toolbar-title { font-size: 14px; font-weight: 700; color: var(--adm-text); }
  .srv-count-chip {
    font: 600 11px var(--ff-mono); color: var(--adm-muted);
    background: rgba(255,255,255,0.06); padding: 2px 8px; border-radius: 6px;
  }
  .srv-seg-group {
    display: flex; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.07);
    border-radius: 9px; padding: 3px;
  }
  .srv-seg-btn {
    padding: 6px 12px; border-radius: 7px; color: var(--adm-muted);
    font-size: 12px; font-weight: 500; background: none; border: none; cursor: pointer;
    font-family: var(--ff-sans);
  }
  .srv-seg-btn.active {
    background: rgba(255,255,255,0.09); color: var(--adm-text); font-weight: 600;
  }
  .btn-register-srv {
    background: var(--adm-blue); color: #fff; font-size: 13px; font-weight: 600;
    padding: 8px 14px; border-radius: 9px; display: flex; align-items: center;
    gap: 7px; border: none; cursor: pointer; font-family: var(--ff-sans);
  }

  /* ---- Server registry table ---- */
  .srv-tbl {
    background: var(--adm-surface); border: 1px solid rgba(255,255,255,0.07);
    border-radius: 12px; overflow: hidden;
  }
  .srv-tbl-head {
    display: grid;
    grid-template-columns: 2.1fr 2.3fr 1.15fr 1.2fr 1.1fr 0.8fr 100px;
    gap: 12px; padding: 11px 18px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
    font: 600 10px var(--ff-mono); letter-spacing: 0.08em; color: #7d838d;
  }
  .srv-tbl-row {
    display: grid;
    grid-template-columns: 2.1fr 2.3fr 1.15fr 1.2fr 1.1fr 0.8fr 100px;
    gap: 12px; align-items: center; padding: 12px 18px;
    border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .srv-tbl-row:last-child { border-bottom: none; }
  .srv-tbl-row:hover { background: rgba(255,255,255,0.02); }
  .srv-tbl-row.row-pending    { background: rgba(251,191,36,0.04); }
  .srv-tbl-row.row-quarantined { background: rgba(248,113,113,0.05); }
  .srv-cell-name   { font-size: 13px; font-weight: 600; color: var(--adm-text); }
  .srv-cell-alias  { font: 500 11px var(--ff-mono); color: var(--adm-dim); }
  .srv-cell-url    { font: 400 12px var(--ff-mono); color: var(--adm-muted); }
  .srv-cell-owner  { font: 400 12px var(--ff-mono); color: var(--adm-muted); }
  .srv-cell-updated { font: 400 11px var(--ff-mono); color: var(--adm-dim); }

  /* ---- Server registry card grid (matches MCP Console design's Registry view) ---- */
  .srv-card-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 14px;
  }
  .srv-card {
    background: var(--adm-surface); border: 1px solid var(--adm-border);
    border-radius: 13px; padding: 16px; transition: border-color .15s;
  }
  .srv-card:hover { border-color: rgba(79,156,249,0.5); }
  .srv-card.row-pending { border-color: rgba(251,191,36,0.35); }
  .srv-card.row-quarantined { border-color: rgba(248,113,113,0.35); }
  .srv-card-top {
    display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px;
  }
  .srv-card-name {
    font-weight: 700; font-size: 14px; font-family: var(--ff-mono); color: var(--adm-text);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .srv-card-meta { font-size: 11.5px; color: var(--adm-muted); margin-bottom: 12px; font-family: var(--ff-mono); }
  .srv-card-badges { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin-bottom: 10px; }
  .srv-card-updated { font: 400 11px var(--ff-mono); color: var(--adm-dim); margin-left: auto; }
  .srv-card-actions { display: flex; justify-content: flex-end; }

  /* Console KPI tile (design §4): card + colored top accent bar */
  .kpi {
    position: relative; overflow: hidden; background: var(--adm-surface);
    border: 1px solid var(--adm-border); border-radius: 12px; padding: 16px 18px;
  }
  .kpi::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--kpi, var(--adm-blue)); }
  .kpi-label { font-size: 11px; font-weight: 600; letter-spacing: 0.02em; color: var(--adm-muted); }
  .kpi-num   { font-size: 27px; font-weight: 800; letter-spacing: -0.02em; color: var(--kpi, var(--adm-text)); margin-top: 6px; line-height: 1; }
  .kpi-sub   { font-size: 11px; color: var(--adm-dim); margin-top: 5px; }
  .kpi-grid  { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; }

  /* Console mode pill: blue-tinted mono, square-ish (design §4) */
  .mode-chip {
    font: 600 10px var(--ff-mono); letter-spacing: 0.03em; color: var(--adm-blue);
    background: rgba(79,156,249,0.13); border: 1px solid rgba(79,156,249,0.3);
    padding: 2px 7px; border-radius: 5px;
  }

  /* ---- Status pills (console recipe §4) ---- */
  .pill {
    display: inline-flex; align-items: center; gap: 5px; padding: 2px 8px;
    border-radius: 999px; font: 600 10px var(--ff-sans); letter-spacing: 0.05em;
    text-transform: uppercase; white-space: nowrap;
  }
  .pill-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
  .pill-approved   { background: rgba(53,200,138,0.14); color: var(--adm-green); border: 1px solid rgba(53,200,138,0.3); }
  .pill-approved   .pill-dot { background: var(--adm-green); }
  .pill-pending    { background: rgba(234,179,8,0.14);  color: var(--adm-amber); border: 1px solid rgba(234,179,8,0.3); }
  .pill-pending    .pill-dot { background: var(--adm-amber); }
  .pill-quarantined { background: rgba(239,83,80,0.14); color: var(--adm-red); border: 1px solid rgba(239,83,80,0.3); }
  .pill-quarantined .pill-dot { background: var(--adm-red); }

  /* ---- Table action buttons (console recipe §4) ---- */
  .btn-approve {
    background: var(--adm-blue); color: var(--adm-on-accent); font-size: 12px; font-weight: 700;
    padding: 7px 13px; border-radius: 8px; border: none; cursor: pointer;
    font-family: var(--ff-sans);
  }
  .btn-release {
    border: 1px solid rgba(255,255,255,0.12); color: #cdd6ea; font-size: 12px;
    font-weight: 600; padding: 6px 12px; border-radius: 8px; background: var(--adm-btn-secondary, #1a2233);
    cursor: pointer; font-family: var(--ff-sans);
  }
  .btn-reject {
    background: rgba(239,83,80,0.13); border: 1px solid rgba(239,83,80,0.28);
    color: #ef8b88; font-size: 12px; font-weight: 600;
    padding: 6px 11px; border-radius: 8px; cursor: pointer; font-family: var(--ff-sans);
  }
  .btn-menu {
    color: var(--adm-dim); font-size: 18px; letter-spacing: 1px;
    background: none; border: none; cursor: pointer; padding: 0 4px;
  }
  .srv-dropdown {
    position: absolute; right: 0; top: 100%; z-index: 50;
    background: #1a1d24; border: 1px solid #2a2d35; border-radius: 8px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.5); padding: 4px; min-width: 130px;
  }
  .srv-dropdown button {
    display: block; width: 100%; text-align: left; padding: 7px 12px;
    background: none; border: none; border-radius: 5px;
    color: #cbd0d7; font-size: 12px; font-weight: 500; cursor: pointer;
    font-family: var(--ff-sans);
  }
  .srv-dropdown button:hover { background: rgba(255,255,255,0.06); color: #e7e9ec; }
  .srv-dropdown button.danger { color: #f87171; }
  .srv-dropdown button.danger:hover { background: rgba(239,68,68,0.1); }

  /* ================================================================
     User Portal card layout
     ================================================================ */
  .portal-layout {
    display: flex; flex-direction: column; min-height: 100vh;
    background: var(--adm-bg); color: var(--adm-text); font-family: var(--ff-sans);
  }
  .portal-topbar {
    height: 60px; flex: none; border-bottom: 1px solid var(--adm-border);
    display: flex; align-items: center; justify-content: space-between; padding: 0 26px;
  }
  .portal-logo { display: flex; align-items: center; gap: 10px; }
  .portal-logo-name { font-size: 15px; font-weight: 800; color: var(--adm-text); letter-spacing: -0.01em; }
  .portal-logo-lbl {
    font: 500 10px var(--ff-mono); letter-spacing: 0.12em; color: #7d838d;
    background: rgba(255,255,255,0.05); padding: 3px 7px; border-radius: 5px;
  }
  .portal-user-area { display: flex; align-items: center; gap: 14px; }
  .portal-role-chip {
    display: flex; align-items: center; gap: 7px;
    background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.25);
    padding: 5px 11px; border-radius: 999px;
    font-size: 12px; font-weight: 600; color: #aac6ff;
  }
  .portal-role-dot { width: 6px; height: 6px; border-radius: 50%; background: #7aa7ff; }
  .portal-uid-block { line-height: 1.1; text-align: right; }
  .portal-uid    { font: 500 11px var(--ff-mono); color: var(--adm-muted); }
  .portal-uid-sub { font-size: 10px; color: var(--adm-dim); }
  .portal-body {
    flex: 1; padding: 24px 26px; display: flex; flex-direction: column;
    gap: 16px; max-width: 1100px; width: 100%; margin: 0 auto;
  }
  .portal-hero { display: flex; align-items: flex-end; justify-content: space-between; gap: 20px; }
  .portal-hero-title { font-size: 22px; font-weight: 800; color: var(--adm-text); letter-spacing: -0.01em; }
  .portal-hero-sub   { font-size: 13px; color: var(--adm-muted); margin-top: 3px; }
  .portal-find-bar {
    display: flex; align-items: center; gap: 9px; width: 340px; flex: none;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px; padding: 9px 12px;
  }
  .portal-find-orb { width: 13px; height: 13px; border-radius: 50%; border: 2px solid var(--adm-blue); flex: none; }
  .portal-find-text { font-size: 12.5px; color: #868c96; flex: 1; }

  /* ---- Profile bar ---- */
  .profile-bar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .profile-lbl { font: 600 10px var(--ff-mono); letter-spacing: 0.12em; color: #7d838d; }
  .profile-pills { display: flex; gap: 7px; flex-wrap: wrap; }
  .profile-pill {
    display: flex; align-items: center; gap: 7px;
    background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08);
    color: var(--adm-muted); font-size: 12.5px; font-weight: 500;
    padding: 6px 12px; border-radius: 999px; cursor: pointer;
    font-family: var(--ff-sans);
  }
  .profile-pill.active {
    background: rgba(59,130,246,0.13); border: 1px solid rgba(59,130,246,0.32);
    color: #aac6ff; font-weight: 600;
  }
  .profile-pill-dot { width: 6px; height: 6px; border-radius: 50%; background: #7aa7ff; }
  .profile-pill-new {
    border: 1px dashed rgba(255,255,255,0.16); color: #868c96;
    background: transparent;
  }
  .profile-summary { font-size: 12px; color: #868c96; margin-left: auto; }
  .profile-summary strong { color: #cbd0d7; }

  /* ---- Server summary strip ---- */
  .srv-strip { display: flex; align-items: center; gap: 18px; padding-bottom: 2px; }
  .srv-strip-cnt { font: 600 12px var(--ff-mono); color: var(--adm-muted); }
  .srv-strip-div { width: 1px; height: 13px; background: rgba(255,255,255,0.12); }
  .srv-strip-item { display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--adm-muted); }
  .dot-green  { width: 7px; height: 7px; border-radius: 50%; background: #4ade80; }
  .dot-red    { width: 7px; height: 7px; border-radius: 50%; background: #f87171; }
  .dot-amber  { width: 7px; height: 7px; border-radius: 50%; background: #fbbf24; }

  /* ---- Server cards ---- */
  .srv-card-grid {
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px;
  }
  @media (max-width: 900px) { .srv-card-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 580px) { .srv-card-grid { grid-template-columns: 1fr; } }
  .srv-card {
    background: var(--adm-surface); border: 1px solid rgba(255,255,255,0.07);
    border-radius: 14px; padding: 15px; display: flex; flex-direction: column;
    gap: 11px; min-height: 165px;
  }
  .srv-card.card-suspended  { border-color: rgba(248,113,113,0.22); }
  .srv-card.card-awaiting   { border-color: rgba(251,191,36,0.2); }
  .srv-card-hdr { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; }
  .srv-card-id  { display: flex; align-items: center; gap: 11px; }
  .srv-card-icon {
    width: 36px; height: 36px; border-radius: 9px;
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08);
    display: flex; align-items: center; justify-content: center;
    font: 700 14px var(--ff-sans); color: #cbd0d7; flex: none;
  }
  .srv-card-icon.dim { background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.07); color: #868c96; }
  .srv-card-name { font-size: 14px; font-weight: 700; color: var(--adm-text); }
  .srv-card-name.dim { color: #cbd0d7; }
  .srv-card-desc { font-size: 12.5px; color: var(--adm-muted); line-height: 1.4; }
  .srv-card-desc.dim { color: #868c96; }
  .srv-card-tools { display: flex; flex-wrap: wrap; gap: 6px; }
  .tool-chip {
    display: inline-flex; align-items: center; gap: 5px;
    font: 500 11px var(--ff-mono); color: #cbd0d7;
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08);
    padding: 3px 8px; border-radius: 6px;
  }
  .tool-chip-dot  { width: 5px; height: 5px; border-radius: 50%; background: #4ade80; }
  .tool-chip-off  {
    font: 500 11px var(--ff-mono); color: #7d838d;
    border: 1px dashed rgba(255,255,255,0.14); padding: 3px 8px; border-radius: 6px;
  }
  .tool-chip-sus  {
    font: 500 11px var(--ff-mono); color: #646b75;
    background: rgba(255,255,255,0.03); padding: 3px 8px; border-radius: 6px;
  }
  .srv-card-footer {
    margin-top: auto; border-top: 1px solid rgba(255,255,255,0.06);
    padding-top: 11px; display: flex; align-items: center; justify-content: space-between;
  }
  .srv-card-footer-lbl { font-size: 12px; color: var(--adm-muted); }
  .srv-card-footer-link { font-size: 12px; color: #7aa7ff; font-weight: 600; cursor: pointer; text-decoration: none; }
  .srv-card-footer-pend { font-size: 12px; color: #868c96; }
  .srv-toggle {
    width: 40px; height: 22px; border-radius: 999px; background: var(--adm-blue);
    position: relative; border: none; cursor: pointer; flex: none; transition: background 0.2s;
  }
  .srv-toggle::after {
    content: ''; position: absolute; top: 2px; left: 20px;
    width: 18px; height: 18px; border-radius: 50%; background: #fff; transition: left 0.2s;
  }
  .srv-toggle.off {
    background: rgba(255,255,255,0.08); cursor: not-allowed; opacity: 0.5;
  }
  .srv-toggle.off::after { left: 2px; background: #868c96; }

  /* ---- Status pills (portal cards) ---- */
  .cpill {
    display: inline-flex; align-items: center; gap: 5px; padding: 3px 8px;
    border-radius: 999px; font-size: 11px; font-weight: 600; white-space: nowrap;
  }
  .cpill-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
  .cpill-active    { background: rgba(74,222,128,0.12);  color: #4ade80; }
  .cpill-active    .cpill-dot { background: #4ade80; }
  .cpill-suspended { background: rgba(248,113,113,0.13); color: #f87171; }
  .cpill-suspended .cpill-dot { background: #f87171; }
  .cpill-awaiting  { background: rgba(251,191,36,0.13);  color: #fbbf24; }
  .cpill-awaiting  .cpill-dot { background: #fbbf24; }
"""




# ---------------------------------------------------------------------------
# Page shell
# ---------------------------------------------------------------------------

_TAB_MAP_PY = {
    "identity":    "Identity (OIDC)",
    "servers":     "MCP Servers",
    "tools":       "Tools",
    "credentials": "Credentials",
    "limits":      "Request Limits",
    "dashboard":   "Posture",
    "detections":  "Detections",
    "sbom":        "SBOM",
    "submissions": "Submissions",
    "prompts":     "Wizard Prompts",
    "llm":         "LLM Provider",
    "git":         "Git Providers",
    "profile":     "Profile",
    "access":      "Access",
}
_VALID_TABS = frozenset(_TAB_MAP_PY)

_ADMIN_GROUPS: list[dict] = [
    {"id": "security", "label": "Security", "panels": ["dashboard", "detections"]},
    {"id": "servers",  "label": "Servers",   "panels": ["servers", "tools", "submissions", "sbom", "credentials"]},
    {"id": "access",   "label": "Access",    "panels": ["access", "limits"]},
    {"id": "settings", "label": "Settings",  "panels": ["identity", "prompts", "llm", "git"]},
    {"id": "profile",  "label": "Profile",   "panels": ["profile"]},
]


def _panel_group(tab: str) -> dict:
    """Return the _ADMIN_GROUPS entry containing `tab`, defaulting to the
    'servers' group for an unrecognized tab (matches the pre-existing
    fallback behavior in portal_admin_tab).

    NOTE: Currently unused — group resolution happens client-side in JS
    (_admGroupFor / _ADM_GROUPS). Kept for any future server-side resolution need."""
    for group in _ADMIN_GROUPS:
        if tab in group["panels"]:
            return group
    return _ADMIN_GROUPS[1]  # "servers" group


@router.get("", response_class=HTMLResponse)
async def portal_shell(request: Request):
    """Serve the full portal page shell (role-aware layout)."""
    _require_portal_access(request)

    roles = _roles(request)
    cid = _client_id(request)
    is_admin = "admin" in roles

    if is_admin or _is_reviewer(roles):
        tab = request.query_params.get("tab", "servers")
        if not is_admin:
            # security_reviewer/platform_admin only have backend rights on the
            # submissions review queue — every other admin fragment still
            # 403s via its own _require_admin(), so land them where their
            # role actually works instead of a dead tab.
            tab = "submissions"
        elif tab not in _VALID_TABS:
            tab = "servers"
        return HTMLResponse(content=await _build_admin_shell(cid, roles, initial_tab=tab))
    return HTMLResponse(content=_build_agent_shell(cid, roles))


@router.get("/admin/{tab}", response_class=HTMLResponse)
async def portal_admin_tab(tab: str, request: Request):
    """Direct URL for admin tabs — /portal/admin/limits etc."""
    _require_portal_access(request)
    roles = _roles(request)
    is_admin = "admin" in roles
    if not is_admin and not _is_reviewer(roles):
        raise HTTPException(status_code=403, detail="admin role required")
    if not is_admin:
        tab = "submissions"
    elif tab not in _VALID_TABS:
        tab = "servers"
    return HTMLResponse(content=await _build_admin_shell(_client_id(request), roles, initial_tab=tab))


def _aegis_logo_mark(size: int = 24, glow: bool = True) -> str:
    """Brand mark — owl icon (docs/assets/owl-icon.png, served at /static/owl-icon.png)."""
    glow_cls = " logo-glow" if glow else ""
    return (
        f'<img src="/static/owl-icon.png" alt="MCP Security Platform" '
        f'width="{size}" height="{size}" class="logo-mark{glow_cls}">'
    )


async def _build_admin_shell(cid: str, roles: list, initial_tab: str = "servers") -> str:
    """Full-page admin sidebar layout."""
    initials = "".join(w[0].upper() for w in cid.replace("-", " ").split()[:2]) or "?"
    display_name = cid

    try:
        from sqlalchemy import text as _sidebar_text
        from app.core.database import AsyncSessionLocal as _SidebarSession
        async with _SidebarSession() as _sidebar_session:
            _admin_awaiting_review_count = (await _sidebar_session.execute(_sidebar_text(
                "SELECT count(*) FROM server_registry "
                "WHERE submission_status = 'awaiting_review' AND deleted_at IS NULL"
            ))).scalar()
    except Exception:
        _admin_awaiting_review_count = None

    def _nav_group(group: dict, active_tab: str) -> str:
        active_panel = active_tab if active_tab in group["panels"] else None
        cls = "adm-nav-item active" if active_panel else "adm-nav-item"
        dot_cls = "adm-nav-dot active" if active_panel else "adm-nav-dot"
        # Clicking a group jumps to its first panel; loadAdminTab resolves
        # the group/subtab bar from there (see Task 2).
        first_panel = group["panels"][0]
        badge_html = ""
        # Badge is the awaiting-review count, NOT total registered servers —
        # a fresh boot seeds servers already-approved (never through the
        # review pipeline), so this is legitimately 0 while real servers
        # exist. Hide at 0 like any other pending-count badge; showing
        # "Servers 0" reads as "zero servers", not "zero pending reviews".
        if group["id"] == "servers" and _admin_awaiting_review_count:
            badge_html = f'<span class="adm-nav-badge" title="{_admin_awaiting_review_count} awaiting review">{_admin_awaiting_review_count}</span>'
        aria_current = ' aria-current="page"' if active_panel else ""
        return (
            f'<button class="{cls}"{aria_current} data-act="loadAdminTab" data-a0="{esc_py(first_panel)}">'
            f'<span class="{dot_cls}"></span>{esc_py(group["label"])}{badge_html}</button>'
        )

    nav_html = "".join(_nav_group(g, initial_tab) for g in _ADMIN_GROUPS)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Platform · Admin</title>
  {_FAVICON_LINK}
  {_FONTS_LINK}
  {_HTMX_TAG}
  <link rel="stylesheet" href="/static/portal.css">
  <script src="/static/portal.js" defer></script>
</head>
<body data-initial-tab="{esc_py(initial_tab)}">
<div class="adm-layout">
  <!-- Sidebar -->
  <aside class="adm-sidebar">
    <div class="adm-logo-row">
      {_aegis_logo_mark(24)}
      <div>
        <div class="adm-logo-name u1" >MCP Security Platform</div>
      </div>
    </div>

    {nav_html}

    <div class="adm-user-panel u2" data-act="loadAdminTab" data-a0="profile"  title="View profile">
      <div class="adm-avatar">{esc_py(initials)}</div>
      <div>
        <div class="adm-user-name">{esc_py(display_name)}</div>
        <div class="adm-user-role">admin</div>
      </div>
    </div>
  </aside>

  <!-- Main area -->
  <div class="adm-main">
    <!-- Topbar -->
    <div class="adm-topbar">
      <div class="adm-breadcrumb">
        MCP Console <span class="adm-breadcrumb-sep">/</span>
        <span class="adm-breadcrumb-page" id="adm-breadcrumb-page">{esc_py(_TAB_MAP_PY.get(initial_tab, initial_tab))}</span>
      </div>
      <a href="/portal/submit"  class="u3">
        &#x2B; Submit MCP Server
      </a>
    </div>

    <div id="adm-migration-banner" class="adm-migration-banner u4" >
      <div  class="u5">
        <div  class="u6">The admin nav is now grouped into 5 sections</div>
        <div  class="u7">
          <div>Dashboard (now Posture), Detections &rarr; <b>Security</b></div>
          <div>MCP Servers, Tools, Submissions, SBOM, Credentials &rarr; <b>Servers</b></div>
          <div>Access, Request Limits &rarr; <b>Access</b></div>
          <div>Identity, Prompts, LLM, Git &rarr; <b>Settings</b></div>
        </div>
      </div>
      <button data-act="_dismissMigrationBanner" aria-label="Dismiss"  class="u8">&times;</button>
    </div>

    <div class="adm-tabs-bar" id="adm-tabs-bar"></div>

    <!-- Content -->
    <div class="adm-body" id="adm-content" tabindex="-1" aria-live="polite" aria-busy="false"
         hx-get="/portal/fragments/admin/{esc_py(initial_tab)}"
         hx-trigger="load"
         hx-swap="innerHTML">
      <div class="loading-state"><span class="spinner"></span> Loading…</div>
    </div>
  </div>
</div>
</body>
</html>"""


def _build_agent_shell(cid: str, roles: list) -> str:
    """Full-page user portal layout."""
    initials = "".join(w[0].upper() for w in cid.replace("-", " ").split()[:2]) or "?"
    role_label = next((r for r in roles if r in ("agent", "admin", "auditor", "reviewer")), roles[0] if roles else "user")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Platform · Portal</title>
  {_FAVICON_LINK}
  {_FONTS_LINK}
  {_HTMX_TAG}
  <link rel="stylesheet" href="/static/portal.css">
  <script src="/static/portal.js" defer></script>
</head>
<body>
<div class="portal-layout">
  <!-- Topbar -->
  <div class="portal-topbar">
    <div class="portal-logo">
      {_aegis_logo_mark(22, glow=True)}
      <div class="portal-logo-name u1" >MCP Security Platform</div>
    </div>
    <div class="portal-user-area">
      <div class="portal-role-chip">
        <span class="portal-role-dot"></span>
        {esc_py(role_label.capitalize())}
      </div>
      <div  class="u9"
           hx-get="/portal/fragments/profile" hx-target="#portal-body" hx-swap="innerHTML"
           title="View profile">
        <div class="portal-uid-block">
          <div class="portal-uid">{esc_py(cid)}</div>
          <div class="portal-uid-sub">service account</div>
        </div>
        <div class="adm-avatar">{esc_py(initials)}</div>
      </div>
    </div>
  </div>

  <!-- Body -->
  <div class="portal-body" id="portal-body" tabindex="-1" aria-live="polite" aria-busy="false"
       hx-get="/portal/fragments/my-access"
       hx-trigger="load"
       hx-swap="innerHTML">
    <div class="loading-state"><span class="spinner"></span> Loading your access…</div>
  </div>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Self-service credential upload (agent role — no admin required)
# ---------------------------------------------------------------------------

@router.put("/credentials/{tool_id}")
async def upload_own_credential(request: Request, tool_id: str):
    """
    Upload a user-mode credential for the calling user.
    Requires agent role; user_sub is taken from the session (not caller-supplied).
    """
    _require_portal_write(request)
    user_sub = _client_id(request)
    if not user_sub:
        raise HTTPException(status_code=401, detail={"code": "UNAUTHENTICATED", "message": "No authenticated identity."})

    body = await request.json()
    secret = (body.get("secret") or "").strip()
    if not secret:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "secret is required."})

    credential_type = body.get("credential_type", "api_key")

    # Validate tool exists
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("SELECT tool_id, name, service_name FROM tool_registry WHERE tool_id = :tid AND deleted_at IS NULL"),
                {"tid": tool_id},
            )
            tool = result.fetchone()
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    if tool is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "message": f"Tool '{tool_id}' not found."})

    service_name = tool.service_name or tool.name

    # Encrypt
    try:
        from app.credential_broker.kms import load_master_secret_standalone
        from app.credential_broker.approaches.approach_a import encrypt

        master = await load_master_secret_standalone()
        blob = encrypt(secret, user_sub, master, service=service_name, tool_id=tool_id, owner_type="user")
    except Exception as exc:
        logger.error("Credential encryption failed: %s", exc)
        raise HTTPException(status_code=500, detail={"code": "ENCRYPTION_ERROR", "message": "Failed to encrypt credential."})

    # Upsert — user-mode credentials keyed on (tool_id, user_sub)
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    INSERT INTO credential_store
                        (user_sub, service, encrypted_blob, owner_type, tool_id, credential_type, description)
                    VALUES
                        (:sub, :svc, :blob, 'user', :tool_id, :ctype, :desc)
                    ON CONFLICT (tool_id, user_sub) WHERE owner_type = 'user' AND tool_id IS NOT NULL
                        DO UPDATE SET
                            encrypted_blob = EXCLUDED.encrypted_blob,
                            credential_type = EXCLUDED.credential_type,
                            rotated_at = NOW(),
                            updated_at = NOW()
                """),
                {"sub": user_sub, "svc": service_name, "blob": blob,
                 "tool_id": tool_id, "ctype": credential_type, "desc": "self-service upload"},
            )
            await session.commit()
    except Exception as exc:
        logger.error("DB error storing credential: %s", exc)
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    logger.info("Self-service credential uploaded", extra={"tool_id": tool_id, "user_sub": user_sub})
    return JSONResponse(content={"ok": True, "tool_id": tool_id})


# ---------------------------------------------------------------------------
# Fragment: Catalog
# ---------------------------------------------------------------------------

@router.get("/fragments/attention", response_class=HTMLResponse)
async def fragment_attention(request: Request):
    """Attention banner: tools needing enrollment or with non-active status."""
    _require_portal_access(request)
    cid = _client_id(request)
    items = []
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT t.name, t.status, t.injection_mode, t.service_name,
                       EXISTS (
                         SELECT 1 FROM credential_store c
                         WHERE c.user_sub = :cid AND c.service = t.service_name
                       ) AS enrolled
                FROM tool_registry t
                WHERE t.deleted_at IS NULL
                ORDER BY t.name
            """), {"cid": cid})
            for row in result.fetchall():
                mode = (row.injection_mode or "none").lower()
                status = (row.status or "active").lower()
                svc = row.service_name or ""
                if status not in ("active",):
                    items.append({
                        "name": row.name,
                        "reason": f"Status: {status}",
                        "kind": "broken",
                        "enroll_url": None,
                    })
                elif mode == "oauth_user_token" and not row.enrolled and svc:
                    items.append({
                        "name": row.name,
                        "reason": "Requires OAuth enrollment",
                        "kind": "needs_auth",
                        "enroll_url": f"/auth/enroll/{svc}",
                    })
    except Exception as exc:
        logger.warning("portal attention query failed: %s", exc)
        return HTMLResponse("")

    if not items:
        return HTMLResponse("")

    rows_html = []
    for it in items:
        badge_cls = "badge-needs-auth" if it["kind"] == "needs_auth" else "badge-broken"
        badge_lbl = "Needs Auth" if it["kind"] == "needs_auth" else it["reason"].split(":")[1].strip().upper()
        action = (
            f'<a class="btn-enroll" href="{esc_py(it["enroll_url"])}">Enroll &rarr;</a>'
            if it["enroll_url"]
            else ""
        )
        rows_html.append(f"""
        <div class="attention-item">
          <div class="attention-item-name">{esc_py(it["name"])}</div>
          <span class="badge {badge_cls}">{esc_py(badge_lbl)}</span>
          <div class="attention-item-reason">{esc_py(it["reason"])}</div>
          {action}
        </div>""")

    count = len(items)
    html = f"""
    <div class="attention-banner">
      <div class="attention-title">&#x26A0; {count} tool{"s" if count != 1 else ""} need attention</div>
      {"".join(rows_html)}
    </div>"""
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# REMOVED 2026-07-25: GET /portal/fragments/catalog
#
# An orphaned route that dumped EVERY non-deleted tool_registry row with no
# per-caller filtering — no entitlement check, no grants check, no profile check —
# while being gated only by _require_portal_access (agent / auditor / admin). Any
# authenticated portal user could hit it directly and enumerate the full tool
# inventory, including tools they were not entitled to and tools their profile
# disabled. That is the listed-but-denied defect plus an inventory disclosure.
#
# It was already dead: the Catalog tab renders inline from _build_portal_access's
# own filtered cards_html, and ssShowTab('catalog') is a client-side tab toggle,
# not an hx-get. Nothing referenced this route but its own docstring.
#
# Deleted rather than filtered: a second, independently-filtered listing surface is
# exactly what produced the discovery/invoke drift in the first place.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fragment: My Access
# ---------------------------------------------------------------------------

@router.get("/fragments/my-access", response_class=HTMLResponse)
async def fragment_my_access(request: Request):
    """User portal: server access cards (new aegis design)."""
    _require_portal_access(request)
    cid = _client_id(request)
    api_key = request.query_params.get("key", "")
    # Thread the caller's bound named profile so the pills reflect the profile they
    # are actually browsing under, not just their legacy per-identity rows.
    profile_uuid = getattr(request.state, "profile_uuid", None)
    from app.services.invocation import ProfileLookupError
    try:
        html = await _build_portal_access(
            cid, api_key, _is_auditor_only(request), profile_uuid=profile_uuid
        )
    except ProfileLookupError:
        # INV-015 fail-closed: we cannot say what this user may call, so we do not
        # guess. Showing the grid with every server marked enabled would be a
        # fail-open in the UI.
        logger.error("portal my-access: profile lookup unavailable for %s", cid)
        return HTMLResponse(
            _error_fragment("Access state unavailable right now — retry shortly."),
            status_code=503,
        )
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: Profile (R-3) — identity, all roles, session, sign-out
# ---------------------------------------------------------------------------

async def _build_profile_fragment(request: Request, back_target: str) -> str:
    """Profile content shared by the admin 'Profile' tab and the agent portal."""
    cid = _client_id(request)
    roles = _roles(request)
    can_manage_mcp_profiles = "admin" in roles or "platform_admin" in roles

    session_info = None
    try:
        from app.routers.oidc_browser import _decode_session_jwt
        from app.core.config import settings
        token = request.cookies.get(settings.SESSION_COOKIE_NAME)
        if token:
            session_info = _decode_session_jwt(token)
    except Exception as exc:
        logger.warning("portal profile: could not decode session: %s", exc)

    roles_html = "".join(
        f'<span  class="u10">{esc_py(r)}</span>'
        for r in roles
    ) or '<span  class="u11">no roles assigned</span>'

    if session_info:
        exp = session_info.get("exp")
        exp_str = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp else "—"
        auth_method = session_info.get("auth_method", "—")
        session_html = f"""
        <div  class="u12">
          Auth method: <span  class="u13">{esc_py(str(auth_method))}</span><br>
          Session expires: <span  class="u13">{esc_py(exp_str)}</span>
        </div>"""
    else:
        session_html = '<div  class="u12">Session details unavailable.</div>'

    # MCP profiles: curated named subsets of servers/tools a user can bind
    # their session to at login (?profile=<name>) so their MCP client only
    # sees that subset instead of everything they're entitled to.
    try:
        from app.routers.profiles import _list_named_profiles, _get_profile_mcp_bindings
        mcp_profiles = await _list_named_profiles(active_only=True)
        for p in mcp_profiles:
            p["bindings"] = await _get_profile_mcp_bindings(str(p["id"]))
    except Exception as exc:
        logger.error("portal profile: could not load MCP profiles: %s", exc)
        mcp_profiles = []

    login_base = str(request.base_url).rstrip("/") + "/api/v1/auth/oidc/login?profile="
    profile_rows_html = []
    for p in mcp_profiles:
        enabled_tools = [b["mcp_name"] for b in p["bindings"] if b["enabled"]]
        tools_html = ", ".join(esc_py(t) for t in enabled_tools[:8]) or '<span  class="u14">no tools bound yet</span>'
        manage_btn = (
            f'<button class="btn-secondary btn-sm" hx-get="/portal/fragments/mcp-profile/{esc_py(p["name"])}" '
            f'hx-target="#mcpprof-detail-{esc_py(_slugify(p["name"]))}" hx-swap="innerHTML" '
            f'data-act="showEl" data-a0="mcpprof-detail-{esc_py(_slugify(p["name"]))}">Manage</button>'
            if can_manage_mcp_profiles else ""
        )
        profile_rows_html.append(f"""
        <div  class="u15">
          <div  class="u16">
            <div>
              <div  class="u17">{esc_py(p.get("display_name") or p["name"])}</div>
              <div  class="u18">{esc_py(p.get("description") or "")}</div>
              <div  class="u19">Tools: {tools_html}</div>
            </div>
            <div  class="u20">
              <button class="btn-secondary btn-sm" data-act="copyText" data-a0="{esc_py(login_base + p['name'])}">Copy login link</button>
              {manage_btn}
            </div>
          </div>
          <div id="mcpprof-detail-{esc_py(_slugify(p["name"]))}"  class="u21"></div>
        </div>""")

    create_form_html = ""
    if can_manage_mcp_profiles:
        create_form_html = """
        <div  class="u22">
          <input id="mcpprof-new-name" aria-label="New profile name" placeholder="profile-name (a-z0-9-_)" class="wiz-input u23" >
          <input id="mcpprof-new-display" aria-label="New profile display name" placeholder="Display name (optional)" class="wiz-input u24" >
          <button class="btn-primary btn-sm" data-act="createMcpProfile">+ New profile</button>
        </div>
        <div id="mcpprof-new-msg"  class="u25"></div>"""

    help_html = """
    <details  class="u26">
      <summary  class="u27">How do I use a profile?</summary>
      <div  class="u28">
        1. Pick or create a profile below and enable the servers/tools it should expose.<br>
        2. Click <strong>Copy login link</strong> on that profile.<br>
        3. In your MCP client's login/auth config, use that link instead of the plain login URL
           (it's the same PKCE login, with <code>?profile=&lt;name&gt;</code> appended).<br>
        4. Your session is then scoped to only that profile's enabled tools — everything else
           you're normally entitled to stays hidden for the life of that session.<br>
        A session with no <code>?profile=</code> behaves as before (your full entitlement set).
      </div>
    </details>"""

    mcp_profiles_html = f"""
    <div  class="u29">
      <div  class="u30">MCP profiles</div>
      <p  class="u31">
        Curated subsets of servers/tools. Point your MCP client's login at a profile's link
        below to see only that profile's tools instead of everything you're entitled to.
      </p>
      {help_html}
      <div  class="u26">
      {"".join(profile_rows_html) if profile_rows_html else '<div  class="u11">No MCP profiles defined yet.</div>'}
      </div>
      {create_form_html if can_manage_mcp_profiles else '<div  class="u32">Ask an admin to create or edit MCP profiles.</div>'}
    </div>"""

    return f"""
    <div class="section-title">&#x1F464; Profile</div>
    <div  class="u33">
      <div  class="u30">Principal</div>
      <div  class="u34">{esc_py(cid)}</div>

      <div  class="u35">Roles</div>
      <div  class="u36">{roles_html}</div>

      <div  class="u35">Session</div>
      {session_html}

      <div  class="u37">
        {'<button class="btn-secondary" hx-get="' + esc_py(back_target) + '" hx-target="#portal-body" hx-swap="innerHTML">&#x2190; Back</button>' if back_target else ''}
        <button  class="u38"
                data-act="portalSignOut">Sign out</button>
      </div>
    </div>

    <div  class="u39">
      <div  class="u30">Certificate setup</div>
      <p  class="u40">
        TLS trust or client-certificate errors (e.g. Codex/Windows)? Get the gateway CA and
        setup instructions.
      </p>
      <button class="btn-secondary btn-sm" hx-get="/portal/fragments/cert-setup" hx-target="#portal-body" hx-swap="innerHTML">
        Certificate setup &#x2192;
      </button>
    </div>

    {mcp_profiles_html}
    """


@router.get("/fragments/profile", response_class=HTMLResponse)
async def fragment_profile(request: Request):
    """Agent-portal profile view."""
    _require_portal_access(request)
    return HTMLResponse(await _build_profile_fragment(request, back_target="/portal/fragments/my-access"))


@router.get("/fragments/cert-setup", response_class=HTMLResponse)
async def fragment_cert_setup(request: Request):
    """Self-service TLS/mTLS certificate setup instructions (2026-07-11).

    /api/v1/tools/ on the gateway's main listener no longer requires a
    client certificate (OAuth/session auth is enough) — the only certs an
    end user typically needs are the gateway's own CA, to trust its TLS
    server certificate. Client-cert (agent) identity remains available on
    the dedicated :8445 listener for callers that want it.
    """
    _require_portal_access(request)
    host_no_port = request.url.hostname or "localhost"
    http_ca_url = f"http://{host_no_port}/ca.crt"
    return HTMLResponse(f"""
    <div class="section-title">&#x1F510; Certificate setup</div>

    <div  class="u41">
      <div  class="u17">1. Trust the gateway's TLS certificate</div>
      <p  class="u40">
        If your client rejects the gateway's HTTPS certificate (e.g. a Windows/Codex TLS
        handshake failure), download and trust this CA once — you don't need mkcert or any
        client certificate to do this.
      </p>
      <a href="/ca.crt" download="mcp-lab-ca.crt" class="btn-primary btn-sm u42" >
        &#x2B07; Download CA certificate
      </a>
      <div  class="u43">
        Plain-HTTP link (fetches before TLS trust is established, e.g. from a fresh machine):
        <code>{esc_py(http_ca_url)}</code>
      </div>

      <details  class="u44">
        <summary  class="u27">Windows install instructions</summary>
        <div  class="u45">
          PowerShell (as Administrator):<br>
          <code>Import-Certificate -FilePath .\\mcp-lab-ca.crt -CertStoreLocation Cert:\\LocalMachine\\Root</code><br>
          or: double-click the downloaded file &rarr; <em>Install Certificate</em> &rarr;
          <em>Local Machine</em> &rarr; <em>Place all certificates in the following store</em> &rarr;
          <em>Trusted Root Certification Authorities</em>. Restart your MCP client (e.g. Codex)
          afterwards so it picks up the updated trust store.
        </div>
      </details>
      <details  class="u46">
        <summary  class="u27">macOS install instructions</summary>
        <div  class="u45">
          <code>sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain mcp-lab-ca.crt</code>
        </div>
      </details>
      <details  class="u46">
        <summary  class="u27">Linux install instructions</summary>
        <div  class="u45">
          <code>sudo cp mcp-lab-ca.crt /usr/local/share/ca-certificates/mcp-lab-ca.crt && sudo update-ca-certificates</code>
        </div>
      </details>
    </div>

    <div  class="u29">
      <div  class="u17">2. Client (mTLS) certificates — usually not needed</div>
      <p  class="u47">
        You do <strong>not</strong> need a client certificate to sign in or call tools — OAuth
        sign-in (this portal's login) is sufficient everywhere, including
        <code>/api/v1/tools/</code>. A client certificate is only relevant if you're
        registering a non-interactive <em>agent</em> identity on the dedicated mTLS listener.
        That's issued via step-ca and isn't self-service yet — ask an admin, or see
        <code>lab/tests/mtls_agent_identity.sh</code> for how one is minted today.
      </p>
    </div>

    <div  class="u48">
      <button class="btn-secondary" hx-get="/portal/fragments/profile" hx-target="#portal-body" hx-swap="innerHTML">&#x2190; Back to profile</button>
    </div>
    """)


@router.get("/fragments/admin/profile", response_class=HTMLResponse)
async def fragment_admin_profile(request: Request):
    """Admin-shell profile tab."""
    _require_portal_access(request)
    return HTMLResponse(await _build_profile_fragment(request, back_target=""))


@router.get("/fragments/mcp-profile/{name}", response_class=HTMLResponse)
async def fragment_mcp_profile_manage(name: str, request: Request):
    """Per-tool toggle list for one named MCP profile — admin/platform_admin only."""
    _require_portal_access(request)
    if not any(r in ("admin", "platform_admin") for r in _roles(request)):
        return HTMLResponse('<div  class="u11">Admin role required.</div>')

    try:
        from collections import defaultdict
        from app.routers.profiles import _get_named_profile, _get_profile_mcp_bindings
        from sqlalchemy import text as _sql_text
        from app.core.database import AsyncSessionLocal as _ASL
        profile = await _get_named_profile(name)
        if profile is None:
            return HTMLResponse('<div  class="u49">Profile not found.</div>')
        bindings = {b["mcp_name"]: b["enabled"] for b in await _get_profile_mcp_bindings(str(profile["id"]))}
        async with _ASL() as session:
            rows = (await session.execute(_sql_text("""
                SELECT t.name AS tool_name, COALESCE(s.name, t.service_name, t.name) AS server_name
                FROM tool_registry t
                LEFT JOIN server_registry s ON s.server_id = t.server_id
                WHERE t.deleted_at IS NULL
                ORDER BY server_name, t.name
            """))).fetchall()
        by_server: dict[str, list[str]] = defaultdict(list)
        for r in rows:
            by_server[r.server_name].append(r.tool_name)
    except Exception as exc:
        logger.error("portal mcp-profile manage error for %r: %s", name, exc)
        return HTMLResponse(_error_fragment("Could not load this profile's tool bindings."))

    slug = _slugify(name)
    server_sections = []
    for server_name, tool_names in sorted(by_server.items()):
        tool_rows = []
        for tool_name in tool_names:
            enabled = bindings.get(tool_name, False)
            tool_rows.append(f"""
            <tr>
              <td  class="u50">{esc_py(tool_name)}</td>
              <td  class="u51">
                <button class="btn-secondary btn-sm mcpprof-toggle-btn"
                        data-profile="{esc_py(name)}" data-mcp="{esc_py(tool_name)}" data-enabled="{"true" if enabled else "false"}"
                        data-container="mcpprof-detail-{esc_py(slug)}">
                  {"Enabled — click to disable" if enabled else "Disabled — click to enable"}
                </button>
              </td>
            </tr>""")
        n_enabled = sum(1 for t in tool_names if bindings.get(t, False))
        server_sections.append(f"""
        <div  class="u52">
          <div  class="u53">
            <div  class="u54">{esc_py(server_name)}
              <span  class="u55">({n_enabled}/{len(tool_names)} tools enabled)</span>
            </div>
            <div  class="u56">
              <button class="btn-secondary btn-sm mcpprof-bulk-btn" data-profile="{esc_py(name)}"
                      data-container="mcpprof-detail-{esc_py(slug)}" data-action="enable"
                      data-tools='{esc_py(json.dumps(tool_names))}'>Enable all</button>
              <button class="btn-secondary btn-sm mcpprof-bulk-btn" data-profile="{esc_py(name)}"
                      data-container="mcpprof-detail-{esc_py(slug)}" data-action="disable"
                      data-tools='{esc_py(json.dumps(tool_names))}'>Disable all</button>
            </div>
          </div>
          <table class="tbl-wrap u57" >
            <tbody>{"".join(tool_rows)}</tbody>
          </table>
        </div>""")

    return HTMLResponse(f"""
    <div>{"".join(server_sections) if server_sections else '<div  class="u58">No servers/tools registered.</div>'}</div>""")


async def _build_portal_access(
    cid: str,
    api_key: str = "",
    is_auditor: bool = False,
    profile_uuid: str | None = None,
) -> str:  # noqa: C901
    """Build the 'Your access' card grid for the user portal.

    `profile_uuid` is the caller's bound named profile (request.state.profile_uuid).
    It MUST be threaded through: the portal previously read `mcp_profiles` directly and
    knew nothing about named profiles, so a caller logged in with ?profile=<uuid> saw a
    green "Access enabled" pill for tools that named profile actually denies at invoke.

    Raises ProfileLookupError (fail-closed) — the caller renders a 503. Rendering an
    unknown profile state as "enabled" is the fail-open this resolver exists to prevent.
    """
    from collections import defaultdict

    # 1. Load grants from data.json (allowed tool names)
    grants: dict[str, Any] = {}
    try:
        data = json.loads(_DATA_JSON.read_text())
        grants = data.get("mcp", {}).get("grants", {}).get(cid, {})
    except Exception as exc:
        logger.warning("portal my-access: could not read data.json: %s", exc)

    allowed_tools: list[str] = grants.get("allowed_tools", [])

    # 2. Fetch tool + server details from DB
    # Group tools by service_name → server cards
    server_tools: dict[str, list[dict]] = defaultdict(list)
    server_meta: dict[str, dict] = {}  # service_name → {status, injection_mode, description}
    profile_states: dict[str, bool] = {}

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            # All tools (not just granted — we show all servers the user can see)
            result = await session.execute(text("""
                SELECT t.name, t.tool_id, t.status, t.injection_mode,
                       t.description, t.service_name,
                       s.status AS srv_status, s.name AS srv_name,
                       s.injection_mode AS srv_injection_mode,
                       s.debug_mode AS srv_debug_mode, s.owner_sub AS srv_owner_sub,
                       s.maintainers AS srv_maintainers,
                       EXISTS (
                         SELECT 1 FROM credential_store c
                         WHERE c.tool_id = t.tool_id
                           OR (c.user_sub = :cid AND c.service = t.service_name)
                       ) AS has_cred
                FROM tool_registry t
                LEFT JOIN server_registry s ON s.server_id = t.server_id
                WHERE t.deleted_at IS NULL
                ORDER BY COALESCE(s.name, t.service_name, t.name), t.name
            """), {"cid": cid})
            for row in result.fetchall():
                svc = row.srv_name or row.service_name or row.name
                granted = row.name in allowed_tools
                server_tools[svc].append({
                    "name": row.name,
                    "status": row.status or "active",
                    "has_cred": bool(row.has_cred),
                    "granted": granted,
                    "injection_mode": row.injection_mode or "none",
                })
                if svc not in server_meta:
                    srv_st = (row.srv_status or row.status or "active").lower()
                    # R-2 debug mode: locked to owner + maintainers only. Everyone
                    # else sees "maintenance", not the underlying deny reason.
                    locked_out = bool(row.srv_debug_mode) and cid not in (
                        {row.srv_owner_sub} | set(row.srv_maintainers or [])
                    )
                    server_meta[svc] = {
                        "status": srv_st,
                        "injection_mode": row.srv_injection_mode or row.injection_mode or "none",
                        "in_maintenance": locked_out,
                    }

            # Profile states are NOT read here any more — see the resolver call after
            # this try/except. They used to be a raw `SELECT ... FROM mcp_profiles`
            # inside this block, which had two faults: it ignored named profiles
            # entirely (a fourth, un-synced re-implementation of the profile decision),
            # and being inside the broad `except Exception` below it failed OPEN — a DB
            # hiccup left profile_states empty, so every server rendered "Access
            # enabled".

            # R-6: caller's own in-flight submissions (not yet active/rejected),
            # so "submitted successfully" isn't the last thing a submitter ever sees.
            mine_result = await session.execute(text("""
                SELECT server_id, name, submission_status, scan_status, scan_report, updated_at,
                       injection_mode, service_name, upstream_url, github_repo_url,
                       requested_upstream_url, review_notes, upstream_idp_config,
                       description, data_categories, has_write_ops
                FROM server_registry
                WHERE owner_sub = :cid
                  AND submission_status NOT IN ('draft')
                  AND deleted_at IS NULL
                ORDER BY updated_at DESC
                LIMIT 10
            """), {"cid": cid})
            my_submissions = [dict(r._mapping) for r in mine_result.fetchall()]
    except Exception as exc:
        logger.error("portal my-access DB error: %s", exc)
        my_submissions = []

    # Resolve the per-server profile state through the SAME resolver the invoke path
    # and /mcp tools/list use, so the pill the user sees matches what a call will do.
    # Deliberately OUTSIDE the broad `except Exception` above: ProfileLookupError must
    # reach fragment_my_access (-> 503), never degrade to "everything enabled".
    # Resolve per TOOL, then fold up to the server card.
    #
    # mcp_profiles is keyed by TOOL name — that is the key the writer uses and the key
    # invoke_tool resolves with (`_lookup_profile_with_cache(client_id, tool_name, …)`).
    # The card key `svc` is a SERVER name (`row.srv_name or row.service_name or row.name`).
    # The previous code looked server names up in a tool-keyed dict, so it matched
    # nothing and every card fell back to the `True` default: the pill read
    # "Access enabled" no matter what the profile actually said. Same shape as the
    # discovery/invoke key mismatch — a lookup keyed on the wrong identifier that fails
    # silently instead of loudly.
    #
    # A card is "enabled" if ANY of its tools is callable; a server with every tool
    # disabled is genuinely unusable and should say so.
    from app.services.invocation import _lookup_profile_with_cache as _resolve_profile
    for _svc, _tools in server_tools.items():
        _names = [t.get("name") for t in _tools if t.get("name")]
        if not _names:
            continue
        _any_enabled = False
        for _tn in _names:
            _p = await _resolve_profile(cid, _tn, profile_uuid=profile_uuid)
            # None = no row from either source = no restriction = enabled.
            if _p is None or bool(_p.get("enabled", True)):
                _any_enabled = True
                break
        profile_states[_svc] = _any_enabled

    # 3. Determine card-level status
    def _card_status(svc: str) -> str:
        meta = server_meta.get(svc, {})
        if meta.get("in_maintenance"):
            return "maintenance"
        srv_st = meta.get("status", "active")
        if srv_st == "pending":
            return "awaiting"
        if srv_st == "quarantined":
            return "suspended"
        tools = server_tools.get(svc, [])
        if any(t["status"] == "quarantined" for t in tools):
            return "suspended"
        return "active"

    # 4. Build cards
    # Limit to servers that have at least one granted tool (or show all if no grants)
    granted_svcs: list[str] = []
    for svc in server_tools:
        if any(t["granted"] for t in server_tools[svc]) or not allowed_tools:
            granted_svcs.append(svc)
    if not granted_svcs:
        granted_svcs = list(server_tools.keys())

    # Fallback when no DB data
    if not granted_svcs:
        if not allowed_tools:
            return '<div class="empty-state">No servers accessible for this identity.</div>'
        # Show granted tool names as pseudo-server cards
        granted_svcs = list(dict.fromkeys(allowed_tools))
        for svc in granted_svcs:
            server_tools[svc] = [{"name": svc, "status": "active", "has_cred": False,
                                   "granted": True, "injection_mode": "none"}]

    n_active    = sum(1 for s in granted_svcs if _card_status(s) == "active")
    n_suspended = sum(1 for s in granted_svcs if _card_status(s) == "suspended")
    n_awaiting  = sum(1 for s in granted_svcs if _card_status(s) == "awaiting")

    cards_html = []
    for svc in granted_svcs:
        cstatus = _card_status(svc)
        tools   = server_tools.get(svc, [])
        meta    = server_meta.get(svc, {})
        mode    = meta.get("injection_mode", "none")
        enabled = profile_states.get(svc, True)

        card_extra_cls = {"suspended": "card-suspended", "awaiting": "card-awaiting",
                           "maintenance": "card-suspended"}.get(cstatus, "")
        icon_cls = "" if cstatus == "active" else "dim"
        name_cls = "" if cstatus == "active" else "dim"
        desc_cls = "" if cstatus == "active" else "dim"

        # Status pill
        pill_cls = {"active": "cpill-active", "suspended": "cpill-suspended", "awaiting": "cpill-awaiting",
                    "maintenance": "cpill-suspended"}[cstatus]
        pill_lbl = {"active": "Active", "suspended": "Suspended", "awaiting": "Awaiting",
                    "maintenance": "Maintenance"}[cstatus]
        pill_html = f'<span class="cpill {pill_cls}"><span class="cpill-dot"></span>{pill_lbl}</span>'

        # Description
        desc_map = {
            "active":      f"Tools available via {esc_py(mode)} injection.",
            "suspended":   "Temporarily blocked by an administrator pending security review.",
            "awaiting":    "Waiting for an admin to approve this server. We’ll notify you.",
            "maintenance": "MCP server in maintenance — only the owner and maintainers can use it right now.",
        }
        desc_text = desc_map[cstatus]

        # Tool chips — show max 3 granted tools + "N more" if overflow
        granted_tool_names = [t["name"] for t in tools if t["granted"]][:4]
        chip_items = []
        for tn in granted_tool_names[:3]:
            if cstatus == "active":
                chip_items.append(
                    f'<span class="tool-chip"><span class="tool-chip-dot"></span>{esc_py(tn)}</span>'
                )
            else:
                chip_items.append(f'<span class="tool-chip-sus">{esc_py(tn)}</span>')
        # Show one dimmed ungranterd tool if room
        ungrantred = [t["name"] for t in tools if not t["granted"]]
        if ungrantred:
            chip_items.append(f'<span class="tool-chip-off">{esc_py(ungrantred[0])}</span>')
        chips_html = "".join(chip_items) if chip_items else f'<span class="tool-chip-off">no tools</span>'

        # Footer
        if cstatus == "active" and enabled:
            toggle_cls = "srv-toggle"
            footer_lbl = '<span class="srv-card-footer-lbl">Access enabled</span>'
            toggle_html = (
                f'<button class="srv-toggle" title="Disable {esc_py(svc)}" aria-label="Disable {esc_py(svc)}" '
                f'hx-post="/portal/actions/profile/{esc_py(svc)}/disable" '
                f'hx-target="closest .srv-card" hx-swap="outerHTML"></button>'
            )
        elif cstatus == "active" and not enabled:
            footer_lbl = '<span class="srv-card-footer-lbl">Access disabled</span>'
            toggle_html = (
                f'<button class="srv-toggle off" title="Enable {esc_py(svc)}" aria-label="Enable {esc_py(svc)}" '
                f'hx-post="/portal/actions/profile/{esc_py(svc)}/enable" '
                f'hx-target="closest .srv-card" hx-swap="outerHTML"></button>'
            )
        elif cstatus == "suspended":
            footer_lbl = '<a class="srv-card-footer-link" href="#">Contact admin →</a>'
            toggle_html = f'<button class="srv-toggle off" disabled aria-label="Access to {esc_py(svc)} suspended"></button>'
        elif cstatus == "maintenance":
            footer_lbl = '<span class="srv-card-footer-pend">In maintenance</span>'
            toggle_html = f'<button class="srv-toggle off" disabled aria-label="{esc_py(svc)} is in maintenance"></button>'
        else:  # awaiting
            footer_lbl = '<span class="srv-card-footer-pend">Pending review</span>'
            toggle_html = f'<button class="srv-toggle off" disabled aria-label="{esc_py(svc)} is pending review"></button>'

        # Auditor is read-only: no enable/disable toggle.
        if is_auditor:
            toggle_html = '<button class="srv-toggle off" disabled title="read-only (auditor)" aria-label="Access toggle unavailable (read-only auditor role)"></button>'

        initials = (svc[0].upper() if svc else "?")
        cards_html.append(f"""
        <div class="srv-card {card_extra_cls}">
          <div class="srv-card-hdr">
            <div class="srv-card-id">
              <div class="srv-card-icon {icon_cls}">{initials}</div>
              <div class="srv-card-name {name_cls}">{esc_py(svc)}</div>
            </div>
            {pill_html}
          </div>
          <div class="srv-card-desc {desc_cls}">{desc_text}</div>
          <div class="srv-card-tools">{chips_html}</div>
          <div class="srv-card-footer">
            {footer_lbl}
            {toggle_html}
          </div>
        </div>""")

    # 4b. My submissions strip (R-6 — scan status visible to the submitter)
    _SUB_CHIP = {
        "awaiting_review":      ("#2563eb", "Awaiting review"),
        "scan_pending":         ("#6b7280", "Queued for scan"),
        "scan_running":         ("#d97706", "Scanning…"),
        "scan_blocked":         ("#dc2626", "Scan blocked"),
        "changes_requested":    ("#d97706", "Changes requested"),
        "approved_pending_url": ("#16a34a", "Approved — needs URL"),
        # R-10/F-15: no-code submissions have no server to run — terminal state is
        # honestly labeled distinct from "active"/"running".
        "scaffold_ready":       ("#0891b2", "Approved — scaffold only (not running)"),
        "active":               ("#16a34a", "Active"),
        "rejected":             ("#dc2626", "Rejected"),
    }
    my_submissions_html = ""
    if my_submissions:
        rows_html = []
        for sub in my_submissions:
            st = sub.get("submission_status") or "draft"
            color, label = _SUB_CHIP.get(st, ("#6b7280", st.replace("_", " ").title()))
            findings = sub.get("scan_report") or []
            n_block = sum(1 for f in findings if isinstance(f, dict) and f.get("block")) if isinstance(findings, list) else 0
            finding_note = f' · <span  class="u59">{n_block} blocking finding{"s" if n_block != 1 else ""}</span>' if n_block else ""
            _mode = sub.get("injection_mode") or "none"
            _svc = sub.get("service_name")
            _url = sub.get("upstream_url") or sub.get("requested_upstream_url")
            _url_label = "backend" if sub.get("upstream_url") else "backend (requested)"
            backend_bits = [f'auth: <span  class="u13">{esc_py(_mode)}</span>']
            if _svc:
                backend_bits.append(f'credential: <span  class="u13">{esc_py(_svc)}</span>')
            if _url:
                backend_bits.append(f'{_url_label}: <span  class="u60">{esc_py(_url)}</span>')
            _repo = sub.get("github_repo_url")
            if _repo and str(_repo).startswith("https://"):
                backend_bits.append(f'code: <a href="{esc_py(_repo)}" target="_blank" rel="noopener noreferrer"  class="u61">{esc_py(_repo)}</a>')
            backend_note = (
                f'<div  class="u18">{" · ".join(backend_bits)}</div>'
            )
            scaffold_note = ""
            if st == "scaffold_ready":
                _ssid = esc_py(str(sub.get("server_id") or ""))
                scaffold_note = (
                    f'<div  class="u18">'
                    f'No server is running yet — build it from the scaffold, then submit '
                    f'it as a new, repo-backed submission to go live. '
                    f'<a href="/api/v1/submissions/{_ssid}/scaffold"  class="u61">Download scaffold.zip</a>'
                    f'</div>'
                )
            provide_url_form = ""
            if st == "approved_pending_url":
                _psid = esc_py(str(sub.get("server_id") or ""))
                provide_url_form = f"""
                <div  class="u62">
                  <input id="provurl-{_psid}" type="url" aria-label="Backend URL" placeholder="https://your-server.example.com/mcp"
                          class="u63">
                  <button class="btn-primary u64" 
                          data-act="providePendingUrl" data-a0="{_psid}">Go live</button>
                </div>"""
            edit_resubmit_form = ""
            if st == "changes_requested":
                _esid = esc_py(str(sub.get("server_id") or ""))
                _idp_cfg = sub.get("upstream_idp_config")
                if isinstance(_idp_cfg, str):
                    try:
                        _idp_cfg = json.loads(_idp_cfg)
                    except (TypeError, ValueError):
                        _idp_cfg = None
                _audience = (_idp_cfg or {}).get("audience") if isinstance(_idp_cfg, dict) else None
                _notes = sub.get("review_notes") or ""
                _notes_html = (
                    f'<div  class="u65">Reviewer notes: {esc_py(_notes)}</div>'
                    if _notes else ""
                )
                edit_resubmit_form = f"""
                {_notes_html}
                <div  class="u66">
                  <input id="editrepo-{_esid}" type="url" aria-label="GitHub repo URL" placeholder="GitHub repo URL"
                         value="{esc_py(sub.get('github_repo_url') or '')}"
                          class="u67">
                  <input id="editurl-{_esid}" type="url" aria-label="Backend URL" placeholder="Backend URL (https://your-server.example.com/mcp)"
                         value="{esc_py(sub.get('requested_upstream_url') or '')}"
                          class="u67">
                  <input id="editdesc-{_esid}" type="text" aria-label="Description" placeholder="Description"
                         value="{esc_py(sub.get('description') or '')}"
                          class="u67">
                  <input id="editaud-{_esid}" type="text" aria-label="Token-exchange audience" placeholder="Token-exchange audience (e.g. lab-tickets) — only needed for kc_token_exchange/oauth_user_token modes"
                         value="{esc_py(_audience or '')}"
                          class="u67">
                  <button class="btn-primary u68" 
                          data-act="editAndResubmit" data-a0="{_esid}">Save &amp; resubmit for review</button>
                </div>"""
            rows_html.append(f"""
            <div  class="u69">
              <div  class="u16">
                <span  class="u70">{esc_py(sub.get("name") or "")}</span>
                <span  class="u71">
                  <span class="chip chip-sm {_chip_cls(color)}">{esc_py(label)}</span>{finding_note}
                </span>
              </div>
              {backend_note}
              {scaffold_note}
              {provide_url_form}
              {edit_resubmit_form}
            </div>""")
        my_submissions_html = f"""
        <details  class="u72" open>
          <summary  class="u73">
            My submissions <span class="count">{len(my_submissions)}</span>
          </summary>
          <div  class="u74">{"".join(rows_html)}</div>
        </details>"""

    # 5. MCP config snippet (compact, below cards)
    platform_host = os.environ.get("PLATFORM_HOST", "https://mcp.example.com")
    mcp_config = {
        "mcpServers": {
            tn: {
                "url": f"{platform_host}/mcp/{tn}",
                **({"headers": {"Authorization": f"Bearer {api_key}"}} if api_key else {}),
            }
            for tn in allowed_tools
        }
    }
    mcp_json = json.dumps(mcp_config, indent=2)

    home_html = f"""
    <div class="srv-strip">
      <div class="srv-strip-cnt">{len(granted_svcs)} servers</div>
      <div class="srv-strip-div"></div>
      <div class="srv-strip-item"><span class="dot-green"></span>{n_active} active</div>
      <div class="srv-strip-item"><span class="dot-red"></span>{n_suspended} suspended</div>
      <div class="srv-strip-item"><span class="dot-amber"></span>{n_awaiting} awaiting approval</div>
    </div>
    <div class="ss-home-tiles">
      <div class="ss-home-tile" data-act="ssShowTab" data-a0="catalog">
        <div class="ss-home-tile-val">{len(granted_svcs)}</div>
        <div class="ss-home-tile-label">Servers you can use</div>
      </div>
      <div class="ss-home-tile" data-act="ssShowTab" data-a0="submit">
        <div class="ss-home-tile-val u75" >{n_awaiting}</div>
        <div class="ss-home-tile-label">Submissions in review</div>
      </div>
    </div>"""

    catalog_html = f"""
    <!-- Card grid -->
    <div class="srv-card-grid">
      {"".join(cards_html) if cards_html else '<div class="empty-state">No servers accessible for this identity.</div>'}
    </div>

    <!-- MCP Config snippet (collapsed by default) -->
    <details  class="u76">
      <summary  class="u77">
        MCP config snippet
      </summary>
      <div  class="u76">
        <p  class="u78">
          Paste into <code  class="u79">~/.mcp.json</code>.
          {"Append <code style=\"font-family:var(--ff-mono)\">?key=YOUR_API_KEY</code> to pre-fill." if not api_key else "API key pre-filled."}
        </p>
        <div class="code-block" id="mcp-config-block">{esc_py(mcp_json)}</div>
        <button class="btn-secondary btn-sm u46"  data-act="copyElementText" data-a0="mcp-config-block">Copy</button>
      </div>
    </details>"""

    submit_html = f"""
    {"" if is_auditor else '''<div  class="u80">
      <a href="/portal/submit"  class="u81">
        &#x2B; Submit MCP Server
      </a>
    </div>'''}
    {my_submissions_html if my_submissions_html else '<div class="empty-state">No submissions yet.</div>'}"""

    return f"""
    <!-- Hero -->
    <div class="portal-hero">
      <div>
        <div class="portal-hero-title">Your access</div>
        <div class="portal-hero-sub">Pick a profile, then choose which servers and tools can reach you on your behalf.</div>
      </div>
      <div class="portal-find-bar">
        <div class="portal-find-orb"></div>
        <span class="portal-find-text">Find a tool — e.g. <strong  class="u82">"send an email"</strong></span>
      </div>
    </div>

    <!-- Profile bar -->
    <div class="profile-bar">
      <span class="profile-lbl">PROFILE</span>
      <div class="profile-pills">
        <button class="profile-pill active">
          <span class="profile-pill-dot"></span>Production agent
        </button>
        <button class="profile-pill">Staging</button>
        <button class="profile-pill">Analytics · read-only</button>
        <button class="profile-pill profile-pill-new">+ New</button>
      </div>
      <span class="profile-summary">
        Scopes <strong>{len(granted_svcs)} servers</strong>
        · <strong>{len(allowed_tools)} tools</strong> granted
      </span>
    </div>

    <div class="ss-tabs-bar" id="ss-tabs-bar">
      <button class="adm-tab active" data-act="ssShowTab" data-a0="home">Home</button>
      <button class="adm-tab" data-act="ssShowTab" data-a0="catalog">Catalog</button>
      <button class="adm-tab" data-act="ssShowTab" data-a0="submit">Submit</button>
      <button class="adm-tab" data-act="ssShowTab" data-a0="profile">Profile</button>
    </div>

    <div id="ss-panel-home" class="ss-panel" tabindex="-1">{home_html}</div>
    <div id="ss-panel-catalog" class="ss-panel u4" tabindex="-1" >{catalog_html}</div>
    <div id="ss-panel-submit" class="ss-panel u4" tabindex="-1" >{submit_html}</div>
    <div id="ss-panel-profile" class="ss-panel u4" tabindex="-1" ></div>
    """


# ---------------------------------------------------------------------------
# Actions: Profile MCP enable/disable (htmx — returns an updated access-row)
# Task 4.2: toggle buttons in My Access tab post here; result replaces the row
# ---------------------------------------------------------------------------

@router.post("/actions/profile/{mcp_name}/enable", response_class=HTMLResponse)
async def portal_profile_enable(mcp_name: str, request: Request) -> HTMLResponse:
    """Enable an MCP for the caller (self-service). Returns updated card fragment."""
    _require_portal_write(request)
    cid = _client_id(request)
    try:
        from app.routers.profiles import enable_mcp as _enable_mcp
        await _enable_mcp(principal=cid, mcp_name=mcp_name, request=request)
    except Exception as exc:
        logger.warning("portal profile enable failed: %s", exc)
        return HTMLResponse(
            f'<div class="srv-card"><div class="srv-card-name">{esc_py(mcp_name)}</div>'
            f'<div  class="u83">Enable failed: {esc_py(str(exc))}</div></div>'
        )
    return await _build_server_card_fragment(mcp_name, cid, enabled=True)


@router.post("/actions/profile/{mcp_name}/disable", response_class=HTMLResponse)
async def portal_profile_disable(mcp_name: str, request: Request) -> HTMLResponse:
    """Disable an MCP for the caller (self-service). Returns updated card fragment."""
    _require_portal_write(request)
    cid = _client_id(request)
    try:
        from app.routers.profiles import disable_mcp as _disable_mcp
        await _disable_mcp(principal=cid, mcp_name=mcp_name, request=request)
    except Exception as exc:
        logger.warning("portal profile disable failed: %s", exc)
        return HTMLResponse(
            f'<div class="srv-card"><div class="srv-card-name">{esc_py(mcp_name)}</div>'
            f'<div  class="u83">Disable failed: {esc_py(str(exc))}</div></div>'
        )
    return await _build_server_card_fragment(mcp_name, cid, enabled=False)


async def _build_server_card_fragment(svc: str, cid: str, enabled: bool) -> HTMLResponse:
    """Return a single srv-card replacement fragment after a toggle."""
    toggle_action = "disable" if enabled else "enable"
    toggle_cls    = "srv-toggle" if enabled else "srv-toggle off"
    footer_lbl    = (
        '<span class="srv-card-footer-lbl">Access enabled</span>'
        if enabled else
        '<span class="srv-card-footer-lbl">Access disabled</span>'
    )
    initials = (svc[0].upper() if svc else "?")
    toggle_html = (
        f'<button class="{toggle_cls}" '
        f'hx-post="/portal/actions/profile/{esc_py(svc)}/{toggle_action}" '
        f'hx-target="closest .srv-card" hx-swap="outerHTML"></button>'
    )
    html = f"""
    <div class="srv-card">
      <div class="srv-card-hdr">
        <div class="srv-card-id">
          <div class="srv-card-icon">{initials}</div>
          <div class="srv-card-name">{esc_py(svc)}</div>
        </div>
        <span class="cpill cpill-active"><span class="cpill-dot"></span>Active</span>
      </div>
      <div class="srv-card-desc">Access {"enabled" if enabled else "disabled"} by you.</div>
      <div class="srv-card-tools"></div>
      <div class="srv-card-footer">
        {footer_lbl}
        {toggle_html}
      </div>
    </div>"""
    return HTMLResponse(html)


def _build_access_row_fragment(mcp_name: str, enabled: bool) -> HTMLResponse:
    """
    Build a minimal .access-row HTML fragment after a profile toggle.
    The htmx swap (hx-target="closest .access-row", hx-swap="outerHTML")
    replaces the old row with this fragment.
    """
    _toggle_action = "disable" if enabled else "enable"
    _toggle_label = "Disable" if enabled else "Enable"
    _toggle_cls = "acc-toggle on" if enabled else "acc-toggle off"
    _enabled_badge = _badge("enabled" if enabled else "disabled",
                            "badge-active" if enabled else "badge-inactive")
    _toggle_btn = (
        f'<button class="btn-sm {_toggle_cls}" '
        f'hx-post="/portal/actions/profile/{esc_py(mcp_name)}/{_toggle_action}" '
        f'hx-swap="outerHTML" '
        f'hx-target="closest .access-row" '
        f'hx-indicator=".htmx-indicator">'
        f'{_toggle_label}</button>'
    )
    html = f"""
        <div class="access-row">
          <div>
            <div class="access-name">{esc_py(mcp_name)}</div>
          </div>
          <div  class="u84">
            {_enabled_badge}
            {_toggle_btn}
          </div>
        </div>"""
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: Admin shell (inner tabs) — legacy entry for old-style tab nav
# ---------------------------------------------------------------------------

@router.get("/fragments/admin", response_class=HTMLResponse)
async def fragment_admin(request: Request):
    """Admin tab shell — kept for backward compat; new shell uses sidebar nav."""
    _require_admin(request)

    html = """
    <div class="section-title">&#x1F6E1;&#xFE0F; Admin Panel</div>
    <div class="inner-tabs">
      <button class="inner-tab-btn" data-itab="servers"      data-act="activateAdminTab" data-a0="servers">MCP Servers</button>
      <button class="inner-tab-btn" data-itab="tools"        data-act="activateAdminTab" data-a0="tools">Tools</button>
      <button class="inner-tab-btn active" data-itab="credentials" data-act="activateAdminTab" data-a0="credentials">Credentials</button>
      <button class="inner-tab-btn"        data-itab="grants"      data-act="activateAdminTab" data-a0="grants">Grants</button>
    </div>
    <div id="admin-inner-content"
         hx-get="/portal/fragments/admin/servers"
         hx-trigger="load"
         hx-swap="innerHTML">
      <div class="loading-state"><span class="spinner"></span> Loading...</div>
    </div>
    """
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: Admin > MCP Servers  (new — server-level registry)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/servers", response_class=HTMLResponse)
async def fragment_admin_servers(request: Request):
    """Admin MCP Servers tab: server registry with approve/quarantine workflow."""
    _require_admin(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT server_id, name, upstream_url, status, owner_sub,
                       injection_mode, updated_at, maintainers, debug_mode,
                       public_to_authenticated, has_write_ops,
                       debug_enabled_at, debug_enabled_by, verification_report,
                       is_self_hosted, github_repo_url,
                       connection_failure_count, last_connection_error, last_connection_error_at
                FROM server_registry
                WHERE deleted_at IS NULL
                ORDER BY name
            """))
            servers = result.fetchall()
            total = len(servers)

            # Pending/quarantined counts for attention band
            pending_names    = [s.name for s in servers if (s.status or "") == "pending"]
            quarantined_names = [s.name for s in servers if (s.status or "") == "quarantined"]

            # Per-server risk/attention rollup: a server card previously showed
            # nothing about its tools at all — a HIGH-risk tool sitting
            # status='disabled' was invisible unless you separately opened the
            # global Tools tab and happened to scroll to it (reported live:
            # "wazuh-siem ... disabled ... HIGH ... no way to enable it" while
            # its server card just said "Approved"). Aggregate max risk_level
            # and a not-active count per server so the card can surface both.
            tool_rollup = await session.execute(text("""
                SELECT server_id,
                       count(*) FILTER (WHERE status IN ('disabled', 'quarantined')) AS not_active_count,
                       max(CASE risk_level
                           WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                           WHEN 'medium' THEN 2 ELSE 1 END) AS risk_rank
                FROM tool_registry
                WHERE deleted_at IS NULL AND server_id IS NOT NULL
                GROUP BY server_id
            """))
            _rank_to_label = {4: "critical", 3: "high", 2: "medium", 1: "low"}
            tool_stats = {
                str(r.server_id): {
                    "not_active": r.not_active_count,
                    "risk": _rank_to_label.get(r.risk_rank, "low"),
                }
                for r in tool_rollup.fetchall()
            }
    except Exception as exc:
        logger.error("portal admin/servers DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading server registry."))

    # Attention band
    attention_items: list[str] = []
    if pending_names:
        attention_items.append(
            f'<span  class="u85">{esc_py(pending_names[0])}</span>'
            f' awaiting approval'
            + (f' and {len(pending_names)-1} more' if len(pending_names) > 1 else '')
        )
    if quarantined_names:
        attention_items.append(
            f'<span  class="u86">'
            f'{esc_py(quarantined_names[0])}</span> is quarantined'
        )

    attention_html = ""
    if attention_items:
        count = len(pending_names) + len(quarantined_names)
        attention_html = f"""
        <div class="adm-attention">
          <div class="adm-attention-icon"><div class="adm-attention-diamond"></div></div>
          <div  class="u87">
            <div class="adm-attention-title">{count} thing{"s" if count != 1 else ""} need your attention</div>
            <div class="adm-attention-body">{" · ".join(attention_items)}</div>
          </div>
          <button class="adm-attention-btn">Review</button>
        </div>"""

    # Build table rows
    def _fmt_time(ts: Any) -> str:
        if ts is None:
            return "—"
        import datetime
        now = datetime.datetime.utcnow()
        try:
            dt = ts if isinstance(ts, datetime.datetime) else datetime.datetime.fromisoformat(str(ts))
            diff = now - dt.replace(tzinfo=None)
            minutes = int(diff.total_seconds() / 60)
            if minutes < 60:
                return f"{minutes}m ago"
            hours = minutes // 60
            if hours < 24:
                return f"{hours}h ago"
            return f"{hours // 24}d ago"
        except Exception:
            return str(ts)[:10]

    rows_html = []
    for s in servers:
        st = (s.status or "pending").lower()
        row_cls = {"pending": "row-pending", "quarantined": "row-quarantined"}.get(st, "")
        pill_cls = {"approved": "pill-approved", "pending": "pill-pending",
                    "quarantined": "pill-quarantined"}.get(st, "pill-pending")
        pill_label = {"approved": "Approved", "pending": "Pending",
                      "quarantined": "Quarantined"}.get(st, st.capitalize())

        mode = (s.injection_mode or "none").lower()
        mode_label = {"oauth_user_token": "OAuth", "service": "Svc acct",
                      "api_key": "API key", "none": "None", "header": "Header"}.get(mode, mode)

        sid = esc_py(str(s.server_id))
        _stats = tool_stats.get(str(s.server_id), {"not_active": 0, "risk": "low"})
        risk_badge = _badge(_stats["risk"].upper(), f"badge-risk-{_stats['risk']}")
        attention_link = (
            f' <a href="#" data-act="adminManageServerTools" data-pd="1" data-a0="{sid}" '
            f' class="u88" '
            f'title="Open this server\'s tools in the Tools tab">'
            f'&#x26A0; {_stats["not_active"]} tool{"s" if _stats["not_active"] != 1 else ""} disabled/quarantined</a>'
            if _stats["not_active"] else ''
        )
        maint_badge = (
            ' <span class="pill u89"  '
            'title="Auto-flagged after repeated connection failures — see the banner below">'
            '&#x274C; doesn\'t work</span>'
            if s.debug_mode and getattr(s, "debug_enabled_by", None) == "system:auto-health-check" else
            ' <span class="pill pill-quarantined" title="Only the owner and maintainers can invoke this server right now">'
            '&#x1F527; maintenance</span>' if s.debug_mode else ''
        )
        public_badge = (
            ' <span class="pill pill-approved" title="Any authenticated user can invoke this read-only server (PRD-0005 R-3)">'
            '&#x1F310; public</span>' if getattr(s, "public_to_authenticated", False) else ''
        )
        if st == "pending":
            action_html = (
                f'<div  class="u90">'
                f'<button class="btn-approve" data-act="adminApproveSrv" data-a0="{sid}">Approve</button>'
                f'<button class="btn-reject" data-act="adminRejectSrv" data-a0="{sid}">Reject</button>'
                f'</div>'
            )
        elif st == "quarantined":
            action_html = (
                f'<div  class="u51">'
                f'<button class="btn-release" data-act="adminReleaseSrv" data-a0="{sid}">Release</button>'
                f'</div>'
            )
        else:
            maintainers = s.maintainers or []
            debug_on = bool(s.debug_mode)
            # R-11: maintainers/debug-mode admin UI on top of the already-built
            # server_registry.py backend (migration V048). Owner/maintainer-only
            # gate is enforced server-side; a 403 here surfaces as a toast, not
            # a silent no-op.
            maint_json = esc_py(json.dumps(maintainers))
            action_html = (
                f'<div  class="u91">'
                f'<button class="btn-menu" data-act="srvMenuToggle" data-evt="1" data-a0="{sid}" aria-label="More actions" aria-haspopup="true">⋯</button>'
                f'<div class="srv-dropdown u4" id="srv-dd-{sid}" >'
                f'<button data-act="htmxGet" data-a0="/portal/fragments/admin/detections?server_id={sid}">Detections</button>'
                f'<button data-act="adminSetMaintainers" data-json="{esc_json_attr(sid, maintainers)}">Maintainers…</button>'
                # PRD-0012 C3/C4: self-hosted-only actions. Edit endpoint/config
                # re-routes through POST /request-change (quarantine+demote+
                # re-verify, never a silent overwrite); Update-from-git calls
                # the ops-agent rebuild path (git-pull + restart), same
                # request-change re-review contract on the backend side.
                + (f'<button data-act="adminEditEndpoint" data-json="{esc_json_attr(sid, s.upstream_url or "")}">'
                   f'Edit endpoint/config…</button>' if s.is_self_hosted else '')
                + (f'<button data-act="adminRebuildSrv" data-a0="{sid}">Update from git &amp; rebuild</button>'
                   if s.is_self_hosted and s.github_repo_url else '')
                + (f'<button data-act="adminVerifySrv" data-a0="{sid}">Retry verification</button>' if debug_on else '')
                + f'<button data-act="adminToggleDebug" data-json="{esc_json_attr(sid, not debug_on)}">'
                f'{"Go live / exit maintenance" if debug_on else "Enable debug mode"}</button>'
                # WS-A: view container logs — only offered while in debug/maintenance
                # mode, matching the server-side debug_mode gate on the logs endpoint.
                + (f'<button data-act="adminViewLogs" data-a0="{sid}">View logs</button>' if debug_on else '')
                + (
                    f'<button data-act="adminSetPublic" data-json="{esc_json_attr(sid, not s.public_to_authenticated)}">'
                    f'{"Make private" if s.public_to_authenticated else "Make public (all users)"}</button>'
                    if not s.has_write_ops else
                    '<button disabled title="Write-capable servers cannot be public" '
                    ' class="u92">Make public (write-op — blocked)</button>'
                )
                + f'<button data-act="adminQuarantineSrv" data-a0="{sid}">Quarantine</button>'
                f'<button class="danger" data-act="adminDeleteSrv" data-a0="{sid}">Delete</button>'
                f'</div></div>'
            )

        # PRD-0012 C4: first-class maintenance banner — NOT buried in the ⋯
        # menu (the original complaint was a hidden control). Shown whenever
        # debug_mode is on, with a staleness hint computed from
        # debug_enabled_at so a server stuck in maintenance for days stands out.
        maint_banner_html = ""
        if st == "approved" and bool(s.debug_mode):
            staleness = ""
            _dea = getattr(s, "debug_enabled_at", None)
            if _dea is not None:
                import datetime as _dt
                try:
                    _dea_dt = _dea if isinstance(_dea, _dt.datetime) else _dt.datetime.fromisoformat(str(_dea))
                    _days = (_dt.datetime.utcnow() - _dea_dt.replace(tzinfo=None)).total_seconds() / 86400
                    if _days >= 1:
                        staleness = f' &middot; in maintenance {int(_days)}d'
                except Exception:
                    staleness = ""
            _vr = getattr(s, "verification_report", None)
            if isinstance(_vr, str):
                try:
                    _vr = json.loads(_vr)
                except (TypeError, ValueError):
                    _vr = None
            verify_note = ""
            if isinstance(_vr, dict):
                if _vr.get("invocation_probe_ok"):
                    verify_note = ' <span  class="u93">&#x2713; last verification passed</span>'
                elif _vr.get("healthcheck") is False:
                    verify_note = ' <span  class="u94">&#x2717; last verification failed — see logs</span>'

            # Auto-flagged vs admin-enabled maintenance: debug_enabled_by is set
            # to this sentinel only by invocation.py's connection-health tracker
            # (N consecutive connection-class failures — unreachable upstream,
            # DNS/SSRF revalidation failure, MCP handshake failure, or the
            # upstream tool itself reporting isError:true), never by a human
            # admin action, so it's unambiguous. Render distinctly (red, "doesn't
            # work") rather than the neutral "an admin is debugging this" banner.
            _auto_flagged = (getattr(s, "debug_enabled_by", None) == "system:auto-health-check")
            if _auto_flagged:
                _last_err = getattr(s, "last_connection_error", None)
                _fail_count = getattr(s, "connection_failure_count", 0) or 0
                maint_banner_html = f"""
                <div class="srv-maint-banner u95" >
                  <span  class="u96">&#x274C; Doesn't work — auto-flagged{esc_py(staleness)}</span>
                  <span  class="u97">
                    {esc_py(_fail_count)} consecutive connection failure{"s" if _fail_count != 1 else ""}
                    {(" — " + esc_py(_last_err)) if _last_err else ""}
                  </span>
                  <div  class="u98">
                    <button class="btn-secondary u99"  data-act="adminViewLogs" data-a0="{sid}">View logs</button>
                    <button class="btn-secondary u99"  data-act="adminVerifySrv" data-a0="{sid}">Retry verification</button>
                    <button class="btn-primary u99"  data-act="adminToggleDebug" data-json="[&quot;{sid}&quot;, false]">Go live</button>
                  </div>
                </div>"""
            else:
                maint_banner_html = f"""
                <div class="srv-maint-banner u100" >
                  <span  class="u101">&#x1F527; In maintenance{esc_py(staleness)}</span>
                  <span  class="u102">Verify (view logs / retry verification), then go live.{verify_note}</span>
                  <div  class="u98">
                    <button class="btn-secondary u99"  data-act="adminViewLogs" data-a0="{sid}">View logs</button>
                    <button class="btn-secondary u99"  data-act="adminVerifySrv" data-a0="{sid}">Retry verification</button>
                    <button class="btn-primary u99"  data-act="adminToggleDebug" data-json="[&quot;{sid}&quot;, false]">Go live</button>
                  </div>
                </div>"""

        rows_html.append(f"""
        <div class="srv-card {row_cls}">
          <div class="srv-card-top">
            <span class="srv-card-name">{esc_py(s.name or "")}</span>
            <span class="pill {pill_cls}"><span class="pill-dot"></span>{pill_label}</span>
          </div>
          <div class="srv-card-meta">{esc_py(s.upstream_url or "—")} &middot; owner: {esc_py(s.owner_sub or "—")}</div>
          <div class="srv-card-badges">
            <span class="mode-chip">{esc_py(mode_label)}</span>{risk_badge}{maint_badge}{public_badge}{attention_link}
            <span class="srv-card-updated">{esc_py(_fmt_time(s.updated_at))}</span>
          </div>
          {maint_banner_html}
          <div class="srv-card-actions">{action_html}</div>
        </div>""")

    rows_block = "".join(rows_html) if rows_html else (
        '<div class="empty-state">No servers registered.</div>'
    )

    return HTMLResponse(f"""
    {attention_html}

    <!-- Toolbar -->
    <div class="srv-toolbar">
      <div class="srv-toolbar-title">Server registry</div>
      <div class="srv-count-chip">{total}</div>
      <div  class="u5"></div>
      <div class="srv-seg-group" id="srv-seg">
        <button class="srv-seg-btn active" data-act="filterSrv" data-self="1" data-a0="">All</button>
        <button class="srv-seg-btn" data-act="filterSrv" data-self="1" data-a0="approved">Approved</button>
        <button class="srv-seg-btn" data-act="filterSrv" data-self="1" data-a0="pending">Pending</button>
        <button class="srv-seg-btn" data-act="filterSrv" data-self="1" data-a0="quarantined">Quarantined</button>
      </div>
      <button class="btn-register-srv" data-act="loadAdminTab" data-a0="submissions">
        <span>+</span>Register server
      </button>
    </div>

    <!-- Card grid -->
    <div class="srv-card-grid">
      {rows_block}
    </div>

    """)


# ---------------------------------------------------------------------------
# Fragment: Admin > Identity (OIDC)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/identity", response_class=HTMLResponse)
async def fragment_admin_identity(request: Request):
    """Admin Identity (OIDC) tab: OIDC provider connection status and config."""
    _require_admin(request)

    oidc_issuer   = os.environ.get("OIDC_ISSUER_URL", "")
    oidc_audience = os.environ.get("OIDC_AUDIENCE", "")
    oidc_client   = os.environ.get("OIDC_CLIENT_ID", "")

    connected = bool(oidc_issuer)
    status_pill = (
        '<span class="pill pill-approved"><span class="pill-dot"></span>Connected</span>'
        if connected else
        '<span class="pill pill-pending"><span class="pill-dot"></span>Not configured</span>'
    )
    status_note = "Discovery document verified" if connected else "Set OIDC_ISSUER_URL to connect"

    rows = [
        ("Issuer URL",   oidc_issuer   or "—"),
        ("Audience",     oidc_audience or "—"),
        ("Client ID",    oidc_client   or "—"),
        ("Algorithm",    "RS256"),
        ("Token type",   "JWT Bearer"),
        ("JWKS caching", "5 min TTL"),
    ]
    rows_html = "".join(f"""
        <div  class="u103">
          <div  class="u104">{esc_py(k)}</div>
          <div  class="u105">{esc_py(v)}</div>
        </div>""" for k, v in rows)

    return HTMLResponse(f"""
    <!-- Connection status band -->
    <div class="conn-band{'' if connected else ' is-hidden'}">
      <span  class="u106"></span>
      <div  class="u107">
        Connected to <strong  class="u108">Keycloak</strong>
        · {status_note}
      </div>
      {status_pill}
    </div>

    <div  class="u109">OIDC configuration</div>

    <!-- Config table -->
    <div class="srv-tbl">
      {rows_html}
    </div>

    <div  class="u110">
      <button class="btn-register-srv u111" 
              data-act="toggleEl" data-a0="oidc-reconfig-note">Reconfigure</button>
      <button  class="u112"
              data-act="toggleEl" data-a0="oidc-reconfig-note">Test connection</button>
    </div>
    <div id="oidc-reconfig-note"  class="u113">
      OIDC reconfiguration is applied via environment variables on the proxy container.<br>
      Restart the proxy after changing these values:
      <ul  class="u114">
        <li><code  class="u61">OIDC_ISSUER_URL</code> — discovery endpoint (e.g. <code>https://keycloak/realms/mcp</code>)</li>
        <li><code  class="u61">OIDC_AUDIENCE</code> — expected <code>aud</code> claim in access tokens</li>
        <li><code  class="u61">OIDC_CLIENT_ID</code> — client registered in the IdP</li>
      </ul>
    </div>
    """)


# ---------------------------------------------------------------------------
# Fragment: Admin > Request Limits
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/limits", response_class=HTMLResponse)
async def fragment_admin_limits(request: Request):
    """Admin Request Limits tab: per-client rate limit and anomaly controls."""
    _require_admin(request)
    return HTMLResponse("""
<div id="limits-root">
  <div  class="u115">
    <div  class="u116">Request Limits</div>
    <button class="btn-primary btn-sm" data-act="limitsRefresh">&#x21BB; Refresh</button>
  </div>

  <div id="limits-table-wrap">
    <div class="loading-state"><span class="spinner"></span> Loading…</div>
  </div>

  <!-- Edit drawer -->
  <div id="limits-drawer"  class="u117">
    <div  class="u118">
      Edit limits for <code id="limits-edit-cid"  class="u119"></code>
    </div>
    <div  class="u120">
      <div>
        <label for="limits-edit-rl"  class="u121">Rate limit (req/window)</label>
        <input id="limits-edit-rl" type="number" min="1" max="100000"
                class="u122">
      </div>
      <div>
        <label for="limits-edit-sens"  class="u121">Anomaly sensitivity</label>
        <select id="limits-edit-sens"
                 class="u122">
          <option value="normal">normal</option>
          <option value="lenient">lenient</option>
          <option value="off">off</option>
        </select>
      </div>
    </div>
    <div  class="u123">
      <button class="btn-primary btn-sm" data-act="limitsSave">Save</button>
      <button class="btn-sm u124" data-act="limitsReset" data-a0="both"
              >
        Reset counters
      </button>
      <button class="btn-sm u125" data-act="limitsCloseDrawer"
              >
        Cancel
      </button>
    </div>
    <div id="limits-drawer-msg"  class="u126"></div>
  </div>
</div>

""")


# ---------------------------------------------------------------------------
# Fragment: Admin > Dashboard / Detections (stubs)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/dashboard", response_class=HTMLResponse)
async def fragment_admin_dashboard(request: Request):
    """PRD-0006 R-5: console posture dashboard — 6 KPI tiles + recent detections."""
    _require_admin(request)
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal

    async def _scalar(session, sql, **p):
        try:
            return int((await session.execute(text(sql), p)).scalar() or 0)
        except Exception:
            return 0

    kpis = []
    recent = []
    try:
        async with AsyncSessionLocal() as s:
            total_tools = await _scalar(s, "SELECT count(*) FROM tool_registry WHERE deleted_at IS NULL")
            sbom_cov = await _scalar(s,
                "SELECT count(DISTINCT sr.tool_id) FROM sbom_records sr "
                "JOIN tool_registry t ON t.tool_id = sr.tool_id WHERE t.deleted_at IS NULL")
            awaiting = await _scalar(s,
                "SELECT count(*) FROM server_registry WHERE submission_status='awaiting_review' AND deleted_at IS NULL")
            approved_srv = await _scalar(s,
                "SELECT count(*) FROM server_registry WHERE status='approved' AND deleted_at IS NULL")
            detections_24h = await _scalar(s,
                "SELECT count(*) FROM audit_events WHERE outcome='deny' AND timestamp > now() - interval '24 hours'")
            # recent detections (reason-classified)
            try:
                rows = (await s.execute(text(
                    "SELECT client_id, deny_reasons, timestamp FROM audit_events "
                    "WHERE outcome='deny' ORDER BY timestamp DESC LIMIT 6"))).mappings().all()
                for r in rows:
                    reasons = r["deny_reasons"] or []
                    if isinstance(reasons, str):
                        try:
                            reasons = json.loads(reasons)
                        except Exception:
                            reasons = [reasons]
                    code = (reasons[0] if reasons else "unknown")
                    name, sev = _classify(str(code).split(":")[0] if ":" not in str(code) else str(code))
                    recent.append({"who": r["client_id"] or "—", "name": name, "sev": sev})
            except Exception:
                pass
    except Exception as exc:
        return HTMLResponse(f'<div class="section-title">Security</div>'
                            f'<div  class="u59">Dashboard unavailable: {esc_py(str(exc))}</div>')

    sbom_ok = total_tools > 0 and sbom_cov >= total_tools
    kpis = [
        ("Registered tools", str(total_tools), "server-linked, active", "var(--adm-blue)"),
        ("SBOM coverage", f"{sbom_cov}/{total_tools}", "tools with a signed SBOM",
         "var(--adm-green)" if sbom_ok else "var(--adm-amber)"),
        ("Awaiting review", str(awaiting), "submissions in the queue",
         "var(--adm-amber)" if awaiting else "var(--adm-green)"),
        ("Advisory detections (24h)", str(detections_24h), "deny-path signals",
         "var(--adm-red)" if detections_24h else "var(--adm-green)"),
        ("Approved servers", str(approved_srv), "network-isolated backends", "var(--adm-blue)"),
        ("Policy engine", "deny-by-default", "OPA fail-closed · signed bundle", "var(--adm-purple)"),
    ]
    tiles = "".join(
        f'<div class="kpi fu {_KPI_TONE.get(color, "kpi-tone-blue")}">'
        f'<div class="kpi-label">{esc_py(label)}</div>'
        f'<div class="kpi-num">{esc_py(num)}</div>'
        f'<div class="kpi-sub">{esc_py(sub)}</div></div>'
        for label, num, sub, color in kpis
    )
    _sevcol = {"high": "var(--adm-red)", "medium": "var(--adm-amber)", "low": "var(--adm-dim)"}
    if recent:
        det_items = "".join(
            f'<div  class="u127">'
            f'<span class="sev-dot sev-{esc_py(d["sev"]) if d["sev"] in ("high","medium","low") else "none"}"></span>'
            f'<span  class="u128">{esc_py(d["name"])}</span>'
            f'<span  class="u129">{esc_py(d["who"])}</span>'
            f'</div>' for d in recent)
    else:
        det_items = ('<div  class="u130">'
                     'No recent deny-path detections.</div>')

    return HTMLResponse(f"""
    <div class="kpi-grid u131" >{tiles}</div>
    <div class="fu u132" >
      <div  class="u133">Recent detections</div>
      {det_items}
    </div>
    """)


# ---------------------------------------------------------------------------
# Detection catalogue: raw OPA/invocation reason → (friendly name, severity)
# ---------------------------------------------------------------------------
_DETECTION_MAP: dict[str, tuple[str, str]] = {
    "suspicious_parameter_pattern":      ("Prompt injection in tool arguments",          "high"),
    "suspicious_path_argument":          ("Sensitive-path / traversal in arguments",    "high"),
    "suspicious_url_scheme":             ("Dangerous URL scheme in arguments",           "high"),
    "response_filter_injection":         ("Prompt injection in tool response (screened)","high"),
    "ssrf_blocked":                      ("SSRF / DNS-rebind blocked at invoke",         "high"),
    "client_not_authorized_for_tool":    ("Unauthorized tool access / enumeration",     "medium"),
    "risk_level_exceeds_threshold":      ("Risk-ceiling violation",                     "medium"),
    "tool_quarantined":                  ("Quarantined-tool invocation attempt",        "medium"),
    "tool_deprecated":                   ("Deprecated-tool invocation attempt",         "medium"),
    "anomaly_threshold_exceeded":        ("Behavioural anomaly (burst/off-hours)",      "medium"),
    "meta_tool_role_not_authorized":     ("Meta-tool privilege probing",                "medium"),
    "mcp_disabled_for_profile":          ("Disabled-capability access attempt",         "medium"),
    "function_not_allowed_for_profile":  ("Function not permitted for profile",         "medium"),
    "scan_freshness_stale":              ("Stale supply-chain scan",                    "low"),
}
# Dynamic prefix matches (checked before fallback)
_DETECTION_PREFIXES: list[tuple[str, str, str]] = [
    ("taint_floor:",  "Cross-trust taint block",          "high"),
    ("not_entitled:", "Credential not-entitled",          "low"),
]

def _classify(reason: str) -> tuple[str, str]:
    if reason in _DETECTION_MAP:
        return _DETECTION_MAP[reason]
    for prefix, name, sev in _DETECTION_PREFIXES:
        if reason.startswith(prefix):
            return name, sev
    return reason, "low"  # fallback — new reasons never silently disappear

# Phase 2 thresholds — named constants so they're visible and tunable
_BRUTE_DENY_COUNT   = 10   # denies per client in the brute-force window
_BRUTE_DENY_MINUTES = 15
_SPRAY_TOOL_COUNT   = 5    # distinct tools per client in the spray window
_SPRAY_HOURS        = 1

# Only reason codes come from here — never render params/free text through this path.
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _find_rego_rule(reason_code: str) -> dict[str, Any] | None:
    """
    Read-only lookup: find the `deny contains "<reason_code>" if { ... }` rule
    body for a detection's reason code, so an admin can see exactly what
    fired without leaving the portal or grepping the repo by hand.

    Brace-balanced extraction (not just "next line with a bare '}'") because
    some deny rules contain nested `{...}` (comprehensions, object literals).
    """
    if not _REASON_CODE_RE.match(reason_code):
        return None
    head_re = re.compile(
        r'^\s*(?:deny|allow)\s+contains\s+"' + re.escape(reason_code) + r'"\s+if\s*\{'
    )
    try:
        for path in sorted(_REGO_DIR.glob("*.rego")):
            if path.name.endswith("_test.rego"):
                continue
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                if not head_re.match(line):
                    continue
                depth = line.count("{") - line.count("}")
                end = i
                for j in range(i + 1, len(lines)):
                    depth += lines[j].count("{") - lines[j].count("}")
                    end = j
                    if depth <= 0:
                        break
                return {
                    "found": True,
                    "file": path.name,
                    "line": i + 1,
                    "source": "\n".join(lines[i:end + 1]),
                }
    except OSError as exc:
        logger.warning("policy-rule lookup failed: %s", exc)
        return None
    return None


@router.get("/policy-rule", response_class=JSONResponse)
async def get_policy_rule(reason: str, request: Request):
    """Read-only: source of the OPA rule behind a detection's reason code."""
    _require_admin(request)
    rule = _find_rego_rule(reason)
    if rule is None:
        return JSONResponse({
            "found": False,
            "reason": reason,
            "note": "No matching OPA rule (this detection may come from the response filter "
                    "or the anomaly-pattern scorer, not a policy.rego deny rule).",
        })
    return JSONResponse({**rule, "reason": reason})


@router.get("/fragments/admin/detections", response_class=HTMLResponse)
async def fragment_admin_detections(request: Request, days: int = 7, server_id: str = "", reason: str = ""):
    _require_admin(request)
    days = max(1, min(days, 90))  # clamp to [1, 90]

    # R-7: validate server_id is a real UUID before using it in a query filter —
    # an invalid value degrades to "no filter" rather than a 500.
    server_filter = ""
    try:
        import uuid as _uuid
        if server_id:
            server_filter = str(_uuid.UUID(server_id))
    except ValueError:
        server_filter = ""

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            # A) rollup by OPA reason
            rollup_rows = (await session.execute(text("""
                SELECT reason, count(*) AS n
                FROM audit_events,
                     jsonb_array_elements_text(opa_reasons) AS reason
                WHERE outcome = 'deny'
                  AND event_ts > now() - (interval '1 day' * :days)
                GROUP BY reason
                ORDER BY n DESC
            """), {"days": days})).fetchall()

            # A2) response-filter detections (original_outcome='error')
            rf_row = (await session.execute(text("""
                SELECT count(*) AS n FROM audit_events
                WHERE original_outcome = 'error'
                  AND event_ts > now() - (interval '1 day' * :days)
            """), {"days": days})).fetchone()
            rf_count = rf_row.n if rf_row else 0

            # B) recent detections feed — R-7: attribute via tool_id → server_id
            # (audit_events.tool_id / tool_registry.server_id), never tool_name
            # (ambiguous under UNIQUE(name, version)). tool_id NULL (legacy rows,
            # or tool deleted since) renders as unattributed, never guessed.
            server_name_for_filter = None
            feed_query = """
                SELECT a.event_id, a.event_ts, a.client_id, a.tool_name, a.opa_reasons,
                       a.original_outcome, a.sha256_hash, a.tool_id,
                       t.server_id, s.name AS server_name
                FROM audit_events a
                LEFT JOIN tool_registry t ON t.tool_id = a.tool_id
                LEFT JOIN server_registry s ON s.server_id = t.server_id
                WHERE (a.outcome = 'deny' OR a.original_outcome = 'error')
                  AND a.event_ts > now() - (interval '1 day' * :days)
            """
            feed_params: dict = {"days": days}
            if server_filter:
                feed_query += " AND t.server_id = :server_id"
                feed_params["server_id"] = server_filter
                srow = (await session.execute(
                    text("SELECT name FROM server_registry WHERE server_id = :sid"),
                    {"sid": server_filter},
                )).fetchone()
                server_name_for_filter = srow.name if srow else server_filter
            if reason:
                feed_query += " AND a.opa_reasons ? :reason"
                feed_params["reason"] = reason
            feed_query += " ORDER BY a.event_ts DESC LIMIT 100"
            feed_rows = (await session.execute(text(feed_query), feed_params)).fetchall()

            # P2-T2.1) brute-force: ≥ N denies per client in last M minutes
            brute_rows = (await session.execute(text("""
                SELECT client_id, count(*) AS denies, max(event_ts) AS last_seen
                FROM audit_events
                WHERE outcome = 'deny'
                  AND event_ts > now() - (interval '1 minute' * :mins)
                GROUP BY client_id
                HAVING count(*) >= :threshold
                ORDER BY denies DESC
            """), {"mins": _BRUTE_DENY_MINUTES, "threshold": _BRUTE_DENY_COUNT})).fetchall()

            # P2-T2.2) tool spray: ≥ K distinct unauthorized tools per client in last H hours
            spray_rows = (await session.execute(text("""
                SELECT client_id, count(DISTINCT tool_name) AS tools
                FROM audit_events,
                     jsonb_array_elements_text(opa_reasons) r
                WHERE r = 'client_not_authorized_for_tool'
                  AND event_ts > now() - (interval '1 hour' * :hours)
                GROUP BY client_id
                HAVING count(DISTINCT tool_name) >= :threshold
                ORDER BY tools DESC
            """), {"hours": _SPRAY_HOURS, "threshold": _SPRAY_TOOL_COUNT})).fetchall()

            # P2-T2.3) repeat injection offenders
            inject_rows = (await session.execute(text("""
                SELECT client_id, count(*) AS hits
                FROM audit_events,
                     jsonb_array_elements_text(opa_reasons) r
                WHERE r IN ('suspicious_parameter_pattern','suspicious_path_argument',
                            'suspicious_url_scheme')
                  AND event_ts > now() - (interval '1 day' * :days)
                GROUP BY client_id
                HAVING count(*) > 1
                ORDER BY hits DESC
                LIMIT 20
            """), {"days": days})).fetchall()

    except Exception as exc:
        logger.error("portal admin/detections DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading detections."))

    # --- Build reason→count map ---
    reason_counts: dict[str, int] = {}
    for row in rollup_rows:
        reason_counts[row.reason] = row.n
    if rf_count:
        reason_counts["response_filter_injection"] = rf_count

    # --- Severity summary ---
    sev_totals: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for reason, n in reason_counts.items():
        _, sev = _classify(reason)
        sev_totals[sev] = sev_totals.get(sev, 0) + n
    total_detections = sum(sev_totals.values())

    _sev_colour = {"high": "#f87171", "medium": "#fbbf24", "low": "#60a5fa"}
    _card = ('background:var(--panel,#11161f);border:1px solid var(--border,#222b3a);'
             'border-radius:9px;padding:0.85rem 1rem;flex:1;min-width:120px')
    _num  = "font-size:1.5rem;font-weight:700;line-height:1.1"
    _lbl  = "color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:.04em;margin-top:.2rem"

    def _sev_num(sev: str) -> str:
        c = _sev_colour.get(sev, "#60a5fa")
        return f'{_num};color:{c}'

    # Window toggle
    def _win_btn(d: int, label: str) -> str:
        active = ' active' if d == days else ''
        return (f'<button data-act="htmxGet" data-a0="/portal/fragments/admin/detections?days={d}" '
                f'class="win-btn{active}">{label}</button>')

    summary_html = f"""
    <div  class="u134">
      <span  class="u11">Window:</span>
      {_win_btn(1,'24 h')}{_win_btn(7,'7 d')}{_win_btn(30,'30 d')}
    </div>
    <div  class="u135">
      <div class="kpi-card"><div class="kpi-num">{total_detections}</div><div class="kpi-lbl">Total detections</div></div>
      <div class="kpi-card"><div class="kpi-num sev-high">{sev_totals['high']}</div><div class="kpi-lbl">High severity</div></div>
      <div class="kpi-card"><div class="kpi-num sev-medium">{sev_totals['medium']}</div><div class="kpi-lbl">Medium severity</div></div>
      <div class="kpi-card"><div class="kpi-num sev-low">{sev_totals['low']}</div><div class="kpi-lbl">Low severity</div></div>
    </div>"""

    # --- Top detections breakdown (R-7: rows filter the feed below) ---
    top_rows_html = ""
    for reason_key, n in sorted(reason_counts.items(), key=lambda x: -x[1])[:15]:
        name, sev = _classify(reason_key)
        sev_badge = _badge(sev.upper(), f"badge-risk-{sev}")
        _filter_url = (f"/portal/fragments/admin/detections?days={days}&reason={esc_py(reason_key)}"
                       + (f"&server_id={esc_py(server_filter)}" if server_filter else ""))
        row_active = ' row-active' if reason_key == reason else ''
        top_rows_html += f"""
        <tr class="u-pointer{row_active}" title="Filter feed to this detection"
            data-act="htmxGet" data-a0="{_filter_url}">
          <td>{esc_py(name)}</td>
          <td><span  class="u136">{esc_py(reason_key)}</span></td>
          <td>{sev_badge}</td>
          <td  class="u137">{n}</td>
        </tr>"""

    top_table = f"""
    <div  class="u138">Top detections — last {days}d</div>
    <div class="tbl-wrap u139" >
      <table>
        <thead><tr><th>Detection</th><th>Raw reason</th><th>Severity</th><th  class="u51">Count</th></tr></thead>
        <tbody>{top_rows_html if top_rows_html else '<tr><td colspan="4"  class="u140">No detections in this window.</td></tr>'}</tbody>
      </table>
    </div>""" if reason_counts else f"""
    <div  class="u141">
      No detections in the last {days} day{'s' if days != 1 else ''}. &#x2705;
    </div>"""

    # --- Recent feed (R-7: clickable rows, server attribution, INV-001-safe) ---
    import json as _json
    feed_html_rows = []
    drawer_data: dict[str, dict] = {}
    for row in feed_rows:
        ts = row.event_ts.strftime("%Y-%m-%d %H:%M") if row.event_ts else "—"
        reasons = []
        if row.original_outcome == "error":
            reasons.append(("response_filter_injection", "Prompt injection in response", "high"))
        raw_reasons: list = []
        try:
            raw_reasons = row.opa_reasons if isinstance(row.opa_reasons, list) else (
                _json.loads(row.opa_reasons) if row.opa_reasons else []
            )
        except Exception:
            pass
        for r in raw_reasons:
            name, sev = _classify(str(r))
            reasons.append((str(r), name, sev))
        badges = " ".join(_badge(name[:30], f"badge-risk-{sev}") for _, name, sev in reasons[:3])
        if not badges:
            badges = '<span  class="u142">deny</span>'

        eid = str(row.event_id)
        server_cell = (
            f'<a href="#" data-act="htmxGet" data-pd="1" data-stop="1" '
            f'data-a0="/portal/fragments/admin/detections?days={days}&amp;server_id={esc_py(str(row.server_id))}" '
            f' class="u61">'
            f'{esc_py(row.server_name or "server")}</a>'
        ) if row.server_id else '<span  class="u14">unattributed</span>'

        drawer_data[eid] = {
            "ts": ts,
            "client_id": row.client_id or "—",
            "tool_name": row.tool_name or "—",
            "reasons": [rr[0] for rr in reasons] or ["deny"],
            "digest": row.sha256_hash or "—",
            "server_name": row.server_name,
            "server_id": str(row.server_id) if row.server_id else None,
        }

        feed_html_rows.append(f"""
        <tr  class="u2" data-act="openDetectionDrawer" data-a0="{esc_py(eid)}">
          <td  class="u143">{esc_py(ts)}</td>
          <td  class="u144">{esc_py(row.client_id or "—")}</td>
          <td  class="u145">{esc_py(row.tool_name or "—")}</td>
          <td  class="u145">{server_cell}</td>
          <td>{badges}</td>
        </tr>""")

    filter_pill = ""
    if server_filter or reason:
        parts = []
        if server_name_for_filter:
            parts.append(f"server: {esc_py(server_name_for_filter)}")
        if reason:
            parts.append(f"reason: {esc_py(reason)}")
        filter_pill = f"""
        <div  class="u146">
          Filtered by {' &middot; '.join(parts)}
          <a href="#" data-act="htmxGet" data-pd="1" data-a0="/portal/fragments/admin/detections?days={days}"  class="u147">&times; clear</a>
        </div>"""

    feed_table = f"""
    <div  class="u138">Recent detections</div>
    {filter_pill}
    <div class="tbl-wrap u139" >
      <table>
        <thead><tr><th>Time</th><th>Principal</th><th>Tool</th><th>Server</th><th>Detection(s)</th></tr></thead>
        <tbody>{"".join(feed_html_rows) if feed_html_rows else '<tr><td colspan="5"  class="u140">No recent detections.</td></tr>'}</tbody>
      </table>
    </div>
    <div id="det-drawer"  class="u148">
      <div id="det-drawer-body"  class="u149"></div>
      <div id="det-drawer-rule"  class="u150">
        <div id="det-drawer-rule-hdr"  class="u151"></div>
        <pre id="det-drawer-rule-src"  class="u152"></pre>
      </div>
      <button class="btn-secondary btn-sm u46"  data-act="hideEl" data-a0="det-drawer">Close</button>
    </div>
    <script nonce="{getattr(request.state, 'csp_nonce', '')}">
      // Per-request data (drawer_data) — the only piece of this fragment's
      // JS that can't live in the static bundle. _escHtml/openDetectionDrawer/
      // viewPolicyRule that read this are defined once in portal.js.
      window._detDrawerData = {_json.dumps(drawer_data).replace("</", "<\\/")};
    </script>"""

    # --- Phase 2: Behavioural panel ---
    behav_sections = []

    if brute_rows:
        brows = "".join(
            f'<tr><td  class="u144">{esc_py(r.client_id or "—")}</td>'
            f'<td  class="u153">{r.denies}</td>'
            f'<td  class="u154">{r.last_seen.strftime("%H:%M:%S") if r.last_seen else "—"}</td></tr>'
            for r in brute_rows
        )
        behav_sections.append(f"""
        <div  class="u138">
          Repeated denials <span  class="u155">(≥{_BRUTE_DENY_COUNT} denies / {_BRUTE_DENY_MINUTES} min)</span>
        </div>
        <div class="tbl-wrap u139" >
          <table>
            <thead><tr><th>Principal</th><th  class="u51">Denies</th><th>Last seen</th></tr></thead>
            <tbody>{brows}</tbody>
          </table>
        </div>""")

    if spray_rows:
        srows = "".join(
            f'<tr><td  class="u144">{esc_py(r.client_id or "—")}</td>'
            f'<td  class="u156">{r.tools}</td></tr>'
            for r in spray_rows
        )
        behav_sections.append(f"""
        <div  class="u138">
          Tool spray / enumeration <span  class="u155">(≥{_SPRAY_TOOL_COUNT} distinct tools / {_SPRAY_HOURS}h)</span>
        </div>
        <div class="tbl-wrap u139" >
          <table>
            <thead><tr><th>Principal</th><th  class="u51">Distinct tools</th></tr></thead>
            <tbody>{srows}</tbody>
          </table>
        </div>""")

    if inject_rows:
        irows = "".join(
            f'<tr><td  class="u144">{esc_py(r.client_id or "—")}</td>'
            f'<td  class="u153">{r.hits}</td></tr>'
            for r in inject_rows
        )
        behav_sections.append(f"""
        <div  class="u138">
          Repeat injection offenders <span  class="u155">(last {days}d)</span>
        </div>
        <div class="tbl-wrap u139" >
          <table>
            <thead><tr><th>Principal</th><th  class="u51">Injection hits</th></tr></thead>
            <tbody>{irows}</tbody>
          </table>
        </div>""")

    behav_html = ""
    if behav_sections:
        behav_html = f"""
        <div  class="u157">
          &#x26A0;&#xFE0F; Behavioural detections
        </div>
        {"".join(behav_sections)}"""

    return HTMLResponse(f"""
    <div class="section-title">&#x1F6A8; Detections</div>
    <p  class="u158">
      Security detections from blocked invocations — read from <code>audit_events</code>.
      Raw tool arguments are never stored (INV-001); only hashed digests and deny reasons are shown.
    </p>
    {summary_html}
    {top_table}
    {feed_table}
    {behav_html}""")


# ---------------------------------------------------------------------------
# Fragment: Admin > Tools
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/tools", response_class=HTMLResponse)
async def fragment_admin_tools(request: Request, server_id: Optional[str] = Query(None)):
    """Admin tools management sub-tab. Optional server_id filters to one
    server's tools — the deep link the MCP Servers tab uses so a reviewer
    who sees a disabled/high-risk tool on a server card lands directly on
    the row that needs action instead of a global, unfiltered list."""
    _require_admin(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT t.tool_id, t.name, t.version, t.status, t.risk_level, t.risk_score,
                       t.injection_mode, t.upstream_url, t.tags, t.created_at, s.name AS server_name
                FROM tool_registry t
                LEFT JOIN server_registry s ON s.server_id = t.server_id
                WHERE t.deleted_at IS NULL
                  AND (CAST(:sid AS uuid) IS NULL OR t.server_id = CAST(:sid AS uuid))
                ORDER BY t.name
            """), {"sid": server_id})
            tools = result.fetchall()
    except Exception as exc:
        logger.error("portal admin/tools DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading tools."))

    filter_banner = ""
    if server_id:
        srv_label = esc_py(tools[0].server_name) if tools and tools[0].server_name else server_id
        filter_banner = (
            f'<div  class="u159">'
            f'Filtered to server <strong  class="u13">{srv_label}</strong> &middot; '
            f'<a href="#" data-act="loadAdminTab" data-pd="1" data-a0="tools"  class="u61">'
            f'&times; clear filter</a></div>'
        )

    rows = []
    for t in tools:
        tool_id = str(t.tool_id)
        status = t.status or "unknown"
        risk = (t.risk_level or "low").lower()
        mode = (t.injection_mode or "none").lower()
        if status == "quarantined":
            toggle_label, toggle_action = "Activate", "active"
        elif status == "disabled":
            toggle_label, toggle_action = "Enable", "active"
        else:
            toggle_label, toggle_action = "Quarantine", "quarantined"

        rows.append(f"""
        <tr id="tool-row-{esc_py(tool_id)}">
          <td><strong>{esc_py(t.name or "")}</strong></td>
          <td  class="u14">{esc_py(t.version or "")}</td>
          <td>{_badge(status, f"badge-{status}")}</td>
          <td>{_badge(risk.upper(), f"badge-risk-{risk}")}</td>
          <td  class="u154">{t.risk_score if t.risk_score is not None else "—"}</td>
          <td>{_badge(mode, f"badge-mode-{mode.replace(' ', '_')}")}</td>
          <td  class="u160">{esc_py(t.upstream_url or "—")}</td>
          <td>
            <button class="btn-secondary btn-sm" class="{'status-active-badge' if status == 'active' else ''}"
                    data-act="toggleStatus" data-a0="{esc_py(tool_id)}" data-a1="{esc_py(toggle_action)}">{esc_py(toggle_label)}</button>
          </td>
        </tr>""")

    table_html = f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Name</th><th>Version</th><th>Status</th><th>Risk</th><th>Score</th>
            <th>Injection</th><th>Upstream URL</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>{"".join(rows) if rows else '<tr><td colspan="8"  class="u161">No tools registered.</td></tr>'}</tbody>
      </table>
    </div>"""

    register_form = """
    <hr class="divider">
    <div class="section-title">&#x2795; Register Tool</div>
    <form id="reg-form"  class="u162">
      <div class="row">
        <div>
          <label for="reg-name">Tool Name *</label>
          <input id="reg-name" type="text" name="name" required placeholder="my-tool">
        </div>
        <div>
          <label for="reg-version">Version *</label>
          <input id="reg-version" type="text" name="version" required placeholder="1.0.0">
        </div>
      </div>
      <label for="reg-description">Description</label>
      <input id="reg-description" type="text" name="description" placeholder="What does this tool do?">
      <div class="row u46" >
        <div>
          <label for="reg-upstream-url">Upstream URL *</label>
          <input id="reg-upstream-url" type="url" name="upstream_url" required placeholder="https://tool.internal">
        </div>
        <div>
          <label for="reg-risk-level">Risk Level</label>
          <select id="reg-risk-level" name="risk_level">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>
      <div class="row u46" >
        <div>
          <label for="reg-injection-mode">Injection Mode</label>
          <select id="reg-injection-mode" name="injection_mode">
            <option value="none">None</option>
            <option value="header">Header</option>
            <option value="user">User</option>
            <option value="service">Service</option>
            <option value="service_account">Service Account</option>
            <option value="oauth_user_token">OAuth User Token</option>
          </select>
        </div>
        <div>
          <label for="reg-tags">Tags (comma-separated)</label>
          <input id="reg-tags" type="text" name="tags" placeholder="monitoring, dcim">
        </div>
      </div>
      <div  class="u26">
        <button type="button" class="btn-primary" data-act="registerTool">Register Tool</button>
      </div>
      <div id="reg-msg"></div>
    </form>

    """

    return HTMLResponse(f"""
    <div class="section-title">&#x1F527; Registered Tools <span class="count">{len(tools)}</span></div>
    {filter_banner}
    {table_html}
    {register_form}
    """)


# ---------------------------------------------------------------------------
# Fragment: Admin > Credentials
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/sbom", response_class=HTMLResponse)
async def fragment_admin_sbom(request: Request, q: str = ""):
    """Admin SBOM inventory sub-tab.

    Read-only view over the existing sbom_records + tool_registry. Shows, per
    registered tool: latest SBOM presence, component count, signed status,
    auditor version, and generated_at. Tools missing an SBOM float to the top
    (INV-006: a tool cannot be activated without a signed SBOM). The component
    count is computed in SQL via jsonb_array_length over the stored CycloneDX
    document — no parsing, no new dependency.

    When q is non-empty, runs a JSONB component search instead.
    """
    _require_admin(request)

    q = q.strip()
    search_box_clear = (
        '<button type="button" class="btn-secondary btn-sm" '
        'data-act="loadAdminTab" data-a0="sbom">Clear</button>' if q else ""
    )
    search_box = f"""
    <form  class="u163"
          onsubmit="event.preventDefault();htmx.ajax('GET',
            '/portal/fragments/admin/sbom?q='+encodeURIComponent(this.q.value),
            {{target:'#adm-content',swap:'innerHTML'}})">
      <input name="q" type="text" aria-label="Search components" placeholder="Search components (name or purl)…"
             value="{esc_py(q)}"
              class="u164"/>
      <button type="submit" class="btn-register-srv u165" >Search</button>
      {search_box_clear}
    </form>"""

    # --- Component search mode ---
    if q:
        pat = f"%{q.lower().replace('%', '').replace('_', '')}%"
        try:
            from sqlalchemy import text
            from app.core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                result = await session.execute(text("""
                    SELECT t.tool_id, t.name AS tool_name,
                           comp->>'name' AS comp_name, comp->>'version' AS comp_version,
                           comp->>'type' AS comp_type, comp->>'purl' AS comp_purl
                    FROM tool_registry t
                    JOIN sbom_records sr ON sr.tool_id = t.tool_id
                    JOIN LATERAL jsonb_array_elements(sr.cyclonedx_json->'components') AS comp ON true
                    WHERE t.deleted_at IS NULL
                      AND (lower(comp->>'name') LIKE :pat OR lower(comp->>'purl') LIKE :pat)
                      AND sr.generated_at = (
                          SELECT MAX(sr2.generated_at) FROM sbom_records sr2 WHERE sr2.tool_id = t.tool_id
                      )
                    ORDER BY t.name, comp->>'name'
                    LIMIT 201
                """), {"pat": pat})
                srecs = result.fetchall()
        except Exception as exc:
            logger.error("portal admin/sbom search DB error: %s", exc)
            return HTMLResponse(_error_fragment("Database error searching SBOM components."))

        capped = len(srecs) > 200
        srecs = srecs[:200]
        s_rows = []
        for r in srecs:
            tid = str(r.tool_id)
            s_rows.append(f"""
            <tr>
              <td><strong>{esc_py(r.tool_name or "")}</strong></td>
              <td>{esc_py(r.comp_name or "")}</td>
              <td  class="u14">{esc_py(r.comp_version or "—")}</td>
              <td>{_badge((r.comp_type or "unknown"), "badge-info")}</td>
              <td  class="u166">{esc_py(r.comp_purl or "—")}</td>
            </tr>""")

        cap_note = (
            '<p  class="u167">'
            'Results capped at 200 — refine your search.</p>' if capped else ""
        )
        s_table = f"""
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr><th>Tool</th><th>Component</th><th>Version</th><th>Type</th><th>PURL</th></tr>
            </thead>
            <tbody>{"".join(s_rows) if s_rows else '<tr><td colspan="5"  class="u161">No components matched.</td></tr>'}</tbody>
          </table>
        </div>{cap_note}"""

        return HTMLResponse(f"""
        <div class="section-title">&#x1F4E6; SBOM Component Search</div>
        {search_box}
        {s_table}""")

    # --- Normal inventory mode ---
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT t.tool_id, t.name, t.version, t.status, t.risk_level,
                       t.server_id, sv.name AS server_name,
                       s.component_count, s.signed, s.auditor_version, s.generated_at
                FROM tool_registry t
                LEFT JOIN server_registry sv ON sv.server_id = t.server_id
                LEFT JOIN LATERAL (
                    SELECT COALESCE(jsonb_array_length(sr.cyclonedx_json->'components'), 0)
                               AS component_count,
                           (sr.signature IS NOT NULL
                                AND length(trim(sr.signature)) > 0) AS signed,
                           sr.auditor_version, sr.generated_at
                    FROM sbom_records sr
                    WHERE sr.tool_id = t.tool_id
                    ORDER BY sr.generated_at DESC
                    LIMIT 1
                ) s ON true
                WHERE t.deleted_at IS NULL
                ORDER BY (s.generated_at IS NULL) DESC, t.name
            """))
            recs = result.fetchall()
    except Exception as exc:
        logger.error("portal admin/sbom DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading SBOM inventory."))

    total = len(recs)
    with_sbom = sum(1 for r in recs if r.generated_at is not None)
    missing = total - with_sbom
    total_components = sum((r.component_count or 0) for r in recs)

    rows = []
    servers_seen: dict[str, str] = {}
    for r in recs:
        tool_id = str(r.tool_id)
        risk = (r.risk_level or "low").lower()
        has_sbom = r.generated_at is not None
        server_name = r.server_name or "—"
        if r.server_id:
            servers_seen[str(r.server_id)] = server_name
        if not has_sbom:
            sbom_cell = _badge("MISSING", "badge-risk-high")
            comp_cell = '<span  class="u14">—</span>'
            signed_cell = '<span  class="u14">—</span>'
            ver_cell = '<span  class="u14">—</span>'
            gen_cell = '<span  class="u14">never</span>'
            action_cell = (
                f'<button class="btn-secondary btn-sm sbom-gen-btn" data-tool-id="{esc_py(tool_id)}">'
                f'Generate SBOM</button>'
            )
        else:
            sbom_cell = _badge("PRESENT", "badge-active")
            comp_cell = str(r.component_count if r.component_count is not None else 0)
            signed_cell = (_badge("signed", "badge-active") if r.signed
                           else _badge("UNSIGNED", "badge-risk-high"))
            ver_cell = f'<span  class="u154">{esc_py(r.auditor_version or "—")}</span>'
            gen_cell = f'<span  class="u154">{r.generated_at.strftime("%Y-%m-%d %H:%M")}</span>'
            action_cell = (  # ponytail: htmx.ajax swap — no full-page reload needed
                f'<button class="btn-secondary btn-sm" '
                f'data-act="htmxGet" data-a0="/portal/fragments/admin/sbom/{esc_py(tool_id)}">Components</button>'
                f' <a class="btn-secondary btn-sm" target="_blank" rel="noopener" '
                f'href="/api/v1/tools/{esc_py(tool_id)}/sbom">JSON</a>'
                f' <button class="btn-secondary btn-sm sbom-gen-btn" data-tool-id="{esc_py(tool_id)}">Refresh</button>'
            )

        rows.append(f"""
        <tr>
          <td><strong>{esc_py(r.name or "")}</strong></td>
          <td  class="u14">{esc_py(r.version or "")}</td>
          <td  class="u154">{esc_py(server_name)}</td>
          <td>{_badge((r.status or "unknown"), f"badge-{r.status or 'unknown'}")}</td>
          <td>{_badge(risk.upper(), f"badge-risk-{risk}")}</td>
          <td>{sbom_cell}</td>
          <td  class="u51">{comp_cell}</td>
          <td>{signed_cell}</td>
          <td>{ver_cell}</td>
          <td>{gen_cell}</td>
          <td>{action_cell}</td>
        </tr>""")

    _card = (
        'background:var(--adm-surface);border:1px solid var(--adm-border);'
        'border-radius:12px;padding:15px 18px;flex:1;min-width:150px'
    )
    _num = "font-size:25px;font-weight:800;line-height:1;letter-spacing:-.02em"
    _lbl = "color:var(--adm-muted);font-size:11.5px;margin-top:5px"
    _ok = "color:var(--adm-green)"
    _bad = "color:var(--adm-red)"
    summary = f"""
    <div class="fu u168" >
      <div class="kpi-card"><div class="kpi-num">{total}</div><div class="kpi-lbl">Registered tools</div></div>
      <div class="kpi-card"><div class="kpi-num{' ok' if with_sbom and not missing else ''}">{with_sbom}</div><div class="kpi-lbl">With signed SBOM</div></div>
      <div class="kpi-card"><div class="kpi-num{' bad' if missing else ' ok'}">{missing}</div><div class="kpi-lbl">Missing SBOM</div></div>
      <div class="kpi-card"><div class="kpi-num">{total_components}</div><div class="kpi-lbl">Total components</div></div>
    </div>"""

    table_html = f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Tool</th><th>Version</th><th>Server</th><th>Status</th><th>Risk</th><th>SBOM</th>
            <th  class="u51">Components</th><th>Signature</th>
            <th>Auditor</th><th>Generated</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>{"".join(rows) if rows else '<tr><td colspan="11"  class="u161">No tools registered.</td></tr>'}</tbody>
      </table>
    </div>"""

    server_buttons = "".join(
        f'<button class="btn-secondary btn-sm sbom-gen-server-btn" data-server-id="{esc_py(sid)}">'
        f'Generate for {esc_py(sname)}</button>'
        for sid, sname in sorted(servers_seen.items(), key=lambda kv: kv[1])
    ) or '<span  class="u11">No servers with tools yet.</span>'

    collection_toolbar = f"""
    <div  class="u169">
      <div  class="u170">
        <div  class="u71">
          Most tools here were seeded directly into the registry and never went through
          <code>POST /tools/register</code>'s inline SBOM step — that's why SBOM is MISSING for them.
          Run collection below to generate one now.
        </div>
        <button class="btn-primary btn-sm" id="sbom-gen-all-btn">Generate All (one by one)</button>
      </div>
      <div  class="u171">{server_buttons}</div>
      <div id="sbom-gen-msg"  class="u172"></div>
    </div>"""

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E6; SBOM Inventory</div>
    <p  class="u158">
      Signed CycloneDX SBOMs per registered tool (INV-006). Tools missing an SBOM cannot be activated.
    </p>
    {summary}
    {collection_toolbar}
    {search_box}
    {table_html}""")


# ---------------------------------------------------------------------------
# Fragment: Admin > SBOM > Component drill-down
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/sbom/{tool_id}", response_class=HTMLResponse)
async def fragment_admin_sbom_detail(tool_id: str, request: Request):
    """Per-tool CycloneDX component drill-down."""
    import uuid as _uuid
    _require_admin(request)
    try:
        _uuid.UUID(tool_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid tool_id")

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            row = await session.execute(text("""
                SELECT t.name AS tool_name,
                       sr.cyclonedx_json, sr.generated_at, sr.auditor_version
                FROM tool_registry t
                LEFT JOIN LATERAL (
                    SELECT sr.cyclonedx_json, sr.generated_at, sr.auditor_version
                    FROM sbom_records sr
                    WHERE sr.tool_id = t.tool_id
                    ORDER BY sr.generated_at DESC
                    LIMIT 1
                ) sr ON true
                WHERE t.tool_id = :tid AND t.deleted_at IS NULL
            """), {"tid": tool_id})
            rec = row.fetchone()
    except Exception as exc:
        logger.error("portal admin/sbom detail DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading SBOM detail."))

    if rec is None:
        return HTMLResponse(_error_fragment("Tool not found."))

    back = (
        '<button class="btn-secondary btn-sm u72"  '
        'data-act="loadAdminTab" data-a0="sbom">&#8592; Back to inventory</button>'
    )
    dl_link = (
        f'<a class="btn-secondary btn-sm u72" target="_blank" rel="noopener" '
        f'href="/api/v1/tools/{esc_py(tool_id)}/sbom" >Download JSON</a>'
    )

    tool_name = esc_py(rec.tool_name or tool_id)

    if rec.cyclonedx_json is None:
        return HTMLResponse(f"""
        <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
        {back}
        <p  class="u14">No SBOM found for this tool.</p>""")

    cdx = rec.cyclonedx_json
    components = cdx.get("components", []) if isinstance(cdx, dict) else []

    if not components:
        return HTMLResponse(f"""
        <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
        {back}
        <p  class="u14">SBOM present but components array is empty.</p>""")

    rows = []
    for c in components:
        # licenses: [{license:{id:...}}] or [{expression:...}]
        lic_parts = []
        for lic in (c.get("licenses") or []):
            if "license" in lic:
                lic_parts.append(lic["license"].get("id") or lic["license"].get("name") or "")
            elif "expression" in lic:
                lic_parts.append(lic["expression"])
        lic_str = ", ".join(filter(None, lic_parts)) or "—"
        ctype = (c.get("type") or "unknown").lower()
        # R-9: components sourced from manifest parsing (declared, unresolved
        # — no download/hash) vs. the schema-digest attestation component
        # (which always carries a real SHA-256 `hashes` entry).
        is_declared = any(
            p.get("name") == "mcp:sbom_source" and p.get("value") == "manifest-declared"
            for p in (c.get("properties") or [])
        )
        resolved_badge = (
            _badge("declared, unresolved", "badge-mode-none")
            if is_declared or not c.get("hashes")
            else _badge("attested", "badge-active")
        )
        rows.append(f"""
        <tr>
          <td><strong>{esc_py(c.get('name') or '')}</strong></td>
          <td  class="u14">{esc_py(c.get('version') or '—')}</td>
          <td>{_badge(ctype, "badge-info")}</td>
          <td  class="u166">{esc_py(c.get('purl') or '—')}</td>
          <td  class="u142">{esc_py(lic_str)}</td>
          <td>{resolved_badge}</td>
        </tr>""")

    gen_str = rec.generated_at.strftime("%Y-%m-%d %H:%M") if rec.generated_at else "unknown"
    auditor = esc_py(rec.auditor_version or "—")

    # R-9 empty-state distinction: only the schema-digest attestation
    # component present (len==1) can mean either "no source repo to scan"
    # (no vcs externalReference on that component) or "repo scanned but no
    # requirements.txt/pyproject.toml/package.json found" (has a vcs ref).
    only_attestation_note = ""
    if len(components) == 1:
        has_vcs_ref = any(
            ref.get("type") == "vcs" for ref in (components[0].get("externalReferences") or [])
        )
        only_attestation_note = (
            '<p  class="u173">'
            + ("No dependency manifest (requirements.txt / pyproject.toml / package.json) "
               "found in the source repo — attestation only."
               if has_vcs_ref else
               "Attestation-only — no source repo to scan.")
            + "</p>"
        )

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
    <div  class="u174">
      {back}
      {dl_link}
    </div>
    <p  class="u158">
      {len(components)} component(s) &nbsp;·&nbsp; generated {esc_py(gen_str)} &nbsp;·&nbsp; auditor {auditor}
    </p>
    {only_attestation_note}
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Version</th><th>Type</th><th>PURL</th><th>Licenses</th><th>Provenance</th></tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
      </table>
    </div>""")


@router.get("/fragments/admin/credentials", response_class=HTMLResponse)
async def fragment_admin_credentials(request: Request):
    """Admin credentials sub-tab — card view of tool credential status."""
    _require_admin(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT
                    t.tool_id, t.name, t.version, t.status,
                    t.injection_mode,
                    t.service_name,
                    t.inject_header, t.inject_prefix,
                    COALESCE(s.platform_managed_creds, FALSE) AS platform_managed_creds,
                    EXISTS (
                        SELECT 1 FROM credential_store c
                        WHERE c.tool_id = t.tool_id
                          OR (c.user_sub = '__service__' AND c.service = t.service_name)
                    ) AS has_service_credential
                FROM tool_registry t
                LEFT JOIN server_registry s ON s.server_id = t.server_id
                WHERE t.deleted_at IS NULL
                ORDER BY t.name
            """))
            tools = result.fetchall()
    except Exception as exc:
        logger.error("portal admin/credentials DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading credentials."))

    if not tools:
        return HTMLResponse('<div class="empty-state">No tools registered.</div>')

    cards = []
    for t in tools:
        tool_id = str(t.tool_id)
        mode = (t.injection_mode or "none").lower()
        has_cred = bool(t.has_service_credential)
        cred_status = "enrolled" if has_cred else "not enrolled"
        cred_badge = _badge(cred_status, "badge-enrolled" if has_cred else "badge-not-enrolled")

        if bool(t.platform_managed_creds):
            cred_section = f"""
          <details>
            <summary>Upload / rotate credential</summary>
            <div  class="u46">
              <label for="cred-{esc_py(tool_id)}">Secret</label>
              <input type="password" id="cred-{esc_py(tool_id)}" placeholder="Paste secret" autocomplete="new-password">
              <div class="row u46" >
                <div>
                  <label for="owner-{esc_py(tool_id)}">Owner type</label>
                  <select id="owner-{esc_py(tool_id)}">
                    <option value="service">service</option>
                    <option value="user">user</option>
                  </select>
                </div>
                <div>
                  <label for="mode-{esc_py(tool_id)}">Injection mode</label>
                  <select id="mode-{esc_py(tool_id)}">
                    <option value="none">none</option>
                    <option value="header">header</option>
                    <option value="user">user</option>
                    <option value="service">service</option>
                    <option value="service_account">service_account</option>
                    <option value="oauth_user_token">oauth_user_token</option>
                  </select>
                </div>
              </div>
              <div  class="u175">
                <button class="btn-primary btn-sm" data-act="uploadCred" data-a0="{esc_py(tool_id)}">Upload</button>
                <button class="btn-danger btn-sm" data-act="revokeCred" data-a0="{esc_py(tool_id)}">Revoke</button>
              </div>
              <div id="cred-msg-{esc_py(tool_id)}"></div>
            </div>
          </details>"""
        else:
            cred_section = '<div  class="u176">No credential injection configured for this server.</div>'

        cards.append(f"""
        <div class="tool-card">
          <div class="tool-card-header">
            <div>
              <div class="tool-name">{esc_py(t.name or "")}</div>
              <div class="tool-version">v{esc_py(t.version or "")}</div>
            </div>
            <div  class="u177">
              {_badge(t.status or "unknown", f"badge-{t.status or 'pending'}")}
              {cred_badge}
            </div>
          </div>
          <div  class="u178">
            Mode: {_badge(mode, f"badge-mode-{mode}")}
            &nbsp;|&nbsp;
            Service: <code  class="u61">{esc_py(t.service_name or "—")}</code>
          </div>
          {cred_section}
        </div>""")

    html = f"""
    <div class="section-title">&#x1F511; Credential Status <span class="count">{len(tools)}</span></div>
    <div class="card-grid">{"".join(cards)}</div>
    """
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: Admin > Grants
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/grants", response_class=HTMLResponse)
async def fragment_admin_grants(request: Request):
    """Admin grants editor — view and modify data.json grants."""
    _require_admin(request)

    try:
        data = json.loads(_DATA_JSON.read_text())
    except Exception as exc:
        logger.error("portal admin/grants: cannot read data.json: %s", exc)
        return HTMLResponse(_error_fragment(f"Cannot read data.json: {exc}"))

    grants: dict[str, Any] = data.get("mcp", {}).get("grants", {})

    cards = []
    for client, grant in grants.items():
        tools_val = ", ".join(grant.get("allowed_tools", []))
        tags_val = ", ".join(grant.get("allowed_tags", []))
        max_risk = grant.get("max_risk_level", "high")

        cards.append(f"""
        <div class="grant-card" id="grant-{esc_py(client)}">
          <div class="grant-client">{esc_py(client)}</div>
          <label>Allowed tools (comma-separated)</label>
          <input type="text" id="tools-{esc_py(client)}" value="{esc_py(tools_val)}"
                 placeholder="tool-a, tool-b">
          <div class="row u46" >
            <div>
              <label>Allowed tags</label>
              <input type="text" id="tags-{esc_py(client)}" value="{esc_py(tags_val)}"
                     placeholder="monitoring, dcim">
            </div>
            <div>
              <label>Max risk level</label>
              <select id="risk-{esc_py(client)}">
                <option value="low"      {'selected' if max_risk=='low' else ''}>Low</option>
                <option value="medium"   {'selected' if max_risk=='medium' else ''}>Medium</option>
                <option value="high"     {'selected' if max_risk=='high' else ''}>High</option>
                <option value="critical" {'selected' if max_risk=='critical' else ''}>Critical</option>
              </select>
            </div>
          </div>
        </div>""")

    grants_json_escaped = esc_py(json.dumps(grants, indent=2))

    html = f"""
    <div class="section-title">&#x1F4CB; Grants Editor
      <span class="count">{len(grants)} identities</span>
    </div>
    <p  class="u179">
      Edit grants below then click <strong  class="u13">Save All Grants</strong>.
      OPA will pick up the new <code  class="u61">data.json</code> within ~5 seconds.
    </p>

    <div id="grant-cards">{"".join(cards)}</div>

    <div  class="u180">
      <button class="btn-primary" data-act="saveGrants">Save All Grants</button>
      <button class="btn-secondary" data-act="addClient">+ Add Identity</button>
      <span id="grants-msg"  class="u181"></span>
    </div>

    <hr class="divider">
    <div class="section-title">&#x1F4C4; Raw data.json</div>
    <div class="code-block" id="raw-grants">{grants_json_escaped}</div>

    """
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Action: Save grants
# ---------------------------------------------------------------------------

@router.post("/actions/save-grants")
async def action_save_grants(request: Request):
    """Atomically write updated grants back to data.json."""
    _require_admin(request)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail={"code": "BAD_REQUEST", "message": "Invalid JSON body."})

    new_grants: dict = body.get("grants")
    if not isinstance(new_grants, dict):
        raise HTTPException(status_code=422, detail={"code": "VALIDATION_ERROR", "message": "'grants' must be an object."})

    VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
    ALLOWED_GRANT_KEYS = {"allowed_tools", "allowed_tags", "max_risk_level"}

    # Validate each grant entry — strict schema, no unknown keys
    for client_id, grant in new_grants.items():
        if not isinstance(grant, dict):
            raise HTTPException(
                status_code=422,
                detail={"code": "VALIDATION_ERROR", "message": f"Grant for '{client_id}' must be an object."},
            )
        unknown_keys = set(grant.keys()) - ALLOWED_GRANT_KEYS
        if unknown_keys:
            raise HTTPException(
                status_code=422,
                detail={"code": "VALIDATION_ERROR", "message": f"Grant for '{client_id}' has unknown keys: {sorted(unknown_keys)}."},
            )
        if "allowed_tools" in grant:
            allowed_tools = grant["allowed_tools"]
            if not isinstance(allowed_tools, list) or not all(isinstance(t, str) for t in allowed_tools):
                raise HTTPException(
                    status_code=422,
                    detail={"code": "VALIDATION_ERROR", "message": f"'allowed_tools' for '{client_id}' must be a list of strings."},
                )
        if "allowed_tags" in grant:
            allowed_tags = grant["allowed_tags"]
            if not isinstance(allowed_tags, list) or not all(isinstance(t, str) for t in allowed_tags):
                raise HTTPException(
                    status_code=422,
                    detail={"code": "VALIDATION_ERROR", "message": f"'allowed_tags' for '{client_id}' must be a list of strings."},
                )
        if "max_risk_level" in grant and grant["max_risk_level"] not in VALID_RISK_LEVELS:
            raise HTTPException(
                status_code=422,
                detail={"code": "VALIDATION_ERROR", "message": f"'max_risk_level' for '{client_id}' must be one of {sorted(VALID_RISK_LEVELS)}."},
            )

    # Read current data.json to preserve non-grants keys
    try:
        current = json.loads(_DATA_JSON.read_text())
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"code": "READ_ERROR", "message": f"Cannot read data.json: {exc}"},
        )

    # Merge: caller's grants overwrite matching identities; other identities survive untouched
    existing_grants = current.get("mcp", {}).get("grants", {})
    merged_grants = {**existing_grants, **new_grants}
    current.setdefault("mcp", {})["grants"] = merged_grants

    # Atomic write via temp file + rename
    try:
        dir_ = _DATA_JSON.parent
        with tempfile.NamedTemporaryFile(
            mode="w", dir=dir_, suffix=".tmp", delete=False, encoding="utf-8"
        ) as tf:
            json.dump(current, tf, indent=2)
            tf.flush()
            os.fsync(tf.fileno())
            tmp_path = tf.name
        os.replace(tmp_path, _DATA_JSON)
    except Exception as exc:
        logger.error("portal save-grants write error: %s", exc)
        raise HTTPException(
            status_code=500,
            detail={"code": "WRITE_ERROR", "message": f"Failed to write data.json: {exc}"},
        )

    logger.info(
        "portal save-grants: merged %d identities (total %d) by %s",
        len(new_grants),
        len(merged_grants),
        _client_id(request),
    )
    return JSONResponse({"ok": True, "identities": len(merged_grants)})


# ---------------------------------------------------------------------------
# Access tab (R-2) — per-principal MCP/tool toggles + API-client grants,
# shown as two honestly-labeled, separately-keyed dimensions (F-2).
# ---------------------------------------------------------------------------

_CROSS_PRINCIPAL_WRITE_ROLES = frozenset({"platform_admin", "profile_service"})


@router.get("/fragments/admin/access", response_class=HTMLResponse)
async def fragment_admin_access(request: Request):
    """Admin Access tab: principals (profile toggles) + API clients (tool grants)."""
    _require_admin(request)
    can_write = any(r in _CROSS_PRINCIPAL_WRITE_ROLES for r in _roles(request))

    try:
        # Reuse the real endpoints in-process rather than an HTTP self-call —
        # consistent with how other routers already import each other directly
        # (e.g. rescan_scheduler → submission_scanner), and avoids the latency/
        # cookie-forwarding fragility of looping a request back through the
        # network stack. Both callees re-check RBAC on this same `request`.
        from app.routers.admin_grants import list_principals, list_grants, list_role_assignments, list_api_keys
        principals = (await list_principals(request)).get("principals", [])
        grants = (await list_grants(request)).get("grants", [])
        roles_resp = await list_role_assignments(request)
        role_assignments = roles_resp.get("assignments", [])
        valid_roles = roles_resp.get("valid_roles", [])
        api_keys = (await list_api_keys(request)).get("keys", [])
    except Exception as exc:
        logger.error("portal admin/access load error: %s", exc)
        return HTMLResponse(_error_fragment("Could not load access data."))

    write_note = "" if can_write else """
    <div class="helper-box u72" >
      &#x26A0; You have <code>admin</code> but not <code>platform_admin</code> —
      you can view access but cannot change another principal's profile (IDOR-005 guard).
      Toggles are self-service-only for your own identity.
    </div>"""

    # RBAC role management now lives in-platform (below) — role_assignments is
    # append-only (INV-011/V050), so grant/revoke are INSERT-only events, never
    # UPDATE/DELETE. KC-sourced roles still resync on every login (oidc_browser.py),
    # so revoking one here only sticks if it's also removed in Keycloak.
    # Keycloak has KC_HOSTNAME_STRICT=true pinned to LAB_GATEWAY_URL (this
    # gateway's own origin) — hitting the admin console on Keycloak's directly
    # -exposed port (8082) fails strict-hostname validation and hangs forever
    # on "Loading the Admin UI". The gateway now proxies /admin/mcp|master|realms/
    # through to Keycloak (mcp-proxy-lab.conf) under the origin it actually
    # expects, so the console link must point at the gateway, not port 8082.
    role_admin_link = ""
    oidc_issuer = os.environ.get("OIDC_ISSUER_URL", "")
    if "/realms/" in oidc_issuer:
        kc_base, _, kc_realm = oidc_issuer.partition("/realms/")
        kc_realm = kc_realm.strip("/")
        console_url = f"{kc_base}/admin/{kc_realm}/console/#/{kc_realm}/users"
        role_admin_link = f"""
        <a href="{esc_py(console_url)}" target="_blank" rel="noopener noreferrer"
           class="btn-secondary btn-sm u182" >
          Manage roles in Keycloak &#x2197;
        </a>"""

    # One unified block per principal: identity + roles (grant/revoke inline,
    # no more separate table + scroll-to-form hack) + MCP/tool access, all in
    # one place — replaces the previously-separate "RBAC role assignments" /
    # "Principals" sections that made it unclear where to actually manage
    # someone (e.g. "make carol admin").
    roles_by_pid: dict[str, list[dict]] = {}
    for a in role_assignments:
        roles_by_pid.setdefault(a["client_id"], []).append(a)

    principal_rows = []
    for p in principals:
        pid = p["principal"]
        my_roles = roles_by_pid.get(pid, [])
        chip_items = []
        for a in my_roles:
            kc_note = (
                ' <span title="Synced from Keycloak — revoking here only sticks if also '
                'removed there"  class="u183">&#x26A0;</span>'
                if a.get("from_keycloak") else ""
            )
            chip_items.append(
                f'<span class="mode-chip u184" >'
                f'{esc_py(a["role"])}'
                f'<button class="role-x-btn u185" data-client-id="{esc_py(pid)}" data-role="{esc_py(a["role"])}" '
                f'title="Revoke {esc_py(a["role"])}" aria-label="Revoke {esc_py(a["role"])} role from {esc_py(pid)}" '
                f'>&times;</button>{kc_note}</span>'
            )
        roles_html = " ".join(chip_items) or '<span  class="u186">no role</span>'

        held = {a["role"] for a in my_roles}
        addable = [r for r in valid_roles if r not in held]
        add_role_control = (
            f'<select class="role-add-select u187" data-client-id="{esc_py(pid)}" '
            f'>'
            f'{"".join(f"<option value=\"{esc_py(r)}\">{esc_py(r)}</option>" for r in addable)}</select>'
            f'<button class="role-add-btn btn-secondary btn-sm u188" data-client-id="{esc_py(pid)}" '
            f'>+ Add role</button>'
            if addable and can_write
            else ('<span  class="u189">all roles held</span>' if not addable else "")
        )

        last_seen = p.get("last_session_at")
        last_seen_str = last_seen[:16].replace("T", " ") if last_seen else "—"
        principal_rows.append(f"""
        <div class="access-principal-row u190" >
          <div  class="u191">
            <div>
              <div  class="u192">{esc_py(pid)}</div>
              <div  class="u193">
                {roles_html}
                {add_role_control}
              </div>
            </div>
            <div  class="u194">
              <span  class="u195">last session: {esc_py(last_seen_str)}</span>
              <button class="btn-secondary btn-sm"
                      hx-get="/portal/fragments/admin/access/{esc_py(pid)}"
                      hx-target="#access-detail-{esc_py(_slugify(pid))}"
                      hx-swap="innerHTML"
                      data-act="showEl" data-a0="access-detail-{esc_py(_slugify(pid))}">
                Manage MCP &amp; tool access
              </button>
            </div>
          </div>
          <div id="access-detail-{esc_py(_slugify(pid))}"  class="u196"></div>
        </div>""")

    principals_html = "".join(principal_rows) if principal_rows else (
        '<div class="empty-state">No known principals yet (no role assignments, profile rows, or active sessions).</div>'
    )

    grant_rows = []
    for g in grants:
        tools_html = ", ".join(esc_py(t) for t in (g.get("allowed_tools") or [])[:6]) or "—"
        tags_html = ", ".join(esc_py(t) for t in (g.get("allowed_tags") or [])[:6]) or "—"
        grant_rows.append(f"""
        <tr>
          <td  class="u197">{esc_py(g["client_id"])}</td>
          <td  class="u198">{tools_html}</td>
          <td  class="u198">{tags_html}</td>
          <td>{_badge(g.get("max_risk_level", "low").upper(), f"badge-risk-{g.get('max_risk_level', 'low')}")}</td>
          <td  class="u51">
            <button class="btn-secondary btn-sm grant-revoke-btn" data-client-id="{esc_py(g["client_id"])}">Revoke</button>
          </td>
        </tr>""")

    grants_table = f"""
    <div class="tbl-wrap u46" >
      <table>
        <thead><tr><th>client_id</th><th>Allowed tools</th><th>Allowed tags</th><th>Max risk</th><th  class="u51">Action</th></tr></thead>
        <tbody>{"".join(grant_rows) if grant_rows else '<tr><td colspan="5"  class="u140">No client grants configured.</td></tr>'}</tbody>
      </table>
    </div>
    <form id="grant-create-form"  class="u199">
      <div>
        <label for="grant-create-client"  class="u200">client_id</label>
        <input id="grant-create-client" type="text" placeholder="my-service-account" required
                class="u201">
      </div>
      <div>
        <label for="grant-create-tools"  class="u200">Allowed tools (comma-separated, blank = none)</label>
        <input id="grant-create-tools" type="text" placeholder="ping, echo_args"
                class="u202">
      </div>
      <div>
        <label for="grant-create-tags"  class="u200">Allowed tags (comma-separated)</label>
        <input id="grant-create-tags" type="text" placeholder="readonly"
                class="u203">
      </div>
      <div>
        <label for="grant-create-risk"  class="u200">Max risk</label>
        <select id="grant-create-risk"
                 class="u201">
          <option value="low">low</option><option value="medium">medium</option>
          <option value="high">high</option><option value="critical">critical</option>
        </select>
      </div>
      <button type="submit" class="btn-secondary btn-sm">+ Add API client</button>
    </form>
    <div id="grant-create-msg"  class="u204"></div>"""

    # API keys — the actual credential. client_grants above is authorization
    # only (what an already-authenticated client may do); this is what lets a
    # client_id authenticate in the first place. Previously there was no
    # admin endpoint that minted one at all — api_keys was only ever
    # populated by the lab seeder script.
    key_rows = []
    for k in api_keys:
        roles_str = ", ".join(esc_py(r) for r in (k.get("roles") or [])) or "—"
        key_rows.append(f"""
        <tr>
          <td  class="u197">{esc_py(k["client_id"])}</td>
          <td  class="u198">{roles_str}</td>
          <td  class="u71">{k.get("rate_limit_rpm", "—")}/min</td>
          <td  class="u195">{esc_py((k.get("created_at") or "")[:16].replace("T", " "))}</td>
          <td  class="u51">
            <button class="btn-secondary btn-sm apikey-revoke-btn" data-key-id="{esc_py(k["key_id"])}" data-client-id="{esc_py(k["client_id"])}">Revoke</button>
          </td>
        </tr>""")

    valid_roles_options = "".join(f'<option value="{esc_py(r)}" {"selected" if r == "agent" else ""}>{esc_py(r)}</option>' for r in valid_roles)
    api_keys_html = f"""
    <div  class="u205">
      API keys (credentials) <span class="count">{len(api_keys)}</span>
    </div>
    <p  class="u206">
      This is the actual credential — the thing that lets a <code>client_id</code> authenticate at
      all. "API clients" above is authorization only (what an already-authenticated client may do);
      creating a key here also grants the selected roles via RBAC so the new client_id can
      immediately do something.
    </p>
    <div class="tbl-wrap">
      <table>
        <thead><tr><th>client_id</th><th>Roles</th><th>Rate limit</th><th>Created</th><th  class="u51">Action</th></tr></thead>
        <tbody id="apikey-table-body">{"".join(key_rows) if key_rows else '<tr id="apikey-empty-row"><td colspan="5"  class="u140">No API keys issued.</td></tr>'}</tbody>
      </table>
    </div>
    <form id="apikey-create-form"  class="u199">
      <div>
        <label for="apikey-create-client"  class="u200">client_id</label>
        <input id="apikey-create-client" type="text" placeholder="my-new-service" required
                class="u201">
      </div>
      <div>
        <label for="apikey-create-role"  class="u200">Role</label>
        <select id="apikey-create-role"
                 class="u201">
          {valid_roles_options}
        </select>
      </div>
      <div>
        <label for="apikey-create-ratelimit"  class="u200">Rate limit (req/min)</label>
        <input id="apikey-create-ratelimit" type="number" value="120" min="1"
                class="u207">
      </div>
      <button type="submit" class="btn-primary btn-sm">+ Create API key</button>
    </form>
    <div id="apikey-create-result"  class="u172"></div>
    """

    return HTMLResponse(f"""
    <div class="section-title">&#x1F510; Access</div>
    <p  class="u158">
      Effective access to a tool is <strong>entitlement AND profile-enabled</strong> — both layers
      must allow it. Per-server entitlement grant/revoke lives on each server's card in
      <a href="#" data-act="loadAdminTab" data-pd="1" data-a0="servers"  class="u61">MCP Servers</a>.
    </p>
    {write_note}

    <div  class="u208">
      <div  class="u209">
        Principals <span class="count">{len(principals)}</span>
        <span  class="u155">— roles + MCP/tool access, all in one place</span>
      </div>
      {role_admin_link}
    </div>
    <p  class="u210">
      Role_assignments is append-only (INV-011/V050) — grant/revoke are both INSERT-only
      events, never UPDATE/DELETE. Roles synced from Keycloak at login are marked &#x26A0;;
      revoking one here only sticks if it's also removed in Keycloak (otherwise the next
      login re-grants it).
    </p>
    <div  class="u211">
      {principals_html}
    </div>

    <div  class="u205">
      API clients <span class="count">{len(grants)}</span>
    </div>
    <p  class="u206">
      Keyed by OAuth <code>client_id</code> — this is a separate dimension from the principals
      above. The portal's PKCE client is shared by all interactive humans, so a client grant here
      cannot target one specific person.
    </p>
    {grants_table}
    {api_keys_html}
    """)


@router.get("/fragments/admin/access/{principal}", response_class=HTMLResponse)
async def fragment_admin_access_detail(principal: str, request: Request):
    """Per-principal tool toggle list — expands inline under the principal's row."""
    _require_admin(request)
    can_write = principal == _client_id(request) or any(
        r in _CROSS_PRINCIPAL_WRITE_ROLES for r in _roles(request)
    )

    try:
        import json as _json
        from sqlalchemy import text as _sql_text
        from app.core.database import AsyncSessionLocal as _ASL
        from app.routers.profiles import list_profile_mcps
        resp = await list_profile_mcps(principal, request)
        mcps = _json.loads(resp.body).get("mcps", [])

        # Group by server (tool_registry.name is what this legacy "mcp_name"
        # column actually stores — one row per TOOL, not per server — so a
        # flat list here reads as "no per-server structure at all" even
        # though the toggle itself is already per-tool. Grouping fixes that.
        async with _ASL() as session:
            srv_result = await session.execute(_sql_text(
                "SELECT t.name AS tool_name, COALESCE(sv.name, '(no server)') AS server_name "
                "FROM tool_registry t LEFT JOIN server_registry sv ON sv.server_id = t.server_id "
                "WHERE t.deleted_at IS NULL"
            ))
            tool_to_server = {r.tool_name: r.server_name for r in srv_result.fetchall()}
    except Exception as exc:
        logger.error("portal admin/access detail error for %r: %s", principal, exc)
        return HTMLResponse(_error_fragment("Could not load this principal's tool toggles."))

    by_server: dict[str, list] = {}
    for m in mcps:
        server_name = tool_to_server.get(m["mcp_name"], "(no server)")
        by_server.setdefault(server_name, []).append(m)

    group_blocks = []
    for server_name in sorted(by_server):
        rows = []
        for m in by_server[server_name]:
            name = m["mcp_name"]
            enabled = m["enabled"]
            toggle_action = "disable" if enabled else "enable"
            toggle_label = "Disable" if enabled else "Enable"
            state_badge = _badge("enabled" if enabled else "disabled", "badge-enrolled" if enabled else "badge-not-enrolled")
            btn = (
                f'<button class="btn-secondary btn-sm access-toggle-btn" '
                f'data-principal="{esc_py(principal)}" data-mcp="{esc_py(name)}" data-action="{esc_py(toggle_action)}">'
                f'{toggle_label}</button>'
                if can_write else '<span  class="u186">read-only</span>'
            )
            rows.append(f"""
            <tr>
              <td  class="u198">{esc_py(name)}</td>
              <td>{state_badge}</td>
              <td  class="u51">{btn}</td>
            </tr>""")
        group_blocks.append(f"""
        <div  class="u212">
          <div  class="u213">{esc_py(server_name)}</div>
          <div class="tbl-wrap">
            <table>
              <thead><tr><th>Tool</th><th>State</th><th  class="u51">Action</th></tr></thead>
              <tbody>{"".join(rows)}</tbody>
            </table>
          </div>
        </div>""")

    return HTMLResponse(f"""
    {"".join(group_blocks) if group_blocks else '<div  class="u214">No tools registered.</div>'}
    <div id="access-toggle-msg-{esc_py(_slugify(principal))}"  class="u25"></div>
    """)


# ---------------------------------------------------------------------------
# Submissions tab (admin review queue)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/submissions", response_class=HTMLResponse)
async def fragment_admin_submissions(request: Request):
    """Security team review queue — all non-draft submissions."""
    _require_submission_reviewer(request)
    try:
        from collections import defaultdict
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            rows = (await session.execute(text("""
                SELECT server_id, name, owner_sub, submission_status, scan_status,
                       injection_mode, data_categories, has_write_ops,
                       github_repo_url, scan_report, review_notes, updated_at,
                       upstream_idp_config, sbom_components, service_name, upstream_url,
                       description, requested_upstream_url,
                       (sbom_cyclonedx IS NOT NULL) AS has_cyclonedx
                FROM server_registry
                WHERE submission_status NOT IN ('draft')
                  AND deleted_at IS NULL
                ORDER BY
                  CASE submission_status
                    WHEN 'awaiting_review'  THEN 1
                    WHEN 'scan_blocked'     THEN 2
                    WHEN 'changes_requested' THEN 3
                    ELSE 4
                  END, updated_at DESC
            """))).fetchall()

            # R-12: SBOM link needs to know whether this submission's
            # provisioned tool(s) (R-10) have an sbom_records row yet — one
            # extra query for the whole queue rather than N+1.
            sids = [str(r.server_id) for r in rows]
            sbom_by_server: dict[str, list[dict]] = defaultdict(list)
            if sids:
                tool_rows = (await session.execute(text("""
                    SELECT t.server_id, t.tool_id, t.name,
                           EXISTS(SELECT 1 FROM sbom_records sr WHERE sr.tool_id = t.tool_id) AS has_sbom
                    FROM tool_registry t
                    WHERE t.server_id = ANY(CAST(:sids AS uuid[])) AND t.deleted_at IS NULL
                """), {"sids": sids})).fetchall()
                for tr in tool_rows:
                    sbom_by_server[str(tr.server_id)].append(
                        {"tool_id": str(tr.tool_id), "name": tr.name, "has_sbom": bool(tr.has_sbom)}
                    )
    except Exception as exc:
        logger.error("portal admin/submissions DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading submissions."))

    _STATUS_COLOR = {
        "awaiting_review":    ("#2563eb", "Awaiting Review"),
        "scan_blocked":       ("#dc2626", "Scan Blocked"),
        "scan_pending":       ("#6b7280", "Scan Queued"),
        "scan_running":       ("#d97706", "Scanning…"),
        "changes_requested":  ("#d97706", "Changes Requested"),
        "approved_pending_url": ("#16a34a", "Approved — Needs URL"),
        # R-10/F-15: no-code terminal state — never "Active"/"running" language.
        "scaffold_ready":     ("#0891b2", "Approved — Scaffold Only (Not Running)"),
        "rejected":           ("#dc2626", "Rejected"),
        "active":             ("#16a34a", "Active"),
    }
    _SENSE_LABEL = {
        "pii": "PII", "financial": "Financial", "health": "Health",
        "internal_docs": "Internal Docs", "source_code": "Source Code",
        "email_calendar": "Email/Calendar", "infrastructure": "Infrastructure",
        "public": "Public",
    }
    # R-12/F-14: allowlist the exact keys the wizard's _collectModeConfig
    # writes (portal.py renderModeConfig) — never dump upstream_idp_config
    # JSONB verbatim, so an unexpected/stray key (e.g. a future field that
    # accidentally carries a secret reference) can't leak into admin HTML.
    _IDP_CFG_LABELS = {
        "audience": "Target audience",
        "tenant_id": "Tenant ID",
        "client_id": "Client ID",
        "scopes": "Scopes",
        "inject_header": "Header",
        "inject_prefix": "Token prefix",
        "issuer": "Issuer URL",
        "token_url": "Token endpoint",
    }
    _SCAN_TERMINAL = {"passed", "blocked", "error"}

    if not rows:
        empty = '<div  class="u215">No submissions in the queue.</div>'
        return HTMLResponse(f'<div class="section-title">&#x1F4E5; Submissions <span class="count">0</span></div>{empty}')

    cards_html = []
    for r in rows:
        sid = str(r.server_id)
        st = r.submission_status or "draft"
        color, label = _STATUS_COLOR.get(st, ("#6b7280", st.replace("_", " ").title()))
        cats = r.data_categories or []
        cats_html = " ".join(
            f'<span  class="u216">'
            f'{esc_py(_SENSE_LABEL.get(c, c))}</span>'
            for c in cats
        )
        raw_report = r.scan_report if isinstance(r.scan_report, list) else []
        # pip-audit silently no-ops when the repo has no requirements.txt/pyproject.toml
        # (e.g. an npm/Node MCP server) — split that out as an informational note
        # rather than either a red warning or a false "pip-audit ran" claim.
        pip_skip_note = next(
            (f.get("message", "") for f in raw_report if f.get("scanner") == "pip-audit" and f.get("skipped")),
            None,
        )
        scan_findings = [f for f in raw_report if not (f.get("scanner") == "pip-audit" and f.get("skipped"))]
        blocked_count = sum(1 for f in scan_findings if f.get("block"))
        scanners_ran = ["trufflehog", "custom rules", "mcp_checker"] + (["pip-audit"] if pip_skip_note is None else [])
        # R-12: render the scan report for any terminal scan status, not just
        # 'scan_blocked' — a passed scan with zero findings is a fact worth
        # showing a reviewer, not silence.
        scan_html = ""
        if (r.scan_status or "") in _SCAN_TERMINAL:
            if scan_findings:
                items = []
                for f in scan_findings:
                    items.append(
                        f'<div  class="u217">'
                        f'&#x26A0; {esc_py(f.get("scanner",""))} · '
                        f'{esc_py(f.get("file",""))}:{f.get("line",0)} — '
                        f'{esc_py(f.get("message",""))}</div>'
                    )
                scan_html = f'<div  class="u218">{"".join(items[:5])}</div>'
            elif r.scan_status == "passed":
                skip_line = f'<div>{esc_py(pip_skip_note)}</div>' if pip_skip_note else ""
                scan_html = (
                    '<div  class="u219">'
                    f'&#x2713; 0 findings — {len(scanners_ran)} scanners ran ({", ".join(scanners_ran)})'
                    f'{skip_line}'
                    '<div  class="u220">Secrets, known-CVE dependencies, basic patterns, '
                    'and MCP-specific static checks (malicious code, tool poisoning, SSRF, crypto stealers, '
                    'SAST). Static analysis only — human review still required.</div></div>'
                )

        # R-12/F-14: show exactly what will be wired at approval time.
        idp_cfg_html = ""
        raw_cfg = r.upstream_idp_config
        if raw_cfg and not isinstance(raw_cfg, dict):
            try:
                raw_cfg = json.loads(raw_cfg)
            except (TypeError, ValueError):
                raw_cfg = None
        if isinstance(raw_cfg, dict):
            cfg_items = [
                f'<span>{esc_py(label)}: <span  class="u13">{esc_py(raw_cfg[key])}</span></span>'
                for key, label in _IDP_CFG_LABELS.items()
                if raw_cfg.get(key)
            ]
            if cfg_items:
                idp_cfg_html = (
                    '<div  class="u221">{"".join(cfg_items)}</div>'
                )

        # High-risk OAuth scopes (write/admin/mail/files/offline_access, or any
        # wildcard-consent scope like Microsoft Graph's "<resource>/.default")
        # require the reviewer to explicitly acknowledge them — the approve
        # endpoint rejects with 422 OAUTH_POLICY_VIOLATION otherwise (fail-closed,
        # see oauth_policy.validate_requested_config). Surface the requirement
        # here so Approve doesn't silently fail leaving the submission stuck in
        # awaiting_review with no visible reason.
        requested_scopes = list((raw_cfg or {}).get("scopes") or []) if isinstance(raw_cfg, dict) else []
        high_risk_hits = sorted(
            {s for s in requested_scopes if s in HIGH_RISK_SCOPES or _is_wildcard_consent_scope(s)}
        )

        review_action = ""
        if st == "awaiting_review":
            approve_note = (
                '<div  class="u222">'
                '&#x2139; No repository — Approve issues a starter scaffold only. Nothing goes live; '
                'the submitter must build it and resubmit with a repo to actually go live.</div>'
                if not r.github_repo_url else ""
            )
            high_risk_html = ""
            if high_risk_hits:
                high_risk_html = (
                    '<label  class="u223">'
                    f'<input type="checkbox" id="hra-{esc_py(sid)}"> '
                    f'&#x26A0; Requested scope(s) <b>{esc_py(", ".join(high_risk_hits))}</b> are high-risk '
                    '(broad/wildcard access) — check this box to acknowledge and allow Approve to proceed.'
                    '</label>'
                )
            review_action = f"""
            <div  class="u224">
              <textarea id="notes-{esc_py(sid)}" placeholder="Review notes (optional)"
                         class="u225"></textarea>
              <div  class="u226">
                <button class="btn-primary u64" 
                        data-act="reviewAction" data-a0="{esc_py(sid)}" data-a1="approve">Approve</button>
                <button class="btn-secondary u64" 
                        data-act="reviewAction" data-a0="{esc_py(sid)}" data-a1="request-changes">Request Changes</button>
                <button  class="u227"
                        data-act="reviewAction" data-a0="{esc_py(sid)}" data-a1="reject">Reject</button>
              </div>
            </div>
            {high_risk_html}
            {approve_note}"""

        github_link = ""
        if r.github_repo_url:
            # Only render as a link if scheme is https — prevents javascript:/data: XSS
            _safe_repo = r.github_repo_url if str(r.github_repo_url).startswith("https://") else None
            if _safe_repo:
                github_link = (f'<a href="{esc_py(_safe_repo)}" target="_blank" rel="noopener noreferrer" '
                               f' class="u228">&#x1F517; {esc_py(_safe_repo)}</a>')
            else:
                github_link = f'<span  class="u49">&#x26A0; invalid repo URL</span>'

        # R-12: SBOM link gets equal visual weight to the repo link — once R-9
        # (manifest parsing) + R-10 (auto-provisioning) land, an approved
        # submission's tool(s) have sbom_records; before that, say so plainly
        # rather than showing nothing.
        sbom_tools = sbom_by_server.get(sid, [])
        if sbom_tools:
            sbom_links = " · ".join(
                f'<a href="/api/v1/tools/{esc_py(t["tool_id"])}/sbom" target="_blank" rel="noopener noreferrer" '
                f' class="u61">{esc_py(t["name"])}</a>'
                for t in sbom_tools if t["has_sbom"]
            )
            sbom_link = (
                f'<span  class="u198">&#x1F4E6; View SBOM: {sbom_links}</span>' if sbom_links else
                '<span  class="u71">&#x1F4E6; SBOM pending (tool(s) provisioned, not yet generated)</span>'
            )
        else:
            sbom_link = '<span  class="u71">&#x1F4E6; Signed SBOM: not yet provisioned (generated at approval)</span>'

        # R-5: declared-dependency inventory collected at submission time
        # (server_registry.sbom_components, parsed by the scanner). Gives the
        # reviewer a component list immediately, before the signed per-tool SBOM
        # exists. Read-only display; never a gate.
        sbom_components_html = ""
        raw_components = r.sbom_components if isinstance(r.sbom_components, list) else []
        if raw_components:
            by_eco: dict[str, list] = defaultdict(list)
            for c in raw_components:
                purl = str(c.get("purl", ""))
                eco = purl.split(":", 2)[1].split("/", 1)[0] if purl.startswith("pkg:") else "other"
                by_eco[eco].append(c)
            eco_blocks = []
            for eco in sorted(by_eco):
                comps = by_eco[eco]
                items = "".join(
                    f'<div  class="u229">'
                    f'{esc_py(str(c.get("name","")))} '
                    f'<span  class="u14">{esc_py(str(c.get("version","*")))}</span></div>'
                    for c in comps[:40]
                )
                more = f'<div  class="u195">+{len(comps)-40} more</div>' if len(comps) > 40 else ""
                eco_blocks.append(
                    f'<div  class="u230"><div  class="u231">{esc_py(eco)} ({len(comps)})</div>{items}{more}</div>'
                )
            cdx_link = (
                f'<a href="/api/v1/admin/submissions/{esc_py(sid)}/sbom" target="_blank" '
                f'rel="noopener noreferrer"  class="u232">'
                f'&#x2B07; CycloneDX SBOM</a>' if getattr(r, "has_cyclonedx", False) else ''
            )
            sbom_components_html = (
                '<details  class="u233">'
                f'<summary  class="u234">&#x1F4E6; '
                f'Declared dependencies ({len(raw_components)}) — collected at submission{cdx_link}</summary>'
                f'<div  class="u235">{"".join(eco_blocks)}</div></details>'
            )

        scaffold_link = ""
        if st == "scaffold_ready":
            scaffold_link = (
                f'<div  class="u236">'
                f'No-code submission — nothing is running. '
                f'<a href="/api/v1/submissions/{sid}/scaffold"  class="u61">Download scaffold.zip</a> '
                f'(submitter must build, self-host, and submit a new repo-backed submission to go live)</div>'
            )

        cards_html.append(f"""
        <div  class="u237">
          <div  class="u238">
            <div>
              <span  class="u239">{esc_py(r.name)}</span>
              <span  class="u240">by {esc_py(r.owner_sub)}</span>
            </div>
            <span class="chip chip-md {_chip_cls(color)}">{esc_py(label)}</span>
          </div>
          {f'<div  class="u241">{esc_py(r.description)}</div>' if r.description else '<div  class="u242">&#x26A0; No description provided — ask the submitter what this server does before approving.</div>'}
          <div  class="u243">
            <span>Mode: <span  class="u13">{esc_py(r.injection_mode or '—')}</span></span>
            {f'<span>Credential: <span  class="u13">{esc_py(r.service_name)}</span></span>' if r.service_name else ''}
            {f'<span>Backend (live): <span  class="u60">{esc_py(r.upstream_url)}</span></span>' if r.upstream_url else (f'<span>Backend (requested): <span  class="u60">{esc_py(r.requested_upstream_url)}</span></span>' if r.requested_upstream_url else ('<span  class="u14">Backend URL: n/a (no repo yet)</span>' if not r.github_repo_url else '<span  class="u183">&#x26A0; Backend URL: not stated — check the description before approving</span>'))}
            <span>Write ops: <span  class="u13">{'Yes' if r.has_write_ops else 'No'}</span></span>
          </div>
          {f'<div  class="u36">{cats_html}</div>' if cats_html else ''}
          {idp_cfg_html}
          <div  class="u244">
            {github_link}
            {sbom_link}
          </div>
          {sbom_components_html}
          {scaffold_link}
          {scan_html}
          {f'<div  class="u245">Reviewer notes: {esc_py(r.review_notes)}</div>' if r.review_notes else ''}
          {review_action}
        </div>""")

    awaiting = sum(1 for r in rows if r.submission_status == "awaiting_review")
    count_badge = f'{len(rows)} total' + (f' · {awaiting} awaiting review' if awaiting else '')

    # Console funnel: Submit → Scan → Review → Approve (design §4)
    def _fpill(label, tone):
        return f'<span class="fpill fpill-{tone}">{label}</span>'
    _arrow = '<span  class="u246">&#8594;</span>'
    funnel = (
        '<div class="fu u247" >'
        + _fpill("Submit", "blue") + _arrow
        + _fpill("Scan", "amber") + _arrow
        + _fpill("Review", "purple") + _arrow
        + _fpill("Approve", "green") + '</div>'
    )
    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E5; Submissions <span class="count">{count_badge}</span>
      <a href="/docs/admin/submission-review.md" target="_blank" rel="noopener"
          class="u248">
        Reviewer guide &#x2197;
      </a>
      <button class="btn-secondary u198" 
              hx-get="/portal/fragments/admin/submissions" hx-target="#adm-content" hx-swap="innerHTML">
        &#x21BB; Refresh
      </button>
    </div>
    {funnel}
    <div id="submissions-list">{"".join(cards_html)}</div>
    """)


# ---------------------------------------------------------------------------
# Wizard Prompts tab (admin — edit self-service design questions)
# ---------------------------------------------------------------------------

_PROMPT_MODE_LABELS = {
    "kc_token_exchange": "Keycloak token exchange",
    "entra_client_credentials": "Entra app identity",
    "entra_user_token": "Entra delegated (per-user)",
    "service": "Shared service account",
    "user": "Per-user stored token",
    "oauth_user_token": "External OAuth (per-user)",
    "none": "No credential injection",
    "shared": "Shared (all modes)",
}


@router.get("/fragments/admin/prompts", response_class=HTMLResponse)
async def fragment_admin_prompts(request: Request):
    """Edit the self-service wizard's design prompts (what it asks submitters)."""
    _require_admin(request)
    from app.services import prompt_store
    try:
        prompts = await prompt_store.list_prompts()
    except Exception as exc:
        return HTMLResponse(f'<div class="section-title">Wizard Prompts</div>'
                            f'<div  class="u59">Could not load prompts: {esc_py(str(exc))}</div>')

    # Group by mode, in a stable, human order.
    order = list(_PROMPT_MODE_LABELS.keys())
    by_mode: dict[str, list] = {}
    for p in prompts:
        by_mode.setdefault(p["mode"], []).append(p)

    groups_html = []
    for mode in sorted(by_mode, key=lambda m: order.index(m) if m in order else 99):
        rows = []
        for p in by_mode[mode]:
            badge = ('<span  class="u249">overridden</span>'
                     if p["is_override"] else "")
            rows.append(f"""
            <div  class="u250">
              <div  class="u251">
                <code  class="u61">{esc_py(p["id"])}</code>{badge}
              </div>
              <textarea id="pt-{esc_py(p["key"])}"
                         class="u252"
                        >{esc_py(p["text"])}</textarea>
              <div  class="u253">
                <button class="btn-primary u254" 
                        data-act="savePrompt" data-a0="{esc_py(p["key"])}">Save</button>
                <button class="btn-secondary u254" 
                        data-act="resetPrompt" data-a0="{esc_py(p["key"])}">Reset to default</button>
              </div>
            </div>""")
        label = _PROMPT_MODE_LABELS.get(mode, mode)
        groups_html.append(f"""
        <details {"open" if mode == "shared" else ""}  class="u255">
          <summary  class="u256">{esc_py(label)}
            <span  class="u55">· {len(by_mode[mode])} prompts</span></summary>
          {"".join(rows)}
        </details>""")

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4DD; Wizard Prompts</div>
    <p  class="u257">
      These are the design questions the self-service submission wizard asks submitters,
      grouped by auth mode. Edits take effect immediately (no redeploy). "Reset" removes the
      override and restores the built-in default.</p>
    {"".join(groups_html)}
    """)


# ---------------------------------------------------------------------------
# LLM Provider tab (admin — configure the AI auditor endpoint/model/token)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/llm", response_class=HTMLResponse)
async def fragment_admin_llm(request: Request):
    """Configure the LLM provider (base_url/model/timeout/token) used by the auditor."""
    _require_admin(request)
    from app.services import llm_config as _llm_config
    from app.services import platform_secrets as _ps
    try:
        eff = await _llm_config.effective(force=True)
        token_set = await _ps.secret_exists("llm-api")
    except Exception as exc:
        return HTMLResponse(f'<div class="section-title">LLM Provider</div>'
                            f'<div  class="u59">Could not load LLM config: {esc_py(str(exc))}</div>')

    token_state = ('<span  class="u93">set</span>' if token_set
                   else '<span  class="u14">not set (local / unauthenticated)</span>')
    return HTMLResponse(f"""
    <div class="section-title">&#x1F916; LLM Provider</div>
    <p  class="u257">
      Configures the AI auditor (runs at tool <b>registration</b>, never on invoke).
      Overrides the env defaults; a token is stored encrypted and only ever sent as a
      Bearer header. In production, a token-protected endpoint that rejects auth is treated
      as "LLM unavailable" (fails closed if REQUIRE_LLM_AUDIT is on) — never a silent
      unauthenticated call.</p>
    <div  class="u258">
      <label>Base URL<input id="llm-base" value="{esc_py(eff.base_url)}"
         class="u259"></label>
      <label>Model<input id="llm-model" value="{esc_py(eff.model)}"
         class="u259"></label>
      <label>Timeout (seconds)<input id="llm-timeout" type="number" min="1" max="600" value="{eff.timeout_seconds}"
         class="u259"></label>
      <label  class="u20"><input id="llm-enabled" type="checkbox" {"checked" if eff.enabled else ""}> Enabled</label>
      <div  class="u260">
        <button class="btn-primary u261"  data-act="saveLlm">Save settings</button>
        <button class="btn-secondary u261"  data-act="testLlm">Test connection</button>
      </div>
      <hr  class="u262">
      <div>API token: {token_state}</div>
      <label>Set / replace token (write-only)<input id="llm-token" type="password" placeholder="paste token — leave blank to keep current"
         class="u259"></label>
      <div  class="u260">
        <button class="btn-primary u261"  data-act="saveLlmToken">Save token</button>
        <button  class="u263" data-act="delLlmToken">Remove token</button>
      </div>
      <div id="llm-test-out"  class="u71"></div>
    </div>
    """)


# ---------------------------------------------------------------------------
# Git Providers tab (admin — configure github/bitbucket clone sources)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/git", response_class=HTMLResponse)
async def fragment_admin_git(request: Request):
    """Configure git providers (host/account/token/allow_private) for repo cloning."""
    _require_admin(request)
    from app.services import platform_secrets as _ps
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        return HTMLResponse('<div class="section-title">Git Providers</div>'
                            '<div  class="u59">Database unavailable.</div>')
    rows = await pool.fetch(
        "SELECT provider, enabled, host, clone_account, allow_private FROM git_providers ORDER BY provider"
    )
    existing = {r["provider"]: r for r in rows}

    cards = []
    for prov in ("github", "bitbucket"):
        r = existing.get(prov)
        host = esc_py(r["host"] if r else ("github.com" if prov == "github" else ""))
        acct = esc_py((r["clone_account"] if r else "") or "")
        enabled = bool(r["enabled"]) if r else False
        allow_priv = bool(r["allow_private"]) if r else False
        token_set = await _ps.secret_exists(f"git-{prov}")
        token_state = ('<span  class="u93">set</span>' if token_set
                       else '<span  class="u14">not set</span>')
        cards.append(f"""
        <details {"open" if enabled or prov=="bitbucket" else ""}  class="u264">
          <summary  class="u256">{esc_py(prov)}
            <span  class="u55">· {"enabled" if enabled else "disabled"}</span></summary>
          <div  class="u265">
            <label>Host (exact)<input id="git-host-{prov}" value="{host}" placeholder="bitbucket.corp.example"
               class="u259"></label>
            <label>Clone account<input id="git-acct-{prov}" value="{acct}" placeholder="mcp-platform-bot"
               class="u259"></label>
            <label  class="u20"><input id="git-enabled-{prov}" type="checkbox" {"checked" if enabled else ""}> Enabled</label>
            <label  class="u20"><input id="git-priv-{prov}" type="checkbox" {"checked" if allow_priv else ""}>
              Allow private/internal host (RFC1918) — <span  class="u266">widens SSRF surface; audited</span></label>
            <div  class="u260">
              <button class="btn-primary u267"  data-act="saveGit" data-a0="{prov}">Save</button>
            </div>
            <div>Token: {token_state}</div>
            <label>Set token (write-only)<input id="git-token-{prov}" type="password" placeholder="paste clone token"
               class="u259"></label>
            <div  class="u260">
              <button class="btn-primary u267"  data-act="saveGitToken" data-a0="{prov}">Save token</button>
              <button  class="u268" data-act="delGitToken" data-a0="{prov}">Remove token</button>
            </div>
          </div>
        </details>""")

    return HTMLResponse(f"""
    <div class="section-title">&#x1F517; Git Providers</div>
    <p  class="u257">
      Repository hosts the submission scanner may clone from. Provider is inferred from a submission's
      URL host; only an <b>enabled</b>, exact-match host is accepted. Loopback/link-local/cloud-metadata
      hosts are always refused; an internal (RFC1918) corporate host requires the explicit
      "Allow private" acknowledgement. Tokens are stored encrypted and only used as clone credentials.</p>
    {"".join(cards)}
    """)


# ---------------------------------------------------------------------------
# Submit MCP Server wizard (agent-facing, standalone page)
# ---------------------------------------------------------------------------

@router.get("/submit", response_class=HTMLResponse)
async def submit_wizard_page(request: Request):
    """Full-page guided MCP server submission wizard."""
    _require_portal_access(request)
    from app.services.submission_scanner import GITHUB_CLONE_ACCOUNT as _CLONE_ACCT
    cid = _client_id(request)
    initials = "".join(w[0].upper() for w in cid.replace("-", " ").split()[:2]) or "?"

    return HTMLResponse(f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Submit MCP Server · MCP Security Platform</title>
  {_FAVICON_LINK}
  {_FONTS_LINK}
  {_HTMX_TAG}
  <script src="/static/portal.js" defer></script>
  <style>
    {_CSS}
    .wiz-shell {{ max-width: 720px; margin: 0 auto; padding: 2rem 1.5rem; }}
    .wiz-header {{ display:flex; align-items:center; gap:1rem; margin-bottom:2rem; }}
    .wiz-steps {{ display:flex; gap:0; margin-bottom:2rem; }}
    .wiz-step  {{ flex:1; text-align:center; font-size:11px; color:var(--muted);
                  padding:0.4rem 0; border-bottom:2px solid #1e293b; position:relative; }}
    .wiz-step.active  {{ color:var(--blue); border-color:var(--blue); }}
    .wiz-step.done    {{ color:#16a34a;     border-color:#16a34a; }}
    .wiz-card  {{ background:#0f172a; border:1px solid #1e293b; border-radius:12px;
                  padding:1.5rem 2rem; }}
    .wiz-label {{ font-size:12px; color:var(--muted); margin-bottom:0.35rem; display:block; }}
    .wiz-input {{ width:100%; background:#0a0f1e; border:1px solid #334155; border-radius:8px;
                  color:var(--text); padding:0.6rem 0.8rem; font-size:14px; box-sizing:border-box; }}
    .wiz-input:focus {{ outline:none; border-color:var(--blue); }}
    .mode-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:0.75rem; margin-top:0.75rem; }}
    .mode-card {{ background:#0a0f1e; border:1px solid #334155; border-radius:10px;
                  padding:1rem; cursor:pointer; transition:border-color 0.15s; }}
    .mode-card:hover {{ border-color:var(--blue); }}
    .mode-card.selected {{ border-color:var(--blue); background:#0d1f3c; }}
    .mode-card-title {{ font-weight:600; font-size:13px; margin-bottom:0.25rem; }}
    .mode-card-desc  {{ font-size:11px; color:var(--muted); line-height:1.4; }}
    .q-tree  {{ background:#0a0f1e; border:1px solid #334155; border-radius:10px; padding:1.25rem; }}
    .q-text  {{ font-size:14px; font-weight:500; margin-bottom:1rem; }}
    .q-opts  {{ display:flex; flex-direction:column; gap:0.5rem; }}
    .q-btn   {{ background:#1e293b; border:1px solid #334155; border-radius:8px; color:var(--text);
                padding:0.6rem 1rem; text-align:left; cursor:pointer; font-size:13px; transition:border-color 0.15s; }}
    .q-btn:hover {{ border-color:var(--blue); color:var(--blue); }}
    .cat-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:0.5rem; margin-top:0.5rem; }}
    .cat-item {{ display:flex; align-items:center; gap:0.5rem; font-size:13px;
                 background:#0a0f1e; border:1px solid #334155; border-radius:8px; padding:0.5rem 0.75rem;
                 cursor:pointer; }}
    .cat-item.selected {{ border-color:var(--blue); background:#0d1f3c; }}
    .helper-box {{ background:#0a1628; border:1px solid #1e4080; border-radius:8px;
                   padding:0.75rem 1rem; margin-top:0.75rem; font-size:12px; color:#93c5fd; }}
    .rec-box    {{ background:#0a1f0e; border:1px solid #166534; border-radius:10px;
                   padding:1rem 1.25rem; margin-top:1rem; }}
    .rec-mode   {{ font-size:15px; font-weight:700; color:#4ade80; margin-bottom:0.25rem; }}
    .rec-reason {{ font-size:12px; color:var(--muted); }}
    .scan-finding {{ font-size:12px; padding:0.5rem 0.75rem; border-radius:6px;
                     margin-bottom:0.35rem; }}
    .scan-finding.block {{ background:#1a0000; color:#fca5a5; border:1px solid #7f1d1d; }}
    .scan-finding.warn  {{ background:#1a1000; color:#fde68a; border:1px solid #78350f; }}
  </style>
</head>
<body>
<div class="adm-layout u269" >
  <div class="wiz-shell">
    <div class="wiz-header">
      <a href="/portal"  class="u270">&#x2190; Portal</a>
      <span  class="u271">/</span>
      <span  class="u1">Submit MCP Server</span>
      <a href="/docs/user/self-service-onboarding.md" target="_blank" rel="noopener"
          class="u272">Walkthrough docs &#x2197;</a>
    </div>
    <div  class="u273">
      Not sure which auth mode to pick? See the
      <a href="/docs/user/auth-mode-decision-guide.md" target="_blank" rel="noopener"  class="u274">auth-mode decision guide</a>.
    </div>

    <div class="wiz-steps" id="wiz-steps">
      <div class="wiz-step active" id="step-ind-1">1 · Basics</div>
      <div class="wiz-step"        id="step-ind-2">2 · Auth</div>
      <div class="wiz-step"        id="step-ind-3">3 · Data</div>
      <div class="wiz-step"        id="step-ind-4">4 · Review</div>
    </div>

    <div id="wiz-body">
      <!-- Step 1 injected here -->
    </div>
  </div>
</div>

<script nonce="{getattr(request.state, 'csp_nonce', '')}">
// Wizard state — accumulated across steps, submitted in one shot
const _wiz = {{
  name: '', description: '', github_repo_url: null, requested_upstream_url: null,
  injection_mode: null, upstream_idp_type: null, upstream_idp_config: {{}},
  mode_override_reason: null,
  data_categories: [], has_write_ops: false,
  server_id: null,
  // PRD-0012: self-hosted (you run/host the backend, URL required up front)
  // is the default; platform-deploy (we build & deploy it for you) collects
  // no URL — one is assigned once the platform deploys it.
  self_host: true,
}};

const _CLONE_ACCT = '{esc_py(_CLONE_ACCT)}';

// ── Step rendering ────────────────────────────────────────────────────────────

function _setStep(n) {{
  document.querySelectorAll('.wiz-step').forEach((el, i) => {{
    el.classList.remove('active', 'done');
    if (i + 1 < n) el.classList.add('done');
    else if (i + 1 === n) el.classList.add('active');
  }});
}}

function showStep1() {{
  _setStep(1);
  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div  class="u275">Tell us about your server</div>

      <label class="wiz-label" for="s1-name">Server name (slug, e.g. <code  class="u61">my-analytics</code>)</label>
      <input id="s1-name" class="wiz-input" placeholder="my-mcp-server" value="${{_wiz.name}}">

      <label class="wiz-label u48" for="s1-desc" >Short description <span  class="u94">*</span></label>
      <input id="s1-desc" class="wiz-input" placeholder="What does this server do? (required — the reviewer approves based on this)" value="${{_wiz.description}}">

      <label class="wiz-label u276" >Where will this run?</label>
      <div class="mode-grid u36" >
        <div class="mode-card ${{_wiz.self_host ? 'selected' : ''}}" id="hosting-self" data-act="pickHosting" data-json="[true]">
          <div class="mode-card-title">I&rsquo;ll self-host it</div>
          <div class="mode-card-desc">You run the backend yourself. You give us the URL now; a reviewer verifies it before it goes live.</div>
        </div>
        <div class="mode-card ${{_wiz.self_host ? '' : 'selected'}}" id="hosting-platform" data-act="pickHosting" data-json="[false]">
          <div class="mode-card-title">Deploy it for me</div>
          <div class="mode-card-desc">The platform builds and hosts it from your repo. No backend URL needed — one is assigned once it's deployed.</div>
        </div>
      </div>

      <label class="wiz-label u276" for="s1-repo" >GitHub repository URL<span id="s1-repo-req" class="req-star${{_wiz.self_host ? ' is-hidden' : ''}}"> *</span></label>
      <input id="s1-repo" class="wiz-input" placeholder="https://github.com/your-org/your-repo"
             value="${{_wiz.github_repo_url || ''}}">
      <div class="helper-box u4" id="clone-helper" >
        &#x1F511; The platform will clone your repository using the account
        <strong  class="u13">${{_CLONE_ACCT}}</strong>.<br>
        Grant this account <strong>read access</strong> to your repository before submitting.
      </div>

      <div id="s1-backend-url-wrap" class="${{_wiz.self_host ? '' : 'is-hidden'}}">
        <label class="wiz-label u48" for="s1-backend-url" >Backend URL (where does/will this run?) <span  class="u94">*</span></label>
        <input id="s1-backend-url" class="wiz-input" placeholder="https://your-server.example.com/mcp"
               value="${{_wiz.requested_upstream_url || ''}}">
        <div  class="u277">
          Required for self-hosted servers — a reviewer cannot approve a server they can't locate. Informational only at
          this stage (not validated yet); you'll confirm the live, verified URL after approval.
          No backend at all yet? Don't submit — call get_server_scaffold instead, no review needed for that.
        </div>

        <label  class="u278">
          <input type="checkbox" id="s1-nocode" onchange="toggleNoCode(this)"> I don&rsquo;t have a repo yet (backend already running elsewhere)
        </label>
      </div>

      <div  class="u279">
        <button class="btn-primary" data-act="submitStep1">Next &#x2192;</button>
      </div>
    </div>`;

  document.getElementById('s1-repo').addEventListener('input', e => {{
    document.getElementById('clone-helper').style.display = e.target.value.trim() ? '' : 'none';
  }});
  if (_wiz.github_repo_url) document.getElementById('clone-helper').style.display = '';
}}

function pickHosting(selfHost) {{
  _wiz.self_host = selfHost;
  document.getElementById('hosting-self').classList.toggle('selected', selfHost);
  document.getElementById('hosting-platform').classList.toggle('selected', !selfHost);
  document.getElementById('s1-backend-url-wrap').style.display = selfHost ? 'block' : 'none';
  document.getElementById('s1-repo-req').style.display = selfHost ? 'none' : 'inline';
  if (!selfHost) {{
    // Platform-deploy always needs a repo to build from; the no-code path
    // (backend already running elsewhere) only applies to self-hosting.
    const nocode = document.getElementById('s1-nocode');
    if (nocode) {{ nocode.checked = false; toggleNoCode(nocode); }}
  }}
}}

function toggleNoCode(cb) {{
  const repoField = document.getElementById('s1-repo');
  repoField.disabled = cb.checked;
  if (cb.checked) {{ repoField.value = ''; _wiz.github_repo_url = null; }}
  document.getElementById('clone-helper').style.display = 'none';
}}

function submitStep1() {{
  const name = document.getElementById('s1-name').value.trim().toLowerCase();
  const desc = document.getElementById('s1-desc').value.trim();
  const repo = document.getElementById('s1-repo').value.trim();
  const selfHost = _wiz.self_host;
  const backendUrl = selfHost ? document.getElementById('s1-backend-url').value.trim() : '';
  const nocode = selfHost && document.getElementById('s1-nocode')?.checked;
  if (!name) {{ toast('Server name is required', 'error'); return; }}
  if (!/^[a-z0-9][a-z0-9\\-]{{1,62}}$/.test(name)) {{
    toast('Name must be 2-63 chars, lowercase letters, numbers, and hyphens only', 'error'); return;
  }}
  if (!desc) {{ toast('Description is required — the reviewer approves your server based on this.', 'error'); return; }}
  if (selfHost && !backendUrl) {{
    toast('Backend URL is required — a reviewer cannot approve a server they can\\'t locate. No backend yet? Use "Get scaffold" from the self-service tools instead of this wizard.', 'error'); return;
  }}
  if (!selfHost && !repo) {{
    toast('A GitHub repository URL is required for the platform to build and deploy your server.', 'error'); return;
  }}
  _wiz.name = name;
  _wiz.description = desc;
  _wiz.github_repo_url = (nocode || !repo) ? null : repo;
  _wiz.requested_upstream_url = selfHost ? backendUrl : null;
  showStep2();
}}

// ── Step 2: Auth ─────────────────────────────────────────────────────────────

const _MODE_CARDS = [
  {{ id:'kc_token_exchange',       title:'Same IdP', desc:'Token exchange — no secret stored. Full per-user attribution. Best for internal services.' }},
  {{ id:'entra_client_credentials', title:'External IdP — Machine', desc:'Microsoft Entra client credentials. App identity, no per-user attribution in upstream.' }},
  {{ id:'entra_user_token',         title:'External IdP — Delegated', desc:'Microsoft Entra per-user delegated token. Full per-user attribution via Entra.' }},
  {{ id:'service',                  title:'Service account', desc:'One shared credential injected for all callers. Attribution at gateway level only.' }},
  {{ id:'user',                     title:'Per-user stored token', desc:'Each user enrolls their own credential. Full per-user attribution in the upstream system.' }},
  {{ id:'none',                     title:'No auth', desc:'No credential injected. Server is public or handles its own auth within the trust boundary.' }},
];

const _MODE_RECOMMEND = {{
  kc_token_exchange:        'Same-IdP token exchange. No secret at rest. Full attribution.',
  entra_client_credentials: 'Entra machine identity (app-only). Attribution at gateway only.',
  entra_user_token:         'Entra delegated token. Full per-user attribution in Entra.',
  service:                  'Shared service account. Attribution at gateway level only.',
  service_account:          'Shared OAuth service account. Attribution at gateway level only.',
  user:                     'Per-user stored token. Full attribution. Users enroll their own credentials.',
  oauth_user_token:         'Per-user OAuth token from external IdP. Full per-user attribution.',
  none:                     'No credential injection.',
}};

function showStep2() {{
  _setStep(2);
  const cards = _MODE_CARDS.map(m => `
    <div class="mode-card ${{_wiz.injection_mode === m.id ? 'selected' : ''}}"
         id="mc-${{m.id}}" data-act="pickMode" data-a0="${{m.id}}">
      <div class="mode-card-title">${{m.title}}</div>
      <div class="mode-card-desc">${{m.desc}}</div>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div  class="u280">How does your server authenticate?</div>
      <div  class="u281">
        Pick a mode directly, or
        <button  class="u282"
                data-act="showGuidedQuestions">help me choose &#x25BC;</button>
      </div>

      <div class="mode-grid">${{cards}}</div>

      <div id="mode-config"  class="u276"></div>

      <div  class="u283">
        <button class="btn-secondary" data-act="showStep1">&#x2190; Back</button>
        <button class="btn-primary" data-act="submitStep2">Next &#x2192;</button>
      </div>
    </div>
    <div id="guided-panel"  class="u48"></div>`;

  if (_wiz.injection_mode) renderModeConfig(_wiz.injection_mode);
}}

function pickMode(mode) {{
  _wiz.injection_mode = mode;
  _wiz.mode_override_reason = null;
  document.querySelectorAll('.mode-card').forEach(c => c.classList.remove('selected'));
  document.getElementById('mc-' + mode)?.classList.add('selected');
  document.getElementById('guided-panel').innerHTML = '';
  renderModeConfig(mode);
}}

function renderModeConfig(mode) {{
  const _snippet = (title, code) => `
    <details  class="u284">
      <summary  class="u285">${{title}}</summary>
      <pre  class="u286">${{code}}</pre>
    </details>`;

  const extras = {{
    kc_token_exchange: `
      <label class="wiz-label u48" for="cfg-audience" >Target audience (service name)</label>
      <input class="wiz-input" id="cfg-audience" placeholder="lab-tickets"
             value="${{(_wiz.upstream_idp_config||{{}}).audience||''}}">
      ${{_snippet('What your server needs to implement',
`# The gateway forwards the caller's Keycloak token.
# Validate it at your service's Keycloak realm:
import httpx

async def get_caller(authorization: str):
    r = await httpx.get(
        "https://keycloak.example.com/realms/mcp"
        "/protocol/openid-connect/userinfo",
        headers={{"Authorization": authorization}},
    )
    r.raise_for_status()
    return r.json()  # {{"sub": "alice", "email": ...}}`
      )}}`,

    entra_client_credentials: `
      <label class="wiz-label u48" for="cfg-tenant" >Tenant ID</label>
      <input class="wiz-input" id="cfg-tenant" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
             value="${{(_wiz.upstream_idp_config||{{}}).tenant_id||''}}">
      <label class="wiz-label u26" for="cfg-client" >Client ID</label>
      <input class="wiz-input" id="cfg-client" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
             value="${{(_wiz.upstream_idp_config||{{}}).client_id||''}}">
      <div class="helper-box u46" >
        &#x1F512; Client secret is uploaded separately after approval via the Credentials tab.
      </div>
      ${{_snippet('What your server needs to implement',
`# The gateway injects an Entra app-only access token.
# Your server receives it in the Authorization header:
from fastapi import Header, HTTPException
import httpx

async def verify_token(authorization: str = Header()):
    # Validate with Microsoft Graph
    r = await httpx.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={{"Authorization": authorization}},
    )
    if r.status_code == 401:
        raise HTTPException(401, "Invalid token")
    return r.json()`
      )}}`,

    entra_user_token: `
      <label class="wiz-label u48" for="cfg-tenant" >Tenant ID</label>
      <input class="wiz-input" id="cfg-tenant" value="${{(_wiz.upstream_idp_config||{{}}).tenant_id||''}}">
      <label class="wiz-label u26" for="cfg-scopes" >Required scopes (space-separated)</label>
      <input class="wiz-input" id="cfg-scopes" placeholder="User.Read Mail.Read"
             value="${{(_wiz.upstream_idp_config||{{}}).scopes||''}}">
      ${{_snippet('What your server needs to implement',
`# The gateway injects each user's delegated Entra token.
# Your server receives it as a Bearer token:
from fastapi import Header
import httpx

async def my_tool(authorization: str = Header()):
    # Call Microsoft Graph on behalf of the user
    r = await httpx.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={{"Authorization": authorization}},
    )
    return r.json()`
      )}}`,

    service: `
      <label class="wiz-label u48" for="cfg-header" >Header your server reads</label>
      <input class="wiz-input" id="cfg-header" placeholder="Authorization"
             value="${{(_wiz.upstream_idp_config||{{}}).inject_header||'Authorization'}}">
      <label class="wiz-label u26" for="cfg-prefix" >Token prefix (e.g. Bearer, Token)</label>
      <input class="wiz-input" id="cfg-prefix" placeholder="Bearer"
             value="${{(_wiz.upstream_idp_config||{{}}).inject_prefix||'Bearer'}}">
      ${{_snippet('What your server needs to implement',
`# The gateway injects a shared service credential.
# Read it from the header you configured above:
from fastapi import Header

async def my_tool(authorization: str = Header()):
    # authorization == "Bearer <your-service-token>"
    # Use it to call your downstream API
    pass

# Environment variable your server needs (set via Credentials tab):
# SERVICE_TOKEN=<value>  (platform injects it; never hardcode)`
      )}}`,

    user: `
      <label class="wiz-label u48" for="cfg-header" >Header your server reads</label>
      <input class="wiz-input" id="cfg-header" placeholder="Authorization"
             value="${{(_wiz.upstream_idp_config||{{}}).inject_header||'Authorization'}}">
      ${{_snippet('What your server needs to implement',
`# Each user stores their own credential via the portal.
# The gateway injects it into every request for that user:
from fastapi import Header

async def my_tool(authorization: str = Header()):
    # authorization == "Bearer <this-user-specific-token>"
    # Full per-user attribution in your upstream system
    pass

# Users enroll their credentials at: /portal → Credentials tab`
      )}}`,

    oauth_user_token: `
      <label class="wiz-label u48" for="cfg-issuer" >External IdP issuer URL</label>
      <input class="wiz-input" id="cfg-issuer" placeholder="https://idp.example.com"
             value="${{(_wiz.upstream_idp_config||{{}}).issuer||''}}">
      <label class="wiz-label u26" for="cfg-client" >Client ID</label>
      <input class="wiz-input" id="cfg-client" value="${{(_wiz.upstream_idp_config||{{}}).client_id||''}}">
      ${{_snippet('What your server needs to implement',
`# The gateway fetches and injects a per-user OAuth token
# from your external IdP. Your server validates it:
from fastapi import Header
import httpx

async def my_tool(authorization: str = Header()):
    # Validate token with your IdP's introspection endpoint
    r = await httpx.post(
        "https://idp.example.com/oauth2/introspect",
        data={{"token": authorization.removeprefix("Bearer ")}},
    )
    assert r.json().get("active"), "Token inactive"`
      )}}`,

    none: `
      ${{_snippet('What your server needs to implement',
`# No credential is injected — your server is open
# within the platform trust boundary, or handles
# its own authentication internally.
#
# The platform still enforces:
#   - OPA policy (entitlements)
#   - Rate limits and anomaly detection
#   - Full audit trail
#
# No extra code needed for auth. Just build your tools.`
      )}}`,

    service_account: `
      <label class="wiz-label u48" for="cfg-tokenurl" >OAuth token endpoint</label>
      <input class="wiz-input" id="cfg-tokenurl" value="${{(_wiz.upstream_idp_config||{{}}).token_url||''}}">`,
  }};
  document.getElementById('mode-config').innerHTML = extras[mode] || '';
}}

function _collectModeConfig(mode) {{
  const g = id => document.getElementById(id)?.value?.trim() || '';
  const cfg = {{}};
  if (mode === 'kc_token_exchange')        cfg.audience      = g('cfg-audience');
  if (mode === 'entra_client_credentials') {{ cfg.tenant_id = g('cfg-tenant'); cfg.client_id = g('cfg-client'); }}
  if (mode === 'entra_user_token')         {{ cfg.tenant_id = g('cfg-tenant'); cfg.scopes = g('cfg-scopes'); }}
  if (mode === 'service' || mode === 'user') {{ cfg.inject_header = g('cfg-header'); cfg.inject_prefix = g('cfg-prefix'); }}
  if (mode === 'oauth_user_token')         {{ cfg.issuer = g('cfg-issuer'); cfg.client_id = g('cfg-client'); }}
  if (mode === 'service_account')          cfg.token_url = g('cfg-tokenurl');
  return cfg;
}}

function submitStep2() {{
  if (!_wiz.injection_mode) {{ toast('Please select an authentication mode', 'error'); return; }}
  _wiz.upstream_idp_config = _collectModeConfig(_wiz.injection_mode);
  showStep3();
}}

// ── Guided questions ──────────────────────────────────────────────────────────

function showGuidedQuestions() {{
  document.getElementById('guided-panel').innerHTML = `
    <div class="wiz-card q-tree u287" >
      <div id="q-content"></div>
    </div>`;
  askQ1();
}}

function _qRender(question, options) {{
  const opts = options.map(([label, fn]) =>
    `<button class="q-btn">${{label}}</button>`).join('');
  const host = document.getElementById('q-content');
  host.innerHTML =
    `<div class="q-text">${{question}}</div><div class="q-opts">${{opts}}</div>`;
  // Bind real listeners rather than emitting onclick=: inline handlers are blocked
  // by any CSP without 'unsafe-inline' and cannot be rescued by a nonce (R1.4).
  host.querySelectorAll('.q-btn').forEach((b, i) => {{
    const handler = options[i] && options[i][1];
    b.addEventListener('click', typeof handler === 'function' ? handler : function() {{}});
  }});
}}

function askQ1() {{
  _qRender('Does your server call any upstream system that requires authentication?', [
    ['Yes — it calls an external or internal API', askQ2],
    ['No — it uses its own data or needs no auth',  () => recommendMode('none')],
  ]);
}}
function askQ2() {{
  _qRender('Is the upstream system protected by the <strong>same Keycloak instance</strong> this platform uses?', [
    ['Yes — same Keycloak realm',   () => recommendMode('kc_token_exchange')],
    ['No — external or different IdP', askQ3],
  ]);
}}
function askQ3() {{
  _qRender('What type of credential does the upstream system accept?', [
    ['Microsoft Entra / Azure AD', askQ4Entra],
    ['API key or static bearer token', askQ5Static],
    ['OAuth (different IdP)', askQ6OAuth],
  ]);
}}
function askQ4Entra() {{
  _qRender('Is this a machine-to-machine call (app identity) or per-user (delegated)?', [
    ['Machine / app identity — one app credential for all callers', () => recommendMode('entra_client_credentials')],
    ['Per-user delegated — each user has their own Entra identity',  () => recommendMode('entra_user_token')],
  ]);
}}
function askQ5Static() {{
  _qRender('Is one credential shared across all callers, or does each user have their own?', [
    ['Shared — one service account for everyone', () => recommendMode('service')],
    ['Per-user — each user has their own token',  () => recommendMode('user')],
  ]);
}}
function askQ6OAuth() {{
  _qRender('Is one token shared across all callers, or per-user?', [
    ['Shared OAuth token', () => recommendMode('service_account')],
    ['Per-user OAuth token', () => recommendMode('oauth_user_token')],
  ]);
}}

function recommendMode(mode) {{
  const label = {{
    kc_token_exchange:        'Same-IdP token exchange',
    entra_client_credentials: 'Entra machine identity',
    entra_user_token:         'Entra per-user delegated',
    service:                  'Shared service account',
    service_account:          'Shared OAuth service account',
    user:                     'Per-user stored token',
    oauth_user_token:         'Per-user OAuth token',
    none:                     'No auth',
  }}[mode] || mode;
  const reason = (_MODE_RECOMMEND[mode] || '');
  document.getElementById('q-content').innerHTML = `
    <div class="rec-box u288" >
      <div  class="u289">RECOMMENDED</div>
      <div class="rec-mode">${{label}}</div>
      <div class="rec-reason">${{reason}}</div>
      <div  class="u22">
        <button class="btn-primary" data-act="applyRecommendation" data-a0="${{mode}}">Use this</button>
        <button class="btn-secondary" data-act="showStep2">Override</button>
      </div>
    </div>`;
}}

function applyRecommendation(mode) {{
  document.getElementById('guided-panel').innerHTML = '';
  pickMode(mode);
}}

// ── Step 3: Data ──────────────────────────────────────────────────────────────

const _CATEGORIES = [
  ['pii',           '&#x1F464; PII / Personal data'],
  ['financial',     '&#x1F4B0; Financial records'],
  ['health',        '&#x2764;&#xFE0F; Health / medical'],
  ['internal_docs', '&#x1F4C4; Internal documents'],
  ['source_code',   '&#x1F4BB; Source code / repos'],
  ['email_calendar','&#x1F4E7; Email and calendar'],
  ['infrastructure','&#x1F5A7; Infrastructure / network'],
  ['public',        '&#x1F310; Public data only'],
];

function showStep3() {{
  _setStep(3);
  const cats = _CATEGORIES.map(([id, label]) => `
    <div class="cat-item ${{_wiz.data_categories.includes(id) ? 'selected' : ''}}"
         id="cat-${{id}}" data-act="toggleCat" data-a0="${{id}}">
      <span>${{label}}</span>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div  class="u280">What data does your server expose?</div>
      <div  class="u281">Select all that apply. This determines the risk level and review priority.</div>

      <div class="cat-grid">${{cats}}</div>

      <div  class="u276">
        <label class="wiz-label">Does this server perform write operations?</label>
        <div  class="u290">
          <label  class="u291">
            <input type="radio" name="write" value="no"  ${{_wiz.has_write_ops ? '' : 'checked'}}
                   onchange="_wiz.has_write_ops=false"> Read-only
          </label>
          <label  class="u291">
            <input type="radio" name="write" value="yes" ${{_wiz.has_write_ops ? 'checked' : ''}}
                   onchange="_wiz.has_write_ops=true"> Read + write
          </label>
        </div>
      </div>

      <div id="risk-preview"  class="u48"></div>

      <div  class="u283">
        <button class="btn-secondary" data-act="showStep2">&#x2190; Back</button>
        <button class="btn-primary" data-act="showStep4">Next &#x2192;</button>
      </div>
    </div>`;

  updateRiskPreview();
}}

function toggleCat(id) {{
  const el = document.getElementById('cat-' + id);
  const idx = _wiz.data_categories.indexOf(id);
  if (idx === -1) {{ _wiz.data_categories.push(id); el.classList.add('selected'); }}
  else            {{ _wiz.data_categories.splice(idx, 1); el.classList.remove('selected'); }}
  updateRiskPreview();
}}

function updateRiskPreview() {{
  const cats = _wiz.data_categories;
  let level = 'low', color = '#16a34a';
  if (cats.includes('public') && cats.length === 1) {{ level = 'low';      color = '#16a34a'; }}
  else if (cats.some(c => ['health','financial'].includes(c))) {{ level = 'critical'; color = '#dc2626'; }}
  else if (cats.some(c => ['pii','email_calendar'].includes(c)) || _wiz.has_write_ops) {{ level = 'high'; color = '#d97706'; }}
  else if (cats.length > 0) {{ level = 'medium'; color = '#2563eb'; }}
  document.getElementById('risk-preview').innerHTML = cats.length === 0 ? '' :
    `<div  class="u71">Derived risk level:
       <span class="risk-${{level}}">${{level}}</span>
       — sets the OPA invocation gate for this server
     </div>`;
}}

// ── Step 4: Review & Submit ───────────────────────────────────────────────────

function showStep4() {{
  _setStep(4);
  const modeLabel = _MODE_CARDS.find(m => m.id === _wiz.injection_mode)?.title || _wiz.injection_mode || '—';
  const cats = _wiz.data_categories.map(c => `<span  class="u216">${{c}}</span>`).join(' ');
  const repoLine = _wiz.github_repo_url
    ? `<a href="${{_wiz.github_repo_url}}"  class="u61">${{_wiz.github_repo_url}}</a>`
    : '<span  class="u14">No code yet — scaffold will be generated</span>';

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div  class="u275">&#x1F4CB; Review your submission</div>

      <table  class="u292">
        <tr><td  class="u293">Server name</td>
            <td  class="u294">${{_wiz.name}}</td></tr>
        <tr><td  class="u295">Hosting</td>
            <td>${{_wiz.self_host ? 'Self-hosted (you run the backend)' : 'Platform-deployed (we build &amp; host it)'}}</td></tr>
        <tr><td  class="u295">Repository</td>
            <td>${{repoLine}}</td></tr>
        ${{_wiz.self_host ? `
        <tr><td  class="u295">Backend URL</td>
            <td>${{_wiz.requested_upstream_url}}</td></tr>` : ''}}
        <tr><td  class="u295">Auth mode</td>
            <td  class="u294">${{modeLabel}}</td></tr>
        <tr><td  class="u295">Data categories</td>
            <td>${{cats || '<span  class="u14">None selected</span>'}}</td></tr>
        <tr><td  class="u295">Write operations</td>
            <td>${{_wiz.has_write_ops ? 'Yes' : 'No'}}</td></tr>
      </table>

      ${{_wiz.github_repo_url ? `
      <div class="helper-box u48" >
        &#x1F511; Before submitting, ensure
        <strong  class="u13">${{_CLONE_ACCT}}</strong>
        has read access to your repository.
      </div>` : ''}}

      <div id="submit-error"  class="u296"></div>

      <div  class="u297">
        <button class="btn-secondary" data-act="showStep3">&#x2190; Back</button>
        <button class="btn-primary" id="submit-btn" data-act="doSubmit">
          Submit for review &#x2192;
        </button>
      </div>
    </div>`;
}}

async function doSubmit() {{
  const btn = document.getElementById('submit-btn');
  btn.disabled = true; btn.textContent = 'Submitting…';

  try {{
    // Create draft
    let r = await fetch('/api/v1/submissions', {{
      method: 'POST', credentials: 'include',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{
        name: _wiz.name, description: _wiz.description, github_repo_url: _wiz.github_repo_url,
        self_host: _wiz.self_host,
      }}),
    }});
    if (!r.ok) {{
      const e = await r.json().catch(() => ({{}}));
      throw new Error(e.detail || 'Failed to create submission');
    }}
    const created = await r.json();
    _wiz.server_id = created.server_id;

    // Patch wizard data
    await fetch('/api/v1/submissions/' + _wiz.server_id, {{
      method: 'PATCH', credentials: 'include',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{
        injection_mode: _wiz.injection_mode,
        upstream_idp_config: _wiz.upstream_idp_config,
        data_categories: _wiz.data_categories,
        has_write_ops: _wiz.has_write_ops,
        description: _wiz.description,
        requested_upstream_url: _wiz.requested_upstream_url,
      }}),
    }});

    // Submit
    r = await fetch('/api/v1/submissions/' + _wiz.server_id + '/submit', {{
      method: 'POST', credentials: 'include',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{}}),
    }});
    if (!r.ok) throw new Error('Submit failed');
    const res = await r.json();

    showResult(res.submission_status);
  }} catch(err) {{
    btn.disabled = false; btn.textContent = 'Submit for review →';
    const errEl = document.getElementById('submit-error');
    if (errEl) {{ errEl.textContent = err.message; errEl.style.display = ''; }}
  }}
}}

async function showResult(status) {{
  const isNoCode = !_wiz.github_repo_url;
  document.getElementById('wiz-steps').style.display = 'none';

  if (!isNoCode) {{
    document.getElementById('wiz-body').innerHTML = `
      <div class="wiz-card u298" >
        <div  class="u299">&#x2705;</div>
        <div  class="u300">Submitted successfully</div>
        <div  class="u301">
          Your server is in the scan queue. We'll notify you when the security review is complete.
        </div>
        <a href="/portal" class="btn-secondary u302" >
          &#x2190; Back to portal
        </a>
      </div>`;
    return;
  }}

  // No-code path: load design prompts + show scaffold download
  let prompts = [];
  try {{
    const pr = await fetch('/api/v1/submissions/' + _wiz.server_id + '/prompts', {{credentials:'include'}});
    if (pr.ok) prompts = (await pr.json()).prompts || [];
  }} catch(_) {{}}

  const promptCards = prompts.map((p, i) => `
    <div  class="u303">
      <div  class="u304">
        Design question ${{i+1}}
      </div>
      <div  class="u305">${{p.prompt}}</div>
      <textarea placeholder="Your answer (optional — helps you plan before writing code)"
                 class="u306"></textarea>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div  class="u307">&#x1F4E6;</div>
      <div  class="u308">Submitted for review — scaffold ready</div>
      <div  class="u309">
        This design just entered the security review queue. Download the scaffold below and start
        building while the reviewer looks at it — approval issues starter code only, nothing goes live
        until you resubmit with a real repository.
      </div>

      <div  class="u310">
        DESIGN QUESTIONS — answer these before writing your server
      </div>
      ${{promptCards || '<div  class="u311">No prompts available.</div>'}}

      <div  class="u312">
        <a href="/api/v1/submissions/${{_wiz.server_id}}/scaffold" class="btn-primary u302"
           >
          &#x2B07; Download scaffold.zip
        </a>
        <a href="/portal/submit" class="btn-secondary u302" >
          Submit when ready &#x2192;
        </a>
      </div>

      <div class="helper-box u276" >
        &#x1F4A1; Paste these questions into Claude, GPT-4, or your preferred AI with your server's context.
        The answers will guide your implementation before you write the first line of code.
      </div>
    </div>`;
}}

// ── Init ──────────────────────────────────────────────────────────────────────
showStep1();
</script>
</body>
</html>""")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def esc_py(value: Any) -> str:
    """HTML-escape a value for safe insertion into HTML attributes and text nodes."""
    import html
    return html.escape(str(value) if value is not None else "", quote=True)


def esc_json_attr(*args: Any) -> str:
    """Render positional handler arguments as a JSON array safe for a data-json attribute.

    R1.4: the delegated dispatcher reads data-json when any argument is not a string —
    a bare data-a0="false" would arrive in JS as the truthy string "false". json.dumps
    emits double quotes, which would terminate the attribute, so they are escaped to
    &quot; (the browser decodes them before JSON.parse sees the value).
    """
    import json as _json
    return _json.dumps(list(args)).replace('"', "&quot;")


_KPI_TONE = {
    "var(--adm-blue)": "kpi-tone-blue", "var(--adm-purple)": "kpi-tone-purple",
    "var(--adm-green)": "kpi-tone-green", "var(--adm-amber)": "kpi-tone-amber",
    "var(--adm-red)": "kpi-tone-red", "var(--adm-cyan)": "kpi-tone-cyan",
}


def _chip_cls(color: str) -> str:
    """Map a status-chip hex colour to its CSS class (R1.5).

    The colour lives in _SUB_CHIP / _STATUS_COLOR alongside the label, so those maps
    stay the single source of truth; this only translates the value the templates
    used to interpolate into a `style=` attribute. Unknown colours fall back to grey
    rather than rendering unstyled.
    """
    return {
        "#2563eb": "chip-blue",  "#6b7280": "chip-grey", "#d97706": "chip-amber",
        "#dc2626": "chip-red",   "#16a34a": "chip-green", "#0891b2": "chip-cyan",
    }.get(color, "chip-grey")


def _slugify(value: str) -> str:
    """Turn an arbitrary principal/client id into a safe DOM id fragment.

    Must match the JS-side regex in the Access tab (accessToggleMcp) exactly —
    both replace every non-alphanumeric character with '_' — so server-rendered
    element ids and client-computed target ids agree.
    """
    import re
    return re.sub(r"[^a-zA-Z0-9]", "_", value)


def _badge(label: str, css_class: str) -> str:
    return f'<span class="badge {esc_py(css_class)}">{esc_py(label)}</span>'


def _error_fragment(message: str) -> str:
    return f'<div class="error-state">&#x26A0;&#xFE0F; {esc_py(message)}</div>'
