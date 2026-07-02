"""
MCP Security Platform — Multi-Role Web Portal

Provides a unified portal UI for all platform roles:
  - agent / admin: Catalog tab (browsable tool cards)
  - agent / admin: My Access tab (personal grants, credential status, MCP config snippet)
  - admin only:    Admin tab (tools table, credentials management, grants editor)

Routes:
  GET /portal                              — full page shell
  GET /portal/fragments/catalog            — catalog tab fragment
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
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/portal", tags=["Portal"])

# Path to OPA data file — resolved relative to this file's location so it works
# regardless of CWD at runtime.
_HERE = Path(__file__).resolve().parent
_DATA_JSON = (_HERE / "../../../../policies/rego/data.json").resolve()

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


# ---------------------------------------------------------------------------
# Shared CSS + JS constants (identical variables to admin_credentials.py)
# ---------------------------------------------------------------------------

_HTMX_TAG = '<script src="/static/htmx.min.js"></script>'

_FONTS_LINK = (
    # Non-blocking async font load: media="print" + onload swap prevents blocking
    # the window load event when fonts.googleapis.com is unreachable (lab network).
    '<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700;800'
    '&family=JetBrains+Mono:wght@400;500;600&display=swap"'
    ' rel="stylesheet" media="print" onload="this.media=\'all\'">'
)

_CSS = """
  :root {
    --bg:      #0f172a;
    --surface: #1e293b;
    --border:  #334155;
    --text:    #e2e8f0;
    --muted:   #94a3b8;
    --primary: #38bdf8;
    --primary-dark: #0284c7;
    --green:   #4ade80;
    --red:     #f87171;
    --amber:   #fbbf24;
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
  .btn-primary { background: #0ea5e9; color: #fff; }
  .btn-primary:hover { background: var(--primary-dark); }
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
    --adm-bg:      #0c0e12;
    --adm-sidebar: #08090c;
    --adm-surface: #13161b;
    --adm-border:  rgba(255,255,255,0.06);
    --adm-text:    #e7e9ec;
    --adm-muted:   #9aa1ab;
    --adm-dim:     #646b75;
    --adm-blue:    #3b82f6;
    --adm-blue2:   #2563eb;
    --adm-green:   #4ade80;
    --adm-amber:   #fbbf24;
    --adm-red:     #f87171;
    --ff-sans: 'Hanken Grotesk', system-ui, sans-serif;
    --ff-mono: 'JetBrains Mono', 'Menlo', monospace;
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
    position: relative; width: 24px; height: 24px; border-radius: 7px; flex: none;
    background: linear-gradient(145deg, #5fa0ff, #2563eb);
    box-shadow: 0 3px 10px rgba(37,99,235,0.45);
    display: flex; align-items: center; justify-content: center;
  }
  .adm-logo-mark::before {
    content: ''; width: 10px; height: 10px; border: 2px solid #fff;
    border-radius: 2px; transform: rotate(45deg);
  }
  .adm-logo-name { font-size: 15px; font-weight: 800; color: var(--adm-text); letter-spacing: -0.01em; }
  .adm-logo-sub  { font: 500 9px var(--ff-mono); letter-spacing: 0.16em; color: #5b626c; }
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
    background: rgba(59,130,246,0.13); color: var(--adm-text); font-weight: 600;
  }
  .adm-nav-item.active::before {
    content: ''; position: absolute; left: -14px; top: 7px; bottom: 7px;
    width: 3px; border-radius: 3px; background: var(--adm-blue);
  }
  .adm-nav-dot {
    width: 6px; height: 6px; border-radius: 2px; background: #454c55; flex: none;
  }
  .adm-nav-dot.active { background: var(--adm-blue); }
  .adm-user-panel {
    margin-top: auto; display: flex; align-items: center; gap: 10px;
    padding: 10px; border-radius: 10px;
    background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.06);
  }
  .adm-avatar {
    width: 30px; height: 30px; border-radius: 8px;
    background: linear-gradient(135deg, #3b82f6, #1d4ed8);
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 12px; color: #fff; flex: none;
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
  .adm-search-text { font-size: 12.5px; color: #717983; flex: 1; }
  .adm-search-kbd {
    font: 500 10px var(--ff-mono); color: #5b626c;
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
    font: 600 10px var(--ff-mono); letter-spacing: 0.08em; color: #5b626c;
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
  .mode-chip {
    font: 500 11px var(--ff-mono); color: var(--adm-muted);
    background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.08);
    padding: 3px 8px; border-radius: 6px;
  }

  /* ---- Status pills (server registry) ---- */
  .pill {
    display: inline-flex; align-items: center; gap: 6px; padding: 4px 9px;
    border-radius: 999px; font: 600 11px var(--ff-mono); letter-spacing: 0.02em;
    text-transform: uppercase; white-space: nowrap;
  }
  .pill-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; }
  .pill-approved   { background: rgba(74,222,128,0.12);  color: #4ade80; }
  .pill-approved   .pill-dot { background: #4ade80; }
  .pill-pending    { background: rgba(251,191,36,0.13);  color: #fbbf24; }
  .pill-pending    .pill-dot { background: #fbbf24; }
  .pill-quarantined { background: rgba(248,113,113,0.14); color: #f87171; }
  .pill-quarantined .pill-dot { background: #f87171; }

  /* ---- Table action buttons ---- */
  .btn-approve {
    background: var(--adm-blue); color: #fff; font-size: 11.5px; font-weight: 600;
    padding: 6px 11px; border-radius: 7px; border: none; cursor: pointer;
    font-family: var(--ff-sans);
  }
  .btn-release {
    border: 1px solid rgba(255,255,255,0.16); color: #cbd0d7; font-size: 11.5px;
    font-weight: 600; padding: 5px 10px; border-radius: 7px; background: transparent;
    cursor: pointer; font-family: var(--ff-sans);
  }
  .btn-reject {
    background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35);
    color: #f87171; font-size: 11.5px; font-weight: 600;
    padding: 5px 10px; border-radius: 7px; cursor: pointer; font-family: var(--ff-sans);
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
    font: 500 10px var(--ff-mono); letter-spacing: 0.12em; color: #5b626c;
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
  .portal-find-text { font-size: 12.5px; color: #717983; flex: 1; }

  /* ---- Profile bar ---- */
  .profile-bar { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  .profile-lbl { font: 600 10px var(--ff-mono); letter-spacing: 0.12em; color: #5b626c; }
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
    border: 1px dashed rgba(255,255,255,0.16); color: #717983;
    background: transparent;
  }
  .profile-summary { font-size: 12px; color: #717983; margin-left: auto; }
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
  .srv-card-icon.dim { background: rgba(255,255,255,0.04); border-color: rgba(255,255,255,0.07); color: #717983; }
  .srv-card-name { font-size: 14px; font-weight: 700; color: var(--adm-text); }
  .srv-card-name.dim { color: #cbd0d7; }
  .srv-card-desc { font-size: 12.5px; color: var(--adm-muted); line-height: 1.4; }
  .srv-card-desc.dim { color: #717983; }
  .srv-card-tools { display: flex; flex-wrap: wrap; gap: 6px; }
  .tool-chip {
    display: inline-flex; align-items: center; gap: 5px;
    font: 500 11px var(--ff-mono); color: #cbd0d7;
    background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.08);
    padding: 3px 8px; border-radius: 6px;
  }
  .tool-chip-dot  { width: 5px; height: 5px; border-radius: 50%; background: #4ade80; }
  .tool-chip-off  {
    font: 500 11px var(--ff-mono); color: #5b626c;
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
  .srv-card-footer-pend { font-size: 12px; color: #717983; }
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
  .srv-toggle.off::after { left: 2px; background: #717983; }

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

_JS_COMMON = """
  // XSS-safe text setter
  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str == null ? '' : String(str);
    return d.innerHTML;
  }

  // Toggle a section's visibility
  function toggle(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = el.style.display === 'none' ? '' : 'none';
  }

  // Activate a top-level tab
  function activateTab(name) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
    const area = document.getElementById('tab-content');
    area.innerHTML = '<div class="loading-state"><span class="spinner"></span> Loading...</div>';
    htmx.ajax('GET', '/portal/fragments/' + name, {target: '#tab-content', swap: 'innerHTML'});
  }

  // Activate an admin inner tab
  function activateAdminTab(name) {
    document.querySelectorAll('.inner-tab-btn').forEach(b => b.classList.toggle('active', b.dataset.itab === name));
    const area = document.getElementById('admin-inner-content');
    area.innerHTML = '<div class="loading-state"><span class="spinner"></span> Loading...</div>';
    htmx.ajax('GET', '/portal/fragments/admin/' + name, {target: '#admin-inner-content', swap: 'innerHTML'});
  }

  // Client-side catalog filter
  function filterCatalog() {
    const q = (document.getElementById('cat-search')?.value || '').toLowerCase();
    const riskFilter = document.getElementById('cat-risk')?.value || '';
    const modeFilter = document.getElementById('cat-mode')?.value || '';
    document.querySelectorAll('.tool-card[data-tool-id]').forEach(card => {
      const name = (card.dataset.name || '').toLowerCase();
      const desc = (card.dataset.desc || '').toLowerCase();
      const tags = (card.dataset.tags || '').toLowerCase();
      const risk = card.dataset.risk || '';
      const mode = card.dataset.mode || '';
      const matchQ    = !q || name.includes(q) || desc.includes(q) || tags.includes(q);
      const matchRisk = !riskFilter || risk === riskFilter;
      const matchMode = !modeFilter || mode === modeFilter;
      card.style.display = (matchQ && matchRisk && matchMode) ? '' : 'none';
    });
  }
"""


# ---------------------------------------------------------------------------
# Page shell
# ---------------------------------------------------------------------------

_TAB_MAP_PY = {
    "identity":    "Identity (OIDC)",
    "servers":     "MCP Servers",
    "credentials": "Credentials",
    "limits":      "Request Limits",
    "dashboard":   "Dashboard",
    "detections":  "Detections",
    "sbom":        "SBOM",
    "submissions": "Submissions",
}
_VALID_TABS = frozenset(_TAB_MAP_PY)


@router.get("", response_class=HTMLResponse)
async def portal_shell(request: Request):
    """Serve the full portal page shell (role-aware layout)."""
    _require_portal_access(request)

    roles = _roles(request)
    cid = _client_id(request)
    is_admin = "admin" in roles

    if is_admin:
        tab = request.query_params.get("tab", "servers")
        if tab not in _VALID_TABS:
            tab = "servers"
        return HTMLResponse(content=_build_admin_shell(cid, roles, initial_tab=tab))
    return HTMLResponse(content=_build_agent_shell(cid, roles))


@router.get("/admin/{tab}", response_class=HTMLResponse)
async def portal_admin_tab(tab: str, request: Request):
    """Direct URL for admin tabs — /portal/admin/limits etc."""
    _require_portal_access(request)
    roles = _roles(request)
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail="admin role required")
    if tab not in _VALID_TABS:
        tab = "servers"
    return HTMLResponse(content=_build_admin_shell(_client_id(request), roles, initial_tab=tab))


def _aegis_logo_mark(size: int = 24, glow: bool = True) -> str:
    shadow = "box-shadow:0 3px 10px rgba(37,99,235,0.45);" if glow else ""
    sqsz = int(size * 0.42)
    dotsz = int(size * 0.125)
    return (
        f'<div class="adm-logo-mark" style="width:{size}px;height:{size}px;{shadow}">'
        f'<div style="width:{sqsz}px;height:{sqsz}px;border:2px solid #fff;border-radius:2px;transform:rotate(45deg)"></div>'
        f'<div style="position:absolute;width:{dotsz}px;height:{dotsz}px;border-radius:50%;background:#fff"></div>'
        f'</div>'
    )


def _build_admin_shell(cid: str, roles: list, initial_tab: str = "servers") -> str:
    """Full-page admin sidebar layout."""
    initials = "".join(w[0].upper() for w in cid.replace("-", " ").split()[:2]) or "?"
    display_name = cid

    def _nav(label: str, tab: str, active: bool = False) -> str:
        cls = "adm-nav-item active" if active else "adm-nav-item"
        dot_cls = "adm-nav-dot active" if active else "adm-nav-dot"
        return (
            f'<button class="{cls}" onclick="loadAdminTab(\'{esc_py(tab)}\')">'
            f'<span class="{dot_cls}"></span>{esc_py(label)}</button>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Platform · Admin</title>
  {_FONTS_LINK}
  {_HTMX_TAG}
  <style>{_CSS}</style>
</head>
<body>
<div class="adm-layout">
  <!-- Sidebar -->
  <aside class="adm-sidebar">
    <div class="adm-logo-row">
      {_aegis_logo_mark(24)}
      <div>
        <div class="adm-logo-name" style="font-weight:700">MCP Security Platform</div>
      </div>
    </div>

    <div class="adm-nav-group">SECURITY</div>
    {_nav("Dashboard",  "dashboard")}
    {_nav("Detections", "detections")}
    {_nav("SBOM",       "sbom")}

    <div class="adm-nav-group">ADMIN</div>
    {_nav("Identity (OIDC)", "identity")}
    {_nav("MCP Servers",     "servers", active=True)}
    {_nav("Submissions",     "submissions")}
    {_nav("Credentials",     "credentials")}
    {_nav("Request Limits",  "limits")}

    <div class="adm-user-panel">
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
        Admin <span class="adm-breadcrumb-sep">/</span>
        <span class="adm-breadcrumb-page" id="adm-breadcrumb-page">{esc_py(_TAB_MAP_PY.get(initial_tab, initial_tab))}</span>
      </div>
      <a href="/portal/submit" style="display:inline-flex;align-items:center;gap:0.35rem;
         background:var(--blue);color:#fff;border-radius:7px;padding:0.35rem 0.85rem;
         font-size:12px;font-weight:600;text-decoration:none;white-space:nowrap">
        &#x2B; Submit MCP Server
      </a>
    </div>


    <!-- Content -->
    <div class="adm-body" id="adm-content"
         hx-get="/portal/fragments/admin/{esc_py(initial_tab)}"
         hx-trigger="load"
         hx-swap="innerHTML">
      <div class="loading-state"><span class="spinner"></span> Loading…</div>
    </div>
  </div>
</div>
<script>
  {_JS_COMMON}
  const _TAB_MAP = {{
    identity:    'Identity (OIDC)',
    servers:     'MCP Servers',
    credentials: 'Credentials',
    limits:      'Request Limits',
    dashboard:   'Dashboard',
    detections:  'Detections',
    sbom:        'SBOM',
    submissions: 'Submissions',
  }};
  function loadAdminTab(name) {{
    // Update breadcrumb
    const bc = document.getElementById('adm-breadcrumb-page');
    if (bc) bc.textContent = _TAB_MAP[name] || name;
    // Update sidebar active item
    document.querySelectorAll('.adm-nav-item').forEach(b => {{
      const match = b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + name + "'");
      b.classList.toggle('active', match);
      const dot = b.querySelector('.adm-nav-dot');
      if (dot) dot.classList.toggle('active', match);
    }});
    // Update top tab bar
    document.querySelectorAll('#adm-tabs-bar .adm-tab').forEach(b => {{
      const match = b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + name + "'");
      b.classList.toggle('active', match);
    }});
    // Load fragment
    htmx.ajax('GET', '/portal/fragments/admin/' + name, {{target: '#adm-content', swap: 'innerHTML'}});
  }}
  // Legacy alias used by existing admin sub-fragments
  function activateAdminTab(name) {{ loadAdminTab(name); }}
</script>
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
  {_FONTS_LINK}
  {_HTMX_TAG}
  <style>{_CSS}</style>
</head>
<body>
<div class="portal-layout">
  <!-- Topbar -->
  <div class="portal-topbar">
    <div class="portal-logo">
      {_aegis_logo_mark(22, glow=True)}
      <div class="portal-logo-name" style="font-weight:700">MCP Security Platform</div>
    </div>
    <div class="portal-user-area">
      <div class="portal-role-chip">
        <span class="portal-role-dot"></span>
        {esc_py(role_label.capitalize())}
      </div>
      <div style="display:flex;align-items:center;gap:9px">
        <div class="portal-uid-block">
          <div class="portal-uid">{esc_py(cid)}</div>
          <div class="portal-uid-sub">service account</div>
        </div>
        <div class="adm-avatar">{esc_py(initials)}</div>
      </div>
    </div>
  </div>

  <!-- Body -->
  <div class="portal-body" id="portal-body"
       hx-get="/portal/fragments/my-access"
       hx-trigger="load"
       hx-swap="innerHTML">
    <div class="loading-state"><span class="spinner"></span> Loading your access…</div>
  </div>
</div>
<script>
  {_JS_COMMON}
</script>
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


@router.get("/fragments/catalog", response_class=HTMLResponse)
async def fragment_catalog(request: Request):
    """Catalog tab: grid of active tool cards."""
    _require_portal_access(request)
    roles = _roles(request)
    is_auditor = _is_auditor_only(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT tool_id, name, version, description, status, risk_level, risk_score,
                       upstream_url, tags, injection_mode, service_name
                FROM tool_registry
                WHERE deleted_at IS NULL
                ORDER BY name
            """))
            tools = result.fetchall()
    except Exception as exc:
        logger.error("portal catalog DB error: %s", exc)
        return HTMLResponse(_error_fragment("Failed to load catalog. Database error."))

    if not tools:
        return HTMLResponse('<div class="empty-state">No tools registered yet.</div>')

    cards = []
    for t in tools:
        tool_id = str(t.tool_id)
        name = t.name or ""
        version = t.version or ""
        desc = t.description or "No description provided."
        status = t.status or "unknown"
        risk = (t.risk_level or "low").lower()
        risk_score = t.risk_score
        mode = (t.injection_mode or "none").lower()
        tags = t.tags or []
        tag_str = " ".join(tags)

        status_badge = _badge(status, f"badge-{status}")
        risk_badge = _badge(risk.upper(), f"badge-risk-{risk}")
        mode_badge = _badge(mode, f"badge-mode-{mode.replace(' ', '_')}")

        tags_html = "".join(f'<span class="tag">{esc_py(tg)}</span>' for tg in tags)

        # Credential upload form for user-mode tools (auditor is read-only — no upload)
        if mode in ("user", "oauth_user_token") and not is_auditor:
            cred_section = f"""
            <details class="cred-form">
              <summary>Upload my credential</summary>
              <div>
                <label>Secret / Token</label>
                <div class="row" style="gap:0.5rem;margin-top:0.25rem">
                  <input type="password" id="cred-{esc_py(tool_id)}" placeholder="Paste secret here" autocomplete="new-password">
                  <button class="btn-primary btn-sm"
                    onclick="submitCred('{esc_py(tool_id)}')">Upload</button>
                </div>
                <div id="cred-msg-{esc_py(tool_id)}"></div>
              </div>
            </details>"""
        else:
            cred_section = f'<div style="margin-top:0.5rem;font-size:0.78rem;color:var(--muted)">Injection: {mode_badge}</div>'

        score_html = f'<span style="font-size:0.72rem;color:var(--muted)">&nbsp;score {risk_score}</span>' if risk_score is not None else ""

        cards.append(f"""
        <div class="tool-card"
             data-tool-id="{esc_py(tool_id)}"
             data-name="{esc_py(name)}"
             data-desc="{esc_py(desc)}"
             data-tags="{esc_py(tag_str)}"
             data-risk="{esc_py(risk)}"
             data-mode="{esc_py(mode)}">
          <div class="tool-card-header">
            <div>
              <div class="tool-name">{esc_py(name)}</div>
              <div class="tool-version">v{esc_py(version)}</div>
            </div>
            <div style="display:flex;gap:0.3rem;flex-wrap:wrap;justify-content:flex-end">
              {status_badge}
              {risk_badge}{score_html}
            </div>
          </div>
          <div class="tool-desc">{esc_py(desc)}</div>
          <div class="tool-tags">{tags_html}</div>
          {cred_section}
        </div>""")

    grid = f'<div class="card-grid">{"".join(cards)}</div>'

    html = f"""
    <div hx-get="/portal/fragments/attention"
         hx-trigger="load"
         hx-swap="outerHTML"></div>
    <div class="filter-bar">
      <input id="cat-search" type="search" placeholder="Search by name, description, tag..."
             oninput="filterCatalog()" style="max-width:360px">
      <select id="cat-risk" onchange="filterCatalog()">
        <option value="">All risk levels</option>
        <option value="low">Low</option>
        <option value="medium">Medium</option>
        <option value="high">High</option>
        <option value="critical">Critical</option>
      </select>
      <select id="cat-mode" onchange="filterCatalog()">
        <option value="">All injection modes</option>
        <option value="none">None</option>
        <option value="header">Header</option>
        <option value="user">User</option>
        <option value="service">Service</option>
        <option value="service_account">Service Account</option>
        <option value="oauth_user_token">OAuth User Token</option>
      </select>
      <span style="font-size:0.8rem;color:var(--muted)">{len(tools)} tool{"s" if len(tools) != 1 else ""}</span>
    </div>
    {grid}
    <script>
    function submitCred(toolId) {{
      const inp = document.getElementById('cred-' + toolId);
      const msgEl = document.getElementById('cred-msg-' + toolId);
      const secret = inp ? inp.value.trim() : '';
      if (!secret) {{ showMsg(msgEl, 'err', 'Please enter a secret.'); return; }}
      fetch('/portal/credentials/' + toolId, {{
        method: 'PUT',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{secret: secret}})
      }}).then(r => r.json().then(d => {{
        if (r.ok) {{
          showMsg(msgEl, 'ok', 'Credential uploaded successfully.');
          inp.value = '';
        }} else {{
          const m = (d.detail?.message) || (d.detail) || 'Upload failed.';
          showMsg(msgEl, 'err', String(m));
        }}
      }})).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }}
    function showMsg(el, type, text) {{
      if (!el) return;
      el.className = 'msg msg-' + type;
      el.textContent = text;
      if (type === 'ok') setTimeout(() => {{ el.textContent = ''; el.className = ''; }}, 4000);
    }}
    </script>
    """
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: My Access
# ---------------------------------------------------------------------------

@router.get("/fragments/my-access", response_class=HTMLResponse)
async def fragment_my_access(request: Request):
    """User portal: server access cards (new aegis design)."""
    _require_portal_access(request)
    cid = _client_id(request)
    api_key = request.query_params.get("key", "")
    return HTMLResponse(await _build_portal_access(cid, api_key, _is_auditor_only(request)))


async def _build_portal_access(cid: str, api_key: str = "", is_auditor: bool = False) -> str:  # noqa: C901
    """Build the 'Your access' card grid for the user portal."""
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
                    server_meta[svc] = {
                        "status": srv_st,
                        "injection_mode": row.srv_injection_mode or row.injection_mode or "none",
                    }

            # Profile states (enable/disable per server alias)
            pres = await session.execute(
                text("SELECT mcp_name, enabled FROM mcp_profiles WHERE profile_id=:cid"),
                {"cid": cid},
            )
            for prow in pres.fetchall():
                profile_states[prow.mcp_name] = bool(prow.enabled)
    except Exception as exc:
        logger.error("portal my-access DB error: %s", exc)

    # 3. Determine card-level status
    def _card_status(svc: str) -> str:
        meta = server_meta.get(svc, {})
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

        card_extra_cls = {"suspended": "card-suspended", "awaiting": "card-awaiting"}.get(cstatus, "")
        icon_cls = "" if cstatus == "active" else "dim"
        name_cls = "" if cstatus == "active" else "dim"
        desc_cls = "" if cstatus == "active" else "dim"

        # Status pill
        pill_cls = {"active": "cpill-active", "suspended": "cpill-suspended", "awaiting": "cpill-awaiting"}[cstatus]
        pill_lbl = {"active": "Active", "suspended": "Suspended", "awaiting": "Awaiting"}[cstatus]
        pill_html = f'<span class="cpill {pill_cls}"><span class="cpill-dot"></span>{pill_lbl}</span>'

        # Description
        desc_map = {
            "active":    f"Tools available via {esc_py(mode)} injection.",
            "suspended": "Temporarily blocked by an administrator pending security review.",
            "awaiting":  "Waiting for an admin to approve this server. We’ll notify you.",
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
                f'<button class="srv-toggle" title="Disable {esc_py(svc)}" '
                f'hx-post="/portal/actions/profile/{esc_py(svc)}/disable" '
                f'hx-target="closest .srv-card" hx-swap="outerHTML"></button>'
            )
        elif cstatus == "active" and not enabled:
            footer_lbl = '<span class="srv-card-footer-lbl">Access disabled</span>'
            toggle_html = (
                f'<button class="srv-toggle off" title="Enable {esc_py(svc)}" '
                f'hx-post="/portal/actions/profile/{esc_py(svc)}/enable" '
                f'hx-target="closest .srv-card" hx-swap="outerHTML"></button>'
            )
        elif cstatus == "suspended":
            footer_lbl = '<a class="srv-card-footer-link" href="#">Contact admin →</a>'
            toggle_html = '<button class="srv-toggle off" disabled></button>'
        else:  # awaiting
            footer_lbl = '<span class="srv-card-footer-pend">Pending review</span>'
            toggle_html = '<button class="srv-toggle off" disabled></button>'

        # Auditor is read-only: no enable/disable toggle.
        if is_auditor:
            toggle_html = '<button class="srv-toggle off" disabled title="read-only (auditor)"></button>'

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

    return f"""
    <!-- Hero -->
    <div class="portal-hero">
      <div>
        <div class="portal-hero-title">Your access</div>
        <div class="portal-hero-sub">Pick a profile, then choose which servers and tools can reach you on your behalf.</div>
      </div>
      <div class="portal-find-bar">
        <div class="portal-find-orb"></div>
        <span class="portal-find-text">Find a tool — e.g. <strong style="color:#cbd0d7">"send an email"</strong></span>
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

    <!-- Summary strip -->
    <div class="srv-strip">
      <div class="srv-strip-cnt">{len(granted_svcs)} servers</div>
      <div class="srv-strip-div"></div>
      <div class="srv-strip-item"><span class="dot-green"></span>{n_active} active</div>
      <div class="srv-strip-item"><span class="dot-red"></span>{n_suspended} suspended</div>
      <div class="srv-strip-item"><span class="dot-amber"></span>{n_awaiting} awaiting approval</div>
    </div>

    <!-- Submit server CTA (hidden for read-only auditor) -->
    {"" if is_auditor else '''<div style="display:flex;justify-content:flex-end;margin-bottom:1rem">
      <a href="/portal/submit" style="display:inline-flex;align-items:center;gap:0.4rem;
         background:var(--blue);color:#fff;border-radius:8px;padding:0.45rem 1rem;
         font-size:13px;font-weight:600;text-decoration:none">
        &#x2B; Submit MCP Server
      </a>
    </div>'''}

    <!-- Card grid -->
    <div class="srv-card-grid">
      {"".join(cards_html) if cards_html else '<div class="empty-state">No servers accessible for this identity.</div>'}
    </div>

    <!-- MCP Config snippet (collapsed by default) -->
    <details style="margin-top:8px">
      <summary style="cursor:pointer;font-size:13px;font-weight:600;color:#9aa1ab;padding:8px 0;font-family:var(--ff-sans)">
        MCP config snippet
      </summary>
      <div style="margin-top:8px">
        <p style="font-size:12px;color:#5b626c;margin-bottom:8px">
          Paste into <code style="font-family:var(--ff-mono);color:#7aa7ff">~/.mcp.json</code>.
          {"Append <code style=\"font-family:var(--ff-mono)\">?key=YOUR_API_KEY</code> to pre-fill." if not api_key else "API key pre-filled."}
        </p>
        <div class="code-block" id="mcp-config-block">{esc_py(mcp_json)}</div>
        <button class="btn-secondary btn-sm" style="margin-top:0.5rem" onclick="
          navigator.clipboard.writeText(document.getElementById('mcp-config-block').textContent).then(()=>{{
            this.textContent='Copied!'; setTimeout(()=>this.textContent='Copy',2000);
          }})">Copy</button>
      </div>
    </details>
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
            f'<div style="color:#f87171;font-size:12px">Enable failed: {esc_py(str(exc))}</div></div>'
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
            f'<div style="color:#f87171;font-size:12px">Disable failed: {esc_py(str(exc))}</div></div>'
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
    _toggle_style = (
        "background:#1e293b;border:1px solid #f87171;color:#f87171;"
        if enabled else
        "background:#1e293b;border:1px solid #4ade80;color:#4ade80;"
    )
    _enabled_badge = _badge("enabled" if enabled else "disabled",
                            "badge-active" if enabled else "badge-inactive")
    _toggle_btn = (
        f'<button class="btn-sm" style="{_toggle_style}padding:0.2rem 0.6rem;'
        f'border-radius:4px;cursor:pointer;font-size:0.75rem" '
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
          <div style="display:flex;gap:0.4rem;align-items:center">
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
      <button class="inner-tab-btn" data-itab="servers"      onclick="activateAdminTab('servers')">MCP Servers</button>
      <button class="inner-tab-btn" data-itab="tools"        onclick="activateAdminTab('tools')">Tools</button>
      <button class="inner-tab-btn active" data-itab="credentials" onclick="activateAdminTab('credentials')">Credentials</button>
      <button class="inner-tab-btn"        data-itab="grants"      onclick="activateAdminTab('grants')">Grants</button>
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
                       injection_mode, updated_at
                FROM server_registry
                ORDER BY name
            """))
            servers = result.fetchall()
            total = len(servers)

            # Pending/quarantined counts for attention band
            pending_names    = [s.name for s in servers if (s.status or "") == "pending"]
            quarantined_names = [s.name for s in servers if (s.status or "") == "quarantined"]
    except Exception as exc:
        logger.error("portal admin/servers DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading server registry."))

    # Attention band
    attention_items: list[str] = []
    if pending_names:
        attention_items.append(
            f'<span style="color:#fbbf24;font-weight:600">{esc_py(pending_names[0])}</span>'
            f' awaiting approval'
            + (f' and {len(pending_names)-1} more' if len(pending_names) > 1 else '')
        )
    if quarantined_names:
        attention_items.append(
            f'<span style="font-family:var(--ff-mono);font-size:11px">'
            f'{esc_py(quarantined_names[0])}</span> is quarantined'
        )

    attention_html = ""
    if attention_items:
        count = len(pending_names) + len(quarantined_names)
        attention_html = f"""
        <div class="adm-attention">
          <div class="adm-attention-icon"><div class="adm-attention-diamond"></div></div>
          <div style="flex:1;line-height:1.3">
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
        if st == "pending":
            action_html = (
                f'<div style="display:flex;gap:6px;justify-content:flex-end">'
                f'<button class="btn-approve" onclick="adminApproveSrv(\'{sid}\')">Approve</button>'
                f'<button class="btn-reject" onclick="adminRejectSrv(\'{sid}\')">Reject</button>'
                f'</div>'
            )
        elif st == "quarantined":
            action_html = (
                f'<div style="text-align:right">'
                f'<button class="btn-release" onclick="adminReleaseSrv(\'{sid}\')">Release</button>'
                f'</div>'
            )
        else:
            action_html = (
                f'<div style="position:relative;text-align:right">'
                f'<button class="btn-menu" onclick="srvMenuToggle(event,\'{sid}\')">⋯</button>'
                f'<div class="srv-dropdown" id="srv-dd-{sid}" style="display:none">'
                f'<button onclick="adminQuarantineSrv(\'{sid}\')">Quarantine</button>'
                f'<button class="danger" onclick="adminDeleteSrv(\'{sid}\')">Delete</button>'
                f'</div></div>'
            )

        rows_html.append(f"""
        <div class="srv-tbl-row {row_cls}">
          <div>
            <div class="srv-cell-name">{esc_py(s.name or "")}</div>
            <div class="srv-cell-alias">{esc_py(s.name or "")}</div>
          </div>
          <div class="srv-cell-url">{esc_py(s.upstream_url or "—")}</div>
          <div><span class="pill {pill_cls}"><span class="pill-dot"></span>{pill_label}</span></div>
          <div class="srv-cell-owner">{esc_py(s.owner_sub or "—")}</div>
          <div><span class="mode-chip">{esc_py(mode_label)}</span></div>
          <div class="srv-cell-updated">{esc_py(_fmt_time(s.updated_at))}</div>
          {action_html}
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
      <div style="flex:1"></div>
      <div class="srv-seg-group" id="srv-seg">
        <button class="srv-seg-btn active" onclick="filterSrv(this,'')">All</button>
        <button class="srv-seg-btn" onclick="filterSrv(this,'approved')">Approved</button>
        <button class="srv-seg-btn" onclick="filterSrv(this,'pending')">Pending</button>
        <button class="srv-seg-btn" onclick="filterSrv(this,'quarantined')">Quarantined</button>
      </div>
      <button class="btn-register-srv" onclick="loadAdminTab('submissions')">
        <span>+</span>Register server
      </button>
    </div>

    <!-- Table -->
    <div class="srv-tbl">
      <div class="srv-tbl-head">
        <div>SERVER</div><div>UPSTREAM URL</div><div>STATUS</div>
        <div>OWNER</div><div>INJECTION</div><div>UPDATED</div><div></div>
      </div>
      {rows_block}
    </div>

    <script>
    function filterSrv(btn, status) {{
      document.querySelectorAll('#srv-seg .srv-seg-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.srv-tbl-row').forEach(r => {{
        if (!status) {{ r.style.display=''; return; }}
        const hasStatus = r.classList.contains('row-' + status) ||
          (!r.classList.contains('row-pending') && !r.classList.contains('row-quarantined') && status === 'approved');
        r.style.display = hasStatus ? '' : 'none';
      }});
    }}
    function adminApproveSrv(id) {{
      if (!confirm('Approve this server? (Requires a consent token — use POST /api/v1/admin/servers/'+id+'/approve with consent_token body)')) return;
      fetch('/api/v1/admin/servers/' + id + '/approve', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{}}'}})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => alert(d.detail?.message || d.detail || 'Consent token required')))
        .catch(e => alert('Network error: ' + e));
    }}
    function adminRejectSrv(id) {{
      if (!confirm('Reject and remove this server?')) return;
      fetch('/api/v1/admin/servers/' + id + '/reject', {{method:'POST'}})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => alert(d.detail?.message || 'Error')))
        .catch(e => alert('Network error: ' + e));
    }}
    function adminReleaseSrv(id) {{
      if (!confirm('Release this server from quarantine?')) return;
      fetch('/api/v1/admin/servers/' + id + '/release', {{method:'POST'}})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => alert(d.detail?.message || 'Error')))
        .catch(e => alert('Network error: ' + e));
    }}
    function adminQuarantineSrv(id) {{
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!confirm('Quarantine this server? It will be blocked from invocations.')) return;
      fetch('/api/v1/admin/servers/' + id + '/quarantine', {{method:'POST'}})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => alert(d.detail?.message || 'Error')))
        .catch(e => alert('Network error: ' + e));
    }}
    function adminDeleteSrv(id) {{
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!confirm('Delete this server? This cannot be undone.')) return;
      fetch('/api/v1/admin/servers/' + id, {{method:'DELETE'}})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => alert(d.detail?.message || 'Error')))
        .catch(e => alert('Network error: ' + e));
    }}
    function srvMenuToggle(evt, id) {{
      evt.stopPropagation();
      const dd = document.getElementById('srv-dd-' + id);
      if (!dd) return;
      const visible = dd.style.display !== 'none';
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      dd.style.display = visible ? 'none' : 'block';
    }}
    document.addEventListener('click', function() {{
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
    }});
    </script>
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
        <div style="display:grid;grid-template-columns:200px 1fr;gap:12px;
                    padding:12px 16px;border-bottom:1px solid rgba(255,255,255,0.05)">
          <div style="font:600 12px var(--ff-mono);color:#5b626c;
                      text-transform:uppercase;letter-spacing:0.06em">{esc_py(k)}</div>
          <div style="font:400 13px var(--ff-mono);color:#9aa1ab">{esc_py(v)}</div>
        </div>""" for k, v in rows)

    return HTMLResponse(f"""
    <!-- Connection status band -->
    <div style="display:flex;align-items:center;gap:11px;padding:11px 14px;
                background:rgba(74,222,128,0.07);border:1px solid rgba(74,222,128,0.22);
                border-radius:11px;{'display:none' if not connected else ''}">
      <span style="width:8px;height:8px;border-radius:50%;background:#4ade80;flex:none"></span>
      <div style="font-size:12.5px;color:#cbd0d7">
        Connected to <strong style="color:#e7e9ec">Keycloak</strong>
        · {status_note}
      </div>
      {status_pill}
    </div>

    <div style="font-size:14px;font-weight:700;color:#e7e9ec;margin-top:4px">OIDC configuration</div>

    <!-- Config table -->
    <div class="srv-tbl">
      {rows_html}
    </div>

    <div style="display:flex;gap:10px;margin-top:4px">
      <button class="btn-register-srv" style="font-size:12px;padding:7px 12px"
              onclick="document.getElementById('oidc-reconfig-note').style.display=document.getElementById('oidc-reconfig-note').style.display==='none'?'block':'none'">Reconfigure</button>
      <button style="background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);
                     color:#9aa1ab;font-size:12px;padding:7px 12px;border-radius:8px;cursor:pointer;
                     font-family:var(--ff-sans)"
              onclick="document.getElementById('oidc-reconfig-note').style.display=document.getElementById('oidc-reconfig-note').style.display==='none'?'block':'none'">Test connection</button>
    </div>
    <div id="oidc-reconfig-note" style="display:none;margin-top:12px;padding:14px 16px;
         background:#13151a;border:1px solid #2a2d35;border-radius:10px;font-size:12.5px;color:#9aa1ab;line-height:1.6">
      OIDC reconfiguration is applied via environment variables on the proxy container.<br>
      Restart the proxy after changing these values:
      <ul style="margin:8px 0 0 18px">
        <li><code style="color:var(--cyan)">OIDC_ISSUER_URL</code> — discovery endpoint (e.g. <code>https://keycloak/realms/mcp</code>)</li>
        <li><code style="color:var(--cyan)">OIDC_AUDIENCE</code> — expected <code>aud</code> claim in access tokens</li>
        <li><code style="color:var(--cyan)">OIDC_CLIENT_ID</code> — client registered in the IdP</li>
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
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
    <div style="font-size:14px;font-weight:700;color:#e7e9ec">Request Limits</div>
    <button class="btn-primary btn-sm" onclick="limitsRefresh()">&#x21BB; Refresh</button>
  </div>

  <div id="limits-table-wrap">
    <div class="loading-state"><span class="spinner"></span> Loading…</div>
  </div>

  <!-- Edit drawer -->
  <div id="limits-drawer" style="display:none;margin-top:20px;background:#13151a;border:1px solid #2a2d35;border-radius:10px;padding:18px">
    <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:12px">
      Edit limits for <code id="limits-edit-cid" style="color:var(--cyan)"></code>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">
      <div>
        <label style="font-size:12px;color:#9aa1ab;display:block;margin-bottom:4px">Rate limit (req/window)</label>
        <input id="limits-edit-rl" type="number" min="1" max="100000"
               style="width:100%;background:#0d0f14;border:1px solid #2a2d35;border-radius:6px;color:#e7e9ec;padding:6px 10px;font-size:13px">
      </div>
      <div>
        <label style="font-size:12px;color:#9aa1ab;display:block;margin-bottom:4px">Anomaly sensitivity</label>
        <select id="limits-edit-sens"
                style="width:100%;background:#0d0f14;border:1px solid #2a2d35;border-radius:6px;color:#e7e9ec;padding:6px 10px;font-size:13px">
          <option value="normal">normal</option>
          <option value="lenient">lenient</option>
          <option value="off">off</option>
        </select>
      </div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn-primary btn-sm" onclick="limitsSave()">Save</button>
      <button class="btn-sm" onclick="limitsReset('both')"
              style="background:#2a2d35;border:none;color:#e7e9ec;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px">
        Reset counters
      </button>
      <button class="btn-sm" onclick="limitsCloseDrawer()"
              style="background:transparent;border:1px solid #2a2d35;color:#9aa1ab;padding:6px 14px;border-radius:6px;cursor:pointer;font-size:12px">
        Cancel
      </button>
    </div>
    <div id="limits-drawer-msg" style="margin-top:8px;font-size:12px"></div>
  </div>
</div>

<style>
.limits-table { width:100%; border-collapse:collapse; font-size:13px; }
.limits-table th { text-align:left; color:#9aa1ab; font-weight:500; padding:6px 10px; border-bottom:1px solid #2a2d35; }
.limits-table td { padding:8px 10px; border-bottom:1px solid #1a1d24; color:#e7e9ec; vertical-align:middle; }
.limits-table tr:hover td { background:#13151a; }
.lbadge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
.lbadge-ok   { background:#16231a; color:#4ade80; }
.lbadge-warn { background:#251f10; color:#fbbf24; }
.lbadge-block{ background:#2a1010; color:#f87171; }
.lbadge-mode { background:#1a1d24; color:#9aa1ab; }
</style>

<script>
(function() {
  function pct(count, limit) { return limit > 0 ? Math.round(count / limit * 100) : 0; }

  function renderTable(data) {
    if (!data.limits || !data.limits.length) {
      document.getElementById('limits-table-wrap').innerHTML =
        '<div style="color:#9aa1ab;font-size:13px;padding:16px 0">No clients seen in the last 24 hours.</div>';
      return;
    }
    window._limitsRowMap = new Map(data.limits.map(c => [c.client_id, c]));
    const rows = data.limits.map(c => {
      const p = pct(c.rate.count, c.rate.limit);
      const rateCls = p >= 100 ? 'lbadge-block' : p >= 75 ? 'lbadge-warn' : 'lbadge-ok';
      const anCls   = c.anomaly.window_calls >= c.anomaly.cutoff ? 'lbadge-block'
                    : c.anomaly.window_calls >= c.anomaly.cutoff * 0.75 ? 'lbadge-warn' : 'lbadge-ok';
      const override = c.rate.is_override
        ? '<span class="lbadge lbadge-mode" style="margin-left:4px">override</span>' : '';
      return `<tr>
        <td><code style="color:var(--cyan)">${esc(c.client_id)}</code></td>
        <td><span class="lbadge ${rateCls}">${c.rate.count} / ${c.rate.limit}</span>${override}</td>
        <td><span class="lbadge ${anCls}">${c.anomaly.window_calls} / ${c.anomaly.cutoff}</span></td>
        <td><span class="lbadge lbadge-mode">${esc(c.anomaly.sensitivity)}</span></td>
        <td style="color:#9aa1ab;font-size:11px">${c.updated_by ? esc(c.updated_by) : '—'}</td>
        <td>
          <button class="limits-edit-btn btn-sm" data-cid="${esc(c.client_id)}"
                  style="background:#1e2230;border:1px solid #2a2d35;color:#e7e9ec;padding:4px 10px;border-radius:5px;cursor:pointer;font-size:11px">
            Edit
          </button>
        </td>
      </tr>`;
    }).join('');
    document.getElementById('limits-table-wrap').innerHTML = `
      <table class="limits-table">
        <thead><tr>
          <th>Client</th><th>Rate (used/limit)</th><th>Anomaly (calls/cutoff)</th>
          <th>Sensitivity</th><th>Last changed by</th><th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="margin-top:10px;font-size:11.5px;color:#5b626c;line-height:1.5">
        <strong style="color:#717983">unauthenticated</strong> = requests counted by the
        rate limiter before authentication resolved (bot probes, health checks, unauthenticated
        endpoint hits). This is intentional: the gateway rate-limits all traffic, not just
        authenticated clients.
      </div>`;
    document.querySelectorAll('.limits-edit-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const c = window._limitsRowMap.get(btn.dataset.cid);
        if (c) limitsEdit(c);
      });
    });
  }

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  window.limitsRefresh = function() {
    document.getElementById('limits-table-wrap').innerHTML =
      '<div class="loading-state"><span class="spinner"></span> Loading…</div>';
    fetch('/api/v1/admin/limits', {credentials: 'include'})
      .then(r => r.json()).then(renderTable)
      .catch(() => {
        document.getElementById('limits-table-wrap').innerHTML =
          '<div style="color:#f87171;font-size:13px">Failed to load limits.</div>';
      });
  };

  window.limitsEdit = function(c) {
    document.getElementById('limits-edit-cid').textContent = c.client_id;
    document.getElementById('limits-edit-rl').value = c.rate.limit;
    document.getElementById('limits-edit-sens').value = c.anomaly.sensitivity;
    document.getElementById('limits-drawer-msg').textContent = '';
    document.getElementById('limits-drawer').style.display = 'block';
    document.getElementById('limits-drawer').dataset.cid = c.client_id;
  };

  window.limitsCloseDrawer = function() {
    document.getElementById('limits-drawer').style.display = 'none';
  };

  window.limitsSave = function() {
    const cid  = document.getElementById('limits-drawer').dataset.cid;
    const rl   = parseInt(document.getElementById('limits-edit-rl').value, 10);
    const sens = document.getElementById('limits-edit-sens').value;
    const msg  = document.getElementById('limits-drawer-msg');
    fetch('/api/v1/admin/limits/' + encodeURIComponent(cid), {
      method: 'PUT',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({rate_limit: rl, anomaly_sensitivity: sens}),
    }).then(r => r.json()).then(d => {
      if (d.ok) { msg.style.color='#4ade80'; msg.textContent='Saved.'; limitsRefresh(); }
      else       { msg.style.color='#f87171'; msg.textContent='Error: ' + JSON.stringify(d); }
    }).catch(e => { msg.style.color='#f87171'; msg.textContent='Request failed.'; });
  };

  window.limitsReset = function(target) {
    const cid = document.getElementById('limits-drawer').dataset.cid;
    const msg = document.getElementById('limits-drawer-msg');
    fetch('/api/v1/admin/limits/' + encodeURIComponent(cid) + '/reset', {
      method: 'POST',
      credentials: 'include',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({target}),
    }).then(r => r.json()).then(d => {
      if (d.ok) { msg.style.color='#4ade80'; msg.textContent='Counters reset.'; limitsRefresh(); }
      else       { msg.style.color='#f87171'; msg.textContent='Error: ' + JSON.stringify(d); }
    }).catch(() => { msg.style.color='#f87171'; msg.textContent='Request failed.'; });
  };

  limitsRefresh();
})();
</script>
""")


# ---------------------------------------------------------------------------
# Fragment: Admin > Dashboard / Detections (stubs)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/dashboard", response_class=HTMLResponse)
async def fragment_admin_dashboard(request: Request):
    _require_admin(request)
    return HTMLResponse("""
    <div style="font-size:14px;font-weight:700;color:#e7e9ec">Security Dashboard</div>
    <div style="font-size:13px;color:#9aa1ab;margin-top:4px">Coming soon.</div>
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


@router.get("/fragments/admin/detections", response_class=HTMLResponse)
async def fragment_admin_detections(request: Request, days: int = 7):
    _require_admin(request)
    days = max(1, min(days, 90))  # clamp to [1, 90]

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

            # B) recent detections feed
            feed_rows = (await session.execute(text("""
                SELECT event_ts, client_id, tool_name, opa_reasons, original_outcome
                FROM audit_events
                WHERE (outcome = 'deny' OR original_outcome = 'error')
                  AND event_ts > now() - (interval '1 day' * :days)
                ORDER BY event_ts DESC
                LIMIT 100
            """), {"days": days})).fetchall()

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
        active = 'background:rgba(255,255,255,0.08);' if d == days else ''
        return (f'<button onclick="htmx.ajax(\'GET\',\'/portal/fragments/admin/detections?days={d}\','
                f'{{target:\'#adm-content\',swap:\'innerHTML\'}})" '
                f'style="{active}background:none;border:none;cursor:pointer;padding:5px 10px;'
                f'border-radius:6px;color:#9aa1ab;font-size:12px;font-family:var(--ff-sans)">{label}</button>')

    summary_html = f"""
    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.75rem">
      <span style="color:var(--muted);font-size:12px">Window:</span>
      {_win_btn(1,'24 h')}{_win_btn(7,'7 d')}{_win_btn(30,'30 d')}
    </div>
    <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:1.25rem">
      <div style="{_card}"><div style="{_num}">{total_detections}</div><div style="{_lbl}">Total detections</div></div>
      <div style="{_card}"><div style="{_sev_num('high')}">{sev_totals['high']}</div><div style="{_lbl}">High severity</div></div>
      <div style="{_card}"><div style="{_sev_num('medium')}">{sev_totals['medium']}</div><div style="{_lbl}">Medium severity</div></div>
      <div style="{_card}"><div style="{_sev_num('low')}">{sev_totals['low']}</div><div style="{_lbl}">Low severity</div></div>
    </div>"""

    # --- Top detections breakdown ---
    top_rows_html = ""
    for reason, n in sorted(reason_counts.items(), key=lambda x: -x[1])[:15]:
        name, sev = _classify(reason)
        sev_badge = _badge(sev.upper(), f"badge-risk-{sev}")
        top_rows_html += f"""
        <tr>
          <td>{esc_py(name)}</td>
          <td><span style="font-family:var(--ff-mono);font-size:0.75rem;color:var(--muted)">{esc_py(reason)}</span></td>
          <td>{sev_badge}</td>
          <td style="text-align:right;font-weight:600">{n}</td>
        </tr>"""

    top_table = f"""
    <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:0.5rem">Top detections — last {days}d</div>
    <div class="tbl-wrap" style="margin-bottom:1.25rem">
      <table>
        <thead><tr><th>Detection</th><th>Raw reason</th><th>Severity</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>{top_rows_html if top_rows_html else '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.5rem">No detections in this window.</td></tr>'}</tbody>
      </table>
    </div>""" if reason_counts else f"""
    <div style="background:var(--panel,#11161f);border:1px solid var(--border,#222b3a);border-radius:9px;
         padding:2rem;text-align:center;color:var(--muted);font-size:13px;margin-bottom:1.25rem">
      No detections in the last {days} day{'s' if days != 1 else ''}. &#x2705;
    </div>"""

    # --- Recent feed ---
    import json as _json
    feed_html_rows = []
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
            badges = '<span style="color:var(--muted);font-size:0.75rem">deny</span>'
        feed_html_rows.append(f"""
        <tr>
          <td style="white-space:nowrap;color:var(--muted);font-size:0.78rem">{esc_py(ts)}</td>
          <td style="font-family:var(--ff-mono);font-size:0.78rem">{esc_py(row.client_id or "—")}</td>
          <td style="font-size:0.78rem">{esc_py(row.tool_name or "—")}</td>
          <td>{badges}</td>
        </tr>""")

    feed_table = f"""
    <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:0.5rem">Recent detections</div>
    <div class="tbl-wrap" style="margin-bottom:1.25rem">
      <table>
        <thead><tr><th>Time</th><th>Principal</th><th>Tool</th><th>Detection(s)</th></tr></thead>
        <tbody>{"".join(feed_html_rows) if feed_html_rows else '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:1.5rem">No recent detections.</td></tr>'}</tbody>
      </table>
    </div>"""

    # --- Phase 2: Behavioural panel ---
    behav_sections = []

    if brute_rows:
        brows = "".join(
            f'<tr><td style="font-family:var(--ff-mono);font-size:0.78rem">{esc_py(r.client_id or "—")}</td>'
            f'<td style="text-align:right;font-weight:600;color:#f87171">{r.denies}</td>'
            f'<td style="color:var(--muted);font-size:0.78rem">{r.last_seen.strftime("%H:%M:%S") if r.last_seen else "—"}</td></tr>'
            for r in brute_rows
        )
        behav_sections.append(f"""
        <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:0.5rem">
          Repeated denials <span style="font-weight:400;color:var(--muted);font-size:11px">(≥{_BRUTE_DENY_COUNT} denies / {_BRUTE_DENY_MINUTES} min)</span>
        </div>
        <div class="tbl-wrap" style="margin-bottom:1.25rem">
          <table>
            <thead><tr><th>Principal</th><th style="text-align:right">Denies</th><th>Last seen</th></tr></thead>
            <tbody>{brows}</tbody>
          </table>
        </div>""")

    if spray_rows:
        srows = "".join(
            f'<tr><td style="font-family:var(--ff-mono);font-size:0.78rem">{esc_py(r.client_id or "—")}</td>'
            f'<td style="text-align:right;font-weight:600;color:#fbbf24">{r.tools}</td></tr>'
            for r in spray_rows
        )
        behav_sections.append(f"""
        <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:0.5rem">
          Tool spray / enumeration <span style="font-weight:400;color:var(--muted);font-size:11px">(≥{_SPRAY_TOOL_COUNT} distinct tools / {_SPRAY_HOURS}h)</span>
        </div>
        <div class="tbl-wrap" style="margin-bottom:1.25rem">
          <table>
            <thead><tr><th>Principal</th><th style="text-align:right">Distinct tools</th></tr></thead>
            <tbody>{srows}</tbody>
          </table>
        </div>""")

    if inject_rows:
        irows = "".join(
            f'<tr><td style="font-family:var(--ff-mono);font-size:0.78rem">{esc_py(r.client_id or "—")}</td>'
            f'<td style="text-align:right;font-weight:600;color:#f87171">{r.hits}</td></tr>'
            for r in inject_rows
        )
        behav_sections.append(f"""
        <div style="font-size:13px;font-weight:600;color:#e7e9ec;margin-bottom:0.5rem">
          Repeat injection offenders <span style="font-weight:400;color:var(--muted);font-size:11px">(last {days}d)</span>
        </div>
        <div class="tbl-wrap" style="margin-bottom:1.25rem">
          <table>
            <thead><tr><th>Principal</th><th style="text-align:right">Injection hits</th></tr></thead>
            <tbody>{irows}</tbody>
          </table>
        </div>""")

    behav_html = ""
    if behav_sections:
        behav_html = f"""
        <div style="font-size:13px;font-weight:700;color:#e7e9ec;margin-bottom:0.75rem;
             padding-top:0.75rem;border-top:1px solid var(--border,#222b3a)">
          &#x26A0;&#xFE0F; Behavioural detections
        </div>
        {"".join(behav_sections)}"""

    return HTMLResponse(f"""
    <div class="section-title">&#x1F6A8; Detections</div>
    <p style="color:var(--muted);font-size:0.82rem;margin:0 0 1rem">
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
async def fragment_admin_tools(request: Request):
    """Admin tools management sub-tab."""
    _require_admin(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(text("""
                SELECT tool_id, name, version, status, risk_level, risk_score,
                       injection_mode, upstream_url, tags, created_at
                FROM tool_registry
                WHERE deleted_at IS NULL
                ORDER BY name
            """))
            tools = result.fetchall()
    except Exception as exc:
        logger.error("portal admin/tools DB error: %s", exc)
        return HTMLResponse(_error_fragment("Database error loading tools."))

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
          <td style="color:var(--muted)">{esc_py(t.version or "")}</td>
          <td>{_badge(status, f"badge-{status}")}</td>
          <td>{_badge(risk.upper(), f"badge-risk-{risk}")}</td>
          <td style="color:var(--muted);font-size:0.78rem">{t.risk_score if t.risk_score is not None else "—"}</td>
          <td>{_badge(mode, f"badge-mode-{mode.replace(' ', '_')}")}</td>
          <td style="color:var(--muted);font-size:0.75rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{esc_py(t.upstream_url or "—")}</td>
          <td>
            <button class="btn-secondary btn-sm" style="{'background:#7f1d1d;color:#fca5a5' if status == 'active' else ''}"
                    onclick="toggleStatus('{esc_py(tool_id)}', '{esc_py(toggle_action)}')">{esc_py(toggle_label)}</button>
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
        <tbody>{"".join(rows) if rows else '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:2rem">No tools registered.</td></tr>'}</tbody>
      </table>
    </div>"""

    register_form = """
    <hr class="divider">
    <div class="section-title">&#x2795; Register Tool</div>
    <form id="reg-form" style="max-width:600px">
      <div class="row">
        <div>
          <label>Tool Name *</label>
          <input type="text" name="name" required placeholder="my-tool">
        </div>
        <div>
          <label>Version *</label>
          <input type="text" name="version" required placeholder="1.0.0">
        </div>
      </div>
      <label>Description</label>
      <input type="text" name="description" placeholder="What does this tool do?">
      <div class="row" style="margin-top:0.5rem">
        <div>
          <label>Upstream URL *</label>
          <input type="url" name="upstream_url" required placeholder="https://tool.internal">
        </div>
        <div>
          <label>Risk Level</label>
          <select name="risk_level">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>
      </div>
      <div class="row" style="margin-top:0.5rem">
        <div>
          <label>Injection Mode</label>
          <select name="injection_mode">
            <option value="none">None</option>
            <option value="header">Header</option>
            <option value="user">User</option>
            <option value="service">Service</option>
            <option value="service_account">Service Account</option>
            <option value="oauth_user_token">OAuth User Token</option>
          </select>
        </div>
        <div>
          <label>Tags (comma-separated)</label>
          <input type="text" name="tags" placeholder="monitoring, dcim">
        </div>
      </div>
      <div style="margin-top:0.75rem">
        <button type="button" class="btn-primary" onclick="registerTool()">Register Tool</button>
      </div>
      <div id="reg-msg"></div>
    </form>

    <script>
    function registerTool() {
      const form = document.getElementById('reg-form');
      const fd = new FormData(form);
      const tagsRaw = fd.get('tags') || '';
      const tags = tagsRaw.split(',').map(s => s.trim()).filter(Boolean);
      const body = {
        name: fd.get('name'),
        version: fd.get('version'),
        description: fd.get('description') || null,
        upstream_url: fd.get('upstream_url'),
        risk_level: fd.get('risk_level'),
        injection_mode: fd.get('injection_mode'),
        tags: tags,
      };
      const msgEl = document.getElementById('reg-msg');
      fetch('/api/v1/tools/register', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body),
      }).then(r => r.json().then(d => {
        if (r.ok) {
          showMsg(msgEl, 'ok', 'Tool registered. Reloading...');
          setTimeout(() => activateAdminTab('tools'), 1200);
        } else {
          const m = d.detail?.message || d.detail || JSON.stringify(d);
          showMsg(msgEl, 'err', String(m));
        }
      })).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }
    function toggleStatus(toolId, newStatus) {
      if (!confirm('Set tool status to "' + newStatus + '"?')) return;
      fetch('/api/v1/tools/' + toolId, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: newStatus}),
      }).then(r => {
        if (r.ok) activateAdminTab('tools');
        else r.json().then(d => alert('Error: ' + (d.detail?.message || d.detail || r.status)));
      }).catch(e => alert('Network error: ' + e));
    }
    function showMsg(el, type, text) {
      if (!el) return;
      el.className = 'msg msg-' + type;
      el.textContent = text;
    }
    </script>"""

    return HTMLResponse(f"""
    <div class="section-title">&#x1F527; Registered Tools <span class="count">{len(tools)}</span></div>
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
        'onclick="loadAdminTab(\'sbom\')">Clear</button>' if q else ""
    )
    search_box = f"""
    <form style="margin-bottom:1rem;display:flex;gap:0.5rem;align-items:center"
          onsubmit="event.preventDefault();htmx.ajax('GET',
            '/portal/fragments/admin/sbom?q='+encodeURIComponent(this.q.value),
            {{target:'#adm-content',swap:'innerHTML'}})">
      <input name="q" type="text" placeholder="Search components (name or purl)…"
             value="{esc_py(q)}"
             style="flex:1;background:#13161d;border:1px solid #2a2d35;border-radius:7px;
                    padding:7px 11px;color:#cbd0d7;font-size:13px;font-family:var(--ff-sans)"/>
      <button type="submit" class="btn-register-srv" style="padding:7px 14px;font-size:12px">Search</button>
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
              <td style="color:var(--muted)">{esc_py(r.comp_version or "—")}</td>
              <td>{_badge((r.comp_type or "unknown"), "badge-info")}</td>
              <td style="color:var(--muted);font-size:0.75rem;word-break:break-all">{esc_py(r.comp_purl or "—")}</td>
            </tr>""")

        cap_note = (
            '<p style="color:var(--muted);font-size:0.78rem;margin-top:0.5rem">'
            'Results capped at 200 — refine your search.</p>' if capped else ""
        )
        s_table = f"""
        <div class="tbl-wrap">
          <table>
            <thead>
              <tr><th>Tool</th><th>Component</th><th>Version</th><th>Type</th><th>PURL</th></tr>
            </thead>
            <tbody>{"".join(s_rows) if s_rows else '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:2rem">No components matched.</td></tr>'}</tbody>
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
                       s.component_count, s.signed, s.auditor_version, s.generated_at
                FROM tool_registry t
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
    for r in recs:
        tool_id = str(r.tool_id)
        risk = (r.risk_level or "low").lower()
        has_sbom = r.generated_at is not None
        if not has_sbom:
            sbom_cell = _badge("MISSING", "badge-risk-high")
            comp_cell = '<span style="color:var(--muted)">—</span>'
            signed_cell = '<span style="color:var(--muted)">—</span>'
            ver_cell = '<span style="color:var(--muted)">—</span>'
            gen_cell = '<span style="color:var(--muted)">never</span>'
            action_cell = '<span style="color:var(--muted);font-size:0.75rem">no SBOM</span>'
        else:
            sbom_cell = _badge("PRESENT", "badge-active")
            comp_cell = str(r.component_count if r.component_count is not None else 0)
            signed_cell = (_badge("signed", "badge-active") if r.signed
                           else _badge("UNSIGNED", "badge-risk-high"))
            ver_cell = f'<span style="color:var(--muted);font-size:0.78rem">{esc_py(r.auditor_version or "—")}</span>'
            gen_cell = f'<span style="color:var(--muted);font-size:0.78rem">{r.generated_at.strftime("%Y-%m-%d %H:%M")}</span>'
            action_cell = (  # ponytail: htmx.ajax swap — no full-page reload needed
                f'<button class="btn-secondary btn-sm" '
                f'onclick="htmx.ajax(\'GET\',\'/portal/fragments/admin/sbom/{esc_py(tool_id)}\','
                f'{{target:\'#adm-content\',swap:\'innerHTML\'}})">Components</button>'
                f' <a class="btn-secondary btn-sm" target="_blank" rel="noopener" '
                f'href="/api/v1/tools/{esc_py(tool_id)}/sbom">JSON</a>'
            )

        rows.append(f"""
        <tr>
          <td><strong>{esc_py(r.name or "")}</strong></td>
          <td style="color:var(--muted)">{esc_py(r.version or "")}</td>
          <td>{_badge((r.status or "unknown"), f"badge-{r.status or 'unknown'}")}</td>
          <td>{_badge(risk.upper(), f"badge-risk-{risk}")}</td>
          <td>{sbom_cell}</td>
          <td style="text-align:right">{comp_cell}</td>
          <td>{signed_cell}</td>
          <td>{ver_cell}</td>
          <td>{gen_cell}</td>
          <td>{action_cell}</td>
        </tr>""")

    _card = (
        'background:var(--panel,#11161f);border:1px solid var(--border,#222b3a);'
        'border-radius:9px;padding:0.85rem 1rem;flex:1;min-width:120px'
    )
    _num = "font-size:1.5rem;font-weight:700;line-height:1.1"
    _lbl = "color:var(--muted);font-size:0.72rem;text-transform:uppercase;letter-spacing:.04em;margin-top:.2rem"
    summary = f"""
    <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:1rem">
      <div style="{_card}"><div style="{_num}">{total}</div><div style="{_lbl}">Registered tools</div></div>
      <div style="{_card}"><div style="{_num}">{with_sbom}</div><div style="{_lbl}">With SBOM</div></div>
      <div style="{_card}"><div style="{_num};{'color:#fca5a5' if missing else ''}">{missing}</div><div style="{_lbl}">Missing SBOM</div></div>
      <div style="{_card}"><div style="{_num}">{total_components}</div><div style="{_lbl}">Total components</div></div>
    </div>"""

    table_html = f"""
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr>
            <th>Tool</th><th>Version</th><th>Status</th><th>Risk</th><th>SBOM</th>
            <th style="text-align:right">Components</th><th>Signature</th>
            <th>Auditor</th><th>Generated</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>{"".join(rows) if rows else '<tr><td colspan="10" style="text-align:center;color:var(--muted);padding:2rem">No tools registered.</td></tr>'}</tbody>
      </table>
    </div>"""

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E6; SBOM Inventory</div>
    <p style="color:var(--muted);font-size:0.82rem;margin:0 0 1rem">
      Signed CycloneDX SBOMs per registered tool (INV-006). Tools missing an SBOM cannot be activated.
    </p>
    {summary}
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
        '<button class="btn-secondary btn-sm" style="margin-bottom:1rem" '
        'onclick="loadAdminTab(\'sbom\')">&#8592; Back to inventory</button>'
    )
    dl_link = (
        f'<a class="btn-secondary btn-sm" target="_blank" rel="noopener" '
        f'href="/api/v1/tools/{esc_py(tool_id)}/sbom" style="margin-bottom:1rem">Download JSON</a>'
    )

    tool_name = esc_py(rec.tool_name or tool_id)

    if rec.cyclonedx_json is None:
        return HTMLResponse(f"""
        <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
        {back}
        <p style="color:var(--muted)">No SBOM found for this tool.</p>""")

    cdx = rec.cyclonedx_json
    components = cdx.get("components", []) if isinstance(cdx, dict) else []

    if not components:
        return HTMLResponse(f"""
        <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
        {back}
        <p style="color:var(--muted)">SBOM present but components array is empty.</p>""")

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
        rows.append(f"""
        <tr>
          <td><strong>{esc_py(c.get('name') or '')}</strong></td>
          <td style="color:var(--muted)">{esc_py(c.get('version') or '—')}</td>
          <td>{_badge(ctype, "badge-info")}</td>
          <td style="color:var(--muted);font-size:0.75rem;word-break:break-all">{esc_py(c.get('purl') or '—')}</td>
          <td style="color:var(--muted);font-size:0.75rem">{esc_py(lic_str)}</td>
        </tr>""")

    gen_str = rec.generated_at.strftime("%Y-%m-%d %H:%M") if rec.generated_at else "unknown"
    auditor = esc_py(rec.auditor_version or "—")

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E6; Components — {tool_name}</div>
    <div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:1rem">
      {back}
      {dl_link}
    </div>
    <p style="color:var(--muted);font-size:0.82rem;margin:0 0 1rem">
      {len(components)} component(s) &nbsp;·&nbsp; generated {esc_py(gen_str)} &nbsp;·&nbsp; auditor {auditor}
    </p>
    <div class="tbl-wrap">
      <table>
        <thead>
          <tr><th>Name</th><th>Version</th><th>Type</th><th>PURL</th><th>Licenses</th></tr>
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
            <div style="margin-top:0.5rem">
              <label>Secret</label>
              <input type="password" id="cred-{esc_py(tool_id)}" placeholder="Paste secret" autocomplete="new-password">
              <div class="row" style="margin-top:0.5rem">
                <div>
                  <label>Owner type</label>
                  <select id="owner-{esc_py(tool_id)}">
                    <option value="service">service</option>
                    <option value="user">user</option>
                  </select>
                </div>
                <div>
                  <label>Injection mode</label>
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
              <div style="display:flex;gap:0.5rem;margin-top:0.75rem">
                <button class="btn-primary btn-sm" onclick="uploadCred('{esc_py(tool_id)}')">Upload</button>
                <button class="btn-danger btn-sm" onclick="revokeCred('{esc_py(tool_id)}')">Revoke</button>
              </div>
              <div id="cred-msg-{esc_py(tool_id)}"></div>
            </div>
          </details>"""
        else:
            cred_section = '<div style="margin-top:0.5rem;font-size:0.78rem;color:var(--muted)">No credential injection configured for this server.</div>'

        cards.append(f"""
        <div class="tool-card">
          <div class="tool-card-header">
            <div>
              <div class="tool-name">{esc_py(t.name or "")}</div>
              <div class="tool-version">v{esc_py(t.version or "")}</div>
            </div>
            <div style="display:flex;gap:0.3rem;align-items:center">
              {_badge(t.status or "unknown", f"badge-{t.status or 'pending'}")}
              {cred_badge}
            </div>
          </div>
          <div style="font-size:0.8rem;color:var(--muted);margin-bottom:0.5rem">
            Mode: {_badge(mode, f"badge-mode-{mode}")}
            &nbsp;|&nbsp;
            Service: <code style="color:var(--cyan)">{esc_py(t.service_name or "—")}</code>
          </div>
          {cred_section}
        </div>""")

    html = f"""
    <div class="section-title">&#x1F511; Credential Status <span class="count">{len(tools)}</span></div>
    <div class="card-grid">{"".join(cards)}</div>
    <script>
    function uploadCred(toolId) {{
      const secret = document.getElementById('cred-' + toolId)?.value?.trim();
      const ownerType = document.getElementById('owner-' + toolId)?.value || 'service';
      const msgEl = document.getElementById('cred-msg-' + toolId);
      if (!secret) {{ showMsg(msgEl, 'err', 'Enter a secret first.'); return; }}
      fetch('/admin/credentials/' + toolId, {{
        method: 'PUT',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{secret, owner_type: ownerType}})
      }}).then(r => r.json().then(d => {{
        if (r.ok) {{ showMsg(msgEl, 'ok', 'Uploaded.'); activateAdminTab('credentials'); }}
        else showMsg(msgEl, 'err', d.detail?.message || d.detail || 'Failed.');
      }})).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }}
    function revokeCred(toolId) {{
      if (!confirm('Revoke credential for this tool?')) return;
      const msgEl = document.getElementById('cred-msg-' + toolId);
      fetch('/admin/credentials/' + toolId, {{method: 'DELETE'}})
        .then(r => {{
          if (r.ok) {{ showMsg(msgEl, 'ok', 'Revoked.'); activateAdminTab('credentials'); }}
          else r.json().then(d => showMsg(msgEl, 'err', d.detail?.message || d.detail || 'Failed.'));
        }}).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }}
    function showMsg(el, type, text) {{
      if (!el) return;
      el.className = 'msg msg-' + type;
      el.textContent = text;
    }}
    </script>"""
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
          <div class="row" style="margin-top:0.5rem">
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
    <p style="font-size:0.83rem;color:var(--muted);margin-bottom:1rem">
      Edit grants below then click <strong style="color:var(--text)">Save All Grants</strong>.
      OPA will pick up the new <code style="color:var(--cyan)">data.json</code> within ~5 seconds.
    </p>

    <div id="grant-cards">{"".join(cards)}</div>

    <div style="margin-top:0.5rem;display:flex;gap:0.75rem;align-items:center">
      <button class="btn-primary" onclick="saveGrants()">Save All Grants</button>
      <button class="btn-secondary" onclick="addClient()">+ Add Identity</button>
      <span id="grants-msg" style="font-size:0.83rem"></span>
    </div>

    <hr class="divider">
    <div class="section-title">&#x1F4C4; Raw data.json</div>
    <div class="code-block" id="raw-grants">{grants_json_escaped}</div>

    <script>
    function collectGrants() {{
      const grants = {{}};
      document.querySelectorAll('.grant-card[id^="grant-"]').forEach(card => {{
        const client = card.id.replace('grant-', '');
        const toolsRaw = document.getElementById('tools-' + client)?.value || '';
        const tagsRaw  = document.getElementById('tags-' + client)?.value || '';
        const maxRisk  = document.getElementById('risk-' + client)?.value || 'high';
        const tools = toolsRaw.split(',').map(s => s.trim()).filter(Boolean);
        const tags  = tagsRaw.split(',').map(s => s.trim()).filter(Boolean);
        grants[client] = {{allowed_tools: tools, allowed_tags: tags, max_risk_level: maxRisk}};
      }});
      return grants;
    }}
    function saveGrants() {{
      const msgEl = document.getElementById('grants-msg');
      const grants = collectGrants();
      fetch('/portal/actions/save-grants', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{grants}})
      }}).then(r => r.json().then(d => {{
        if (r.ok) {{
          msgEl.className = 'msg msg-ok';
          msgEl.textContent = 'Saved. OPA will reload in ~5s.';
          const raw = document.getElementById('raw-grants');
          if (raw) raw.textContent = JSON.stringify({{mcp: {{grants}}}}, null, 2);
          setTimeout(() => {{ msgEl.textContent = ''; msgEl.className = ''; }}, 6000);
        }} else {{
          msgEl.className = 'msg msg-err';
          msgEl.textContent = d.detail?.message || d.detail || 'Save failed.';
        }}
      }})).catch(e => {{
        msgEl.className = 'msg msg-err';
        msgEl.textContent = 'Network error: ' + e;
      }});
    }}
    function addClient() {{
      const client = prompt('New client_id:');
      if (!client) return;
      const container = document.getElementById('grant-cards');

      // Build the card entirely with DOM APIs — no innerHTML with user input.
      const card = document.createElement('div');
      card.className = 'grant-card';
      // card.id is set via property (safe — not interpreted as HTML)
      card.id = 'grant-' + client;

      const heading = document.createElement('div');
      heading.className = 'grant-client';
      heading.textContent = client;          // textContent: never interpreted as HTML
      card.appendChild(heading);

      const lbl1 = document.createElement('label');
      lbl1.textContent = 'Allowed tools (comma-separated)';
      card.appendChild(lbl1);

      const toolsInput = document.createElement('input');
      toolsInput.type = 'text';
      toolsInput.id = 'tools-' + client;
      toolsInput.placeholder = 'tool-a, tool-b';
      card.appendChild(toolsInput);

      const row = document.createElement('div');
      row.className = 'row';
      row.style.marginTop = '0.5rem';

      // Tags column
      const tagsCol = document.createElement('div');
      const lbl2 = document.createElement('label');
      lbl2.textContent = 'Allowed tags';
      const tagsInput = document.createElement('input');
      tagsInput.type = 'text';
      tagsInput.id = 'tags-' + client;
      tagsInput.placeholder = 'monitoring, dcim';
      tagsCol.appendChild(lbl2);
      tagsCol.appendChild(tagsInput);

      // Risk column
      const riskCol = document.createElement('div');
      const lbl3 = document.createElement('label');
      lbl3.textContent = 'Max risk level';
      const riskSel = document.createElement('select');
      riskSel.id = 'risk-' + client;
      [['low','Low'],['medium','Medium'],['high','High'],['critical','Critical']].forEach(([val, label]) => {{
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = label;
        if (val === 'medium') opt.selected = true;
        riskSel.appendChild(opt);
      }});
      riskCol.appendChild(lbl3);
      riskCol.appendChild(riskSel);

      row.appendChild(tagsCol);
      row.appendChild(riskCol);
      card.appendChild(row);

      container.appendChild(card);
    }}
    </script>"""
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
# Submissions tab (admin review queue)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin/submissions", response_class=HTMLResponse)
async def fragment_admin_submissions(request: Request):
    """Security team review queue — all non-draft submissions."""
    _require_admin(request)
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            rows = (await session.execute(text("""
                SELECT server_id, name, owner_sub, submission_status, scan_status,
                       injection_mode, data_categories, has_write_ops,
                       github_repo_url, scan_report, review_notes, updated_at
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
        "rejected":           ("#dc2626", "Rejected"),
        "active":             ("#16a34a", "Active"),
    }
    _SENSE_LABEL = {
        "pii": "PII", "financial": "Financial", "health": "Health",
        "internal_docs": "Internal Docs", "source_code": "Source Code",
        "email_calendar": "Email/Calendar", "infrastructure": "Infrastructure",
        "public": "Public",
    }

    if not rows:
        empty = '<div style="color:var(--muted);padding:2rem 0">No submissions in the queue.</div>'
        return HTMLResponse(f'<div class="section-title">&#x1F4E5; Submissions <span class="count">0</span></div>{empty}')

    cards_html = []
    for r in rows:
        sid = str(r.server_id)
        st = r.submission_status or "draft"
        color, label = _STATUS_COLOR.get(st, ("#6b7280", st.replace("_", " ").title()))
        cats = r.data_categories or []
        cats_html = " ".join(
            f'<span style="background:#1e293b;border-radius:4px;padding:1px 6px;font-size:11px">'
            f'{esc_py(_SENSE_LABEL.get(c, c))}</span>'
            for c in cats
        )
        scan_findings = r.scan_report or []
        blocked_count = sum(1 for f in scan_findings if f.get("block")) if isinstance(scan_findings, list) else 0
        scan_html = ""
        if st == "scan_blocked" and scan_findings:
            items = []
            for f in (scan_findings if isinstance(scan_findings, list) else []):
                items.append(
                    f'<div style="font-size:11px;color:#fca5a5;padding:2px 0">'
                    f'&#x26A0; {esc_py(f.get("scanner",""))} · '
                    f'{esc_py(f.get("file",""))}:{f.get("line",0)} — '
                    f'{esc_py(f.get("message",""))}</div>'
                )
            scan_html = f'<div style="margin:0.5rem 0;background:#1a0000;border-radius:6px;padding:0.5rem 0.75rem">{"".join(items[:5])}</div>'

        review_action = ""
        if st == "awaiting_review":
            review_action = f"""
            <div style="display:flex;gap:0.5rem;margin-top:0.75rem;align-items:center">
              <textarea id="notes-{esc_py(sid)}" placeholder="Review notes (optional)"
                        style="flex:1;background:#0f172a;border:1px solid #334155;border-radius:6px;
                               color:var(--text);padding:0.4rem 0.6rem;font-size:12px;resize:vertical;min-height:48px"></textarea>
              <div style="display:flex;flex-direction:column;gap:0.4rem">
                <button class="btn-primary" style="font-size:12px;padding:0.3rem 0.75rem"
                        onclick="reviewAction('{esc_py(sid)}','approve')">Approve</button>
                <button class="btn-secondary" style="font-size:12px;padding:0.3rem 0.75rem"
                        onclick="reviewAction('{esc_py(sid)}','request-changes')">Request Changes</button>
                <button style="background:#7f1d1d;color:#fca5a5;border:none;border-radius:6px;cursor:pointer;font-size:12px;padding:0.3rem 0.75rem"
                        onclick="reviewAction('{esc_py(sid)}','reject')">Reject</button>
              </div>
            </div>"""

        github_link = ""
        if r.github_repo_url:
            # Only render as a link if scheme is https — prevents javascript:/data: XSS
            _safe_repo = r.github_repo_url if str(r.github_repo_url).startswith("https://") else None
            if _safe_repo:
                github_link = (f'<a href="{esc_py(_safe_repo)}" target="_blank" rel="noopener noreferrer" '
                               f'style="color:var(--cyan);font-size:12px">&#x1F517; {esc_py(_safe_repo)}</a>')
            else:
                github_link = f'<span style="color:#fca5a5;font-size:12px">&#x26A0; invalid repo URL</span>'

        cards_html.append(f"""
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:1rem 1.25rem;margin-bottom:0.75rem">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <span style="font-weight:600;font-size:15px">{esc_py(r.name)}</span>
              <span style="color:var(--muted);font-size:12px;margin-left:0.75rem">by {esc_py(r.owner_sub)}</span>
            </div>
            <span style="background:{color}22;color:{color};border:1px solid {color}44;
                         border-radius:20px;padding:2px 10px;font-size:12px;font-weight:600">{esc_py(label)}</span>
          </div>
          <div style="margin-top:0.5rem;display:flex;gap:1rem;flex-wrap:wrap;font-size:12px;color:var(--muted)">
            <span>Mode: <span style="color:var(--text)">{esc_py(r.injection_mode or '—')}</span></span>
            <span>Write ops: <span style="color:var(--text)">{'Yes' if r.has_write_ops else 'No'}</span></span>
          </div>
          {f'<div style="margin-top:0.4rem">{cats_html}</div>' if cats_html else ''}
          {f'<div style="margin-top:0.4rem">{github_link}</div>' if github_link else ''}
          {scan_html}
          {f'<div style="margin-top:0.4rem;font-size:12px;color:#d97706">Reviewer notes: {esc_py(r.review_notes)}</div>' if r.review_notes else ''}
          {review_action}
        </div>""")

    awaiting = sum(1 for r in rows if r.submission_status == "awaiting_review")
    count_badge = f'{len(rows)} total' + (f' · {awaiting} awaiting review' if awaiting else '')

    return HTMLResponse(f"""
    <div class="section-title">&#x1F4E5; Submissions <span class="count">{count_badge}</span>
      <button class="btn-secondary" style="margin-left:auto;font-size:12px"
              hx-get="/portal/fragments/admin/submissions" hx-target="#adm-content" hx-swap="innerHTML">
        &#x21BB; Refresh
      </button>
    </div>
    <div id="submissions-list">{"".join(cards_html)}</div>
    <script>
    async function reviewAction(sid, action) {{
      const notes = document.getElementById('notes-' + sid)?.value || '';
      const r = await fetch('/api/v1/admin/submissions/' + sid + '/' + action, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        credentials: 'include',
        body: JSON.stringify({{notes}}),
      }});
      if (r.ok) {{
        htmx.ajax('GET', '/portal/fragments/admin/submissions', {{target:'#adm-content', swap:'innerHTML'}});
      }} else {{
        const err = await r.json().catch(() => ({{}}));
        alert('Action failed: ' + (err.detail || r.status));
      }}
    }}
    </script>
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
  {_FONTS_LINK}
  {_HTMX_TAG}
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
<div class="adm-layout" style="background:#080b14;min-height:100vh">
  <div class="wiz-shell">
    <div class="wiz-header">
      <a href="/portal" style="color:var(--muted);font-size:13px;text-decoration:none">&#x2190; Portal</a>
      <span style="color:#334155">/</span>
      <span style="font-weight:700">Submit MCP Server</span>
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

<script>
// Wizard state — accumulated across steps, submitted in one shot
const _wiz = {{
  name: '', description: '', github_repo_url: null,
  injection_mode: null, upstream_idp_type: null, upstream_idp_config: {{}},
  mode_override_reason: null,
  data_categories: [], has_write_ops: false,
  server_id: null,
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
      <div style="font-size:17px;font-weight:700;margin-bottom:1.25rem">Tell us about your server</div>

      <label class="wiz-label">Server name (slug, e.g. <code style="color:var(--cyan)">my-analytics</code>)</label>
      <input id="s1-name" class="wiz-input" placeholder="my-mcp-server" value="${{_wiz.name}}">

      <label class="wiz-label" style="margin-top:1rem">Short description</label>
      <input id="s1-desc" class="wiz-input" placeholder="What does this server do?" value="${{_wiz.description}}">

      <label class="wiz-label" style="margin-top:1rem">GitHub repository URL</label>
      <input id="s1-repo" class="wiz-input" placeholder="https://github.com/your-org/your-repo"
             value="${{_wiz.github_repo_url || ''}}">
      <div class="helper-box" id="clone-helper" style="display:none">
        &#x1F511; The platform will clone your repository using the account
        <strong style="color:var(--text)">${{_CLONE_ACCT}}</strong>.<br>
        Grant this account <strong>read access</strong> to your repository before submitting.
      </div>

      <label style="display:flex;align-items:center;gap:0.5rem;margin-top:1rem;font-size:13px;cursor:pointer">
        <input type="checkbox" id="s1-nocode" onchange="toggleNoCode(this)"> I don&rsquo;t have code yet
      </label>

      <div style="margin-top:1.5rem;display:flex;justify-content:flex-end">
        <button class="btn-primary" onclick="submitStep1()">Next &#x2192;</button>
      </div>
    </div>`;

  document.getElementById('s1-repo').addEventListener('input', e => {{
    document.getElementById('clone-helper').style.display = e.target.value.trim() ? '' : 'none';
  }});
  if (_wiz.github_repo_url) document.getElementById('clone-helper').style.display = '';
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
  const nocode = document.getElementById('s1-nocode')?.checked;
  if (!name) {{ alert('Server name is required'); return; }}
  if (!/^[a-z0-9][a-z0-9\\-]{{1,62}}$/.test(name)) {{
    alert('Name must be 2-63 chars, lowercase letters, numbers, and hyphens only'); return;
  }}
  _wiz.name = name;
  _wiz.description = desc;
  _wiz.github_repo_url = (nocode || !repo) ? null : repo;
  showStep2();
}}

// ── Step 2: Auth ─────────────────────────────────────────────────────────────

const _MODE_CARDS = [
  {{ id:'kc_token_exchange',       title:'Same IdP (Keycloak)', desc:'Token exchange — no secret stored. Full per-user attribution. Best for internal services.' }},
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
         id="mc-${{m.id}}" onclick="pickMode('${{m.id}}')">
      <div class="mode-card-title">${{m.title}}</div>
      <div class="mode-card-desc">${{m.desc}}</div>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div style="font-size:17px;font-weight:700;margin-bottom:0.25rem">How does your server authenticate?</div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:1.25rem">
        Pick a mode directly, or
        <button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:12px;padding:0"
                onclick="showGuidedQuestions()">help me choose &#x25BC;</button>
      </div>

      <div class="mode-grid">${{cards}}</div>

      <div id="mode-config" style="margin-top:1.25rem"></div>

      <div style="margin-top:1.5rem;display:flex;justify-content:space-between">
        <button class="btn-secondary" onclick="showStep1()">&#x2190; Back</button>
        <button class="btn-primary" onclick="submitStep2()">Next &#x2192;</button>
      </div>
    </div>
    <div id="guided-panel" style="margin-top:1rem"></div>`;

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
    <details style="margin-top:0.85rem">
      <summary style="font-size:11px;font-weight:600;color:var(--cyan);cursor:pointer;
                      text-transform:uppercase;letter-spacing:0.04em">${{title}}</summary>
      <pre style="margin:0.5rem 0 0;background:#050810;border:1px solid #1e293b;border-radius:6px;
                  padding:0.75rem 1rem;font-size:11px;line-height:1.6;color:#93c5fd;
                  overflow-x:auto;white-space:pre">${{code}}</pre>
    </details>`;

  const extras = {{
    kc_token_exchange: `
      <label class="wiz-label" style="margin-top:1rem">Target audience (service name)</label>
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
      <label class="wiz-label" style="margin-top:1rem">Tenant ID</label>
      <input class="wiz-input" id="cfg-tenant" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
             value="${{(_wiz.upstream_idp_config||{{}}).tenant_id||''}}">
      <label class="wiz-label" style="margin-top:0.75rem">Client ID</label>
      <input class="wiz-input" id="cfg-client" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
             value="${{(_wiz.upstream_idp_config||{{}}).client_id||''}}">
      <div class="helper-box" style="margin-top:0.5rem">
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
      <label class="wiz-label" style="margin-top:1rem">Tenant ID</label>
      <input class="wiz-input" id="cfg-tenant" value="${{(_wiz.upstream_idp_config||{{}}).tenant_id||''}}">
      <label class="wiz-label" style="margin-top:0.75rem">Required scopes (space-separated)</label>
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
      <label class="wiz-label" style="margin-top:1rem">Header your server reads</label>
      <input class="wiz-input" id="cfg-header" placeholder="Authorization"
             value="${{(_wiz.upstream_idp_config||{{}}).inject_header||'Authorization'}}">
      <label class="wiz-label" style="margin-top:0.75rem">Token prefix (e.g. Bearer, Token)</label>
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
      <label class="wiz-label" style="margin-top:1rem">Header your server reads</label>
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
      <label class="wiz-label" style="margin-top:1rem">External IdP issuer URL</label>
      <input class="wiz-input" id="cfg-issuer" placeholder="https://idp.example.com"
             value="${{(_wiz.upstream_idp_config||{{}}).issuer||''}}">
      <label class="wiz-label" style="margin-top:0.75rem">Client ID</label>
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
      <label class="wiz-label" style="margin-top:1rem">OAuth token endpoint</label>
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
  if (!_wiz.injection_mode) {{ alert('Please select an authentication mode'); return; }}
  _wiz.upstream_idp_config = _collectModeConfig(_wiz.injection_mode);
  showStep3();
}}

// ── Guided questions ──────────────────────────────────────────────────────────

function showGuidedQuestions() {{
  document.getElementById('guided-panel').innerHTML = `
    <div class="wiz-card q-tree" style="margin-top:0">
      <div id="q-content"></div>
    </div>`;
  askQ1();
}}

function _qRender(question, options) {{
  const opts = options.map(([label, fn]) =>
    `<button class="q-btn" onclick="${{fn}}">${{label}}</button>`).join('');
  document.getElementById('q-content').innerHTML =
    `<div class="q-text">${{question}}</div><div class="q-opts">${{opts}}</div>`;
}}

function askQ1() {{
  _qRender('Does your server call any upstream system that requires authentication?', [
    ['Yes — it calls an external or internal API', 'askQ2()'],
    ['No — it uses its own data or needs no auth',  "recommendMode('none')"],
  ]);
}}
function askQ2() {{
  _qRender('Is the upstream system protected by the <strong>same Keycloak instance</strong> this platform uses?', [
    ['Yes — same Keycloak realm',   "recommendMode('kc_token_exchange')"],
    ['No — external or different IdP', 'askQ3()'],
  ]);
}}
function askQ3() {{
  _qRender('What type of credential does the upstream system accept?', [
    ['Microsoft Entra / Azure AD', 'askQ4Entra()'],
    ['API key or static bearer token', 'askQ5Static()'],
    ['OAuth (different IdP)', 'askQ6OAuth()'],
  ]);
}}
function askQ4Entra() {{
  _qRender('Is this a machine-to-machine call (app identity) or per-user (delegated)?', [
    ['Machine / app identity — one app credential for all callers', "recommendMode('entra_client_credentials')"],
    ['Per-user delegated — each user has their own Entra identity',  "recommendMode('entra_user_token')"],
  ]);
}}
function askQ5Static() {{
  _qRender('Is one credential shared across all callers, or does each user have their own?', [
    ['Shared — one service account for everyone', "recommendMode('service')"],
    ['Per-user — each user has their own token',  "recommendMode('user')"],
  ]);
}}
function askQ6OAuth() {{
  _qRender('Is one token shared across all callers, or per-user?', [
    ['Shared OAuth token', "recommendMode('service_account')"],
    ['Per-user OAuth token', "recommendMode('oauth_user_token')"],
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
    <div class="rec-box" style="margin:0">
      <div style="font-size:11px;color:var(--muted);margin-bottom:0.25rem">RECOMMENDED</div>
      <div class="rec-mode">${{label}}</div>
      <div class="rec-reason">${{reason}}</div>
      <div style="margin-top:0.75rem;display:flex;gap:0.5rem">
        <button class="btn-primary" onclick="applyRecommendation('${{mode}}')">Use this</button>
        <button class="btn-secondary" onclick="showStep2()">Override</button>
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
         id="cat-${{id}}" onclick="toggleCat('${{id}}')">
      <span>${{label}}</span>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div style="font-size:17px;font-weight:700;margin-bottom:0.25rem">What data does your server expose?</div>
      <div style="font-size:12px;color:var(--muted);margin-bottom:1.25rem">Select all that apply. This determines the risk level and review priority.</div>

      <div class="cat-grid">${{cats}}</div>

      <div style="margin-top:1.25rem">
        <label class="wiz-label">Does this server perform write operations?</label>
        <div style="display:flex;gap:1rem;margin-top:0.35rem">
          <label style="display:flex;align-items:center;gap:0.4rem;cursor:pointer;font-size:13px">
            <input type="radio" name="write" value="no"  ${{_wiz.has_write_ops ? '' : 'checked'}}
                   onchange="_wiz.has_write_ops=false"> Read-only
          </label>
          <label style="display:flex;align-items:center;gap:0.4rem;cursor:pointer;font-size:13px">
            <input type="radio" name="write" value="yes" ${{_wiz.has_write_ops ? 'checked' : ''}}
                   onchange="_wiz.has_write_ops=true"> Read + write
          </label>
        </div>
      </div>

      <div id="risk-preview" style="margin-top:1rem"></div>

      <div style="margin-top:1.5rem;display:flex;justify-content:space-between">
        <button class="btn-secondary" onclick="showStep2()">&#x2190; Back</button>
        <button class="btn-primary" onclick="showStep4()">Next &#x2192;</button>
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
    `<div style="font-size:12px;color:var(--muted)">Derived risk level:
       <span style="color:${{color}};font-weight:700;text-transform:uppercase">${{level}}</span>
       — sets the OPA invocation gate for this server
     </div>`;
}}

// ── Step 4: Review & Submit ───────────────────────────────────────────────────

function showStep4() {{
  _setStep(4);
  const modeLabel = _MODE_CARDS.find(m => m.id === _wiz.injection_mode)?.title || _wiz.injection_mode || '—';
  const cats = _wiz.data_categories.map(c => `<span style="background:#1e293b;border-radius:4px;padding:1px 6px;font-size:11px">${{c}}</span>`).join(' ');
  const repoLine = _wiz.github_repo_url
    ? `<a href="${{_wiz.github_repo_url}}" style="color:var(--cyan)">${{_wiz.github_repo_url}}</a>`
    : '<span style="color:var(--muted)">No code yet — scaffold will be generated</span>';

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div style="font-size:17px;font-weight:700;margin-bottom:1.25rem">&#x1F4CB; Review your submission</div>

      <table style="width:100%;border-collapse:collapse;font-size:13px">
        <tr><td style="color:var(--muted);padding:0.35rem 0;width:140px">Server name</td>
            <td style="font-weight:600">${{_wiz.name}}</td></tr>
        <tr><td style="color:var(--muted);padding:0.35rem 0">Repository</td>
            <td>${{repoLine}}</td></tr>
        <tr><td style="color:var(--muted);padding:0.35rem 0">Auth mode</td>
            <td style="font-weight:600">${{modeLabel}}</td></tr>
        <tr><td style="color:var(--muted);padding:0.35rem 0">Data categories</td>
            <td>${{cats || '<span style="color:var(--muted)">None selected</span>'}}</td></tr>
        <tr><td style="color:var(--muted);padding:0.35rem 0">Write operations</td>
            <td>${{_wiz.has_write_ops ? 'Yes' : 'No'}}</td></tr>
      </table>

      ${{_wiz.github_repo_url ? `
      <div class="helper-box" style="margin-top:1rem">
        &#x1F511; Before submitting, ensure
        <strong style="color:var(--text)">${{_CLONE_ACCT}}</strong>
        has read access to your repository.
      </div>` : ''}}

      <div id="submit-error" style="color:#fca5a5;font-size:13px;margin-top:0.75rem;display:none"></div>

      <div style="margin-top:1.5rem;display:flex;justify-content:space-between;align-items:center">
        <button class="btn-secondary" onclick="showStep3()">&#x2190; Back</button>
        <button class="btn-primary" id="submit-btn" onclick="doSubmit()">
          ${{_wiz.github_repo_url ? 'Submit for review &#x2192;' : 'Get scaffold &#x2193;'}}
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
      body: JSON.stringify({{ name: _wiz.name, description: _wiz.description, github_repo_url: _wiz.github_repo_url }}),
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
      <div class="wiz-card" style="text-align:center;padding:2.5rem">
        <div style="font-size:36px;margin-bottom:1rem">&#x2705;</div>
        <div style="font-size:20px;font-weight:700;margin-bottom:0.5rem">Submitted successfully</div>
        <div style="font-size:13px;color:var(--muted);max-width:400px;margin:0 auto 1.5rem">
          Your server is in the scan queue. We'll notify you when the security review is complete.
        </div>
        <a href="/portal" class="btn-secondary" style="display:inline-block;text-decoration:none">
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
    <div style="background:#0a0f1e;border:1px solid #1e293b;border-radius:8px;padding:1rem;margin-bottom:0.75rem">
      <div style="font-size:11px;color:var(--blue);font-weight:700;margin-bottom:0.4rem;text-transform:uppercase">
        Design question ${{i+1}}
      </div>
      <div style="font-size:13px;line-height:1.6;color:var(--text)">${{p.prompt}}</div>
      <textarea placeholder="Your answer (optional — helps you plan before writing code)"
                style="width:100%;margin-top:0.6rem;background:#080b14;border:1px solid #334155;
                       border-radius:6px;color:var(--text);padding:0.5rem 0.75rem;font-size:12px;
                       resize:vertical;min-height:60px;box-sizing:border-box"></textarea>
    </div>`).join('');

  document.getElementById('wiz-body').innerHTML = `
    <div class="wiz-card">
      <div style="font-size:36px;margin-bottom:0.5rem;text-align:center">&#x1F4E6;</div>
      <div style="font-size:20px;font-weight:700;margin-bottom:0.25rem;text-align:center">Scaffold ready</div>
      <div style="font-size:13px;color:var(--muted);text-align:center;margin-bottom:1.5rem">
        Answer the design questions below, then download your starter code.
      </div>

      <div style="font-size:13px;font-weight:600;margin-bottom:0.75rem;color:var(--muted)">
        DESIGN QUESTIONS — answer these before writing your server
      </div>
      ${{promptCards || '<div style="color:var(--muted);font-size:13px">No prompts available.</div>'}}

      <div style="margin-top:1.5rem;display:flex;gap:0.75rem;justify-content:center;flex-wrap:wrap">
        <a href="/api/v1/submissions/${{_wiz.server_id}}/scaffold" class="btn-primary"
           style="display:inline-block;text-decoration:none">
          &#x2B07; Download scaffold.zip
        </a>
        <a href="/portal/submit" class="btn-secondary" style="display:inline-block;text-decoration:none">
          Submit when ready &#x2192;
        </a>
      </div>

      <div class="helper-box" style="margin-top:1.25rem">
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


def _badge(label: str, css_class: str) -> str:
    return f'<span class="badge {esc_py(css_class)}">{esc_py(label)}</span>'


def _error_fragment(message: str) -> str:
    return f'<div class="error-state">&#x26A0;&#xFE0F; {esc_py(message)}</div>'
