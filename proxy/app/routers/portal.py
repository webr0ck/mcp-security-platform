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
    """Catalog and My Access require agent or admin role."""
    roles = _roles(request)
    if not any(r in {"agent", "admin"} for r in roles):
        raise HTTPException(
            status_code=403,
            detail={"code": "FORBIDDEN", "message": "agent or admin role required to access the portal."},
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

_HTMX_TAG = (
    '<script src="https://unpkg.com/htmx.org@1.9.12"'
    ' integrity="sha384-ujb1lZYygJmzgSwoxRggbCHcjc0rB4IgmFsNghFBFGPYNP5CZqLqSKJOZJlXe/r7"'
    ' crossorigin="anonymous"></script>'
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

@router.get("", response_class=HTMLResponse)
async def portal_shell(request: Request):
    """Serve the full portal page shell."""
    _require_portal_access(request)

    roles = _roles(request)
    cid = _client_id(request)
    is_admin = "admin" in roles

    role_pills = "".join(
        f'<span class="role-pill role-{r if r in ("admin","agent","auditor","reviewer") else "other"}">{esc_py(r)}</span>'
        for r in roles
    )

    admin_tab = (
        '<button class="tab-btn" data-tab="admin" onclick="activateTab(\'admin\')">&#x1F6E1; Admin</button>'
        if is_admin else ""
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Security Platform</title>
  {_HTMX_TAG}
  <style>{_CSS}</style>
</head>
<body>
  <!-- Header -->
  <header class="header">
    <div class="header-title">&#x1F510; MCP Security Platform</div>
    <div class="user-chip">
      <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" style="color:#64748b">
        <path d="M10 10a4 4 0 100-8 4 4 0 000 8zm-7 9a7 7 0 1114 0H3z"/>
      </svg>
      <span class="uid">{esc_py(cid)}</span>
      {role_pills}
    </div>
  </header>

  <!-- Tab bar -->
  <nav class="tabs" role="tablist">
    <button class="tab-btn active" data-tab="catalog" onclick="activateTab('catalog')">&#x1F4D6; Catalog</button>
    <button class="tab-btn" data-tab="my-access" onclick="activateTab('my-access')">&#x1F511; My Access</button>
    {admin_tab}
  </nav>

  <!-- Tab content -->
  <main class="content" id="tab-content"
        hx-get="/portal/fragments/catalog"
        hx-trigger="load"
        hx-swap="innerHTML">
    <div class="loading-state"><span class="spinner"></span> Loading catalog...</div>
  </main>

  <script>
    {_JS_COMMON}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Fragment: Catalog
# ---------------------------------------------------------------------------

@router.get("/fragments/catalog", response_class=HTMLResponse)
async def fragment_catalog(request: Request):
    """Catalog tab: grid of active tool cards."""
    _require_portal_access(request)
    roles = _roles(request)

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

        # Credential upload form for user-mode tools
        if mode in ("user", "oauth_user_token"):
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
      fetch('/admin/credentials/' + toolId, {{
        method: 'PUT',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{secret: secret, owner_type: 'user'}})
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
    """My Access tab: granted tools, credential status, MCP config snippet."""
    _require_portal_access(request)
    cid = _client_id(request)
    api_key = request.query_params.get("key", "")

    # 1. Load grants from data.json
    grants: dict[str, Any] = {}
    try:
        data = json.loads(_DATA_JSON.read_text())
        grants = data.get("mcp", {}).get("grants", {}).get(cid, {})
    except Exception as exc:
        logger.warning("portal my-access: could not read data.json: %s", exc)

    allowed_tools: list[str] = grants.get("allowed_tools", [])
    allowed_tags: list[str] = grants.get("allowed_tags", [])
    max_risk: str = grants.get("max_risk_level", "—")

    # 2. Fetch tool details + credential status from DB
    tool_rows: dict[str, Any] = {}
    audit_rows: dict[str, Any] = {}
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            # Tool details
            if allowed_tools:
                placeholders = ", ".join(f":t{i}" for i in range(len(allowed_tools)))
                params = {f"t{i}": n for i, n in enumerate(allowed_tools)}
                result = await session.execute(
                    text(f"""
                        SELECT t.name, t.tool_id, t.version, t.status, t.risk_level,
                               t.injection_mode, t.description,
                               EXISTS (
                                 SELECT 1 FROM credential_store c
                                 WHERE c.tool_id = t.tool_id
                                   OR (c.user_sub = :cid AND c.service = t.service_name)
                               ) AS has_cred
                        FROM tool_registry t
                        WHERE t.name IN ({placeholders}) AND t.deleted_at IS NULL
                    """),
                    {"cid": cid, **params},
                )
                for row in result.fetchall():
                    tool_rows[row.name] = row

            # Audit events: last used + call count per tool
            audit_result = await session.execute(
                text("""
                    SELECT tool_name,
                           MAX(created_at) AS last_used,
                           COUNT(*) AS call_count,
                           SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) AS success_count
                    FROM audit_events
                    WHERE client_id = :cid
                    GROUP BY tool_name
                    ORDER BY last_used DESC
                    LIMIT 20
                """),
                {"cid": cid},
            )
            for row in audit_result.fetchall():
                audit_rows[row.tool_name] = row
    except Exception as exc:
        logger.error("portal my-access DB error: %s", exc)

    # 3. Build access rows
    rows_html = []
    for tool_name in allowed_tools:
        t = tool_rows.get(tool_name)
        a = audit_rows.get(tool_name)
        status = (t.status if t else "unknown") or "unknown"
        risk = (t.risk_level if t else "—") or "—"
        mode = (t.injection_mode if t else "none") or "none"
        has_cred = bool(t.has_cred) if t else False
        cred_badge = _badge("enrolled" if has_cred else "not enrolled",
                            "badge-enrolled" if has_cred else "badge-not-enrolled")

        last_used = "Never"
        stats = ""
        if a:
            last_used = a.last_used.strftime("%Y-%m-%d %H:%M") if a.last_used else "Never"
            stats = f"{a.call_count} calls, {a.success_count} ok"

        rows_html.append(f"""
        <div class="access-row">
          <div>
            <div class="access-name">{esc_py(tool_name)}</div>
            <div class="access-stats">Last used: {esc_py(last_used)}{" &nbsp;·&nbsp; " + esc_py(stats) if stats else ""}</div>
          </div>
          <div style="display:flex;gap:0.4rem;align-items:center">
            {_badge(status, f"badge-{status}")}
            {_badge(risk.lower() + " risk", f"badge-risk-{risk.lower()}")}
            {cred_badge}
          </div>
        </div>""")

    rows_block = "".join(rows_html) if rows_html else '<div class="empty-state">No tools granted to this identity.</div>'

    # 4. Grants summary
    tags_html = "".join(f'<span class="tag">{esc_py(tg)}</span>' for tg in allowed_tags) or '<span style="color:var(--muted);font-size:0.8rem">none</span>'

    # 5. MCP config snippet
    platform_host = os.environ.get("PLATFORM_HOST", "https://mcp.example.com")
    mcp_config = {
        "mcpServers": {
            tool_name: {
                "url": f"{platform_host}/mcp/{tool_name}",
                **({"headers": {"Authorization": f"Bearer {api_key}"}} if api_key else {}),
            }
            for tool_name in allowed_tools
        }
    }
    mcp_json = json.dumps(mcp_config, indent=2)

    key_note = (
        '<p style="font-size:0.8rem;color:var(--muted);margin-top:0.75rem">Tip: append <code style="color:var(--cyan)">?key=YOUR_API_KEY</code> to this portal URL to pre-fill your API key in the snippet below.</p>'
        if not api_key else
        '<p style="font-size:0.8rem;color:#86efac;margin-top:0.75rem">API key pre-filled from URL parameter.</p>'
    )

    html = f"""
    <div style="max-width:860px">
      <div class="section-title">&#x1F511; My Grants
        <span class="count">{len(allowed_tools)} tools</span>
      </div>

      <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:0.9rem 1rem;margin-bottom:1rem;font-size:0.83rem">
        <div style="display:flex;gap:2rem;flex-wrap:wrap">
          <div><span style="color:var(--muted)">Max risk allowed:</span>&nbsp;
            {_badge(max_risk.upper(), f"badge-risk-{max_risk.lower()}")}
          </div>
          <div><span style="color:var(--muted)">Allowed tags:</span>&nbsp;{tags_html}</div>
        </div>
      </div>

      {rows_block}

      <hr class="divider">

      <div class="section-title">&#x1F4CB; MCP Config Snippet</div>
      <p style="font-size:0.83rem;color:var(--muted);margin-bottom:0.75rem">
        Paste this into <code style="color:var(--cyan)">~/.mcp.json</code> to wire up your granted tools.
      </p>
      {key_note}
      <div class="code-block" id="mcp-config-block">{esc_py(mcp_json)}</div>
      <button class="btn-secondary btn-sm" style="margin-top:0.6rem" onclick="copyMcpConfig()">Copy</button>
      <span id="copy-msg" style="font-size:0.78rem;color:var(--green);margin-left:0.5rem"></span>
    </div>

    <script>
    function copyMcpConfig() {{
      const text = document.getElementById('mcp-config-block').textContent;
      navigator.clipboard.writeText(text).then(() => {{
        const m = document.getElementById('copy-msg');
        m.textContent = 'Copied!';
        setTimeout(() => {{ m.textContent = ''; }}, 2000);
      }});
    }}
    </script>
    """
    return HTMLResponse(html)


# ---------------------------------------------------------------------------
# Fragment: Admin shell (inner tabs)
# ---------------------------------------------------------------------------

@router.get("/fragments/admin", response_class=HTMLResponse)
async def fragment_admin(request: Request):
    """Admin tab shell with inner tab navigation."""
    _require_admin(request)

    html = """
    <div class="section-title">&#x1F6E1;&#xFE0F; Admin Panel</div>
    <div class="inner-tabs">
      <button class="inner-tab-btn active" data-itab="tools"       onclick="activateAdminTab('tools')">Tools</button>
      <button class="inner-tab-btn"        data-itab="credentials" onclick="activateAdminTab('credentials')">Credentials</button>
      <button class="inner-tab-btn"        data-itab="grants"      onclick="activateAdminTab('grants')">Grants</button>
    </div>
    <div id="admin-inner-content"
         hx-get="/portal/fragments/admin/tools"
         hx-trigger="load"
         hx-swap="innerHTML">
      <div class="loading-state"><span class="spinner"></span> Loading...</div>
    </div>
    """
    return HTMLResponse(html)


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
        is_quarantined = status == "quarantined"
        toggle_label = "Activate" if is_quarantined else "Quarantine"
        toggle_action = "active" if is_quarantined else "quarantined"

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
            <button class="btn-secondary btn-sm" style="{'background:#7f1d1d;color:#fca5a5' if not is_quarantined else ''}"
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
                    EXISTS (
                        SELECT 1 FROM credential_store c
                        WHERE c.tool_id = t.tool_id
                          OR (c.user_sub = '__service__' AND c.service = t.service_name)
                    ) AS has_service_credential
                FROM tool_registry t
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
          </details>
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
