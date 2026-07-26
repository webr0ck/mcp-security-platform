/*
 * MCP Security Platform — Portal client-side script
 *
 * Extracted from proxy/app/routers/portal.py (roadmap R1.1): this content
 * used to live inline in Python f-strings scattered across every shell and
 * fragment, with no ruff/mypy/formatter coverage. Consolidated here so it
 * gets normal JS tooling and (eventually) CSP tightening.
 *
 * Loaded ONCE per full-page shell (_build_admin_shell / _build_agent_shell)
 * via <script src="/static/portal.js" defer> — fragments swapped in by
 * htmx must NOT re-include it. Per-fragment click/submit handlers that used
 * to be bound with `document.querySelectorAll(...).forEach(el =>
 * el.addEventListener(...))` inside each fragment's own inline <script>
 * (so they'd be (re-)bound every time htmx swapped that fragment in) are
 * consolidated below into event delegation on document.body, registered
 * once here — functionally equivalent (same click behavior, same DOM
 * mutations, same requests) but correct regardless of how many times a
 * fragment is swapped in, and without stacking duplicate listeners.
 *
 * A few fragments interpolate a Python value (a JSON blob, a client-id) or
 * must react to being swapped into the DOM (e.g. the Request Limits tab's
 * initial data fetch) — those specific bits stay inline in portal.py, or
 * are dispatched here off an `htmx:afterSettle` listener. See portal.py's
 * per-route docstrings/comments for the exact split.
 */

// ---------------------------------------------------------------------------
// Shared helpers (session-expiry redirect, esc(), toggle, tab activation, catalog filter)
// ---------------------------------------------------------------------------

  // Session expiry: htmx does not swap non-2xx responses by default, so an
  // expired session silently no-ops every tab click (or, depending on the
  // route's Accept-header branch, dumps a raw JSON error into the content
  // pane) with no visible sign of what's wrong — the only working recovery
  // was a full page reload (which sends a browser-navigation Accept header
  // and correctly hits the login-redirect branch). Catch it at the network
  // layer instead: any htmx request that comes back 401 means the session
  // is gone, so send the user to login immediately rather than leaving a
  // dead tab on screen.
  document.body.addEventListener('htmx:responseError', function(evt) {
    if (evt.detail && evt.detail.xhr && evt.detail.xhr.status === 401) {
      window.location.href = '/api/v1/auth/oidc/login?redirect=' + encodeURIComponent(window.location.pathname);
    }
  });

  // XSS-safe text setter
  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str == null ? '' : String(str);
    return d.innerHTML;
  }

  // ---------------------------------------------------------------------
  // toast() / confirmDialog() — R1.2: replace the blocking window dialogs.
  // ---------------------------------------------------------------------

  function _toastContainer() {
    let c = document.getElementById('_toast-container');
    if (!c) {
      c = document.createElement('div');
      c.id = '_toast-container';
      document.body.appendChild(c);
    }
    return c;
  }

  // Non-blocking notification. kind: 'success' | 'error' | 'info' (default).
  // 'error' toasts do NOT auto-dismiss — error text must stay on screen and
  // selectable long enough for a user to copy it into a bug report, which a
  // timed dismiss (like the old blocking window dialog's "click OK to lose
  // it forever", but silent) would regress. success/info auto-dismiss after
  // 5s, paused on hover/focus so a user mid-read/copy doesn't have it
  // vanish under them.
  function toast(message, kind) {
    kind = kind === 'success' || kind === 'error' ? kind : 'info';
    const container = _toastContainer();
    const el = document.createElement('div');
    el.className = 'toast toast-' + kind;
    el.setAttribute('role', 'status');
    const msgEl = document.createElement('span');
    msgEl.className = 'toast-msg';
    msgEl.textContent = message == null ? '' : String(message);
    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', 'Dismiss notification');
    closeBtn.textContent = '×';
    let timer = null;
    function remove() {
      if (timer) clearTimeout(timer);
      el.remove();
    }
    closeBtn.addEventListener('click', remove);
    el.append(msgEl, closeBtn);
    container.appendChild(el);
    if (kind !== 'error') {
      timer = setTimeout(remove, 5000);
      el.addEventListener('mouseenter', () => { if (timer) { clearTimeout(timer); timer = null; } });
      el.addEventListener('mouseleave', () => { if (!timer) timer = setTimeout(remove, 5000); });
    }
    return el;
  }

  // Promise-based, accessible replacement for the blocking window dialog.
  // Resolves true/false — callers await it, so "a confirmation that
  // currently blocks an action must still block it" holds (the action only
  // proceeds after the promise settles, same net effect as the old
  // synchronous blocking call).
  //
  // a11y: role=alertdialog + aria-modal + aria-labelledby give it an
  // accessible name; Escape cancels; Enter confirms (default focus lands on
  // the Confirm button, so plain Enter activates it natively — the explicit
  // handler below also covers Enter while focus is elsewhere, e.g. after a
  // Tab press, as long as it's not on the Cancel button); Tab/Shift+Tab are
  // trapped between the two buttons; focus returns to whatever triggered
  // the dialog when it closes.
  function confirmDialog(message, opts) {
    opts = opts || {};
    const confirmLabel = opts.confirmLabel || 'Confirm';
    const cancelLabel = opts.cancelLabel || 'Cancel';
    const danger = opts.danger !== false;
    return new Promise(function(resolve) {
      const previouslyFocused = document.activeElement;
      const overlay = document.createElement('div');
      overlay.className = 'confirm-overlay';

      const dialog = document.createElement('div');
      dialog.className = 'confirm-dialog';
      dialog.setAttribute('role', 'alertdialog');
      dialog.setAttribute('aria-modal', 'true');
      const titleId = '_confirm-msg-' + Math.random().toString(36).slice(2);
      dialog.setAttribute('aria-labelledby', titleId);

      const msgEl = document.createElement('p');
      msgEl.id = titleId;
      msgEl.className = 'confirm-dialog-msg';
      msgEl.textContent = message == null ? '' : String(message);

      const actions = document.createElement('div');
      actions.className = 'confirm-dialog-actions';
      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'btn-secondary';
      cancelBtn.textContent = cancelLabel;
      const confirmBtn = document.createElement('button');
      confirmBtn.type = 'button';
      confirmBtn.className = danger ? 'btn-danger' : 'btn-primary';
      confirmBtn.textContent = confirmLabel;
      actions.append(cancelBtn, confirmBtn);
      dialog.append(msgEl, actions);
      overlay.appendChild(dialog);
      document.body.appendChild(overlay);

      function close(result) {
        document.removeEventListener('keydown', onKeydown, true);
        overlay.remove();
        if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
          previouslyFocused.focus();
        }
        resolve(result);
      }
      function onKeydown(e) {
        if (e.key === 'Escape') { e.preventDefault(); close(false); return; }
        if (e.key === 'Enter' && document.activeElement !== cancelBtn) {
          e.preventDefault(); close(true); return;
        }
        if (e.key === 'Tab') {
          e.preventDefault();
          const focusables = [cancelBtn, confirmBtn];
          const idx = focusables.indexOf(document.activeElement);
          const next = e.shiftKey
            ? focusables[(idx - 1 + focusables.length) % focusables.length]
            : focusables[(idx + 1) % focusables.length];
          next.focus();
        }
      }
      cancelBtn.addEventListener('click', () => close(false));
      confirmBtn.addEventListener('click', () => close(true));
      document.addEventListener('keydown', onKeydown, true);
      confirmBtn.focus();
    });
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


// ---------------------------------------------------------------------------
// Admin shell chrome (tab map, nav groups, breadcrumb, subtabs bar, migration banner)
// ---------------------------------------------------------------------------
  const _TAB_MAP = {
    identity:    'Identity (OIDC)',
    servers:     'MCP Servers',
    tools:       'Tools',
    credentials: 'Credentials',
    limits:      'Request Limits',
    dashboard:   'Posture',
    detections:  'Detections',
    sbom:        'SBOM',
    submissions: 'Submissions',
    prompts:     'Wizard Prompts',
    llm:         'LLM Provider',
    git:         'Git Providers',
    profile:     'Profile',
    access:      'Access',
  };
  const _ADM_GROUPS = [
    {id:'security', label:'Security', panels:['dashboard','detections']},
    {id:'servers',  label:'Servers',  panels:['servers','tools','submissions','sbom','credentials']},
    {id:'access',   label:'Access',   panels:['access','limits']},
    {id:'settings', label:'Settings', panels:['identity','prompts','llm','git']},
    {id:'profile',  label:'Profile',  panels:['profile']},
  ];
  function _admGroupFor(name) {
    return _ADM_GROUPS.find(g => g.panels.includes(name)) || _ADM_GROUPS[1];
  }
  function _renderTabsBar(group, activeName) {
    const bar = document.getElementById('adm-tabs-bar');
    if (!bar) return;
    if (group.panels.length <= 1) { bar.style.display = 'none'; bar.innerHTML = ''; return; }
    bar.style.display = 'flex';
    bar.innerHTML = group.panels.map(p => {
      const active = p === activeName;
      return '<button class="adm-tab' + (active ? ' active' : '') + '"' +
             (active ? ' aria-current="page"' : '') + ' ' +
             'data-act="loadAdminTab" data-a0="' + p + '">' + (_TAB_MAP[p] || p) + '</button>';
    }).join('');
  }
  function loadAdminTab(name, opts) {
    opts = opts || {};
    const group = _admGroupFor(name);
    // Update breadcrumb
    const bc = document.getElementById('adm-breadcrumb-page');
    if (bc) bc.textContent = _TAB_MAP[name] || name;
    // Update sidebar active group
    document.querySelectorAll('.adm-nav-item').forEach(b => {
      const match = b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + group.panels[0] + "'");
      b.classList.toggle('active', match);
      if (match) { b.setAttribute('aria-current', 'page'); } else { b.removeAttribute('aria-current'); }
      const dot = b.querySelector('.adm-nav-dot');
      if (dot) dot.classList.toggle('active', match);
    });
    // Update subtab bar
    _renderTabsBar(group, name);
    // Load fragment. Focus moves to the content region once the new
    // fragment settles, so keyboard/screen-reader users land on the tab's
    // content instead of being stranded wherever they clicked from.
    htmx.ajax('GET', '/portal/fragments/admin/' + name, {target: '#adm-content', swap: 'innerHTML'})
      .then(function() {
        const content = document.getElementById('adm-content');
        if (content) content.focus();
      });
    if (!opts.fromPopState) {
      history.pushState({admTab: name}, '', '/portal/admin/' + name);
    }
  }
  window.addEventListener('popstate', function(e) {
    if (e.state && e.state.admTab) {
      location.reload();
    }
  });
  // initial_tab is passed from Python via data-initial-tab on <body> (see
  // _build_admin_shell) — absent on the agent shell, which has no admin
  // nav/tabs-bar to render.
  const _initialAdmTab = document.body.dataset.initialTab;
  if (_initialAdmTab) {
    _renderTabsBar(_admGroupFor(_initialAdmTab), _initialAdmTab);
  }
  (function() {
    if (_initialAdmTab && !localStorage.getItem('adm_nav_regroup_seen')) {
      const b = document.getElementById('adm-migration-banner');
      if (b) b.style.display = 'flex';
    }
  })();
  function _dismissMigrationBanner() {
    localStorage.setItem('adm_nav_regroup_seen', '1');
    const b = document.getElementById('adm-migration-banner');
    if (b) b.style.display = 'none';
  }
  // Legacy alias used by existing admin sub-fragments
  function activateAdminTab(name) { loadAdminTab(name); }

// ---------------------------------------------------------------------------
// Admin > MCP Servers fragment actions
// ---------------------------------------------------------------------------
    function filterSrv(btn, status) {
      document.querySelectorAll('#srv-seg .srv-seg-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.srv-card').forEach(r => {
        if (!status) { r.style.display=''; return; }
        const hasStatus = r.classList.contains('row-' + status) ||
          (!r.classList.contains('row-pending') && !r.classList.contains('row-quarantined') && status === 'approved');
        r.style.display = hasStatus ? '' : 'none';
      });
    }
    async function adminApproveSrv(id) {
      if (!(await confirmDialog('Approve this server? This mints a dual-control consent token and immediately consumes it.'))) return;
      fetch('/api/v1/servers/' + id + '/consent', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})
        .then(r => r.ok ? r.json() : r.json().then(d => Promise.reject(d.detail?.message || d.detail || 'Failed to mint consent token')))
        .then(d => fetch('/api/v1/admin/servers/' + id + '/approve', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({consent_token: d.consent_token})}))
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => Promise.reject(d.detail?.message || d.detail || 'Approve failed')))
        .catch(e => toast('Error: ' + e, 'error'));
    }
    async function adminRejectSrv(id) {
      if (!(await confirmDialog('Reject and remove this server?'))) return;
      fetch('/api/v1/admin/servers/' + id + '/reject', {method:'POST'})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.detail?.message || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminReleaseSrv(id) {
      if (!(await confirmDialog('Release this server from quarantine?'))) return;
      fetch('/api/v1/admin/servers/' + id + '/release', {method:'POST'})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.detail?.message || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminSetPublic(id, enable) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!(await confirmDialog(enable
          ? 'Make this server reachable by ALL authenticated users? (Read-only servers only.)'
          : 'Make this server private again (explicit grants only)?'))) return;
      fetch('/api/v1/admin/servers/' + id + '/public', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({enabled: enable})
      })
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.detail || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminQuarantineSrv(id) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!(await confirmDialog('Quarantine this server? It will be blocked from invocations.'))) return;
      fetch('/api/v1/admin/servers/' + id + '/quarantine', {method:'POST'})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.detail?.message || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminDeleteSrv(id) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!(await confirmDialog('Delete this server? This cannot be undone.'))) return;
      fetch('/api/v1/admin/servers/' + id, {method:'DELETE'})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.detail?.message || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    function adminSetMaintainers(id, current) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      const raw = prompt('Maintainer client_ids, comma-separated (max 2):', current.join(', '));
      if (raw === null) return;
      const maintainers = raw.split(',').map(s => s.trim()).filter(Boolean);
      fetch('/api/v1/servers/' + id + '/maintainers', {
        method: 'PUT', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({maintainers}),
      }).then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.error?.message || d.detail?.message || d.detail || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminToggleDebug(id, enable) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      const msg = enable
        ? 'Enable debug/maintenance mode for this server? Only the owner and maintainers will be able to invoke it while enabled.'
        : 'Go live? This exits maintenance mode and opens invocation to every entitled caller. Make sure verification has passed first.';
      if (!(await confirmDialog(msg))) return;
      fetch('/api/v1/servers/' + id + '/debug-mode', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: enable}),
      }).then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.error?.message || d.detail?.message || d.detail || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    function adminVerifySrv(id) {
      // PRD-0012 C4: distinct from go-live — re-runs verification probes and
      // reports the result inline; a failure keeps the server in maintenance.
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      fetch('/api/v1/servers/' + id + '/verify', {method: 'POST', headers: {'Content-Type': 'application/json'}})
        .then(async r => {
          const d = await r.json().catch(() => ({}));
          if (r.ok && d.verified) {
            toast('Verification passed. You can now go live.', 'success');
          } else {
            const reason = d.verification_report
              ? JSON.stringify(d.verification_report)
              : (d.detail?.message || d.detail || 'verification failed');
            toast('Verification failed — still in maintenance.\n' + reason, 'error');
          }
          loadAdminTab('servers');
        })
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminEditEndpoint(id, currentUrl) {
      // PRD-0012 C3: edits are never a silent overwrite — this always goes
      // through POST /request-change, which quarantines every tool and
      // demotes the server before re-verifying (or re-reviewing) the change.
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      const url = prompt('New backend (upstream) URL:', currentUrl || '');
      if (url === null) return;
      const trimmed = url.trim();
      if (!trimmed) { toast('URL is required.', 'error'); return; }
      const ipOnly = await confirmDialog(
        'Did ONLY the address change (same code, e.g. IP/DNS rotation)?\n\n' +
        'OK = yes, same code, address only — may auto-approve after re-verifying.\n' +
        'Cancel = no, this is a code/config change — goes through full reviewer re-approval.',
        {confirmLabel: 'Address only', cancelLabel: 'Code/config change', danger: false}
      );
      if (!(await confirmDialog('Submit this change? The server will be quarantined and re-verified' +
          (ipOnly ? ' (auto-approve if nothing else changed).' : ', then a reviewer must re-approve.')))) return;
      fetch('/api/v1/servers/' + id + '/request-change', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({new_upstream_url: trimmed, asserted_ip_only: ipOnly, reason: 'edit endpoint via portal'}),
      }).then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.error?.message || d.detail?.message || d.detail || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    async function adminRebuildSrv(id) {
      // "Update from git & rebuild" — pulls latest from the linked repo and
      // rebuilds/restarts the container (ops-agent), then the backend's own
      // request-change contract re-verifies/re-reviews as needed.
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      if (!(await confirmDialog('Pull the latest commit and rebuild this server\'s container? It will be briefly unavailable.'))) return;
      fetch('/api/v1/admin/servers/' + id + '/rebuild', {method: 'POST'})
        .then(r => r.ok ? loadAdminTab('servers') : r.json().then(d => toast(d.error?.message || d.detail?.message || d.detail || 'Error', 'error')))
        .catch(e => toast('Network error: ' + e, 'error'));
    }
    function adminViewLogs(id) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      fetch('/api/v1/admin/servers/' + id + '/logs?tail=200', {credentials:'include'})
        .then(r => r.ok ? r.json() : r.json().then(d => { throw new Error(d.error?.message || d.detail?.message || d.detail || ('HTTP ' + r.status)); }))
        .then(d => {
          const ov = document.createElement('div');
          ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:9999;display:flex;align-items:center;justify-content:center';
          ov.onclick = function(e) { if (e.target === ov) ov.remove(); };
          const box = document.createElement('div');
          box.style.cssText = 'background:#0b0f17;color:#d6deeb;max-width:900px;width:92%;max-height:80vh;display:flex;flex-direction:column;border-radius:8px;overflow:hidden;border:1px solid #2a3550';
          const hdr = document.createElement('div');
          hdr.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-bottom:1px solid #2a3550;font-weight:600';
          const ttl = document.createElement('span'); ttl.textContent = 'Logs (last 200 lines)';
          const cls = document.createElement('button'); cls.textContent = 'Close'; cls.onclick = function() { ov.remove(); };
          hdr.appendChild(ttl); hdr.appendChild(cls);
          const pre = document.createElement('pre');
          pre.style.cssText = 'margin:0;padding:14px;overflow:auto;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-word';
          pre.textContent = d.logs || '(no output)';
          box.appendChild(hdr); box.appendChild(pre); ov.appendChild(box);
          document.body.appendChild(ov);
        })
        .catch(e => toast('Could not load logs: ' + e.message, 'error'));
    }
    function adminManageServerTools(sid) {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      // Inlines loadAdminTab's nav/breadcrumb-state logic instead of calling
      // it directly — loadAdminTab also fires its OWN unfiltered fetch to
      // the same #adm-content target, and firing a second (filtered) fetch
      // right after it is a race: whichever response lands second wins the
      // swap, so the unfiltered list could silently overwrite the filtered
      // one depending on response timing. One fetch only, always filtered.
      const group = _admGroupFor('tools');
      const bc = document.getElementById('adm-breadcrumb-page');
      if (bc) bc.textContent = _TAB_MAP['tools'] || 'tools';
      document.querySelectorAll('.adm-nav-item').forEach(b => {
        const match = b.getAttribute('onclick') && b.getAttribute('onclick').includes("'" + group.panels[0] + "'");
        b.classList.toggle('active', match);
        if (match) { b.setAttribute('aria-current', 'page'); } else { b.removeAttribute('aria-current'); }
        const dot = b.querySelector('.adm-nav-dot');
        if (dot) dot.classList.toggle('active', match);
      });
      _renderTabsBar(group, 'tools');
      htmx.ajax('GET', '/portal/fragments/admin/tools?server_id=' + sid, {target: '#adm-content', swap: 'innerHTML'})
        .then(function() {
          const content = document.getElementById('adm-content');
          if (content) content.focus();
        });
      history.pushState({admTab: 'tools'}, '', '/portal/admin/tools');
    }
    function srvMenuToggle(evt, id) {
      evt.stopPropagation();
      const dd = document.getElementById('srv-dd-' + id);
      if (!dd) return;
      const visible = dd.style.display !== 'none';
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
      dd.style.display = visible ? 'none' : 'block';
    }
    document.addEventListener('click', function() {
      document.querySelectorAll('.srv-dropdown').forEach(d => d.style.display='none');
    });

// ---------------------------------------------------------------------------
// Profile fragment: create MCP profile
// ---------------------------------------------------------------------------
      async function createMcpProfile() {
        const name = document.getElementById('mcpprof-new-name').value.trim();
        const display = document.getElementById('mcpprof-new-display').value.trim();
        const msgEl = document.getElementById('mcpprof-new-msg');
        if (!name) { msgEl.style.color = '#fca5a5'; msgEl.textContent = 'Name is required.'; return; }
        try {
          const r = await fetch('/api/v1/profiles/named', {
            method: 'POST', credentials: 'include', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name: name, display_name: display || null}),
          });
          if (!r.ok) { const d = await r.json().catch(()=>({})); throw new Error(d.detail || ('HTTP ' + r.status)); }
          const created = await r.json();
          // Reload just the profile fragment in place (not the whole page) so the admin
          // stays on Profile instead of bouncing to whatever the shell's default tab is.
          const isAdmin = !!document.getElementById('adm-content');
          const url = isAdmin ? '/portal/fragments/admin/profile' : '/portal/fragments/profile';
          const target = isAdmin ? '#adm-content' : '#portal-body';
          await htmx.ajax('GET', url, {target: target, swap: 'innerHTML'});
          // Auto-open the Manage panel for the profile just created, so its (empty)
          // configuration is immediately visible instead of requiring another click.
          const slug = created.name.replace(/[^a-zA-Z0-9]/g, '_');
          const detailEl = document.getElementById('mcpprof-detail-' + slug);
          if (detailEl) {
            detailEl.style.display = 'block';
            htmx.ajax('GET', '/portal/fragments/mcp-profile/' + encodeURIComponent(created.name),
                       {target: '#mcpprof-detail-' + slug, swap: 'innerHTML'});
            detailEl.scrollIntoView({behavior: 'smooth', block: 'center'});
          }
        } catch (err) { msgEl.style.color = '#fca5a5'; msgEl.textContent = err.message; }
      }

// ---------------------------------------------------------------------------
// Profile fragment: sign out
// ---------------------------------------------------------------------------
      function portalSignOut() {
        fetch('/api/v1/auth/oidc/logout', {method:'POST', credentials:'include'})
          .finally(() => { window.location.href = '/'; });
      }

// ---------------------------------------------------------------------------
// My Access fragment: pending-URL / edit-and-resubmit for in-flight submissions
// ---------------------------------------------------------------------------
        async function providePendingUrl(sid) {
          const input = document.getElementById('provurl-' + sid);
          const url = (input.value || '').trim();
          if (!url) { toast('Enter the URL your server is running at.', 'error'); return; }
          try {
            const r = await fetch('/api/v1/submissions/' + sid + '/provide-url', {
              method: 'POST', headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({upstream_url: url}),
            });
            const d = await r.json();
            if (!r.ok) { toast(d.detail || 'Failed to go live', 'error'); return; }
            await htmx.ajax('GET', '/portal/fragments/my-access', {target:'#portal-body', swap:'innerHTML'});
            ssShowTab('submit');
          } catch (e) { toast('Network error: ' + e, 'error'); }
        }
        async function editAndResubmit(sid) {
          const repo = (document.getElementById('editrepo-' + sid)?.value || '').trim();
          const url = (document.getElementById('editurl-' + sid)?.value || '').trim();
          const desc = (document.getElementById('editdesc-' + sid)?.value || '').trim();
          const aud = (document.getElementById('editaud-' + sid)?.value || '').trim();
          const patchBody = {};
          if (repo) patchBody.github_repo_url = repo;
          if (url) patchBody.requested_upstream_url = url;
          if (desc) patchBody.description = desc;
          if (aud) patchBody.upstream_idp_config = {audience: aud};
          try {
            const pr = await fetch('/api/v1/submissions/' + sid, {
              method: 'PATCH', headers: {'Content-Type': 'application/json'},
              body: JSON.stringify(patchBody),
            });
            if (!pr.ok) {
              const d = await pr.json().catch(() => ({}));
              toast('Save failed: ' + (d.detail?.message || d.detail || pr.status), 'error');
              return;
            }
            const sr = await fetch('/api/v1/submissions/' + sid + '/submit', {
              method: 'POST', headers: {'Content-Type': 'application/json'}, body: '{}',
            });
            if (!sr.ok) {
              const d = await sr.json().catch(() => ({}));
              toast('Resubmit failed: ' + (d.detail?.message || d.detail || sr.status), 'error');
              return;
            }
            await htmx.ajax('GET', '/portal/fragments/my-access', {target:'#portal-body', swap:'innerHTML'});
            ssShowTab('submit');
          } catch (e) { toast('Network error: ' + e, 'error'); }
        }

// ---------------------------------------------------------------------------
// My Access fragment: self-service tab switcher
// ---------------------------------------------------------------------------
    function ssShowTab(name) {
      document.querySelectorAll('.ss-panel').forEach(p => p.style.display = 'none');
      document.querySelectorAll('#ss-tabs-bar .adm-tab').forEach(b => { b.classList.remove('active'); b.removeAttribute('aria-current'); });
      const panel = document.getElementById('ss-panel-' + name);
      panel.style.display = 'block';
      const idx = ['home','catalog','submit','profile'].indexOf(name);
      const tabBtn = document.querySelectorAll('#ss-tabs-bar .adm-tab')[idx];
      tabBtn.classList.add('active');
      tabBtn.setAttribute('aria-current', 'page');
      // Move focus into the newly-shown panel so keyboard/screen-reader users
      // land on the tab's content instead of staying on the tab button.
      panel.focus();
      if (name === 'profile' && !document.getElementById('ss-panel-profile').dataset.loaded) {
        htmx.ajax('GET', '/portal/fragments/profile', {target: '#ss-panel-profile', swap: 'innerHTML'});
        document.getElementById('ss-panel-profile').dataset.loaded = '1';
      }
    }

// ---------------------------------------------------------------------------
// Admin > Request Limits fragment
// ---------------------------------------------------------------------------
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
      <div style="margin-top:10px;font-size:11.5px;color:#7d838d;line-height:1.5">
        <strong style="color:#868c96">unauthenticated</strong> = requests counted by the
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

})();

// ---------------------------------------------------------------------------
// Admin > Detections fragment (drawer + policy-rule viewer)
// ---------------------------------------------------------------------------
      function _escHtml(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
      }
      function openDetectionDrawer(eid) {
        const d = window._detDrawerData[eid];
        if (!d) return;
        document.getElementById('det-drawer-rule').style.display = 'none';
        const reasonsHtml = d.reasons.map(r =>
          '<code style="font-size:11px;background:rgba(255,255,255,0.06);border-radius:4px;padding:1px 5px;margin-right:4px">' + _escHtml(r) + '</code>' +
          '<a href="#" class="pol-rule-link" data-act="viewPolicyRule" data-pd="1" data-json="' + _escHtml(JSON.stringify([r])) + '">view rule</a>'
        ).join(' ');
        const serverHtml = d.server_id
          ? '<a href="#" class="srv-link" data-act="htmxGet" data-pd="1" data-a0="/portal/fragments/admin/servers">' + _escHtml(d.server_name) + '</a>'
          : '<span style="color:var(--muted)">unattributed (legacy row or tool deleted)</span>';
        document.getElementById('det-drawer-body').innerHTML =
          '<div><strong>Time</strong> — ' + _escHtml(d.ts) + '</div>' +
          '<div><strong>Principal</strong> — <span style="font-family:var(--ff-mono)">' + _escHtml(d.client_id) + '</span></div>' +
          '<div><strong>Tool</strong> — ' + _escHtml(d.tool_name) + '</div>' +
          '<div><strong>MCP Server</strong> — ' + serverHtml + '</div>' +
          '<div><strong>Deny reason(s)</strong> — ' + reasonsHtml + '</div>' +
          '<div style="margin-top:6px"><strong>Digest</strong> — <span style="font-family:var(--ff-mono);font-size:11px;color:var(--muted)">' + _escHtml(d.digest) + '</span></div>';
        document.getElementById('det-drawer').style.display = 'block';
      }
      async function viewPolicyRule(reason) {
        const panel = document.getElementById('det-drawer-rule');
        const hdr = document.getElementById('det-drawer-rule-hdr');
        const src = document.getElementById('det-drawer-rule-src');
        panel.style.display = 'block';
        hdr.textContent = 'Loading rule for ' + reason + '…';
        src.textContent = '';
        try {
          const r = await fetch('/portal/policy-rule?reason=' + encodeURIComponent(reason), {credentials: 'include'});
          const d = await r.json();
          if (d.found) {
            hdr.textContent = d.file + ':' + d.line + ' (read-only)';
            src.textContent = d.source;
          } else {
            hdr.textContent = 'No OPA rule found for "' + reason + '"';
            src.textContent = d.note || '';
          }
        } catch (err) {
          hdr.textContent = 'Failed to load rule';
          src.textContent = String(err);
        }
      }

// ---------------------------------------------------------------------------
// Admin > Tools fragment
// ---------------------------------------------------------------------------
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
    async function toggleStatus(toolId, newStatus) {
      if (!(await confirmDialog('Set tool status to "' + newStatus + '"?'))) return;
      fetch('/api/v1/tools/' + toolId, {
        method: 'PATCH',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({status: newStatus}),
      }).then(r => {
        if (r.ok) activateAdminTab('tools');
        else r.json().then(d => toast('Error: ' + (d.detail?.message || d.detail || r.status), 'error'));
      }).catch(e => toast('Network error: ' + e, 'error'));
    }
    function showMsg(el, type, text) {
      if (!el) return;
      el.className = 'msg msg-' + type;
      el.textContent = text;
    }

// ---------------------------------------------------------------------------
// Admin > Credentials fragment
// ---------------------------------------------------------------------------
    function uploadCred(toolId) {
      const secret = document.getElementById('cred-' + toolId)?.value?.trim();
      const ownerType = document.getElementById('owner-' + toolId)?.value || 'service';
      const msgEl = document.getElementById('cred-msg-' + toolId);
      if (!secret) { showMsg(msgEl, 'err', 'Enter a secret first.'); return; }
      fetch('/admin/credentials/' + toolId, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({secret, owner_type: ownerType})
      }).then(r => r.json().then(d => {
        if (r.ok) { showMsg(msgEl, 'ok', 'Uploaded.'); activateAdminTab('credentials'); }
        else showMsg(msgEl, 'err', d.detail?.message || d.detail || 'Failed.');
      })).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }
    async function revokeCred(toolId) {
      if (!(await confirmDialog('Revoke credential for this tool?'))) return;
      const msgEl = document.getElementById('cred-msg-' + toolId);
      fetch('/admin/credentials/' + toolId, {method: 'DELETE'})
        .then(r => {
          if (r.ok) { showMsg(msgEl, 'ok', 'Revoked.'); activateAdminTab('credentials'); }
          else r.json().then(d => showMsg(msgEl, 'err', d.detail?.message || d.detail || 'Failed.'));
        }).catch(e => showMsg(msgEl, 'err', 'Network error: ' + e));
    }
    function showMsg(el, type, text) {
      if (!el) return;
      el.className = 'msg msg-' + type;
      el.textContent = text;
    }

// ---------------------------------------------------------------------------
// Admin > Grants fragment (legacy data.json editor)
// ---------------------------------------------------------------------------
    function collectGrants() {
      const grants = {};
      document.querySelectorAll('.grant-card[id^="grant-"]').forEach(card => {
        const client = card.id.replace('grant-', '');
        const toolsRaw = document.getElementById('tools-' + client)?.value || '';
        const tagsRaw  = document.getElementById('tags-' + client)?.value || '';
        const maxRisk  = document.getElementById('risk-' + client)?.value || 'high';
        const tools = toolsRaw.split(',').map(s => s.trim()).filter(Boolean);
        const tags  = tagsRaw.split(',').map(s => s.trim()).filter(Boolean);
        grants[client] = {allowed_tools: tools, allowed_tags: tags, max_risk_level: maxRisk};
      });
      return grants;
    }
    function saveGrants() {
      const msgEl = document.getElementById('grants-msg');
      const grants = collectGrants();
      fetch('/portal/actions/save-grants', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({grants})
      }).then(r => r.json().then(d => {
        if (r.ok) {
          msgEl.className = 'msg msg-ok';
          msgEl.textContent = 'Saved. OPA will reload in ~5s.';
          const raw = document.getElementById('raw-grants');
          if (raw) raw.textContent = JSON.stringify({mcp: {grants}}, null, 2);
          setTimeout(() => { msgEl.textContent = ''; msgEl.className = ''; }, 6000);
        } else {
          msgEl.className = 'msg msg-err';
          msgEl.textContent = d.detail?.message || d.detail || 'Save failed.';
        }
      })).catch(e => {
        msgEl.className = 'msg msg-err';
        msgEl.textContent = 'Network error: ' + e;
      });
    }
    function addClient() {
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
      [['low','Low'],['medium','Medium'],['high','High'],['critical','Critical']].forEach(([val, label]) => {
        const opt = document.createElement('option');
        opt.value = val;
        opt.textContent = label;
        if (val === 'medium') opt.selected = true;
        riskSel.appendChild(opt);
      });
      riskCol.appendChild(lbl3);
      riskCol.appendChild(riskSel);

      row.appendChild(tagsCol);
      row.appendChild(riskCol);
      card.appendChild(row);

      container.appendChild(card);
    }

// ---------------------------------------------------------------------------
// Admin > Submissions fragment: review actions
// ---------------------------------------------------------------------------
    async function reviewAction(sid, action) {
      const notes = document.getElementById('notes-' + sid)?.value || '';
      const payload = {notes};
      if (action === 'approve') {
        // Only present when the submission has high-risk scopes (see
        // portal fragment above) — send its checked state so the backend's
        // fail-closed high-risk-scope gate (oauth_policy.py) can actually be
        // satisfied instead of always defaulting to false and 422'ing.
        const hra = document.getElementById('hra-' + sid);
        if (hra) payload.high_risk_scopes_approved = hra.checked;
      }
      const r = await fetch('/api/v1/admin/submissions/' + sid + '/' + action, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'include',
        body: JSON.stringify(payload),
      });
      if (r.ok) {
        htmx.ajax('GET', '/portal/fragments/admin/submissions', {target:'#adm-content', swap:'innerHTML'});
      } else {
        const err = await r.json().catch(() => ({}));
        const msg = (err.detail && typeof err.detail === 'object') ? (err.detail.message || JSON.stringify(err.detail)) : (err.detail || r.status);
        toast('Action failed: ' + msg, 'error');
      }
    }

// ---------------------------------------------------------------------------
// Admin > Wizard Prompts fragment
// ---------------------------------------------------------------------------
    async function savePrompt(key) {
      const el = document.getElementById('pt-' + key);
      const r = await fetch('/api/v1/admin/prompts/' + encodeURIComponent(key), {
        method: 'PUT', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({text: el.value})
      });
      if (r.ok) { htmx.ajax('GET', '/portal/fragments/admin/prompts', {target: '#adm-content', swap: 'innerHTML'}); }
      else { const e = await r.json().catch(() => ({})); toast('Save failed: ' + (e.detail || r.status), 'error'); }
    }
    async function resetPrompt(key) {
      if (!(await confirmDialog('Reset this prompt to its built-in default?'))) return;
      const r = await fetch('/api/v1/admin/prompts/' + encodeURIComponent(key), {method: 'DELETE'});
      if (r.ok) { htmx.ajax('GET', '/portal/fragments/admin/prompts', {target: '#adm-content', swap: 'innerHTML'}); }
      else { const e = await r.json().catch(() => ({})); toast('Reset failed: ' + (e.detail || r.status), 'error'); }
    }

// ---------------------------------------------------------------------------
// Admin > LLM Provider fragment
// ---------------------------------------------------------------------------
    async function saveLlm() {
      const body = {
        base_url: document.getElementById('llm-base').value || null,
        model: document.getElementById('llm-model').value || null,
        timeout_seconds: parseInt(document.getElementById('llm-timeout').value) || null,
        enabled: document.getElementById('llm-enabled').checked
      };
      const r = await fetch('/api/v1/admin/llm', {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/llm',{target:'#adm-content',swap:'innerHTML'}); }
      else { const e=await r.json().catch(()=>({})); toast('Save failed: '+(e.detail||r.status), 'error'); }
    }
    async function saveLlmToken() {
      const t = document.getElementById('llm-token').value;
      if (!t) { toast('Enter a token first.', 'error'); return; }
      const r = await fetch('/api/v1/admin/llm/token', {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/llm',{target:'#adm-content',swap:'innerHTML'}); }
      else { const e=await r.json().catch(()=>({})); toast('Token save failed: '+(e.detail||r.status), 'error'); }
    }
    async function delLlmToken() {
      if (!(await confirmDialog('Remove the stored LLM token?'))) return;
      const r = await fetch('/api/v1/admin/llm/token', {method:'DELETE'});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/llm',{target:'#adm-content',swap:'innerHTML'}); }
    }
    async function testLlm() {
      const out = document.getElementById('llm-test-out'); out.textContent = 'Testing…';
      const r = await fetch('/api/v1/admin/llm/test',{method:'POST'});
      const d = await r.json().catch(()=>({}));
      out.textContent = d.ok ? ('OK (status '+d.status+', token '+(d.token_used?'used':'not used')+')')
                             : ('Failed: '+(d.error||('status '+d.status)));
      out.style.color = d.ok ? '#4ade80' : '#fca5a5';
    }

// ---------------------------------------------------------------------------
// Admin > Git Providers fragment
// ---------------------------------------------------------------------------
    async function saveGit(prov) {
      const body = {
        host: document.getElementById('git-host-'+prov).value,
        clone_account: document.getElementById('git-acct-'+prov).value || null,
        enabled: document.getElementById('git-enabled-'+prov).checked,
        allow_private: document.getElementById('git-priv-'+prov).checked
      };
      const r = await fetch('/api/v1/admin/git-providers/'+prov, {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/git',{target:'#adm-content',swap:'innerHTML'}); }
      else { const e=await r.json().catch(()=>({})); toast('Save failed: '+(e.detail||r.status), 'error'); }
    }
    async function saveGitToken(prov) {
      const t = document.getElementById('git-token-'+prov).value;
      if (!t) { toast('Enter a token first.', 'error'); return; }
      const r = await fetch('/api/v1/admin/git-providers/'+prov+'/token', {method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:t})});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/git',{target:'#adm-content',swap:'innerHTML'}); }
      else { const e=await r.json().catch(()=>({})); toast('Token save failed: '+(e.detail||r.status), 'error'); }
    }
    async function delGitToken(prov) {
      if (!(await confirmDialog('Remove the stored token for '+prov+'?'))) return;
      const r = await fetch('/api/v1/admin/git-providers/'+prov+'/token', {method:'DELETE'});
      if (r.ok) { htmx.ajax('GET','/portal/fragments/admin/git',{target:'#adm-content',swap:'innerHTML'}); }
    }

// ---------------------------------------------------------------------------
// Consolidated event delegation — replaces the per-fragment
// `document.querySelectorAll('.foo').forEach(el => el.addEventListener(...))`
// wiring that used to live in each admin fragment's own inline <script>
// (mcp-profile manage, SBOM, Access — API keys/roles/grants/per-principal
// toggles). Registered once on document.body, which persists across every
// htmx swap, so it works regardless of when the matched elements appear.
// ---------------------------------------------------------------------------

function _mcpProfileReload(container, profile) {
  htmx.ajax('GET', '/portal/fragments/mcp-profile/' + encodeURIComponent(profile),
             {target: '#' + container, swap: 'innerHTML'});
}

function _sbomRefresh() {
  htmx.ajax('GET', '/portal/fragments/admin/sbom', {target: '#adm-content', swap: 'innerHTML'});
}
function _sbomReport(msgEl, label, data) {
  const gen = (data.generated || []).length;
  const fail = (data.failed || []).length;
  msgEl.style.color = fail ? '#fbbf24' : '#4ade80';
  msgEl.textContent = label + ': ' + gen + ' generated' + (fail ? (', ' + fail + ' failed') : '');
}

function _accessRefresh() {
  htmx.ajax('GET', '/portal/fragments/admin/access', {target: '#adm-content', swap: 'innerHTML'});
}

document.body.addEventListener('click', async function(e) {
  // --- MCP named-profile manage: per-tool toggle + bulk enable/disable ---
  const mcpToggle = e.target.closest('.mcpprof-toggle-btn');
  if (mcpToggle) {
    const btn = mcpToggle;
    const profile = btn.dataset.profile, mcpName = btn.dataset.mcp;
    const newEnabled = btn.dataset.enabled !== 'true';
    btn.disabled = true;
    fetch('/api/v1/profiles/named/' + encodeURIComponent(profile) + '/mcps/' + encodeURIComponent(mcpName), {
      method: 'PUT', credentials: 'include', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enabled: newEnabled}),
    }).then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      _mcpProfileReload(btn.dataset.container, profile);
    }).catch(function(err) {
      btn.disabled = false;
      toast('Failed to update: ' + err.message, 'error');
    });
    return;
  }
  const mcpBulk = e.target.closest('.mcpprof-bulk-btn');
  if (mcpBulk) {
    const btn = mcpBulk;
    const profile = btn.dataset.profile;
    const enabled = btn.dataset.action === 'enable';
    const tools = JSON.parse(btn.dataset.tools);
    btn.disabled = true;
    (async function() {
      try {
        for (const mcpName of tools) {
          const r = await fetch('/api/v1/profiles/named/' + encodeURIComponent(profile) + '/mcps/' + encodeURIComponent(mcpName), {
            method: 'PUT', credentials: 'include', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled: enabled}),
          });
          if (!r.ok) throw new Error('HTTP ' + r.status + ' on ' + mcpName);
        }
        _mcpProfileReload(btn.dataset.container, profile);
      } catch (err) {
        btn.disabled = false;
        toast('Failed to update all tools: ' + err.message, 'error');
      }
    })();
    return;
  }

  // --- SBOM: per-tool / per-server / global generate buttons ---
  const sbomGenBtn = e.target.closest('.sbom-gen-btn');
  if (sbomGenBtn) {
    sbomGenBtn.disabled = true;
    fetch('/api/v1/tools/' + encodeURIComponent(sbomGenBtn.dataset.toolId) + '/sbom/generate',
          {method: 'POST', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail && d.detail.message || ('HTTP ' + r.status)); }); _sbomRefresh(); })
      .catch(function(err) { sbomGenBtn.disabled = false; toast(err.message, 'error'); });
    return;
  }
  const sbomGenServerBtn = e.target.closest('.sbom-gen-server-btn');
  if (sbomGenServerBtn) {
    sbomGenServerBtn.disabled = true;
    const msgEl = document.getElementById('sbom-gen-msg');
    fetch('/api/v1/servers/' + encodeURIComponent(sbomGenServerBtn.dataset.serverId) + '/sbom/generate-all',
          {method: 'POST', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail && d.detail.message || ('HTTP ' + r.status)); }); return r.json(); })
      .then(function(data) { _sbomReport(msgEl, sbomGenServerBtn.textContent, data); _sbomRefresh(); })
      .catch(function(err) { sbomGenServerBtn.disabled = false; if (msgEl) { msgEl.style.color = '#fca5a5'; msgEl.textContent = err.message; } });
    return;
  }
  const sbomGenAllBtn = e.target.closest('#sbom-gen-all-btn');
  if (sbomGenAllBtn) {
    sbomGenAllBtn.disabled = true;
    sbomGenAllBtn.textContent = 'Generating…';
    const msgEl = document.getElementById('sbom-gen-msg');
    fetch('/api/v1/tools/sbom/generate-all', {method: 'POST', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail && d.detail.message || ('HTTP ' + r.status)); }); return r.json(); })
      .then(function(data) { _sbomReport(msgEl, 'All tools', data); _sbomRefresh(); })
      .catch(function(err) { sbomGenAllBtn.disabled = false; sbomGenAllBtn.textContent = 'Generate All (one by one)'; if (msgEl) { msgEl.style.color = '#fca5a5'; msgEl.textContent = err.message; } });
    return;
  }

  // --- Access tab: API key revoke, role revoke/add, client grant revoke, per-principal toggle ---
  const apikeyRevokeBtn = e.target.closest('.apikey-revoke-btn');
  if (apikeyRevokeBtn) {
    const keyId = apikeyRevokeBtn.dataset.keyId, clientId = apikeyRevokeBtn.dataset.clientId;
    if (!(await confirmDialog('Revoke API key for "' + clientId + '"? It stops authenticating immediately.'))) return;
    fetch('/api/v1/admin/api-keys/' + encodeURIComponent(keyId), {method: 'DELETE', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); _accessRefresh(); })
      .catch(function(err) { toast(err.message, 'error'); });
    return;
  }
  const roleXBtn = e.target.closest('.role-x-btn');
  if (roleXBtn) {
    const clientId = roleXBtn.dataset.clientId, role = roleXBtn.dataset.role;
    if (!(await confirmDialog('Revoke role "' + role + '" from ' + clientId + '?'))) return;
    fetch('/api/v1/admin/roles/' + encodeURIComponent(clientId) + '/' + encodeURIComponent(role),
          {method: 'DELETE', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); _accessRefresh(); })
      .catch(function(err) { toast(err.message, 'error'); });
    return;
  }
  const roleAddBtn = e.target.closest('.role-add-btn');
  if (roleAddBtn) {
    const clientId = roleAddBtn.dataset.clientId;
    const select = document.querySelector('.role-add-select[data-client-id="' + CSS.escape(clientId) + '"]');
    const role = select ? select.value : null;
    if (!role) return;
    fetch('/api/v1/admin/roles', {
      method: 'POST', credentials: 'include',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({client_id: clientId, role: role}),
    }).then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); _accessRefresh(); })
      .catch(function(err) { toast(err.message, 'error'); });
    return;
  }
  const grantRevokeBtn = e.target.closest('.grant-revoke-btn');
  if (grantRevokeBtn) {
    const clientId = grantRevokeBtn.dataset.clientId;
    if (!(await confirmDialog('Revoke API client grant for "' + clientId + '"? It will lose all tool/tag access immediately.'))) return;
    fetch('/api/v1/admin/grants/' + encodeURIComponent(clientId), {method: 'DELETE', credentials: 'include'})
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); _accessRefresh(); })
      .catch(function(err) { toast(err.message, 'error'); });
    return;
  }
  // Unobtrusive binding (not inline onclick=) — principal/mcp names come from the
  // DB (OAuth client_id / tool_registry.name) and aren't guaranteed to be free of
  // quote/script characters, so they must never be interpolated into a JS literal.
  const accessToggleBtn = e.target.closest('.access-toggle-btn');
  if (accessToggleBtn) {
    const principal = accessToggleBtn.dataset.principal;
    const mcpName = accessToggleBtn.dataset.mcp;
    const action = accessToggleBtn.dataset.action;
    const slug = principal.replace(/[^a-zA-Z0-9]/g, '_');
    const msgEl = document.getElementById('access-toggle-msg-' + slug);
    fetch('/api/v1/profiles/' + encodeURIComponent(principal) + '/mcps/' + encodeURIComponent(mcpName) + '/' + encodeURIComponent(action),
          {method: 'POST', credentials: 'include'})
      .then(function(r) {
        if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || ('HTTP ' + r.status)); });
        htmx.ajax('GET', '/portal/fragments/admin/access/' + encodeURIComponent(principal),
                   {target: '#access-detail-' + slug, swap: 'innerHTML'});
      })
      .catch(function(err) { if (msgEl) { msgEl.style.color = '#fca5a5'; msgEl.textContent = err.message; } });
  }
});

document.body.addEventListener('submit', function(e) {
  if (e.target && e.target.id === 'apikey-create-form') {
    const form = e.target;
    e.preventDefault();
    const resultEl = document.getElementById('apikey-create-result');
    const clientId = document.getElementById('apikey-create-client').value.trim();
    const role = document.getElementById('apikey-create-role').value;
    const rateLimit = parseInt(document.getElementById('apikey-create-ratelimit').value, 10) || 120;
    fetch('/api/v1/admin/api-keys', {
      method: 'POST', credentials: 'include',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({client_id: clientId, roles: [role], rate_limit_rpm: rateLimit}),
    })
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); return r.json(); })
      .then(function(data) {
        if (resultEl) {
          resultEl.style.color = '#4ade80';
          resultEl.innerHTML = '&#x2713; Saved. Copy this key now — it will never be shown again:<br>' +
            '<code style="user-select:all;background:#0f172a;padding:4px 8px;border-radius:4px;display:inline-block;margin-top:4px">' +
            esc(data.api_key) + '</code>';
        }
        // Reflect the new key in the table immediately — a full fragment
        // refresh here would wipe the one-time key display above before
        // the admin has a chance to copy it, which read as "created but
        // not saved" even though it was. The new row's Revoke button is
        // matched by the delegated .apikey-revoke-btn handler above, same
        // as every other row — no per-element binding needed.
        const emptyRow = document.getElementById('apikey-empty-row');
        if (emptyRow) emptyRow.remove();
        const tbody = document.getElementById('apikey-table-body');
        if (tbody) {
          const tr = document.createElement('tr');
          const tdClient = document.createElement('td');
          tdClient.style.fontFamily = 'var(--ff-mono)'; tdClient.style.fontSize = '12px';
          tdClient.textContent = data.client_id;
          const tdRoles = document.createElement('td');
          tdRoles.style.fontSize = '12px'; tdRoles.textContent = (data.roles || []).join(', ');
          const tdRate = document.createElement('td');
          tdRate.style.fontSize = '12px'; tdRate.style.color = 'var(--muted)';
          tdRate.textContent = data.rate_limit_rpm + '/min';
          const tdCreated = document.createElement('td');
          tdCreated.style.fontSize = '11px'; tdCreated.style.color = 'var(--muted)';
          tdCreated.textContent = (data.created_at || '').slice(0, 16).replace('T', ' ');
          const tdAction = document.createElement('td');
          tdAction.style.textAlign = 'right';
          const revokeBtn = document.createElement('button');
          revokeBtn.className = 'btn-secondary btn-sm apikey-revoke-btn';
          revokeBtn.dataset.keyId = data.key_id;
          revokeBtn.dataset.clientId = data.client_id;
          revokeBtn.textContent = 'Revoke';
          tdAction.appendChild(revokeBtn);
          tr.append(tdClient, tdRoles, tdRate, tdCreated, tdAction);
          tbody.prepend(tr);
        }
        form.reset();
      })
      .catch(function(err) { if (resultEl) { resultEl.style.color = '#fca5a5'; resultEl.textContent = err.message; } });
    return;
  }
  if (e.target && e.target.id === 'grant-create-form') {
    e.preventDefault();
    const msgEl = document.getElementById('grant-create-msg');
    const clientId = document.getElementById('grant-create-client').value.trim();
    const tools = document.getElementById('grant-create-tools').value.split(',').map(s => s.trim()).filter(Boolean);
    const tags = document.getElementById('grant-create-tags').value.split(',').map(s => s.trim()).filter(Boolean);
    const risk = document.getElementById('grant-create-risk').value;
    fetch('/api/v1/admin/grants', {
      method: 'POST', credentials: 'include',
      headers: {'content-type': 'application/json'},
      body: JSON.stringify({client_id: clientId, allowed_tools: tools, allowed_tags: tags, max_risk_level: risk}),
    })
      .then(function(r) { if (!r.ok) return r.json().then(function(d) { throw new Error((d.detail && d.detail.message) || d.detail || ('HTTP ' + r.status)); }); _accessRefresh(); })
      .catch(function(err) { if (msgEl) { msgEl.style.color = '#fca5a5'; msgEl.textContent = err.message; } });
  }
});

// --- Request Limits tab: fetch the table as soon as it's swapped into the
// DOM (this used to be a bare `limitsRefresh();` call at the bottom of the
// fragment's own inline <script>, which ran because htmx re-executes
// <script> tags in swapped content; htmx:afterSettle fires for the same
// swap and is the static-file-safe equivalent). ---
document.body.addEventListener('htmx:afterSettle', function(evt) {
  const root = evt.detail && evt.detail.elt;
  if (root && root.querySelector && root.querySelector('#limits-table-wrap') && window.limitsRefresh) {
    window.limitsRefresh();
  }
});


// ---------------------------------------------------------------------------
// R1.4 — delegated action dispatcher (replaces inline onclick= attributes)
//
// Inline event-handler attributes are unconditionally blocked by any CSP that
// does not include 'unsafe-inline', and unlike inline <script> they cannot be
// rescued by a nonce. They were also invisible to every JS tool: the handler
// bodies lived inside Python f-strings, so a typo surfaced only as a dead
// button in the browser.
//
// Markup contract, emitted by portal.py:
//     data-act="fnName"     required — key into PORTAL_ACTIONS below
//     data-a0 / data-a1…    positional STRING arguments, in order
//     data-json='[…]'       positional arguments as a JSON array; used instead
//                           of data-aN when any argument is not a string
//                           (booleans and embedded JSON would otherwise arrive
//                           as the truthy strings "false" / "[object Object]")
//     data-evt="1"          pass the DOM event as the FIRST argument
//     data-self="1"         pass the clicked element as the FIRST argument
//     data-pd="1"           preventDefault (the old `; return false` idiom)
//
// PORTAL_ACTIONS is an explicit allowlist rather than a `window[name]` lookup.
// The markup is server-rendered and escaped, so this is defence in depth, but
// a name-indexed global lookup turns any injected data-act into a call into
// arbitrary page globals — a needless second gadget for one saved line.
// ---------------------------------------------------------------------------
// Allowlisted NAMES, resolved to functions at click time — deliberately NOT a
// snapshot of function references taken at registration. Many handlers here are
// declared inside blocks rather than at top level, so they are not yet defined as
// globals when this file finishes executing: measured at load, only 56 of 64 names
// resolved. A snapshot would have silently dropped the other 8, leaving buttons
// that look normal and do nothing. Late lookup by name is what makes this correct;
// the Set still constrains which names are callable at all.
const PORTAL_ACTIONS = new Set();

function registerPortalActions(names) {
  names.forEach(function(n) { PORTAL_ACTIONS.add(n); });
  // Exposed for the AC-11 acceptance check; a top-level `const` is not a window
  // property, so without this the test cannot see the allowlist at all.
  window.PORTAL_ACTIONS = PORTAL_ACTIONS;
  // Accumulates across every registerPortalActions call — assigning here would
  // report only the last batch, which is exactly the kind of number that ends up
  // quoted in a comment and is wrong.
  window.__PORTAL_ACTIONS_DEFINED_AT_LOAD__ =
    (window.__PORTAL_ACTIONS_DEFINED_AT_LOAD__ || 0) +
    names.filter(function(n) { return typeof window[n] === 'function'; }).length;
}

document.body.addEventListener('click', function(e) {
  const el = e.target.closest && e.target.closest('[data-act]');
  if (!el) { return; }
  const name = el.dataset.act;
  if (!PORTAL_ACTIONS.has(name)) {
    console.error('portal: data-act="' + name + '" is not in the action allowlist');
    return;
  }
  const fn = window[name];
  if (typeof fn !== 'function') {
    console.error('portal: no handler defined for data-act="' + name + '"');
    return;
  }
  if (el.dataset.pd === '1') { e.preventDefault(); }
  if (el.dataset.stop === '1') { e.stopPropagation(); }

  let args;
  if (el.dataset.json !== undefined) {
    try {
      args = JSON.parse(el.dataset.json);
    } catch (err) {
      console.error('portal: bad data-json on action ' + name, err);
      return;
    }
  } else {
    args = [];
    for (let i = 0; el.dataset['a' + i] !== undefined; i++) { args.push(el.dataset['a' + i]); }
  }
  if (el.dataset.self === '1') { args.unshift(el); }
  if (el.dataset.evt === '1') { args.unshift(e); }
  fn.apply(el, args);
});

// --- Named helpers for handlers that used to be inline expressions ---------
// Each of these replaced a raw JS expression in an onclick attribute. They are
// deliberately tiny; the point is that the behaviour is now in a linted file
// with a name, not that the abstraction earns its keep.

function htmxGet(url, target) {
  htmx.ajax('GET', url, { target: target || '#adm-content', swap: 'innerHTML' });
}

function toggleDisplay(id, shown) {
  const el = document.getElementById(id);
  if (!el) { return; }
  const show = shown !== undefined ? shown : (el.style.display === 'none' || !el.style.display);
  el.style.display = show ? 'block' : 'none';
}

function copyText(text, doneLabel) {
  const btn = this instanceof Element ? this : null;
  navigator.clipboard.writeText(text).then(function() {
    if (!btn) { return; }
    const prev = btn.textContent;
    btn.textContent = doneLabel || 'Copied!';
    setTimeout(function() { btn.textContent = prev; }, 1500);
  });
}

function copyElementText(sourceId, doneLabel) {
  const src = document.getElementById(sourceId);
  copyText.call(this, src ? src.textContent : '', doneLabel);
}

// Allowlist of every function reachable from a data-act attribute. Generated from
// the conversion of the original inline onclick handlers (roadmap R1.4); add a name
// here when you add a new data-act, or the dispatcher logs and refuses to call it.
registerPortalActions([
  'viewPolicyRule',
  '_dismissMigrationBanner', 'activateAdminTab', 'addClient', 'adminApproveSrv',
  'adminDeleteSrv', 'adminManageServerTools', 'adminQuarantineSrv', 'adminRebuildSrv',
  'adminRejectSrv', 'adminReleaseSrv', 'adminToggleDebug', 'adminVerifySrv',
  'adminViewLogs', 'applyRecommendation', 'copyElementText', 'copyText',
  'createMcpProfile', 'delGitToken', 'delLlmToken', 'doSubmit', 'editAndResubmit',
  'filterSrv', 'htmxGet', 'limitsCloseDrawer', 'limitsRefresh', 'limitsReset',
  'limitsSave', 'loadAdminTab', 'openDetectionDrawer', 'pickHosting', 'pickMode',
  'portalSignOut', 'providePendingUrl', 'registerTool', 'reviewAction', 'revokeCred',
  'saveGit', 'saveGitToken', 'saveGrants', 'saveLlm', 'saveLlmToken',
  'showGuidedQuestions', 'showStep1', 'showStep2', 'showStep3', 'showStep4',
  'srvMenuToggle', 'ssShowTab', 'submitStep1', 'submitStep2', 'testLlm', 'toggleCat',
  'toggleDisplay', 'toggleStatus', 'uploadCred',
]);

function showEl(id)  { toggleDisplay(id, true); }
function hideEl(id)  { toggleDisplay(id, false); }
function toggleEl(id) { toggleDisplay(id); }

registerPortalActions([
  'showEl', 'hideEl', 'toggleEl', 'htmxGet', 'toggleDisplay', 'copyText', 'copyElementText',
  'adminSetMaintainers', 'adminEditEndpoint', 'adminSetPublic', 'savePrompt', 'resetPrompt',
]);

// Async webfont swap — replaces onload="this.media='all'" on the Google Fonts <link>,
// which the portal CSP blocks (inline handlers cannot carry a nonce). Checks .sheet
// first because this file is deferred and the stylesheet may already have loaded, in
// which case the load event has been and gone.
document.querySelectorAll('link[data-media-swap]').forEach(function(l) {
  if (l.sheet) { l.media = 'all'; }
  else { l.addEventListener('load', function() { l.media = 'all'; }); }
});
