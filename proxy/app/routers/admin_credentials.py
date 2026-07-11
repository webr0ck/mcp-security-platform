"""
MCP Security Platform — Credential Management Admin UI

Provides:
  GET  /admin/credentials          — HTML credential management page (htmx)
  GET  /admin/credentials/api      — JSON list of tools + credential status
  PUT  /admin/credentials/{tool_id} — Upload/rotate credential for a tool
  DELETE /admin/credentials/{tool_id} — Revoke credential for a tool
  POST /admin/credentials/{tool_id}/enroll — Start device-flow OAuth2 enrollment

Requires admin role. All mutations emit an audit event.
Credentials are encrypted with AES-256-GCM (Approach A) before storage.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/credentials", tags=["Admin: Credentials"])


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CredentialUpload(BaseModel):
    """Body for PUT /admin/credentials/{tool_id}"""
    secret: str                         # plaintext secret to encrypt + store
    credential_type: str = "api_key"    # api_key | oauth2_refresh | entra_client_secret | basic_auth | ...
    owner_type: str = "service"         # service | user
    user_sub: str | None = None         # required when owner_type='user'
    username: str | None = None         # required when credential_type='basic_auth' (RFC 7617)
    description: str | None = None


class EntraConfig(BaseModel):
    """Body for configuring Entra ID per tool."""
    tenant_id: str
    client_id: str
    client_secret: str
    scope: str = "https://graph.microsoft.com/.default"


# ---------------------------------------------------------------------------
# Authorization helper
# ---------------------------------------------------------------------------

def _require_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if "admin" not in roles:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "Admin role required."})


# ---------------------------------------------------------------------------
# HTML UI
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
async def admin_credentials_page(request: Request):
    """Serve the credential management page."""
    _require_admin(request)
    html = _build_html()
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@router.get("/api")
async def list_tools_with_credential_status(request: Request):
    """Return all registered tools with their injection_mode and credential status."""
    _require_admin(request)

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("""
                    SELECT
                        t.tool_id, t.name, t.version, t.status,
                        t.injection_mode,
                        t.service_name,
                        t.inject_header, t.inject_prefix,
                        t.kc_client_id, t.kc_token_audience,
                        t.entra_tenant_id, t.entra_client_id,
                        t.entra_scope,
                        EXISTS (
                            SELECT 1 FROM credential_store c
                            WHERE c.tool_id = t.tool_id
                              OR (c.user_sub = '__service__' AND c.service = t.service_name)
                        ) AS has_service_credential
                    FROM tool_registry t
                    WHERE t.deleted_at IS NULL
                    ORDER BY t.name
                """)
            )
            rows = result.fetchall()
    except Exception as exc:
        logger.error("DB error in admin/credentials/api: %s", exc)
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    tools = []
    for row in rows:
        tools.append({
            "tool_id": str(row.tool_id),
            "name": row.name,
            "version": row.version,
            "status": row.status,
            "injection_mode": row.injection_mode or "none",
            "service_name": row.service_name,
            "inject_header": row.inject_header,
            "inject_prefix": row.inject_prefix,
            "kc_client_id": row.kc_client_id,
            "kc_token_audience": row.kc_token_audience,
            "entra_tenant_id": row.entra_tenant_id,
            "entra_client_id": row.entra_client_id,
            "entra_scope": row.entra_scope,
            "has_service_credential": bool(row.has_service_credential),
        })

    return JSONResponse(content={"tools": tools, "count": len(tools)})


@router.put("/{tool_id}")
async def upload_credential(request: Request, tool_id: str, body: CredentialUpload):
    """
    Upload or rotate a credential for a tool.
    Encrypts the secret with AES-256-GCM before storage.
    """
    _require_admin(request)

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
    owner_type = body.owner_type
    user_sub = "__service__" if owner_type == "service" else (body.user_sub or "")

    if owner_type == "user" and not user_sub:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "user_sub required for user-mode credentials."})

    # CR-05: basic_auth is stored as the structured JSON payload the dispatcher's
    # _inject_basic_auth expects — {"username", "secret"} — NEVER a prebuilt
    # "Basic <b64>" header. Same unified approach_a codec as every other type.
    if body.credential_type == "basic_auth":
        if not body.username:
            raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "username required for basic_auth credentials."})
        if ":" in body.username:
            raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": "RFC 7617 forbids ':' in the username."})
        import json as _json
        plaintext = _json.dumps({"username": body.username, "secret": body.secret})
    else:
        plaintext = body.secret

    # Encrypt with Approach A
    try:
        from app.credential_broker.kms import load_master_secret_standalone
        from app.credential_broker.approaches.approach_a import encrypt

        master = await load_master_secret_standalone()
        blob = encrypt(
            plaintext,
            user_sub,
            master,
            service=service_name,
            # Canonical UUID string from the DB row (not the raw path param) so the
            # AAD matches exactly what dispatcher/retrieve_credential rebuilds.
            tool_id=str(tool.tool_id),
            owner_type=owner_type,
        )
    except Exception as exc:
        logger.error("Credential encryption failed: %s", exc)
        raise HTTPException(status_code=500, detail={"code": "ENCRYPTION_ERROR", "message": "Failed to encrypt credential."})

    # Upsert into credential_store
    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("""
                    INSERT INTO credential_store
                        (user_sub, service, encrypted_blob, owner_type, tool_id, credential_type, description)
                    VALUES
                        (:sub, :svc, :blob, :owner_type, :tool_id, :ctype, :desc)
                    ON CONFLICT (tool_id, service) WHERE owner_type = 'service' AND tool_id IS NOT NULL
                        DO UPDATE SET
                            encrypted_blob = EXCLUDED.encrypted_blob,
                            credential_type = EXCLUDED.credential_type,
                            description = EXCLUDED.description,
                            rotated_at = NOW(),
                            updated_at = NOW()
                    RETURNING id
                """),
                {
                    "sub": user_sub,
                    "svc": service_name,
                    "blob": blob,
                    "owner_type": owner_type,
                    "tool_id": tool_id,
                    "ctype": body.credential_type,
                    "desc": body.description,
                },
            )
            credential_id = result.scalar_one()
            if owner_type == "service":
                # Link the tool to its default credential so the dispatcher's
                # stored-credential modes (e.g. entra_client_credentials) can
                # resolve it via tool_record["credential_id"].
                await session.execute(
                    text("UPDATE tool_registry SET credential_id = :cid WHERE tool_id = :tid"),
                    {"cid": credential_id, "tid": tool_id},
                )
            await session.commit()
    except Exception as exc:
        logger.error("DB error storing credential: %s", exc)
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    admin_id = getattr(request.state, "client_id", "unknown")
    logger.info(
        "Credential uploaded",
        extra={"tool_id": tool_id, "service": service_name, "owner_type": owner_type, "admin": admin_id},
    )
    await _emit_credential_audit(
        event_type="CREDENTIAL_UPLOADED",
        tool_id=tool_id,
        tool_name=tool.name,
        actor=admin_id,
        detail={"service": service_name, "owner_type": owner_type,
                "credential_type": body.credential_type, "user_sub": user_sub},
    )

    return JSONResponse(
        status_code=200,
        content={"message": "Credential stored.", "tool_id": tool_id, "service": service_name, "owner_type": owner_type},
    )


@router.delete("/{tool_id}")
async def revoke_credential(
    request: Request,
    tool_id: str,
    owner_type: str = "service",
    user_sub: str | None = None,
):
    """Hard-delete a credential from credential_store."""
    _require_admin(request)

    if owner_type == "user" and not user_sub:
        raise HTTPException(
            status_code=422,
            detail={"code": "VALIDATION_ERROR", "message": "user_sub is required when owner_type is 'user'"},
        )

    _user_sub = "__service__" if owner_type == "service" else (user_sub or "")

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                text("""
                    DELETE FROM credential_store
                    WHERE tool_id = :tid AND owner_type = :otype
                    AND user_sub = :sub
                """),
                {"tid": tool_id, "otype": owner_type, "sub": _user_sub},
            )
            deleted = result.rowcount
            await session.commit()
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    admin_id = getattr(request.state, "client_id", "unknown")
    logger.info("Credential revoked", extra={"tool_id": tool_id, "owner_type": owner_type, "admin": admin_id, "count": deleted})
    await _emit_credential_audit(
        event_type="CREDENTIAL_REVOKED",
        tool_id=tool_id,
        tool_name=tool_id,
        actor=admin_id,
        detail={"owner_type": owner_type, "user_sub": _user_sub, "rows_deleted": deleted},
    )

    return JSONResponse(content={"message": f"Deleted {deleted} credential(s).", "tool_id": tool_id})


@router.put("/{tool_id}/injection-mode")
async def update_injection_mode(
    request: Request,
    tool_id: str,
    mode: str,
    kc_client_id: str | None = None,
    kc_token_audience: str | None = None,
    entra_tenant_id: str | None = None,
    entra_client_id: str | None = None,
    entra_scope: str | None = None,
):
    """Update the injection_mode and Keycloak/Entra metadata for a tool."""
    _require_admin(request)

    # WP-A5 (CR-02 completion): this is the ONLY admin write path for
    # injection_mode, so it must accept the FULL canonical set
    # (services/auth_modes.py::all_mode_values) — including passthrough,
    # whose AUTH_MODES status is literally "admin_only" (settable only
    # through the admin credential store, never self-service). The previous
    # self-service-tier-only list made passthrough unreachable via any API,
    # contradicting its own status label.
    from app.services.auth_modes import all_mode_values
    valid_modes = tuple(sorted(all_mode_values()))
    if mode not in valid_modes:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "message": f"injection_mode must be one of: {valid_modes}"})

    try:
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    UPDATE tool_registry SET
                        injection_mode = :mode,
                        kc_client_id = COALESCE(:kc_cid, kc_client_id),
                        kc_token_audience = COALESCE(:kc_aud, kc_token_audience),
                        entra_tenant_id = COALESCE(:e_tid, entra_tenant_id),
                        entra_client_id = COALESCE(:e_cid, entra_client_id),
                        entra_scope = COALESCE(:e_scope, entra_scope),
                        updated_at = NOW()
                    WHERE tool_id = :tid AND deleted_at IS NULL
                """),
                {
                    "mode": mode,
                    "kc_cid": kc_client_id,
                    "kc_aud": kc_token_audience,
                    "e_tid": entra_tenant_id,
                    "e_cid": entra_client_id,
                    "e_scope": entra_scope,
                    "tid": tool_id,
                },
            )
            await session.commit()
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"code": "INTERNAL_ERROR", "message": str(exc)})

    admin_id = getattr(request.state, "client_id", "unknown")
    logger.info("Injection mode updated", extra={"tool_id": tool_id, "mode": mode, "admin": admin_id})
    await _emit_credential_audit(
        event_type="CREDENTIAL_MODE_CHANGED",
        tool_id=tool_id,
        tool_name=tool_id,
        actor=admin_id,
        detail={"injection_mode": mode, "kc_client_id": kc_client_id,
                "kc_token_audience": kc_token_audience, "entra_tenant_id": entra_tenant_id},
    )

    return JSONResponse(content={"message": "Injection mode updated.", "tool_id": tool_id, "injection_mode": mode})


# ---------------------------------------------------------------------------
# Audit helper — durable credential lifecycle events (FIND-008 fix)
# ---------------------------------------------------------------------------

async def _emit_credential_audit(
    event_type: str,
    tool_id: str,
    tool_name: str,
    actor: str,
    detail: dict,
) -> None:
    """
    Emit a durable audit event for credential lifecycle mutations.
    Logs at CRITICAL on failure — does not raise so it doesn't mask the
    response, but the failure is visible in monitoring (unlike a silent pass).
    """
    try:
        from mcp_audit_logger import AuditEvent, AuditEventType, MCPAuditLogger
        from sqlalchemy import text
        from app.core.database import AsyncSessionLocal

        event = AuditEvent(
            event_type=AuditEventType(event_type),
            tool_id=tool_id,
            tool_name=tool_name,
            client_id=actor,
            outcome="allow",
            metadata=detail,
        )
        al = MCPAuditLogger()
        await al.emit(event)

        async with AsyncSessionLocal() as session:
            await session.execute(
                text("""
                    INSERT INTO audit_events (tool_id, event_type, client_id, outcome, metadata)
                    VALUES (:tid, :etype, :cid, 'allow', :meta::jsonb)
                """),
                {"tid": tool_id, "etype": event_type, "cid": actor,
                 "meta": __import__("json").dumps(detail)},
            )
            await session.commit()
    except Exception as exc:
        logger.critical("AUDIT FAILURE for %s on tool %s: %s", event_type, tool_id, exc)


# ---------------------------------------------------------------------------
# HTML template (htmx, no build step)
# ---------------------------------------------------------------------------

def _build_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP Credential Manager</title>
  <script src="/static/htmx.min.js"></script>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; background: #0f172a; color: #e2e8f0; }
    h1 { color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .tool-card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 1rem; margin: 0.75rem 0; }
    .tool-name { font-weight: 600; color: #f1f5f9; }
    .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; margin-left: 0.5rem; }
    .badge-none { background: #475569; }
    .badge-service { background: #065f46; color: #6ee7b7; }
    .badge-user { background: #1e3a5f; color: #7dd3fc; }
    .badge-service_account { background: #4c1d95; color: #c4b5fd; }
    .badge-oauth_user_token { background: #7c2d12; color: #fdba74; }
    .badge-active { background: #166534; color: #86efac; }
    .badge-quarantined { background: #7f1d1d; color: #fca5a5; }
    .badge-disabled { background: #374151; color: #9ca3af; }
    label { display: block; font-size: 0.8rem; color: #94a3b8; margin-top: 0.5rem; }
    input, select { width: 100%; padding: 0.4rem 0.6rem; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #e2e8f0; font-size: 0.85rem; box-sizing: border-box; }
    button { padding: 0.4rem 1rem; border-radius: 4px; border: none; cursor: pointer; font-size: 0.85rem; }
    .btn-primary { background: #0ea5e9; color: #fff; }
    .btn-danger { background: #dc2626; color: #fff; }
    .btn-primary:hover { background: #0284c7; }
    .btn-danger:hover { background: #b91c1c; }
    .cred-form { display: none; margin-top: 0.75rem; border-top: 1px solid #334155; padding-top: 0.75rem; }
    .cred-status { font-size: 0.8rem; }
    .has-cred { color: #4ade80; }
    .no-cred { color: #f87171; }
    .row { display: flex; gap: 0.5rem; align-items: flex-end; }
    .row > * { flex: 1; }
    .msg { padding: 0.5rem; border-radius: 4px; margin-top: 0.5rem; font-size: 0.85rem; }
    .msg-ok { background: #14532d; color: #86efac; }
    .msg-err { background: #7f1d1d; color: #fca5a5; }
  </style>
</head>
<body>
  <h1>🔐 MCP Credential Manager</h1>
  <p style="color:#94a3b8">Upload and manage credentials injected into upstream MCP server calls.</p>

  <div id="tool-list" hx-get="/admin/credentials/api" hx-trigger="load" hx-swap="innerHTML">
    <p style="color:#64748b">Loading tools…</p>
  </div>

  <script>
    document.addEventListener('htmx:afterSwap', (e) => {
      if (e.target.id !== 'tool-list') return;
      const data = JSON.parse(e.detail.xhr.responseText || '{}');
      renderTools(data.tools || []);
    });

    // Escape HTML to prevent XSS when injecting server-supplied strings into the DOM.
    function esc(str) {
      const d = document.createElement('div');
      d.textContent = str == null ? '' : String(str);
      return d.innerHTML;
    }

    function renderTools(tools) {
      const el = document.getElementById('tool-list');
      if (!tools.length) {
        el.textContent = 'No tools registered.';
        return;
      }
      // Build the list using DOM API to avoid innerHTML with raw server data.
      el.innerHTML = '';
      tools.forEach(t => el.appendChild(buildCard(t)));
    }

    function buildCard(t) {
      // Use a template with escaped values — all dynamic strings go through esc().
      const wrapper = document.createElement('div');
      wrapper.className = 'tool-card';
      wrapper.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center">
          <span class="tool-name">${esc(t.name)} <small style="color:#94a3b8">v${esc(t.version)}</small></span>
          <span>
            <span class="badge badge-${esc(t.status)}">${esc(t.status)}</span>
            <span class="badge badge-${esc(t.injection_mode)}">${esc(t.injection_mode)}</span>
          </span>
        </div>
        <div style="font-size:0.8rem;color:#94a3b8;margin-top:0.25rem">
          <span class="cred-status ${t.has_service_credential ? 'has-cred' : 'no-cred'}">
            ${t.has_service_credential ? '✓ credential enrolled' : '✗ no credential'}
          </span>
          &nbsp;|&nbsp; service_name: <code>${esc(t.service_name || '—')}</code>
          &nbsp;|&nbsp; inject_header: <code>${esc(t.inject_header || 'Authorization')}</code>
        </div>
        <div style="margin-top:0.5rem;display:flex;gap:0.5rem">
          <button class="btn-primary" data-action="toggle-cred">Manage Credential</button>
          <button class="btn-primary" data-action="toggle-mode">Set Mode</button>
        </div>
        <div class="cred-form" data-section="cred">
          <div class="row">
            <div>
              <label>Credential type</label>
              <select data-field="ctype">
                <option value="api_key">api_key</option>
                <option value="oauth2_refresh">oauth2_refresh</option>
                <option value="entra_client_secret">entra_client_secret</option>
                <option value="service_account_jwt">service_account_jwt</option>
                <option value="basic_auth">basic_auth</option>
              </select>
            </div>
            <div>
              <label>Owner type</label>
              <select data-field="otype">
                <option value="service">service (shared)</option>
                <option value="user">user (per-identity)</option>
              </select>
            </div>
          </div>
          <label>Secret value</label>
          <input type="password" data-field="secret" placeholder="Paste secret here">
          <label>Description (optional)</label>
          <input type="text" data-field="desc" placeholder="e.g. Grafana SA token rotated 2026-06">
          <div style="display:flex;gap:0.5rem;margin-top:0.75rem">
            <button class="btn-primary" data-action="save-cred">Save Credential</button>
            <button class="btn-danger" data-action="revoke-cred">Revoke</button>
          </div>
          <div data-section="msg"></div>
        </div>
        <div class="cred-form" data-section="mode">
          <div class="row">
            <div>
              <label>Injection mode</label>
              <select data-field="mode">
                <option value="none">none</option>
                <option value="service">service</option>
                <option value="user">user</option>
                <option value="service_account">service_account (KC)</option>
                <option value="oauth_user_token">oauth_user_token (KC exchange)</option>
              </select>
            </div>
            <div>
              <label>KC client ID</label>
              <input type="text" data-field="kccid" placeholder="grafana-sa">
            </div>
          </div>
          <div class="row">
            <div>
              <label>KC token audience</label>
              <input type="text" data-field="kcaud" placeholder="grafana-service">
            </div>
            <div>
              <label>Entra tenant ID</label>
              <input type="text" data-field="etid" placeholder="UUID">
            </div>
          </div>
          <div class="row">
            <div>
              <label>Entra client ID</label>
              <input type="text" data-field="ecid" placeholder="UUID">
            </div>
            <div>
              <label>Entra scope</label>
              <input type="text" data-field="escope" placeholder="https://graph.microsoft.com/.default">
            </div>
          </div>
          <div style="margin-top:0.75rem">
            <button class="btn-primary" data-action="save-mode">Save Mode</button>
          </div>
          <div data-section="modemsg"></div>
        </div>`;

      // Populate selects and inputs with server data using .value (safe, not innerHTML)
      wrapper.querySelector('[data-field="mode"]').value = t.injection_mode || 'none';
      wrapper.querySelector('[data-field="kccid"]').value = t.kc_client_id || '';
      wrapper.querySelector('[data-field="kcaud"]').value = t.kc_token_audience || '';
      wrapper.querySelector('[data-field="etid"]').value = t.entra_tenant_id || '';
      wrapper.querySelector('[data-field="ecid"]').value = t.entra_client_id || '';
      wrapper.querySelector('[data-field="escope"]').value = t.entra_scope || '';

      // Attach event listeners (no onclick= attributes with interpolated data)
      wrapper.querySelector('[data-action="toggle-cred"]').addEventListener('click', () => {
        const s = wrapper.querySelector('[data-section="cred"]');
        s.style.display = s.style.display === 'block' ? 'none' : 'block';
      });
      wrapper.querySelector('[data-action="toggle-mode"]').addEventListener('click', () => {
        const s = wrapper.querySelector('[data-section="mode"]');
        s.style.display = s.style.display === 'block' ? 'none' : 'block';
      });
      wrapper.querySelector('[data-action="save-cred"]').addEventListener('click', () => uploadCred(t.tool_id, wrapper));
      wrapper.querySelector('[data-action="revoke-cred"]').addEventListener('click', () => revokeCred(t.tool_id, wrapper));
      wrapper.querySelector('[data-action="save-mode"]').addEventListener('click', () => saveMode(t.tool_id, wrapper));

      return wrapper;
    }

    // toolCard kept as alias for backward compat but no longer used for innerHTML insertion
    function toolCard(t) { return ''; }
    }

    function f(card, field) { return card.querySelector('[data-field="' + field + '"]'); }

    async function uploadCred(toolId, card) {
      const secret = f(card, 'secret').value;
      const ctype = f(card, 'ctype').value;
      const otype = f(card, 'otype').value;
      const desc = f(card, 'desc').value;
      if (!secret) { showMsg(card, 'Secret is required.', false); return; }
      const resp = await fetch('/admin/credentials/' + encodeURIComponent(toolId), {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({secret, credential_type: ctype, owner_type: otype, description: desc})
      });
      const data = await resp.json();
      showMsg(card, data.message || (resp.ok ? 'Saved.' : 'Error.'), resp.ok);
      if (resp.ok) f(card, 'secret').value = '';
    }

    async function revokeCred(toolId, card) {
      if (!confirm('Revoke this credential?')) return;
      const otype = f(card, 'otype').value;
      const resp = await fetch(
        '/admin/credentials/' + encodeURIComponent(toolId) + '?owner_type=' + encodeURIComponent(otype),
        {method: 'DELETE'}
      );
      const data = await resp.json();
      showMsg(card, data.message || 'Revoked.', resp.ok);
    }

    async function saveMode(toolId, card) {
      const mode = f(card, 'mode').value;
      const kccid = f(card, 'kccid').value;
      const kcaud = f(card, 'kcaud').value;
      const etid = f(card, 'etid').value;
      const ecid = f(card, 'ecid').value;
      const escope = f(card, 'escope').value;
      const params = new URLSearchParams({mode});
      if (kccid) params.set('kc_client_id', kccid);
      if (kcaud) params.set('kc_token_audience', kcaud);
      if (etid) params.set('entra_tenant_id', etid);
      if (ecid) params.set('entra_client_id', ecid);
      if (escope) params.set('entra_scope', escope);
      const resp = await fetch(
        '/admin/credentials/' + encodeURIComponent(toolId) + '/injection-mode?' + params,
        {method: 'PUT'}
      );
      const data = await resp.json();
      const msgEl = card.querySelector('[data-section="modemsg"]');
      const div = document.createElement('div');
      div.className = 'msg ' + (resp.ok ? 'msg-ok' : 'msg-err');
      div.textContent = data.message || 'Error';
      msgEl.replaceChildren(div);
    }

    function showMsg(card, msg, ok) {
      const el = card.querySelector('[data-section="msg"]');
      const div = document.createElement('div');
      div.className = 'msg ' + (ok ? 'msg-ok' : 'msg-err');
      div.textContent = msg;
      el.replaceChildren(div);
    }

    // Auto-load on page load
    fetch('/admin/credentials/api')
      .then(r => r.json())
      .then(data => renderTools(data.tools || []));
  </script>
</body>
</html>"""
