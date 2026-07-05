"""
MCP Security Platform — Server Registry Router

CRUD endpoints for the server_registry table.
Platform admins register and approve MCP server endpoints.
Approval locks the injection_mode and records the owner.

Admin endpoints:
  GET  /api/v1/admin/servers            — list all servers (platform_admin)
  POST /api/v1/admin/servers            — register a new server (platform_admin)
  GET  /api/v1/admin/servers/{id}       — get a server (platform_admin)
  PATCH /api/v1/admin/servers/{id}      — update server metadata (platform_admin)
  DELETE /api/v1/admin/servers/{id}     — soft-delete (platform_admin; sets deleted_at, status→suspended)
  POST /api/v1/admin/servers/{id}/approve — approve a pending server (platform_admin + owner consent token)

Self-service registration (Task 7):
  POST /api/v1/servers                  — self-service registration (server_owner or platform_admin)

Server approval flow (D3 dual-control):
  POST /api/v1/servers/{id}/consent     — mint owner consent token (server_owner or platform_admin)

List approved:
  GET /api/v1/servers                   — list approved servers visible to authenticated caller (any role)

Consent flow (D3 dual-control):
  1. Server owner calls POST /api/v1/servers/{id}/consent → receives a single-use consent_token (15 min TTL)
  2. Platform admin calls POST /api/v1/admin/servers/{id}/approve with {"consent_token": "<token>"}
     The handler: verifies HMAC signature + server binding, consumes the token (marks jti used),
     then commits the approval — all in a single transaction.
  Without both steps, the approve handler returns 409 owner_consent_required.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import logging
import re
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, field_validator
from sqlalchemy import text

from app.core.database import AsyncSessionLocal
from app.services.consent import (
    ConsentTokenAlreadyConsumedError,
    ConsentTokenError,
    consume_consent_token,
    issue_approve_consent_token,
    persist_consent_token,
    verify_approve_consent_token,
)
from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    UpstreamRevalidationError,
    revalidate_upstream_ip_at_invoke,
    validate_mode_and_idp,
    validate_upstream_url_ssrf,
    validate_upstream_idp_config,
)
from app.services.ssrf import SSRFError, validate_server_url
from app.credential_broker.adapters.healthcheck import get_healthcheck, HealthcheckFailed

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = frozenset({"admin", "platform_admin"})
_PATCH_ALLOWED = frozenset({"name", "upstream_url", "service_name"})


def _require_platform_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="platform_admin role required")


def _require_server_owner_or_admin(request: Request) -> None:
    """Enforce server_owner or platform_admin role."""
    roles = getattr(request.state, "client_roles", [])
    _allowed = {"server_owner", "platform_admin", "admin"}
    if not any(r in _allowed for r in roles):
        raise HTTPException(status_code=403, detail="server_owner or platform_admin role required")


async def _emit_registration_audit(
    server_id: str,
    service_name: str,
    client_id: str,
    outcome: str,
    request_id: str,
) -> None:
    """
    Emit a synchronous audit event for server registration (INV-001).

    Args:
        server_id: UUID of the registered server
        service_name: service_name from the registration request
        client_id: authenticated caller's client_id
        outcome: 'allow' or 'deny'
        request_id: request tracking ID

    Raises:
        RuntimeError if audit emission fails (caller must convert to 500)
    """
    import json
    try:
        async with AsyncSessionLocal() as db:
            event_id = str(uuid.uuid4())
            await db.execute(
                text(
                    """
                    INSERT INTO audit_events (
                        event_id, event_type, client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, 'SERVER_REGISTRATION', :client_id, :service_name,
                        :outcome, :request_id, :hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "client_id": client_id,
                    "service_name": service_name,
                    "outcome": outcome,
                    "request_id": request_id,
                    "hash": hashlib.sha256(json.dumps({"server_id": server_id}).encode()).hexdigest(),
                },
            )
            await db.commit()
        logger.info(
            "server_registration_audited event_id=%s server_id=%s service_name=%s "
            "client_id=%s outcome=%s",
            event_id, server_id, service_name, client_id, outcome,
        )
    except Exception as exc:
        logger.error(
            "audit_emission_failed server_id=%s service_name=%s client_id=%s: %s",
            server_id, service_name, client_id, exc,
        )
        raise RuntimeError(f"Audit emission failed: {exc}") from exc


class ServerCreate(BaseModel):
    name: str
    upstream_url: str
    injection_mode: str = "none"
    service_name: Optional[str] = None
    owner_sub: Optional[str] = None  # defaults to request.state.client_id

    @field_validator("injection_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        # AUTH-R6 (Task 3.4): passthrough and entra_user_token are now exposed.
        # kc_token_exchange is the canonical name for the former oauth_user_token.
        valid = {
            "none",
            "service",
            "user",
            "service_account",
            "kc_token_exchange",
            "oauth_user_token",   # accepted alias; normalised to kc_token_exchange in dispatcher
            "passthrough",
            "entra_user_token",
            "entra_client_credentials",
        }
        if v not in valid:
            raise ValueError(f"injection_mode must be one of {sorted(valid)}")
        return v


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    service_name: Optional[str] = None


class ServerRegister(BaseModel):
    """
    Request body for POST /api/v1/servers — self-service registration by server_owner.

    service_name: human-readable service name (e.g., "gitea", "m365")
    upstream_url: HTTPS URL to the upstream MCP server
    injection_mode: token injection mode (user, service, service_account, none, etc.)
    upstream_idp_type: optional IdP type for OAuth flows (gateway_idp, entra, etc.)
    upstream_idp_config: optional dict with IdP configuration (issuer, client_id, scopes)
    adapter_name: optional adapter name for health checks (gitea, m365, etc.)

    AUTH-R6 (Task 3.4): passthrough and entra_user_token are now exposed here.
    entra_user_token and entra_client_credentials require ENTRA_TENANT_ID to be set;
    the validator checks this at request time and returns 422 if missing.
    """
    service_name: str
    upstream_url: str
    injection_mode: str = "none"
    upstream_idp_type: Optional[str] = None
    upstream_idp_config: Optional[dict] = None
    adapter_name: Optional[str] = None

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("service_name must not be empty")
        return v.strip()

    @field_validator("injection_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        # AUTH-R6 (Task 3.4): passthrough and entra_user_token are now exposed.
        # kc_token_exchange is the canonical name; oauth_user_token is accepted alias.
        _ENTRA_MODES = {"entra_user_token", "entra_client_credentials"}
        valid = {
            "none",
            "service",
            "user",
            "service_account",
            "kc_token_exchange",
            "oauth_user_token",   # accepted alias; normalised to kc_token_exchange in dispatcher
            "passthrough",
            "entra_user_token",
            "entra_client_credentials",
        }
        if v not in valid:
            raise ValueError(f"injection_mode must be one of {sorted(valid)}")
        # Entra modes require AZURE_TENANT_ID (surfaced as ENTRA_TENANT_ID in settings).
        # Validate eagerly so operators get a clear 422 instead of a runtime failure.
        if v in _ENTRA_MODES:
            from app.core.config import get_settings
            cfg = get_settings()
            if not getattr(cfg, "ENTRA_TENANT_ID", None):
                raise ValueError(
                    f"injection_mode='{v}' requires ENTRA_TENANT_ID to be configured. "
                    "Set the ENTRA_TENANT_ID environment variable and restart the service."
                )
        return v


class ConsentRequest(BaseModel):
    """Request body for POST /api/v1/servers/{id}/consent — mint a single-use approval token."""
    action: str = "approve"

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in {"approve"}:
            raise ValueError("action must be 'approve'")
        return v


class ApproveBody(BaseModel):
    """Request body for POST /api/v1/admin/servers/{id}/approve — requires owner consent token."""
    consent_token: str


def _serialize(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if isinstance(v, (datetime.datetime, datetime.date)):
            out[k] = v.isoformat()
        elif v is None or isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


@router.get("/api/v1/admin/servers")
async def list_servers(request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                "SELECT server_id, name, upstream_url, status, owner_sub, "
                "injection_mode, created_at, approved_at "
                "FROM server_registry WHERE deleted_at IS NULL ORDER BY created_at DESC"
            )
        )
        servers = [_serialize(dict(r._mapping)) for r in rows]
    return JSONResponse({"servers": servers})


@router.post("/api/v1/admin/servers", status_code=201)
async def create_server(body: ServerCreate, request: Request):
    _require_platform_admin(request)
    # Always attribute ownership to the authenticated requester, not the submitted value
    effective_owner_sub = getattr(request.state, "client_id", "unknown")
    owner = effective_owner_sub

    # SSRF check with allowlist (Task 3.1)
    from app.core.config import get_settings as _get_settings
    _settings = _get_settings()
    _allowlist = _settings.upstream_private_cidr_allowlist_parsed
    try:
        _ae = await validate_upstream_url_ssrf(body.upstream_url, private_cidr_allowlist=_allowlist)
    except InvalidOnboardingConfig as exc:
        raise HTTPException(status_code=400, detail=f"SSRF validation failed: {exc}") from exc
    _upstream_allowlist_entry: str | None = _ae if _ae else None

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "INSERT INTO server_registry "
                "(name, upstream_url, injection_mode, service_name, owner_sub, status, upstream_allowlist_entry) "
                "VALUES (:name, :url, CAST(:mode AS injection_mode_enum), :svc, :owner, 'pending', :allowlist_entry) "
                "RETURNING server_id, name, status, created_at"
            ),
            {"name": body.name, "url": body.upstream_url, "mode": body.injection_mode,
             "svc": body.service_name, "owner": owner, "allowlist_entry": _upstream_allowlist_entry},
        )
        await db.commit()
        row = result.fetchone()
    return JSONResponse(
        {"server_id": str(row.server_id), "name": row.name, "status": row.status},
        status_code=201,
    )


@router.get("/api/v1/admin/servers/{server_id}")
async def get_server(server_id: str, request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            text("SELECT * FROM server_registry WHERE server_id = :id AND deleted_at IS NULL"),
            {"id": server_id},
        )
        record = row.mappings().fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return JSONResponse(_serialize(dict(record)))


@router.patch("/api/v1/admin/servers/{server_id}")
async def update_server(server_id: str, body: ServerUpdate, request: Request):
    _require_platform_admin(request)
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    # Filter to allowed fields — injection_mode changes after approval require owner consent (Plan 7)
    updates = {k: v for k, v in updates.items() if k in _PATCH_ALLOWED}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    # SSRF guard: fail-closed DNS — DNS failure rejects the URL (same as registration).
    # Task 3.1: also update upstream_allowlist_entry when upstream_url changes.
    if "upstream_url" in updates:
        from app.core.config import get_settings as _get_settings
        _settings = _get_settings()
        _allowlist = _settings.upstream_private_cidr_allowlist_parsed
        try:
            _patch_ae = await validate_upstream_url_ssrf(updates["upstream_url"], private_cidr_allowlist=_allowlist)
        except (SSRFError, ValueError, InvalidOnboardingConfig) as exc:
            raise HTTPException(status_code=422, detail=f"upstream_url blocked by SSRF policy: {exc}") from exc
        updates["upstream_allowlist_entry"] = _patch_ae if _patch_ae else None

    # Column names are interpolated — frozenset above is the ONLY guard.
    # Never add user-supplied strings to the allowlist.
    assert all(re.match(r'^[a-z_]+$', k) for k in updates), f"Unsafe column names: {updates.keys()}"
    set_clauses = ", ".join(f"{k} = :{k}" for k in updates)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                f"UPDATE server_registry SET {set_clauses} "
                "WHERE server_id = :server_id AND deleted_at IS NULL "
                "RETURNING server_id"
            ),
            {**updates, "server_id": server_id},
        )
        await db.commit()
        rows_updated = result.rowcount
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    return JSONResponse({"server_id": server_id, "updated": list(updates)})


async def _get_server_owner_row(server_id: str) -> dict | None:
    async with AsyncSessionLocal() as db:
        row = (await db.execute(
            text("SELECT owner_sub, maintainers, debug_mode FROM server_registry "
                 "WHERE server_id = :sid AND deleted_at IS NULL"),
            {"sid": server_id},
        )).fetchone()
    return dict(row._mapping) if row else None


def _require_owner_or_maintainer(row: dict, request: Request, *, allow_platform_admin: bool = False) -> None:
    """
    Per-server ownership check (distinct from the role-based
    _require_server_owner_or_admin above) — the caller must actually be
    *this* server's owner_sub or one of its listed maintainers, not merely
    hold a role called "server_owner". platform_admin is only an allowed
    override where explicitly opted in (e.g. force-clearing a stuck
    maintenance lock), never for enabling it in the first place.
    """
    client_id = getattr(request.state, "client_id", "") or ""
    if client_id == row["owner_sub"] or client_id in (row.get("maintainers") or []):
        return
    if allow_platform_admin:
        roles = getattr(request.state, "client_roles", [])
        if any(r in _ADMIN_ROLES for r in roles):
            return
    raise HTTPException(status_code=403, detail="only the server owner or a maintainer may do this")


class MaintainersUpdate(BaseModel):
    maintainers: list[str]

    @field_validator("maintainers")
    @classmethod
    def max_two(cls, v: list[str]) -> list[str]:
        if len(v) > 2:
            raise ValueError("at most 2 maintainers are allowed")
        if len(set(v)) != len(v):
            raise ValueError("duplicate maintainer entries")
        return v


@router.put("/api/v1/servers/{server_id}/maintainers")
async def set_server_maintainers(server_id: str, body: MaintainersUpdate, request: Request):
    """
    Set (replace) a server's maintainer list. Owner or existing maintainer only.

    Security fix: platform_admin may only CLEAR the list (body.maintainers == []),
    as a rescue valve — never set an arbitrary new list. Allowing an admin to set
    an arbitrary list would let them insert their own client_id and self-grant
    access to a server while debug_mode=true, defeating the "no admin bypass"
    invariant enforced in services/invocation.py Step 1.1.
    """
    row = await _get_server_owner_row(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    is_rescue_clear = not body.maintainers
    _require_owner_or_maintainer(row, request, allow_platform_admin=is_rescue_clear)

    actor = getattr(request.state, "client_id", "unknown")
    async with AsyncSessionLocal() as db:
        try:
            await db.execute(
                text("UPDATE server_registry SET maintainers = :m WHERE server_id = :sid"),
                {"m": body.maintainers, "sid": server_id},
            )
            await db.commit()
        except Exception as exc:
            # CHECK constraint (max 2) is the DB-side backstop; the Pydantic
            # validator above should already have caught this.
            raise HTTPException(status_code=422, detail=f"could not set maintainers: {exc}") from exc

    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor=actor, action="server_maintainers_set", client_id=server_id,
        details={"maintainers": body.maintainers},
    )
    return JSONResponse({"server_id": server_id, "maintainers": body.maintainers})


class DebugModeUpdate(BaseModel):
    enabled: bool


@router.post("/api/v1/servers/{server_id}/debug-mode")
async def set_server_debug_mode(server_id: str, body: DebugModeUpdate, request: Request):
    """
    Toggle a server's debug/maintenance mode.

    While enabled, ONLY the owner and its maintainers may invoke this
    server's tools (enforced in services/invocation.py) — everyone else,
    including admins, is denied SERVER_IN_MAINTENANCE. Enabling requires
    being the owner or a maintainer (manual, deliberate action — never
    automatic); disabling additionally allows platform_admin, as a rescue
    valve if an owner is unreachable and a server is stuck locked down.
    """
    row = await _get_server_owner_row(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    _require_owner_or_maintainer(row, request, allow_platform_admin=not body.enabled)

    actor = getattr(request.state, "client_id", "unknown")
    async with AsyncSessionLocal() as db:
        if body.enabled:
            await db.execute(
                text("UPDATE server_registry SET debug_mode = TRUE, "
                     "debug_enabled_by = :actor, debug_enabled_at = now() "
                     "WHERE server_id = :sid"),
                {"actor": actor, "sid": server_id},
            )
        else:
            await db.execute(
                text("UPDATE server_registry SET debug_mode = FALSE, "
                     "debug_enabled_by = NULL, debug_enabled_at = NULL "
                     "WHERE server_id = :sid"),
                {"sid": server_id},
            )
        await db.commit()

    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor=actor, action="server_debug_mode_" + ("enabled" if body.enabled else "disabled"),
        client_id=server_id, details={"server_id": server_id},
    )
    return JSONResponse({"server_id": server_id, "debug_mode": body.enabled})


@router.delete("/api/v1/admin/servers/{server_id}", status_code=204, response_class=Response)
async def delete_server(server_id: str, request: Request):
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        # Soft-delete: set deleted_at + suspend. Status 'deleted' is NOT a valid enum value.
        await db.execute(
            text(
                "UPDATE server_registry SET deleted_at = now(), status = 'suspended' "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        await db.commit()


@router.post("/api/v1/admin/servers/{server_id}/reject", status_code=204, response_class=Response)
async def reject_server(server_id: str, request: Request):
    """Reject a pending server — soft-deletes and sets status='rejected'."""
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "UPDATE server_registry SET deleted_at = now(), status = 'rejected' "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        await db.commit()


@router.post("/api/v1/admin/servers/{server_id}/quarantine", status_code=204, response_class=Response)
async def quarantine_server(server_id: str, request: Request):
    """Quarantine an approved server — blocks invocations without deleting it."""
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "UPDATE server_registry SET status = 'quarantined' "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        await db.commit()


@router.post("/api/v1/admin/servers/{server_id}/release", status_code=204, response_class=Response)
async def release_server(server_id: str, request: Request):
    """Release a quarantined server back to 'approved'."""
    _require_platform_admin(request)
    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "UPDATE server_registry SET status = 'approved' "
                "WHERE server_id = :id AND deleted_at IS NULL AND status = 'quarantined'"
            ),
            {"id": server_id},
        )
        await db.commit()


class PublicToggle(BaseModel):
    enabled: bool


@router.post("/api/v1/admin/servers/{server_id}/public")
async def set_server_public(server_id: str, body: PublicToggle, request: Request):
    """PRD-0005 R-3: toggle public_to_authenticated on a server.

    Any authenticated principal may invoke a server flagged public — but ONLY a
    read-only server (has_write_ops=false). Enabling on a write-op server is
    rejected by the DB CHECK (ck_public_not_write_ops); we surface that as 409
    rather than a 500. Audited via the HMAC-signed admin chain.
    """
    _require_platform_admin(request)
    actor = getattr(request.state, "client_id", "unknown-admin")
    try:
        async with AsyncSessionLocal() as db:
            res = await db.execute(
                text(
                    "UPDATE server_registry SET public_to_authenticated = :en "
                    "WHERE server_id = :id AND deleted_at IS NULL "
                    "RETURNING name, has_write_ops"
                ),
                {"en": body.enabled, "id": server_id},
            )
            row = res.mappings().first()
            if row is None:
                await db.rollback()
                raise HTTPException(status_code=404, detail="server not found")
            await db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        # ck_public_not_write_ops violation (enabling public on a write-op server).
        msg = str(exc).lower()
        if "ck_public_not_write_ops" in msg or "check constraint" in msg:
            raise HTTPException(
                status_code=409,
                detail="A write-capable server (has_write_ops=true) cannot be made public.",
            )
        logger.warning("set_server_public failed for %s: %s", server_id, exc)
        raise HTTPException(status_code=500, detail="failed to update public flag")

    try:
        from app.services.admin_audit import emit_admin_config_event
        await emit_admin_config_event(
            actor, "set_server_public", server_id, {"enabled": body.enabled, "name": row["name"]},
        )
    except Exception:
        pass  # audit failure must not fail the committed operation
    return {"ok": True, "server_id": server_id, "public_to_authenticated": body.enabled}


@router.post("/api/v1/servers/{server_id}/consent", status_code=201)
async def mint_consent_token(server_id: str, body: ConsentRequest, request: Request):
    """
    Mint a single-use consent token for the 'approve' action (D3 dual-control).

    The server owner calls this endpoint to produce a token, which the platform admin
    then passes to POST /api/v1/admin/servers/{id}/approve as {"consent_token": "<token>"}.

    Roles: server_owner or platform_admin.
    The owner_sub bound into the token is the authenticated caller's client_id.
    """
    caller_roles = getattr(request.state, "client_roles", [])
    _allowed = {"server_owner", "platform_admin", "admin"}
    if not any(r in _allowed for r in caller_roles):
        raise HTTPException(status_code=403, detail="server_owner or platform_admin role required")

    owner_sub = getattr(request.state, "client_id", "unknown")

    # Verify the server exists and hasn't been deleted
    async with AsyncSessionLocal() as db:
        row = await db.execute(
            text("SELECT server_id, status FROM server_registry WHERE server_id = :id AND deleted_at IS NULL"),
            {"id": server_id},
        )
        record = row.fetchone()
    if record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    if record.status != "pending":
        raise HTTPException(status_code=409, detail=f"Server is not pending approval (status={record.status})")

    token_str, jti = issue_approve_consent_token(
        server_id=server_id,
        owner_sub=owner_sub,
        ttl_seconds=900,  # 15 minutes
    )

    # Persist the jti so consume_consent_token() can mark it used on first verification.
    # Without this, consume_consent_token() silently no-ops and replay is possible.
    payload_hash = hashlib.sha256(token_str.encode()).hexdigest()
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=900)
    await persist_consent_token(
        jti=jti,
        server_id=server_id,
        old_mode="__approve_pending__",
        new_mode="__approve_approved__",
        owner_sub=owner_sub,
        payload_hash=payload_hash,
        expires_at=expires_at,
    )

    logger.info(
        "consent_token_issued server_id=%s jti=%s owner_sub=%s action=approve",
        server_id, jti, owner_sub,
    )
    return JSONResponse(
        {"consent_token": token_str, "jti": jti, "expires_in_seconds": 900},
        status_code=201,
    )


@router.post("/api/v1/admin/servers/{server_id}/approve")
async def approve_server(server_id: str, body: ApproveBody, request: Request):
    """
    Approve a pending server (D3 dual-control).

    Requires a valid, single-use consent token minted by the server owner via
    POST /api/v1/servers/{id}/consent.

    The token is verified AND consumed atomically before the state change commits.
    If consume_consent_token returns False (already consumed or never persisted),
    the request is rejected with 409 — this prevents replay within the 15-minute window.
    """
    _require_platform_admin(request)
    approver = getattr(request.state, "client_id", "unknown")

    # D1 SSRF allowlist: re-validate the upstream URL at approval time (Task 3.1)
    async with AsyncSessionLocal() as db:
        url_row = await db.execute(
            text(
                "SELECT upstream_url, owner_sub, adapter_name, upstream_allowlist_entry "
                "FROM server_registry "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        url_record = url_row.fetchone()
    if url_record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    from app.core.config import get_settings as _get_settings
    _approval_settings = _get_settings()
    _approval_allowlist = _approval_settings.upstream_private_cidr_allowlist_parsed
    try:
        await validate_upstream_url_ssrf(url_record[0], private_cidr_allowlist=_approval_allowlist)
    except (SSRFError, ValueError, InvalidOnboardingConfig) as exc:
        raise HTTPException(status_code=422, detail=f"SSRF validation failed: {exc}") from exc

    # S3: Pin the healthcheck to the IP already validated above (TOCTOU rebind fix).
    # A TTL-0 DNS flip between validate_upstream_url_ssrf and the healthcheck
    # connect could redirect the request to 169.254.169.254 / vault:8200 / etc.
    # revalidate_upstream_ip_at_invoke resolves now and returns the validated IPs;
    # we pin httpx to the first one via PinnedIPTransport inside get_healthcheck().
    # Pass the per-server upstream_allowlist_entry (str | None), matching the
    # same field invocation.py reads from the tool_record / server_registry row.
    from urllib.parse import urlparse as _urlparse
    _registered_allowlist_entry: str | None = url_record[3]  # upstream_allowlist_entry column
    _pinned_ips: list[str] = []
    _healthcheck_hostname: str | None = None
    try:
        _pinned_ips = await revalidate_upstream_ip_at_invoke(
            upstream_url=url_record[0],
            registered_allowlist_entry=_registered_allowlist_entry,
        )
        _healthcheck_hostname = _urlparse(url_record[0]).hostname or None
    except UpstreamRevalidationError as exc:
        raise HTTPException(status_code=400, detail=f"IP revalidation failed at approval: {exc}") from exc

    owner_sub = url_record[1]
    adapter_name = url_record[2]

    # Task 6: Adapter healthcheck at approval
    # Verify the upstream server is reachable before marking as approved.
    # If the server has an adapter_name, validate it's healthy via healthcheck.
    if adapter_name:
        try:
            # revalidate_upstream_ip_at_invoke raises on failure; non-empty list guaranteed on success
            healthcheck_adapter = get_healthcheck(
                adapter_name,
                url_record[0],
                pinned_ip=_pinned_ips[0] if _pinned_ips else None,
                original_hostname=_healthcheck_hostname,
            )
            await healthcheck_adapter.healthcheck()
        except HealthcheckFailed as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Healthcheck failed: {exc}",
            ) from exc

    # D3 dual-control: verify the consent token before committing the state change.
    # verify_approve_consent_token raises ConsentTokenError subclasses on any failure.
    try:
        consent_payload = verify_approve_consent_token(
            token=body.consent_token,
            expected_server_id=server_id,
            expected_owner_sub=owner_sub,
        )
    except ConsentTokenError as exc:
        raise HTTPException(status_code=409, detail=f"owner_consent_required: {exc}") from exc

    # consume_consent_token returns False if already consumed (replay) or never persisted.
    # Treat False as a hard reject — never allow-through on ambiguous consent state.
    consumed = await consume_consent_token(consent_payload.jti)
    if not consumed:
        raise HTTPException(
            status_code=409,
            detail="owner_consent_required: consent token already used or invalid",
        )

    # Both verify and consume succeeded — commit the approval.
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                "UPDATE server_registry "
                "SET status = 'approved', mode_locked_at_approval = TRUE, "
                "    approved_at = now(), approved_by = :approver, url_allowlist_checked = TRUE, "
                "    consent_jti = :consent_jti "
                "WHERE server_id = :id AND deleted_at IS NULL AND status = 'pending' "
                "RETURNING server_id"
            ),
            {"id": server_id, "approver": approver, "consent_jti": consent_payload.jti},
        )
        # A-07: append-only audit record so approval history survives future UPDATEs.
        await db.execute(
            text(
                "INSERT INTO audit_events "
                "(event_id, event_type, client_id, tool_name, outcome, request_id, sha256_hash, latency_ms) "
                "VALUES (:eid, 'SERVER_APPROVED', :approver, :server_id, 'success', :rid, '', 0)"
            ),
            {
                "eid": str(uuid.uuid4()),
                "approver": approver,
                "server_id": server_id,
                "rid": getattr(request.state, "request_id", ""),
            },
        )
        await db.commit()
        rows_updated = result.rowcount
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found or not in pending state")

    logger.info(
        "server_approved server_id=%s approver=%s consent_jti=%s",
        server_id, approver, consent_payload.jti,
    )
    return JSONResponse({
        "server_id": server_id,
        "status": "approved",
        "approved_by": approver,
        "consent_jti": consent_payload.jti,
    })


@router.post("/api/v1/servers", status_code=201)
async def register_server_self_service(body: ServerRegister, request: Request):
    """
    Self-service server registration by server_owner role (Task 7).

    Roles: server_owner, platform_admin

    Validates:
      1. Caller has server_owner or platform_admin role (RBAC)
      2. injection_mode ↔ upstream_idp_type compatibility (validate_mode_and_idp)
      3. upstream_url is HTTPS and not private IP (validate_upstream_url_ssrf)
      4. upstream_idp_config structure if provided (validate_upstream_idp_config)

    Creates server_registry row with status='pending' awaiting admin approval.

    INV-001: Audit event emitted BEFORE 201 response.

    Args:
        body: ServerRegister with service_name, upstream_url, injection_mode, etc.
        request: FastAPI request context

    Returns:
        201 JSON: {"server_id": "<uuid>", "service_name": "...", "status": "pending"}

    Raises:
        403: Missing server_owner or platform_admin role
        400: Invalid registration config (mode↔IdP, SSRF, IdP config)
        500: Audit emission failed
    """
    # RBAC: Require server_owner or platform_admin
    _require_server_owner_or_admin(request)

    # Get request metadata
    client_id = getattr(request.state, "client_id", "unknown")
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))

    # Validation 1: Injection mode ↔ IdP type compatibility
    try:
        validate_mode_and_idp(
            injection_mode=body.injection_mode,
            upstream_idp_type=body.upstream_idp_type,
            upstream_idp_config=body.upstream_idp_config,
        )
    except InvalidOnboardingConfig as exc:
        raise HTTPException(status_code=400, detail=f"Invalid mode/IdP config: {exc}") from exc

    # Validation 2: IdP configuration structure
    if body.upstream_idp_type:
        try:
            validate_upstream_idp_config(
                upstream_idp_type=body.upstream_idp_type,
                upstream_idp_config=body.upstream_idp_config,
            )
        except InvalidOnboardingConfig as exc:
            raise HTTPException(status_code=400, detail=f"Invalid IdP config: {exc}") from exc

    # Validation 3: Upstream URL SSRF check (async) — pass allowlist for private upstreams
    from app.core.config import get_settings as _get_settings
    _settings = _get_settings()
    _allowlist = _settings.upstream_private_cidr_allowlist_parsed
    try:
        allowlist_entry = await validate_upstream_url_ssrf(body.upstream_url, private_cidr_allowlist=_allowlist)
    except InvalidOnboardingConfig as exc:
        raise HTTPException(status_code=400, detail=f"SSRF validation failed: {exc}") from exc
    # Normalise: empty string → None so the DB column is NULL for public upstreams
    upstream_allowlist_entry: str | None = allowlist_entry if allowlist_entry else None

    # Generate server_id and emit audit BEFORE database insert (INV-001)
    server_id = str(uuid.uuid4())
    try:
        await _emit_registration_audit(
            server_id=server_id,
            service_name=body.service_name,
            client_id=client_id,
            outcome="allow",
            request_id=request_id,
        )
    except RuntimeError as exc:
        logger.error(f"Audit emission failed: {exc}")
        raise HTTPException(status_code=500, detail="Audit emission failed") from exc

    # Create server_registry row with status='pending'
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            text(
                """
                INSERT INTO server_registry (
                    server_id, service_name, upstream_url, injection_mode,
                    upstream_idp_type, upstream_idp_config, adapter_name,
                    owner_sub, status, upstream_allowlist_entry
                ) VALUES (
                    :server_id, :service_name, :upstream_url, CAST(:injection_mode AS injection_mode_enum),
                    :upstream_idp_type, CAST(:upstream_idp_config AS jsonb), :adapter_name,
                    :owner_sub, 'pending', :upstream_allowlist_entry
                )
                RETURNING server_id, service_name, status, created_at
                """
            ),
            {
                "server_id": server_id,
                "service_name": body.service_name,
                "upstream_url": body.upstream_url,
                "injection_mode": body.injection_mode,
                "upstream_idp_type": body.upstream_idp_type,
                "upstream_idp_config": json.dumps(body.upstream_idp_config) if body.upstream_idp_config is not None else None,
                "adapter_name": body.adapter_name,
                "owner_sub": client_id,
                "upstream_allowlist_entry": upstream_allowlist_entry,
            },
        )
        await db.commit()
        row = result.fetchone()

    logger.info(
        "server_registered_pending server_id=%s service_name=%s "
        "owner_sub=%s injection_mode=%s",
        server_id, body.service_name, client_id, body.injection_mode,
    )

    return JSONResponse(
        {
            "server_id": str(row.server_id),
            "service_name": row.service_name,
            "status": row.status,
        },
        status_code=201,
    )


@router.get("/api/v1/servers")
async def list_approved_servers(request: Request):
    """List approved servers — visible to any authenticated caller."""
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            text(
                "SELECT server_id, name, upstream_url, injection_mode "
                "FROM server_registry "
                "WHERE status = 'approved' AND deleted_at IS NULL "
                "ORDER BY name"
            )
        )
        servers = [_serialize(dict(r._mapping)) for r in rows]
    return JSONResponse({"servers": servers})
