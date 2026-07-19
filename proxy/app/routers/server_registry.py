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
    upstream_idp_type_for_mode,
    validate_mode_and_idp,
    validate_upstream_url_ssrf,
    validate_upstream_idp_config,
)
from app.services import oauth_provider_profile as oauth_provider_profile_svc
from app.services.ssrf import SSRFError, validate_server_url
from app.credential_broker.adapters.healthcheck import get_healthcheck, HealthcheckFailed
from app.services.auth_modes import all_mode_values

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = frozenset({"admin", "platform_admin"})
_PATCH_ALLOWED = frozenset({"name", "upstream_url", "service_name", "trust_tier"})


def _require_platform_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="platform_admin role required")


def _require_server_owner_or_admin(request: Request) -> None:
    """Enforce the role required for POST /api/v1/servers direct registration.

    CR-08: this path creates an admin-approvable server_registry row with NO
    submission-scan/review evidence. Unlike admin roles (inherently trusted),
    'server_owner' is a role ordinary self-service users can hold, so letting
    it register directly is a bypass around the scanned submission funnel.
    Gated behind ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN (default
    false) — admins can always use this path regardless of the flag.
    """
    from app.core.config import get_settings as _get_settings
    roles = getattr(request.state, "client_roles", [])
    if any(r in {"platform_admin", "admin"} for r in roles):
        return
    if _get_settings().ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN and "server_owner" in roles:
        return
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
        # WP-A5 (CR-02 completion): sourced from the canonical AuthMode enum
        # instead of a hand-maintained set (was missing basic_auth and both
        # external_oauth_* modes — real drift, not just theoretical).
        valid = all_mode_values()
        if v not in valid:
            raise ValueError(f"injection_mode must be one of {sorted(valid)}")
        return v


class ServerUpdate(BaseModel):
    name: Optional[str] = None
    upstream_url: Optional[str] = None
    service_name: Optional[str] = None
    # SEP-1913 trust_tier rank (2026-07-15): no endpoint previously existed to
    # raise a server's trust_tier after activation — the only path was a raw
    # SQL UPDATE. Every newly-discovered server defaults to trust_tier=0
    # (untrustedPublic), which taints the calling session's next call for up
    # to an hour (taint_floor.py) regardless of which tool is called next.
    # That's the correct behavior for a server nobody has vetted yet, but
    # there was no legitimate way for a platform_admin to promote a server
    # once they'd actually verified it — found while onboarding
    # test-api-noauth/basicauth and entra-id-directory. See taint_floor.py's
    # SEP-1913 rank table for the meaning of each value.
    trust_tier: Optional[int] = None

    @field_validator("trust_tier")
    @classmethod
    def trust_tier_range(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and not (0 <= v <= 4):
            raise ValueError("trust_tier must be 0-4 (SEP-1913: 0=untrustedPublic, "
                              "1=trustedPublic, 2=internal, 3=user, 4=system)")
        return v


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
    oauth_provider_profile_id: Optional[str] = None

    @field_validator("service_name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("service_name must not be empty")
        return v.strip()

    @field_validator("injection_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        # WP-A5 (CR-02 completion): sourced from the canonical AuthMode enum
        # instead of a hand-maintained set (was missing basic_auth and both
        # external_oauth_* modes — real drift, not just theoretical).
        _ENTRA_MODES = {"entra_user_token", "entra_client_credentials"}
        valid = all_mode_values()
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
                "injection_mode, service_name, debug_mode, trust_tier, "
                "created_at, approved_at "
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
        _ae = await validate_upstream_url_ssrf(
            body.upstream_url, private_cidr_allowlist=_allowlist,
            allow_http_dev=(_settings.ENVIRONMENT == "development"),
        )
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
    # PRD-0012 C3: a live self-hosted server's upstream_url must go through
    # request-change (quarantine every tool + demote status + re-verify),
    # never a silent overwrite (the original defect this PRD fixes —
    # server_registry.py:356 used to PATCH upstream_url straight onto a live
    # server with no re-scan/re-review at all). Platform-deployed servers
    # (is_self_hosted=false) and rows that aren't live yet (not yet
    # status='approved') have nothing to protect and fall through unchanged.
    reroute_result: dict | None = None
    if "upstream_url" in updates:
        async with AsyncSessionLocal() as db:
            _reroute_row = (await db.execute(
                text("SELECT is_self_hosted, status FROM server_registry "
                     "WHERE server_id = :sid AND deleted_at IS NULL"),
                {"sid": server_id},
            )).mappings().first()
        if _reroute_row is None:
            raise HTTPException(status_code=404, detail="Server not found")
        if _reroute_row["is_self_hosted"] and _reroute_row["status"] == "approved":
            from app.services.server_lifecycle import (
                RequestChangeNotEligibleError,
                ServerNotFoundError,
                request_change_for_server,
            )
            _new_url = updates.pop("upstream_url")
            _actor = getattr(request.state, "client_id", "unknown-admin")
            try:
                reroute_result = await request_change_for_server(
                    server_id, _actor, new_upstream_url=_new_url,
                    asserted_ip_only=True,
                    reason="admin PATCH upstream_url (re-routed to request-change)",
                )
            except ServerNotFoundError as exc:
                raise HTTPException(status_code=404, detail=str(exc)) from exc
            except RequestChangeNotEligibleError as exc:
                raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    if not updates:
        if reroute_result is not None:
            return JSONResponse({
                "server_id": server_id, "updated": ["upstream_url"], "request_change": reroute_result,
            })
        raise HTTPException(status_code=400, detail="No fields to update")

    # SSRF guard: fail-closed DNS — DNS failure rejects the URL (same as registration).
    # Task 3.1: also update upstream_allowlist_entry when upstream_url changes.
    # (Reached only for a non-self-hosted or not-yet-live row — the live
    # self-hosted case is popped from `updates` and re-routed above.)
    if "upstream_url" in updates:
        from app.core.config import get_settings as _get_settings
        _settings = _get_settings()
        _allowlist = _settings.upstream_private_cidr_allowlist_parsed
        try:
            _patch_ae = await validate_upstream_url_ssrf(
                updates["upstream_url"], private_cidr_allowlist=_allowlist,
                allow_http_dev=(_settings.ENVIRONMENT == "development"),
            )
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
        rows_updated = result.rowcount
        if rows_updated and "trust_tier" in updates:
            # Security-sensitive escalation (SEP-1913 rank change affects the
            # taint floor for every future caller of this server) — append-only
            # audit record, same pattern as SERVER_APPROVED in approve_server().
            await db.execute(
                text(
                    "INSERT INTO audit_events "
                    "(event_id, event_type, client_id, tool_name, outcome, request_id, sha256_hash, latency_ms) "
                    "VALUES (:eid, 'SERVER_TRUST_TIER_CHANGED', :actor, :server_id, 'allow', :rid, '', 0)"
                ),
                {
                    "eid": str(uuid.uuid4()),
                    "actor": getattr(request.state, "client_id", "unknown"),
                    "server_id": server_id,
                    "rid": getattr(request.state, "request_id", ""),
                },
            )
        await db.commit()
    if rows_updated == 0:
        raise HTTPException(status_code=404, detail="Server not found")
    resp: dict = {"server_id": server_id, "updated": list(updates)}
    if reroute_result is not None:
        resp["updated"] = resp["updated"] + ["upstream_url"]
        resp["request_change"] = reroute_result
    return JSONResponse(resp)


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


class RequestChangeBody(BaseModel):
    """Request body for POST /api/v1/servers/{id}/request-change (PRD-0012 C3)."""
    new_upstream_url: Optional[str] = None
    new_github_repo_url: Optional[str] = None
    # Submitter-asserted claim that only the endpoint address changed, not the
    # code. Default False (conservative — full re-review) per the PRD's
    # fail-safe-toward-more-review rule: an unasserted or wrongly-asserted
    # claim never skips re-verification of the running endpoint itself, it
    # only affects whether a human reviewer is also required.
    asserted_ip_only: bool = False
    reason: str = ""


@router.post("/api/v1/servers/{server_id}/request-change")
async def request_change(server_id: str, body: RequestChangeBody, request: Request):
    """
    PRD-0012 C3 — request a backend/endpoint change on a live self-hosted
    server. Owner or maintainer (platform_admin as a rescue valve, same
    pattern as debug-mode). Quarantines every tool for this server and
    demotes server_registry.status to 'quarantined' atomically (TRAP-2/
    TRAP-5), then classifies the change as IP-only (auto-approved once a
    live schema fetch confirms nothing else changed) or code-change (full
    guarded re-scan + reviewer re-approval).
    """
    row = await _get_server_owner_row(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    _require_owner_or_maintainer(row, request, allow_platform_admin=True)
    actor = getattr(request.state, "client_id", "unknown")

    from app.services.server_lifecycle import ChangeApprovalError as _CAErr
    from app.services.server_lifecycle import (
        RequestChangeNotEligibleError,
        ServerNotFoundError,
        request_change_for_server,
    )
    try:
        result = await request_change_for_server(
            server_id, actor,
            new_upstream_url=body.new_upstream_url,
            new_github_repo_url=body.new_github_repo_url,
            asserted_ip_only=body.asserted_ip_only,
            reason=body.reason,
        )
    except ServerNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except RequestChangeNotEligibleError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except _CAErr as exc:
        raise HTTPException(status_code=422, detail=f"upstream_url rejected: {exc}") from exc

    from app.services.admin_audit import emit_admin_config_event
    await emit_admin_config_event(
        actor, "server_request_change", server_id,
        {"reason": body.reason, **{k: v for k, v in result.items() if k != "server_id"}},
    )
    return JSONResponse(result)


@router.post("/api/v1/servers/{server_id}/verify")
async def verify_server_endpoint(server_id: str, request: Request):
    """
    PRD-0012 C4 — retry verification while in debug/maintenance mode.
    Distinct from "go live" (POST /servers/{id}/debug-mode {enabled:false}):
    this only re-runs run_verification_probes and reports the result; on
    failure the server stays in debug mode with the probe error surfaced,
    never advancing toward invocable-by-everyone on its own.
    """
    row = await _get_server_owner_row(server_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Server not found")
    _require_owner_or_maintainer(row, request, allow_platform_admin=True)
    if not row.get("debug_mode"):
        raise HTTPException(
            status_code=409, detail="server is not in debug/maintenance mode — nothing to verify",
        )

    async with AsyncSessionLocal() as db:
        _url_row = (await db.execute(
            text(
                "SELECT upstream_url FROM server_registry "
                "WHERE server_id = :sid AND deleted_at IS NULL"
            ),
            {"sid": server_id},
        )).mappings().first()
    upstream_url = _url_row["upstream_url"] if _url_row else None
    if not upstream_url:
        raise HTTPException(status_code=409, detail="server has no upstream_url set")

    actor = getattr(request.state, "client_id", "unknown")
    from app.services.deploy_verifier import VerificationFailedError, run_verification_probes

    try:
        report = await run_verification_probes(
            server_id, upstream_url, actor_client_id=actor, require_approved=False,
        )
    except VerificationFailedError as exc:
        async with AsyncSessionLocal() as db:
            await db.execute(
                text(
                    "UPDATE server_registry SET verification_report = CAST(:report AS jsonb), "
                    "updated_at = now() WHERE server_id = :sid"
                ),
                {"report": json.dumps(exc.report), "sid": server_id},
            )
            await db.commit()
        return JSONResponse(
            {
                "server_id": server_id, "verified": False,
                "debug_mode": True, "verification_report": exc.report,
            },
            status_code=422,
        )

    async with AsyncSessionLocal() as db:
        await db.execute(
            text(
                "UPDATE server_registry SET verification_report = CAST(:report AS jsonb), "
                "updated_at = now() WHERE server_id = :sid"
            ),
            {"report": json.dumps(report), "sid": server_id},
        )
        await db.commit()
    return JSONResponse({
        "server_id": server_id, "verified": True, "debug_mode": True, "verification_report": report,
    })


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
                "SELECT upstream_url, owner_sub, adapter_name, upstream_allowlist_entry, "
                "       injection_mode, upstream_idp_config, submission_status "
                "FROM server_registry "
                "WHERE server_id = :id AND deleted_at IS NULL"
            ),
            {"id": server_id},
        )
        url_record = url_row.fetchone()
    if url_record is None:
        raise HTTPException(status_code=404, detail="Server not found")
    # This D3 direct-registration path only ever touches `status`, never
    # `submission_status` — approving a server that's actually mid-flow in
    # the self-service submission pipeline (submission_status != 'draft')
    # here would flip `status='approved'` (what the servers-list UI reads)
    # while `submission_status` stays 'awaiting_review' etc. (what the
    # submissions admin page reads), and would skip that pipeline's
    # high-risk-scope reviewer gate entirely. Found 2026-07-19: exactly this
    # happened for codex-2026-07-19-entra-id-directory.
    if url_record[6] != "draft":
        raise HTTPException(
            status_code=409,
            detail=(
                "This server is under self-service submission review "
                f"(submission_status={url_record[6]!r}) — approve it via "
                "POST /api/v1/admin/submissions/{id}/approve instead."
            ),
        )
    from app.core.config import get_settings as _get_settings
    _approval_settings = _get_settings()
    _approval_allowlist = _approval_settings.upstream_private_cidr_allowlist_parsed
    # NOTE (2026-07-14): the self-service submission flow (submission.py's
    # create/patch/submit) stores the submitter's URL in the separate
    # `requested_upstream_url` column, not `upstream_url` — by design, the
    # real `upstream_url` is only populated post-approval via the "provide
    # the live backend URL" PATCH step (which already runs this same SSRF
    # check itself). Re-validating an intentionally-still-empty upstream_url
    # here always failed with a misleading "must have an explicit scheme"
    # error for every self-service submission, regardless of what the
    # submitter actually provided. Skip validation (nothing to validate yet)
    # when upstream_url is empty; only re-validate when it's already set
    # (e.g. a server registered directly via /api/v1/servers, which does
    # populate upstream_url immediately).
    if url_record[0]:
        try:
            await validate_upstream_url_ssrf(
                url_record[0], private_cidr_allowlist=_approval_allowlist,
                allow_http_dev=(_approval_settings.ENVIRONMENT == "development"),
            )
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
    if url_record[0]:
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
    _reg_upstream_idp_config = url_record[5]  # already jsonb -> dict, or None

    # WP-A6 Finding 1: this D3 dual-control path (unlike submission.py's
    # /admin/submissions/{id}/approve) has no separate reviewer-adjustment
    # step for OAuth scopes/audience — the platform_admin approving here IS
    # the review, so the requested upstream_idp_config is copied through
    # verbatim into the approved_* columns dispatch actually reads
    # (dynamic_external_oauth.py resolves only from approved_upstream_idp_config,
    # never the submitter-controlled upstream_idp_config). Previously this
    # path approved status='approved' without ever populating those columns,
    # so self-service-registered OAuth servers had no approved config at all.
    _approved_upstream_idp_config = _reg_upstream_idp_config
    _approved_token_audience = (_reg_upstream_idp_config or {}).get("audience")
    _approved_oauth_scopes = (_reg_upstream_idp_config or {}).get("scopes") or []

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
                "    consent_jti = :consent_jti, "
                "    approved_upstream_idp_config = CAST(:approved_idp_config AS jsonb), "
                "    approved_token_audience = :approved_token_audience, "
                "    approved_oauth_scopes = :approved_oauth_scopes "
                "WHERE server_id = :id AND deleted_at IS NULL AND status = 'pending' "
                "RETURNING server_id"
            ),
            {
                "id": server_id, "approver": approver, "consent_jti": consent_payload.jti,
                "approved_idp_config": json.dumps(_approved_upstream_idp_config) if _approved_upstream_idp_config is not None else None,
                "approved_token_audience": _approved_token_audience,
                "approved_oauth_scopes": _approved_oauth_scopes,
            },
        )
        # A-07: append-only audit record so approval history survives future UPDATEs.
        await db.execute(
            text(
                "INSERT INTO audit_events "
                "(event_id, event_type, client_id, tool_name, outcome, request_id, sha256_hash, latency_ms) "
                # 'success' violated audit_events_outcome_check (only 'allow'/'deny' are
                # permitted) — this silently rolled back every approval's whole transaction
                # (UPDATE + INSERT share one commit). Found 2026-07-14 approving test-api-noauth.
                "VALUES (:eid, 'SERVER_APPROVED', :approver, :server_id, 'allow', :rid, '', 0)"
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

    # WP-A6 Finding 1: a selected, reviewer-approved oauth_provider_profile
    # is authoritative for injection_mode/upstream_idp_type/issuer+endpoints/
    # scopes/audience — a non-expert submitter picks the profile instead of
    # hand-authoring raw OAuth JSON. Only the profile-unowned pieces
    # (client_id, and scopes narrower than the profile default) still come
    # from the request body.
    injection_mode = body.injection_mode
    upstream_idp_type = body.upstream_idp_type
    upstream_idp_config = body.upstream_idp_config
    if body.oauth_provider_profile_id:
        async with AsyncSessionLocal() as db:
            try:
                profile = await oauth_provider_profile_svc.get_profile(db, body.oauth_provider_profile_id)
            except oauth_provider_profile_svc.ProfileNotFoundError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        if profile.status != "approved":
            raise HTTPException(
                status_code=400,
                detail=f"oauth_provider_profile {profile.id!r} is not approved (status={profile.status!r})",
            )
        injection_mode = profile.injection_mode
        upstream_idp_type = upstream_idp_type_for_mode(injection_mode)

        requested_scopes = (body.upstream_idp_config or {}).get("scopes")
        if requested_scopes is not None:
            blocked = sorted(set(requested_scopes) & set(profile.blocked_scopes))
            if blocked:
                raise HTTPException(status_code=400, detail=f"scope(s) {blocked} are blocked by this oauth_provider_profile")
            allowed_ceiling = set(profile.allowed_scopes) or set(profile.default_scopes)
            overbroad = sorted(set(requested_scopes) - allowed_ceiling)
            if overbroad:
                raise HTTPException(status_code=400, detail=f"scope(s) {overbroad} exceed this oauth_provider_profile's allowed scopes")
            effective_scopes = requested_scopes
        else:
            effective_scopes = profile.default_scopes

        if upstream_idp_type is not None:
            upstream_idp_config = {
                **(body.upstream_idp_config or {}),
                "issuer": profile.issuer,
                "authorization_endpoint": profile.authorization_endpoint,
                "token_endpoint": profile.token_endpoint,
                "scopes": effective_scopes,
            }
            # A generic_oauth2/custom_oidc/entra profile still needs a
            # per-server client_id (and, out of band, a client_secret in
            # credential_store) — that's not profile-owned, since one
            # provider profile can back many servers with distinct app
            # registrations. Fail closed rather than register a server whose
            # dispatcher has no client to authenticate as.
            if not upstream_idp_config.get("client_id"):
                raise HTTPException(
                    status_code=400,
                    detail="upstream_idp_config.client_id is required when registering against an oauth_provider_profile",
                )
        else:
            upstream_idp_config = None

    # Validation 1: Injection mode ↔ IdP type compatibility
    try:
        validate_mode_and_idp(
            injection_mode=injection_mode,
            upstream_idp_type=upstream_idp_type,
            upstream_idp_config=upstream_idp_config,
        )
    except InvalidOnboardingConfig as exc:
        raise HTTPException(status_code=400, detail=f"Invalid mode/IdP config: {exc}") from exc

    # Validation 2: IdP configuration structure
    if upstream_idp_type:
        try:
            validate_upstream_idp_config(
                upstream_idp_type=upstream_idp_type,
                upstream_idp_config=upstream_idp_config,
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
                    owner_sub, status, upstream_allowlist_entry, oauth_provider_profile_id
                ) VALUES (
                    :server_id, :service_name, :upstream_url, CAST(:injection_mode AS injection_mode_enum),
                    :upstream_idp_type, CAST(:upstream_idp_config AS jsonb), :adapter_name,
                    :owner_sub, 'pending', :upstream_allowlist_entry, CAST(:oauth_provider_profile_id AS uuid)
                )
                RETURNING server_id, service_name, status, created_at
                """
            ),
            {
                "server_id": server_id,
                "service_name": body.service_name,
                "upstream_url": body.upstream_url,
                "injection_mode": injection_mode,
                "upstream_idp_type": upstream_idp_type,
                "upstream_idp_config": json.dumps(upstream_idp_config) if upstream_idp_config is not None else None,
                "adapter_name": body.adapter_name,
                "owner_sub": client_id,
                "upstream_allowlist_entry": upstream_allowlist_entry,
                "oauth_provider_profile_id": body.oauth_provider_profile_id,
            },
        )
        await db.commit()
        row = result.fetchone()

    logger.info(
        "server_registered_pending server_id=%s service_name=%s "
        "owner_sub=%s injection_mode=%s",
        server_id, body.service_name, client_id, injection_mode,
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
