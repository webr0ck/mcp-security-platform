from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import text

from app.core.config import get_settings
from app.core.public_url import derive_public_base_url
from app.credential_broker.adapters.base import TokenExchangeError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["oauth-enrollment"])

_OAUTH_ADAPTERS: dict = {}

# CB-003: pending PKCE-flow records live server-side in Redis, keyed by an
# unguessable nonce (the OAuth `state`), single-use, short TTL.
# State is ONLY written after a valid POST /consent (D2, R-5).
_PENDING_PREFIX = "oauth_flow:"
_PENDING_TTL_SECONDS = 300

# R-5: pending consent records (written at GET /enroll, consumed at POST /consent).
# Key: enroll_consent:{csrf}  Value: JSON {client_id, service, requested_scopes}
_CONSENT_PREFIX = "enroll_consent:"
_CONSENT_TTL_SECONDS = 300  # independent of PKCE TTL — consent precedes PKCE (D2)


async def _get_adapter(service: str):
    """Resolve an Approach-A OAuth adapter by service name.

    Two sources, tried in order:
      1. The static plugin registry (adapters/registry.py) — a platform-wide
         integration self-registered from env vars (m365, dex, bitbucket, ...).
         Cached per service for the process lifetime, as before.
      2. WP-A3 (CR-04): a self-service-onboarded external OAuth server with
         injection_mode='external_oauth_user_token'. Built dynamically, per
         call, from that server's reviewer-APPROVED config
         (server_registry.approved_upstream_idp_config) — never cached, since
         approval can change and the config is cheap to re-read. See
         adapters/dynamic_external_oauth.py.
    """
    if service not in _OAUTH_ADAPTERS:
        from app.credential_broker.adapters.registry import get_spec

        spec = get_spec(service)
        if spec is not None and spec.approach == "A":
            _OAUTH_ADAPTERS[service] = spec.build(get_settings())
    static_adapter = _OAUTH_ADAPTERS.get(service)
    if static_adapter is not None:
        return static_adapter

    from app.credential_broker.adapters.dynamic_external_oauth import resolve_external_oauth_adapter
    from app.services.invocation import broker_instance

    if broker_instance is None:
        return None
    return await resolve_external_oauth_adapter(
        service, db_factory=broker_instance.db_pool, vault_client=broker_instance.vault_client
    )


@router.get("/status/{service}")
async def enrollment_status(service: str, request: Request) -> JSONResponse:
    """
    WP-A3 (CR-04): enrollment-status endpoint for per-user OAuth services.
    Generalizes to every approach-A adapter (m365, dex, bitbucket, entra_user_token,
    external_oauth_user_token), not just the new external_oauth mode — this was a
    gap for ALL of them (no way to check "am I enrolled?" without attempting an
    invoke and getting a CredentialEnrollmentRequiredError).

    Returns {"service", "enrolled": bool, "enrollment_url"} for the AUTHENTICATED
    caller. Never returns the credential itself, never decrypts it — existence-only
    check via the same typed-principal dual-read the broker uses at resolve time,
    so the answer matches what an actual invoke would see.
    """
    client_id = _authenticated_client_id(request)
    principal_id = getattr(request.state, "principal_id", None)
    principal_type = getattr(request.state, "principal_type", None)

    enrolled = False
    try:
        from app.core.database import AsyncSessionLocal
        from app.credential_broker.principal_resolution import (
            resolve_credential_owner,
            CrossTypePrincipalMismatch,
        )

        async with AsyncSessionLocal() as session:
            try:
                resolved = await resolve_credential_owner(
                    session,
                    principal_id=principal_id,
                    principal_type=principal_type,
                    bare_sub=client_id,
                    service=service,
                )
            except CrossTypePrincipalMismatch:
                # A cross-type bare-sub collision is NOT an enrollment for this
                # caller — same fail-closed semantics as the broker/dispatcher.
                resolved = None
            if resolved is not None:
                row = (
                    await session.execute(
                        text(
                            "SELECT 1 FROM credential_store WHERE user_sub = :sub "
                            "AND service = :svc LIMIT 1"
                        ),
                        {"sub": resolved.owner_key, "svc": service},
                    )
                ).fetchone()
                enrolled = row is not None
    except Exception as exc:
        logger.warning(
            "enrollment_status_lookup_failed",
            extra={"service": service, "error": str(exc)},
        )
        # Fail closed on "enrolled" (never claim enrolled when the check itself
        # errored) but still return 200 — this is a status read, not a gate.
        enrolled = False

    base = get_settings().PROXY_BASE_URL.rstrip("/")
    return JSONResponse({
        "service": service,
        "enrolled": enrolled,
        "enrollment_url": f"{base}/auth/enroll/{service}",
    })


def _pkce_pair() -> tuple[str, str]:
    """CB-011: return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)  # 86 chars — within RFC 7636 43..128
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def _authenticated_client_id(request: Request) -> str:
    """
    CB-001: the broker identity is the identity AuthMiddleware resolved
    (mTLS CN post-verification / API key / OIDC sub) — never a raw,
    client-controllable header. /auth/enroll/* is a protected path, so
    this must be populated; reject loudly if it is not.
    """
    client_id = getattr(request.state, "client_id", None)
    if not client_id:
        raise HTTPException(
            status_code=401,
            detail="Credential enrollment requires an authenticated identity.",
        )
    return str(client_id)


def _canonical_scopes(scopes: list[str]) -> str:
    """Canonical scope string: sorted, lowercase, space-separated, deduplicated."""
    return " ".join(sorted(set(s.lower() for s in scopes if s)))


def _scope_hash(scopes_str: str) -> str:
    """INV-002: SHA-256 hex of a canonical scope string (never log raw scopes)."""
    return hashlib.sha256(scopes_str.encode()).hexdigest()


def _render_consent_page(
    client_id: str,
    service: str,
    requested_scopes: list[str],
    csrf_token: str,
    redirect_uri: str,
    stored_scopes: str | None = None,
) -> str:
    """
    D1: Render the server-side HTML consent page.

    Shows: requesting client_id, service, exact requested scopes (with
    additions highlighted on upgrade vs stored_scopes), exact redirect_uri.
    Embeds the unguessable csrf_token in the POST form.

    INV-002: csrf_token is embedded in the form only — not in any log line.
    """
    service_display = html_escape(service)
    client_display = html_escape(client_id)
    redirect_display = html_escape(redirect_uri)

    # Scope diff for upgrade detection (D1)
    stored_set: set[str] = set(stored_scopes.lower().split()) if stored_scopes else set()
    requested_set: set[str] = set(s.lower() for s in requested_scopes)

    new_scopes = requested_set - stored_set
    retained_scopes = requested_set & stored_set

    scope_rows = []
    for s in sorted(requested_scopes, key=str.lower):
        s_lower = s.lower()
        if s_lower in new_scopes:
            scope_rows.append(
                f'<li><strong style="color:#b91c1c">{html_escape(s)} '
                f'<span style="font-weight:normal;color:#b91c1c">(new)</span></strong></li>'
            )
        else:
            scope_rows.append(f"<li>{html_escape(s)}</li>")

    scope_list = "\n".join(scope_rows) or "<li>(no scopes)</li>"

    if stored_scopes and new_scopes:
        scope_notice = (
            '<p style="color:#b91c1c;font-weight:bold">'
            "This request includes NEW permissions not previously consented to "
            "(highlighted in red). You must approve to continue."
            "</p>"
        )
    elif stored_scopes:
        scope_notice = (
            '<p style="color:#166534">No new permissions requested since last enrollment.</p>'
        )
    else:
        scope_notice = ""

    # csrf_token embedded in hidden form input — NOT in any visible text or log
    csrf_hidden = html_escape(csrf_token)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize {service_display} Access</title>
  <style>
    body {{ font-family: sans-serif; max-width: 540px; margin: 60px auto; padding: 0 20px; }}
    .box {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 24px; }}
    h2 {{ margin-top: 0; }}
    .field {{ margin: 8px 0; }}
    .label {{ color: #6b7280; font-size: 0.85em; }}
    .value {{ font-weight: 600; word-break: break-all; }}
    ul {{ margin: 8px 0; padding-left: 24px; }}
    .btn-approve {{ background: #1d4ed8; color: white; border: none; padding: 10px 28px;
                    border-radius: 6px; font-size: 1em; cursor: pointer; }}
    .btn-approve:hover {{ background: #1e40af; }}
    .btn-cancel {{ background: #f3f4f6; color: #374151; border: 1px solid #d1d5db;
                   padding: 10px 20px; border-radius: 6px; font-size: 1em; cursor: pointer;
                   text-decoration: none; margin-left: 8px; }}
  </style>
</head>
<body>
  <div class="box">
    <h2>Authorize {service_display} Access</h2>
    <p>The following MCP client is requesting access to <strong>{service_display}</strong>
       (Microsoft Graph) on your behalf.</p>

    <div class="field">
      <div class="label">Requesting client</div>
      <div class="value">{client_display}</div>
    </div>

    <div class="field">
      <div class="label">Redirect URI (will be used)</div>
      <div class="value">{redirect_display}</div>
    </div>

    <div class="field">
      <div class="label">Permissions requested</div>
      {scope_notice}
      <ul>{scope_list}</ul>
    </div>

    <form method="POST" action="/auth/enroll/{service_display}/consent">
      <input type="hidden" name="csrf_token" value="{csrf_hidden}">
      <button type="submit" class="btn-approve">Approve</button>
      <a href="/" class="btn-cancel">Cancel</a>
    </form>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# D1 / R-5: GET /auth/enroll/{service} — render consent page, NO redirect
# ---------------------------------------------------------------------------

@router.get("/enroll/{service}")
async def enroll(service: str, request: Request) -> HTMLResponse:
    """
    R-5 / D1 / D2 / Task 12: Render the server-side consent page.

    Task 12 enhancement: resolve {service} from server_registry first.
    If found and upstream_idp_config is populated, extract issuer/client_id/scopes
    from the registry. Otherwise fall back to hardcoded adapters (m365, bitbucket, dex)
    for backward compatibility.

    Previous behaviour: minted PKCE + immediately 302'd to Entra (no consent).
    New behaviour:
      1. Resolve and authenticate the client_id (CB-001).
      2. Store a pending-consent record in Redis (enroll_consent:{csrf}).
      3. Return a 200 HTML consent page with the CSRF token embedded in the form.
      4. PKCE state / oauth_flow: key are NOT written here — only after POST /consent.

    R-3b seam: when a signed link-token (ADR-002) is present, client_id is derived
    from it; otherwise from the server-side session (CB-001). Link-token verification
    is R-3b; here we use session identity only.
    """
    client_id = _authenticated_client_id(request)

    # Task 12: Try to resolve service from server_registry first
    registry_config = None
    adapter = None
    idp_config = None

    try:
        from app.services.invocation import registry_instance
        if registry_instance:
            registry_config = registry_instance.get_config(service)
    except Exception as exc:
        logger.warning(
            "registry_lookup_failed",
            extra={"service": service, "error": str(exc)},
        )

    # Task 12 / WP-A6 Finding 2: If server found in registry, use its
    # REVIEWER-APPROVED config — never the submitter-controlled
    # upstream_idp_config. Reading the requested config here let the consent
    # page (and the audit record of what scopes the user consented to)
    # diverge from what the dynamic_external_oauth adapter actually dispatches
    # with (which has always read approved_upstream_idp_config only).
    approved_oauth_scopes: list[str] | None = None
    _has_requested_idp_type = False
    if registry_config and registry_config.status == "approved":
        try:
            from app.core.database import engine as _db_engine
            async with _db_engine.connect() as conn:
                row = await conn.execute(
                    text(
                        "SELECT approved_upstream_idp_config, approved_oauth_scopes, upstream_idp_type "
                        "FROM server_registry "
                        "WHERE service_name = :sname AND status = :st LIMIT 1"
                    ),
                    {"sname": service, "st": "approved"},
                )
                result = row.fetchone()
                if result:
                    if result[0]:
                        idp_config = result[0] if isinstance(result[0], dict) else json.loads(result[0])
                    approved_oauth_scopes = list(result[1]) if result[1] else None
                    _has_requested_idp_type = bool(result[2])
        except Exception as exc:
            logger.warning(
                "approved_upstream_idp_config_lookup_failed",
                extra={"service": service, "error": str(exc)},
            )

        if idp_config:
            if not idp_config.get("issuer") or not idp_config.get("client_id"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Service '{service}' has an approved IdP config missing issuer or client_id",
                )
            requested_scopes = approved_oauth_scopes if approved_oauth_scopes else idp_config.get("scopes", [])
            if isinstance(requested_scopes, str):
                requested_scopes = [s.strip() for s in requested_scopes.split() if s.strip()]
        elif _has_requested_idp_type:
            # Fail closed (WP-A6 Finding 2): the submitter requested an OAuth/IdP
            # config for this server, but no reviewer has approved it yet — never
            # fall back to the unapproved requested config.
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Service '{service}' has a submitted OAuth/IdP config that has not "
                    "been reviewer-approved yet. An admin must approve this server's "
                    "OAuth configuration before it can be enrolled."
                ),
            )
        else:
            # No OAuth/IdP config was ever requested for this server — fall through
            # to hardcoded adapters so existing m365/bitbucket/dex enrollments keep working.
            registry_config = None

    if not registry_config:
        # Fallback to hardcoded adapters for backward compatibility
        adapter = await _get_adapter(service)
        if adapter is None:
            raise HTTPException(status_code=404, detail=f"Service '{service}' not found or not OAuth")

        # Resolve the requested scopes from the adapter (R-2: from tool_registry.entra_scope)
        try:
            requested_scopes: list[str] = list(adapter.scopes)
        except AttributeError:
            settings = get_settings()
            requested_scopes = getattr(settings, "entra_scopes_list", [])

    # Look up any previously stored scopes for diff/highlight (D1)
    stored_scopes: str | None = None
    try:
        from app.core.database import engine as _db_engine
        async with _db_engine.connect() as conn:
            row = await conn.execute(
                text(
                    "SELECT scopes FROM credential_store "
                    "WHERE user_sub = :sub AND service = :svc LIMIT 1"
                ),
                {"sub": client_id, "svc": service},
            )
            existing = row.fetchone()
            if existing:
                stored_scopes = existing[0] or None
    except Exception:
        # Non-fatal: DB may be unavailable in test/staging; proceed without diff
        pass

    # Mint the CSRF token and store the pending consent record (D2)
    csrf_token = secrets.token_urlsafe(32)
    canonical = _canonical_scopes(requested_scopes)

    # CR-10 (WP-A1): capture the typed principal at the authenticated GET step
    # so the eventual credential_store write (at /callback, a PUBLIC path with
    # no request.state identity of its own) can key under it. /auth/enroll/*
    # is NOT a public path (see middleware/auth.py), so request.state is fully
    # resolved here.
    principal_id = getattr(request.state, "principal_id", None)
    principal_type = getattr(request.state, "principal_type", None)

    from app.core.redis_client import redis_pool
    await redis_pool.client.setex(
        f"{_CONSENT_PREFIX}{csrf_token}",
        _CONSENT_TTL_SECONDS,
        json.dumps({
            "client_id": client_id,
            "service": service,
            "requested_scopes": canonical,
            "principal_id": principal_id,
            "principal_type": principal_type,
        }),
    )

    # Resolve redirect_uri for display (D1: show exact redirect_uri).
    # WP-A6 Finding 2: this must reflect the actual resolved adapter/config,
    # not always the Entra-specific setting — a generic external_oauth
    # service's real redirect_uri (idp_config['redirect_uri'], or the
    # {PROXY_BASE_URL}/auth/callback/{service} default computed by
    # dynamic_external_oauth.py) was previously shown as the unrelated Entra one.
    try:
        settings = get_settings()
        if idp_config:
            redirect_uri = idp_config.get("redirect_uri") or f"{settings.PROXY_BASE_URL.rstrip('/')}/auth/callback/{service}"
        else:
            redirect_uri = getattr(settings, "ENTRA_REDIRECT_URI", "")
    except Exception:
        redirect_uri = "(configured on server)"

    html = _render_consent_page(
        client_id=client_id,
        service=service,
        requested_scopes=requested_scopes,
        csrf_token=csrf_token,
        redirect_uri=redirect_uri,
        stored_scopes=stored_scopes,
    )
    # INV-002: csrf_token must not appear in any log line
    logger.info(
        "enrollment_consent_page_served",
        extra={"client_id": client_id, "service": service},
    )
    return HTMLResponse(content=html, status_code=200)


# ---------------------------------------------------------------------------
# D2 / R-5: POST /auth/enroll/{service}/consent — the gate
# ---------------------------------------------------------------------------

@router.post("/enroll/{service}/consent")
async def enroll_consent(
    service: str,
    request: Request,
    csrf_token: Annotated[str, Form()],
) -> RedirectResponse:
    """
    R-5 / C4 / C5 / C8 / D2: Validate consent and mint PKCE state.

    C4: client_id is derived EXCLUSIVELY from the server-side Redis consent
        record (keyed by csrf_token). It is NEVER read from body/query/header.

    C5: CSRF token validated via atomic get_and_delete (single-use). A non-atomic
        GET-then-DEL would allow double-submit → two Entra redirects on one consent.

    C8 / INV-001: on any failure (invalid/expired CSRF, service mismatch), a
        synchronous CREDENTIAL_CONSENT_DENIED audit event is emitted BEFORE the 4xx.

    D2: PKCE state (oauth_flow: key) is ONLY written here, after valid consent.
    """
    from app.core.redis_client import redis_pool
    from app.core.redis_atomic import get_and_delete

    redis = redis_pool.client

    # C5: atomic consume of the CSRF-keyed consent record
    raw = await get_and_delete(redis, f"{_CONSENT_PREFIX}{csrf_token}")

    if not raw:
        # Expired, already consumed, or forged CSRF — emit deny audit first (C8/INV-001)
        await _emit_consent_denied_audit(
            request=request,
            client_id=getattr(request.state, "client_id", "unknown"),
            service=service,
            reason="invalid_or_expired_csrf",
            outcome="deny",
            event_type="CREDENTIAL_CONSENT_DENIED",
        )
        raise HTTPException(
            status_code=403,
            detail="Consent token invalid, expired, or already used.",
        )

    consent = json.loads(raw)

    # C4: the enrollment binding uses the Redis-stored client_id, never a request param.
    record_client_id: str = consent["client_id"]
    consented_scopes: str = consent.get("requested_scopes", "")

    # SEC (AppSec commit-review HIGH — CSRF token not bound to session): a valid CSRF
    # token is necessary but NOT sufficient. The POST must come from the SAME
    # authenticated identity that initiated the GET; otherwise a leaked/redirected
    # consent token could be redeemed by another (or unauthenticated) caller and bind
    # the victim's credential. This is ADR-003 D2's "re-confirm client_id ==
    # request.state.client_id". Emit a deny audit (INV-001) then 401/403.
    # R-3b NOTE: when the signed link-token flow (ADR-002) lands, the unauthenticated
    # fresh-browser case is satisfied by matching the link-token's bound client_id here.
    try:
        session_client_id = _authenticated_client_id(request)
    except HTTPException:
        await _emit_consent_denied_audit(
            request=request,
            client_id=record_client_id,
            service=service,
            reason="unauthenticated_consent_post",
            outcome="deny",
            event_type="CREDENTIAL_CONSENT_DENIED",
        )
        raise
    if session_client_id != record_client_id:
        await _emit_consent_denied_audit(
            request=request,
            client_id=session_client_id,
            service=service,
            reason="consent_session_mismatch",
            outcome="deny",
            event_type="CREDENTIAL_CONSENT_DENIED",
        )
        raise HTTPException(
            status_code=403,
            detail="Consent record does not belong to the authenticated client.",
        )
    client_id: str = record_client_id

    # Service must match (guard against cross-service CSRF replay)
    if consent.get("service") != service:
        await _emit_consent_denied_audit(
            request=request,
            client_id=client_id,
            service=service,
            reason="service_mismatch",
            outcome="deny",
            event_type="CREDENTIAL_CONSENT_DENIED",
        )
        raise HTTPException(
            status_code=403,
            detail="Consent record service mismatch.",
        )

    adapter = await _get_adapter(service)
    if adapter is None:
        await _emit_consent_denied_audit(
            request=request,
            client_id=client_id,
            service=service,
            reason="unknown_service",
            outcome="deny",
            event_type="CREDENTIAL_CONSENT_DENIED",
        )
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found or not OAuth")

    # D2: NOW mint PKCE state — only after valid consent
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()

    # CR-10 (WP-A1): re-derive the typed principal from THIS authenticated
    # request (already re-confirmed == the GET step's session_client_id above)
    # rather than trusting the Redis-stored consent record's copy, for the
    # same reason session_client_id is re-checked here instead of reused
    # verbatim from the consent record.
    principal_id = getattr(request.state, "principal_id", None)
    principal_type = getattr(request.state, "principal_type", None)

    # Derive the callback URL from THIS request's host (LAN IP, Tailscale,
    # localhost, ...) rather than a static configured value — Microsoft
    # redirects back to exactly whatever redirect_uri is sent below, so a
    # static value that doesn't match the host the user actually reached the
    # proxy on sends them to an unreachable/wrong address at callback time
    # (reported live: enrolled via a Tailscale IP, Microsoft bounced back to
    # a static LAN IP instead). Persisted alongside the flow state so the
    # callback step below reuses the IDENTICAL value — Azure rejects a
    # mismatch between the authorize and token-exchange redirect_uri.
    # NOTE: the resulting host must still be pre-registered in the Azure App
    # Registration's redirect URI allowlist; this only fixes which registered
    # host we ask Microsoft to use, not Azure's own allowlist enforcement.
    redirect_uri = f"{derive_public_base_url(request)}/auth/callback/{service}"

    await redis.setex(
        f"{_PENDING_PREFIX}{nonce}",
        _PENDING_TTL_SECONDS,
        json.dumps({
            "client_id": client_id,
            "service": service,
            "cv": code_verifier,
            "scopes": consented_scopes,  # C6: store consent-time scopes with the flow
            "principal_id": principal_id,
            "principal_type": principal_type,
            "redirect_uri": redirect_uri,
        }),
    )

    # Issue the durable EnrollmentConsentPayload audit attestation (D4, C7)
    # jti-burn for this payload is Redis-side (the enroll_consent: key was already
    # consumed above via get_and_delete) — NOT via consume_consent_token / mode_change_consent
    scopes_list = [s for s in consented_scopes.split() if s]
    from app.services.consent import issue_enrollment_consent_token
    _attestation_token, attestation_jti = issue_enrollment_consent_token(
        client_id=client_id,
        service=service,
        scopes=scopes_list,
    )
    # The token is not sent to the browser — it is the durable audit record only
    # (could be stored alongside the enrollment record in a future iteration)

    # INV-001: emit synchronous consent GRANT audit before 302 response
    await _emit_consent_grant_audit(
        request=request,
        client_id=client_id,
        service=service,
        scopes_hash=_scope_hash(consented_scopes),
        attestation_jti=attestation_jti,
    )

    # INV-002: log service and client only — no raw scopes, no CSRF, no state
    logger.info(
        "enrollment_consent_granted",
        extra={"client_id": client_id, "service": service},
    )

    auth_url = adapter.build_auth_url(state=nonce, code_challenge=code_challenge, redirect_uri=redirect_uri)
    return RedirectResponse(url=auth_url, status_code=302)


async def _run_post_enrollment_discovery(*, service: str, access_token: str) -> None:
    """
    WP-A6 Finding 3: immediately after a successful OAuth enrollment, run the
    server's ServiceAdapter (resolved via its oauth_provider_profile.service_adapter
    slug — GenericServiceAdapter/no-op if the server has no profile or the
    profile has no adapter) and persist any resolved runtime context to
    server_registry.service_context.

    Security boundary (C-01/C-02 fix, 2026-07-11 audit): only ever reads
    approved_upstream_idp_config (never the submitter-controlled
    upstream_idp_config — see server_registry.py:736's documented rule), and
    only runs for app-level injection modes where service_context is a
    single, server-wide value. Per-user modes (external_oauth_user_token)
    must never write server_registry.service_context: that column has no
    principal dimension, so the last user to enroll would silently
    overwrite the resource/tenant context used by every other user and by
    the deployed container.

    Fail-soft by design (mirrors RFC 8414 discover_metadata's posture): a
    discovery failure here must not fail an otherwise-successful OAuth
    enrollment — the resource/tenant context can always be resolved again on
    a later enrollment, whereas enrollment itself is now-or-never for this
    callback. The enforcement/fail-closed half of Finding 3
    (verify_access()) runs at deploy-verify time instead (deploy_verifier.py).
    """
    # C-02: app-level injection modes only — service_context is server-wide,
    # not per-principal. Allow-list, deny-by-default for anything else
    # (including per-user external_oauth_user_token and unrecognized modes).
    _APP_LEVEL_INJECTION_MODES = {"external_oauth_client_credentials", "kc_token_exchange"}
    try:
        from app.core.database import engine as _db_engine
        async with _db_engine.connect() as conn:
            row = (await conn.execute(
                text(
                    "SELECT sr.server_id, sr.approved_upstream_idp_config, p.service_adapter, p.injection_mode "
                    "FROM server_registry sr JOIN oauth_provider_profile p "
                    "ON p.id = sr.oauth_provider_profile_id "
                    "WHERE sr.service_name = :sname AND sr.status = 'approved' LIMIT 1"
                ),
                {"sname": service},
            )).fetchone()
        if row is None:
            return  # no profile selected for this server — nothing to discover
        server_id, approved_config_raw, adapter_slug, injection_mode = row
        if injection_mode not in _APP_LEVEL_INJECTION_MODES:
            return  # per-user or unrecognized mode — never write global service_context
        if not approved_config_raw:
            return  # C-01: not yet approved — never discover against submitter-controlled config
        approved_config = approved_config_raw if isinstance(approved_config_raw, dict) else (
            json.loads(approved_config_raw) if approved_config_raw else {}
        )

        from app.credential_broker.adapters.service_adapter_registry import get_service_adapter
        svc_adapter = get_service_adapter(adapter_slug)

        discovered = await svc_adapter.post_enrollment_discovery(access_token, approved_config)
        selected = svc_adapter.select_resource(discovered, user_choice=None)
        runtime_context = svc_adapter.build_runtime_context(approved_config, selected)

        from app.core.database import AsyncSessionLocal as _AsyncSessionLocal
        async with _AsyncSessionLocal() as db:
            await db.execute(
                text(
                    "UPDATE server_registry SET service_context = CAST(:ctx AS jsonb), updated_at = now() "
                    "WHERE server_id = :sid"
                ),
                {"ctx": json.dumps(runtime_context.to_dict()), "sid": str(server_id)},
            )
            await db.commit()
    except Exception as exc:
        logger.warning(
            "post_enrollment_discovery_failed",
            extra={"service": service, "error": str(exc)},
        )


@router.get("/callback/{service}")
async def callback(service: str, code: str, state: str, request: Request) -> HTMLResponse:
    adapter = await _get_adapter(service)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    # CB-003: recover the flow from the server-side store and consume the
    # nonce atomically so a captured callback URL cannot be replayed.
    from app.core.redis_client import redis_pool
    redis = redis_pool.client
    pending_key = f"{_PENDING_PREFIX}{state}"
    pipe = redis.pipeline()
    pipe.get(pending_key)
    pipe.delete(pending_key)
    results = await pipe.execute()
    raw = results[0]
    if not raw:
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state — possible CSRF/replay")

    flow = json.loads(raw)
    client_id: str = flow["client_id"]
    if flow.get("service") != service:
        raise HTTPException(status_code=400, detail="OAuth state/service mismatch")
    code_verifier: str = flow["cv"]

    # CR-10 (WP-A1): ALL NEW enrollments key the credential_store row by the
    # typed principal_id (captured at the authenticated GET/POST consent
    # steps — this /callback path is itself public/unauthenticated, per
    # RFC-required OAuth redirect semantics, so it has no request.state
    # identity of its own). Falls back to the bare client_id only if the
    # flow record predates this field (defensive; should not occur for any
    # flow started after this change ships).
    principal_id: str = flow.get("principal_id") or client_id
    principal_type: str | None = flow.get("principal_type")

    # C6: read the consent-time scopes from the flow record — NEVER re-read tool_registry
    # at callback time. The user consented to these exact scopes; the callback stores
    # exactly what was consented. TOCTOU note: if tool_registry.entra_scope changes
    # between consent and callback, the stored scopes will reflect the consent-time value.
    # Re-enrollment (a new GET/POST /consent) is required to pick up any scope changes.
    consented_scopes: str = flow.get("scopes", "")  # "" for pre-R5 records (backward compat)
    # Reuse the EXACT redirect_uri computed at consent time (see enroll_consent
    # above) — falls back to None (adapter's static configured default) for a
    # flow record from before this field existed.
    flow_redirect_uri: str | None = flow.get("redirect_uri")

    try:
        access_token, refresh_token, _ = await adapter.exchange_code(
            code, code_verifier=code_verifier, redirect_uri=flow_redirect_uri
        )
    except TokenExchangeError as exc:
        # Was previously uncaught here — propagated past FastAPI's own
        # exception handling straight into a raw 500 "unexpected error",
        # discarding the one thing that would tell an admin what's actually
        # wrong (401 invalid_client → bad/expired IdP client secret; 400
        # invalid_grant → the authorization code was already used or the
        # redirect_uri didn't match what was sent to the authorize endpoint).
        # CB-010: still never surface exc.response.text (may echo secrets).
        logger.error(
            "oauth_callback_token_exchange_failed",
            extra={"client_id": client_id, "service": service, "status_code": exc.status_code},
        )
        raise HTTPException(
            status_code=502,
            detail={
                "code": "OAUTH_TOKEN_EXCHANGE_FAILED",
                "message": (
                    f"{service} token endpoint rejected the authorization code exchange "
                    f"(HTTP {exc.status_code}). "
                    + (
                        "This usually means the platform's configured IdP client "
                        "credentials (client_id/client_secret) for this service are "
                        "invalid or expired — an admin needs to verify/rotate them."
                        if exc.status_code in (401, 403)
                        else "Retry enrollment — the authorization code may have expired "
                             "or already been used."
                    )
                ),
            },
        ) from exc

    from app.credential_broker.kms import VaultKMSClient
    from app.credential_broker.approaches.approach_a import encrypt
    settings = get_settings()
    kms = VaultKMSClient(
        addr=settings.VAULT_ADDR,
        token=settings.VAULT_TOKEN,
        ca_bundle=settings.VAULT_CA_BUNDLE or None,
    )
    master = await kms.get_master_secret(settings.BROKER_MASTER_SECRET_PATH)
    # CB-001: encrypt under the AUTHENTICATED identity, never a header value.
    # CR-10 (WP-A1): keyed by the typed principal_id, not the bare client_id —
    # this is the "writes are always typed" half of the dual-read migration.
    #
    # FIND-010 AAD: broker.py::_resolve_a's decrypt() call binds against the
    # FULL four-field AAD (user_sub, service, tool_id=None, owner_type="user")
    # — service/tool_id/owner_type must be passed here too, or every future
    # refresh() decrypts against a mismatched AAD and raises InvalidTag.
    # Discovered live: every prior "enrollment" for an approach-A adapter in
    # this lab (m365 delegated, dex-calendar) was pre-seeded directly into
    # credential_store using the CORRECT four-field AAD, so this endpoint's
    # own encrypt() call (defaulting service="") was never actually exercised
    # until the WP-A3 Dex-as-second-IdP live browser flow (Task 12).
    encrypted = encrypt(
        refresh_token, principal_id, master,
        service=service, tool_id=None, owner_type="user",
    )

    from app.core.database import get_db
    # V011 dropped the plain (user_sub, service) UNIQUE constraint in favor of a
    # PARTIAL unique index scoped to owner_type='user' (uq_credential_user_mode)
    # — an ON CONFLICT target must repeat that predicate or Postgres has no
    # arbiter to match, and 500s ("no unique or exclusion constraint matching
    # the ON CONFLICT specification"). Discovered live: every prior
    # "enrollment" test in this lab pre-seeds credential_store directly rather
    # than driving this real /auth/callback endpoint, so this bug was never
    # exercised end-to-end until the WP-A3 Dex-as-second-IdP live-flow proof
    # (Task 12) actually completed a browser-driven authorization_code flow.
    async for db in get_db():
        await db.execute(
            text(
                "INSERT INTO credential_store "
                "(user_sub, service, encrypted_blob, scopes, principal_type) "
                "VALUES (:sub, :svc, :blob, :scopes, :ptype) "
                "ON CONFLICT (user_sub, service) WHERE owner_type = 'user' DO UPDATE "
                "SET encrypted_blob=:blob, scopes=:scopes, principal_type=:ptype"
            ),
            {
                "sub": principal_id,
                "svc": service,
                "blob": encrypted,
                "scopes": consented_scopes,  # C6: consent-time value from oauth_flow: record
                "ptype": principal_type,
            },
        )
        await db.commit()

        if service == "m365":
            # Per-caller UPN capture (V085): a one-time Graph /me call with
            # THIS caller's fresh delegated token, so app-only get_me can
            # later resolve /users/{upn} for this specific principal instead
            # of one shared, hand-configured M365_USER mailbox for everyone.
            # Best-effort: enrollment must still succeed if this fails (e.g.
            # scopes don't include User.Read, or Graph is briefly unreachable).
            try:
                import httpx as _httpx
                graph_base = (os.environ.get("M365_GRAPH_BASE") or "https://graph.microsoft.com/v1.0").rstrip("/")
                async with _httpx.AsyncClient(timeout=10.0) as _client:
                    _me_resp = await _client.get(
                        f"{graph_base}/me", headers={"Authorization": f"Bearer {access_token}"}
                    )
                if _me_resp.status_code == 200:
                    upn = (_me_resp.json() or {}).get("userPrincipalName") or (_me_resp.json() or {}).get("mail")
                    if upn:
                        await db.execute(
                            text(
                                "UPDATE credential_store SET upn=:upn "
                                "WHERE user_sub=:sub AND service=:svc AND owner_type='user'"
                            ),
                            {"upn": upn, "sub": principal_id, "svc": service},
                        )
                        await db.commit()
            except Exception as exc:
                logger.warning("m365_upn_capture_failed", extra={"client_id": client_id, "error": str(exc)})

    await _run_post_enrollment_discovery(service=service, access_token=access_token)

    await _emit_credential_audit(request, client_id, service)

    logger.info("oauth_enrollment_complete", extra={"client_id": client_id, "service": service})
    return HTMLResponse(
        "<html><body><h2>Authorization complete.</h2><p>You can close this tab.</p></body></html>"
    )


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

async def _emit_credential_audit(request: Request, client_id: str, service: str) -> None:
    """
    CB-004 / INV-001: credential enrollment is a security-relevant state
    change and MUST produce a synchronous audit record before the response
    is returned. Audit emission failure is a hard error.
    """
    request_id: str = getattr(request.state, "request_id", "unknown")
    try:
        from app.core.database import engine as _db_engine

        event_id = str(uuid4())
        ts = datetime.now(timezone.utc)
        sha256_hash = hashlib.sha256(
            f"{event_id}|CREDENTIAL_ENROLLED|{client_id}|{service}|{ts.isoformat()}".encode()
        ).hexdigest()

        async with _db_engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    -- audit_events has no event_type column; event semantics live in
                    -- tool_name + the sha256 preimage + structured logs. event_ts/
                    -- created_at default to now(). Matches invocation.py._emit_audit_event.
                    INSERT INTO audit_events (
                        event_id, client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, :client_id, :tool_name,
                        'allow', :request_id, :sha256_hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "client_id": client_id,
                    "tool_name": f"credential:{service}",
                    "request_id": request_id,
                    "sha256_hash": sha256_hash,
                },
            )
    except Exception as exc:
        logger.error(
            "Audit event emission failed after credential enrollment — INV-001 violation",
            extra={"client_id": client_id, "service": service, "error": str(exc)},
        )
        raise RuntimeError(f"audit event emission failed: {exc}") from exc


async def _emit_consent_grant_audit(
    request: Request,
    client_id: str,
    service: str,
    scopes_hash: str,
    attestation_jti: str,
) -> None:
    """
    R-5 / INV-001 / INV-002: emit a synchronous CREDENTIAL_CONSENT grant audit.

    Records client_id, service, scopes_hash (never raw scopes), and the
    attestation jti for correlation with the EnrollmentConsentPayload.
    Emitted BEFORE the 302 redirect to Entra.
    """
    request_id: str = getattr(request.state, "request_id", "unknown")
    try:
        from app.core.database import engine as _db_engine

        event_id = str(uuid4())
        ts = datetime.now(timezone.utc)
        # Payload hash covers consent-event fields — not raw scopes (INV-002)
        sha256_hash = hashlib.sha256(
            f"{event_id}|CREDENTIAL_CONSENT|{client_id}|{service}|{scopes_hash}|{ts.isoformat()}".encode()
        ).hexdigest()

        async with _db_engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    -- No event_type column (see _emit_credential_audit). outcome=allow
                    -- + tool_name=consent:{service} distinguishes the consent grant.
                    INSERT INTO audit_events (
                        event_id, client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, :client_id, :tool_name,
                        'allow', :request_id, :sha256_hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "client_id": client_id,
                    "tool_name": f"consent:{service}",
                    "request_id": request_id,
                    "sha256_hash": sha256_hash,
                },
            )
    except Exception as exc:
        logger.error(
            "Consent grant audit emission failed — INV-001 violation",
            extra={"client_id": client_id, "service": service, "error": str(exc)},
        )
        raise RuntimeError(f"consent grant audit emission failed: {exc}") from exc


async def _emit_consent_denied_audit(
    request: Request,
    client_id: str,
    service: str,
    reason: str,
    outcome: str = "deny",
    event_type: str = "CREDENTIAL_CONSENT_DENIED",
) -> None:
    """
    R-5 / C8 / INV-001: emit a synchronous CREDENTIAL_CONSENT_DENIED audit BEFORE
    the 4xx response is returned. Mirrors the pattern in _emit_audit_event
    (invocation.py) for deny-before-raise.

    INV-002: reason is a classification label (no raw tokens/scopes/CSRF values).
    Audit failure is a hard error (INV-001 must not be silently skipped).
    """
    request_id: str = getattr(request.state, "request_id", "unknown")
    try:
        from app.core.database import engine as _db_engine

        event_id = str(uuid4())
        ts = datetime.now(timezone.utc)
        sha256_hash = hashlib.sha256(
            f"{event_id}|{event_type}|{client_id}|{service}|{reason}|{ts.isoformat()}".encode()
        ).hexdigest()

        async with _db_engine.begin() as conn:
            await conn.execute(
                text(
                    """
                    -- No event_type column (see _emit_credential_audit). The deny
                    -- reason is carried in the sha256 preimage + structured log;
                    -- tool_name=consent:{service}, outcome=deny.
                    INSERT INTO audit_events (
                        event_id, client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, :client_id, :tool_name,
                        :outcome, :request_id, :sha256_hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "client_id": client_id,
                    "tool_name": f"consent:{service}",
                    "outcome": outcome,
                    "request_id": request_id,
                    "sha256_hash": sha256_hash,
                },
            )
    except Exception as exc:
        logger.error(
            "Consent denied audit emission failed — INV-001 violation",
            extra={"client_id": client_id, "service": service, "error": str(exc)},
        )
        raise RuntimeError(f"consent denied audit emission failed: {exc}") from exc
