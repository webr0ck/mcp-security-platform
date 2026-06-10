from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from html import escape as html_escape
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text

from app.core.config import get_settings

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


def _get_adapter(service: str):
    settings = get_settings()
    if service not in _OAUTH_ADAPTERS:
        if service == "m365":
            from app.credential_broker.adapters.m365 import M365Adapter
            _OAUTH_ADAPTERS["m365"] = M365Adapter(
                client_id=settings.ENTRA_CLIENT_ID,
                client_secret=settings.ENTRA_CLIENT_SECRET,
                tenant_id=settings.ENTRA_TENANT_ID,
                redirect_uri=settings.ENTRA_REDIRECT_URI,
                scopes=settings.entra_scopes_list,
                token_url=settings.entra_token_url,
                auth_url=settings.entra_auth_url,
            )
        elif service == "bitbucket":
            from app.credential_broker.adapters.bitbucket import BitbucketAdapter
            _OAUTH_ADAPTERS["bitbucket"] = BitbucketAdapter(
                client_id=settings.BITBUCKET_CLIENT_ID,
                client_secret=settings.BITBUCKET_CLIENT_SECRET,
                redirect_uri=settings.BITBUCKET_REDIRECT_URI,
                scopes=settings.bitbucket_scopes_list,
                auth_url=settings.BITBUCKET_AUTH_URL,
                token_url=settings.BITBUCKET_TOKEN_URL,
            )
        elif service == "dex":
            from app.credential_broker.adapters.dex import DexAdapter
            _OAUTH_ADAPTERS["dex"] = DexAdapter(
                issuer_url=settings.DEX_ISSUER_URL,
                client_id=settings.DEX_CLIENT_ID,
                client_secret=settings.DEX_CLIENT_SECRET,
                redirect_uri=settings.DEX_REDIRECT_URI,
                scopes=settings.dex_scopes_list,
            )
        else:
            return None
    return _OAUTH_ADAPTERS.get(service)


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

    # Task 12: If server found in registry with upstream_idp_config, use it
    if registry_config and registry_config.status == "approved":
        # Query upstream_idp_config from DB (registry.ServerConfig doesn't include it)
        try:
            from app.core.database import engine as _db_engine
            async with _db_engine.connect() as conn:
                row = await conn.execute(
                    text(
                        "SELECT upstream_idp_config FROM server_registry "
                        "WHERE service_name = :sname AND status = :st LIMIT 1"
                    ),
                    {"sname": service, "st": "approved"},
                )
                result = row.fetchone()
                if result and result[0]:
                    idp_config = result[0] if isinstance(result[0], dict) else json.loads(result[0])
        except Exception as exc:
            logger.warning(
                "upstream_idp_config_lookup_failed",
                extra={"service": service, "error": str(exc)},
            )

        # Task 12: If upstream_idp_config found, validate required fields
        if idp_config:
            if not idp_config.get("issuer") or not idp_config.get("client_id"):
                raise HTTPException(
                    status_code=400,
                    detail=f"Service '{service}' has no IdP configured (issuer or client_id missing)",
                )
            # Extract scopes from idp_config (or use default if missing)
            requested_scopes = idp_config.get("scopes", [])
            if isinstance(requested_scopes, str):
                requested_scopes = [s.strip() for s in requested_scopes.split() if s.strip()]
        else:
            # Server found but no upstream_idp_config
            raise HTTPException(
                status_code=400,
                detail=f"Service '{service}' has no IdP configured",
            )
    else:
        # Fallback to hardcoded adapters for backward compatibility
        adapter = _get_adapter(service)
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

    from app.core.redis_client import redis_pool
    await redis_pool.client.setex(
        f"{_CONSENT_PREFIX}{csrf_token}",
        _CONSENT_TTL_SECONDS,
        json.dumps({
            "client_id": client_id,
            "service": service,
            "requested_scopes": canonical,
        }),
    )

    # Resolve redirect_uri for display (D1: show exact redirect_uri)
    try:
        settings = get_settings()
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

    adapter = _get_adapter(service)
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

    await redis.setex(
        f"{_PENDING_PREFIX}{nonce}",
        _PENDING_TTL_SECONDS,
        json.dumps({
            "client_id": client_id,
            "service": service,
            "cv": code_verifier,
            "scopes": consented_scopes,  # C6: store consent-time scopes with the flow
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

    auth_url = adapter.build_auth_url(state=nonce, code_challenge=code_challenge)
    return RedirectResponse(url=auth_url, status_code=302)


@router.get("/callback/{service}")
async def callback(service: str, code: str, state: str, request: Request) -> HTMLResponse:
    adapter = _get_adapter(service)
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

    # C6: read the consent-time scopes from the flow record — NEVER re-read tool_registry
    # at callback time. The user consented to these exact scopes; the callback stores
    # exactly what was consented. TOCTOU note: if tool_registry.entra_scope changes
    # between consent and callback, the stored scopes will reflect the consent-time value.
    # Re-enrollment (a new GET/POST /consent) is required to pick up any scope changes.
    consented_scopes: str = flow.get("scopes", "")  # "" for pre-R5 records (backward compat)

    _, refresh_token, _ = await adapter.exchange_code(code, code_verifier=code_verifier)

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
    encrypted = encrypt(refresh_token, client_id, master)

    from app.core.database import get_db
    async for db in get_db():
        await db.execute(
            text(
                "INSERT INTO credential_store (user_sub, service, encrypted_blob, scopes) "
                "VALUES (:sub, :svc, :blob, :scopes) "
                "ON CONFLICT (user_sub, service) DO UPDATE "
                "SET encrypted_blob=:blob, scopes=:scopes"
            ),
            {
                "sub": client_id,
                "svc": service,
                "blob": encrypted,
                "scopes": consented_scopes,  # C6: consent-time value from oauth_flow: record
            },
        )
        await db.commit()

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
