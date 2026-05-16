from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import text

from app.core.config import get_settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["oauth-enrollment"])

_OAUTH_ADAPTERS: dict = {}

# CB-003: pending-flow records live server-side in Redis, keyed by an
# unguessable nonce, single-use, short TTL. The nonce is the OAuth `state`.
_PENDING_PREFIX = "oauth_flow:"
_PENDING_TTL_SECONDS = 300


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


@router.get("/enroll/{service}")
async def enroll(service: str, request: Request) -> RedirectResponse:
    adapter = _get_adapter(service)
    if adapter is None:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found or not OAuth")

    client_id = _authenticated_client_id(request)
    nonce = secrets.token_urlsafe(32)
    code_verifier, code_challenge = _pkce_pair()

    from app.core.redis_client import redis_pool
    await redis_pool.client.setex(
        f"{_PENDING_PREFIX}{nonce}",
        _PENDING_TTL_SECONDS,
        json.dumps({"client_id": client_id, "service": service, "cv": code_verifier}),
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
                "INSERT INTO credential_store (user_sub, service, encrypted_blob) "
                "VALUES (:sub, :svc, :blob) "
                "ON CONFLICT (user_sub, service) DO UPDATE SET encrypted_blob=:blob"
            ),
            {"sub": client_id, "svc": service, "blob": encrypted},
        )
        await db.commit()

    await _emit_credential_audit(request, client_id, service)

    logger.info("oauth_enrollment_complete", extra={"client_id": client_id, "service": service})
    return HTMLResponse(
        "<html><body><h2>Authorization complete.</h2><p>You can close this tab.</p></body></html>"
    )


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
                    INSERT INTO audit_events (
                        event_id, event_type, created_at,
                        client_id, tool_name,
                        outcome, request_id, sha256_hash, latency_ms
                    ) VALUES (
                        :event_id, 'CREDENTIAL_ENROLLED', :ts,
                        :client_id, :tool_name,
                        'allow', :request_id, :sha256_hash, 0
                    )
                    """
                ),
                {
                    "event_id": event_id,
                    "ts": ts,
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
