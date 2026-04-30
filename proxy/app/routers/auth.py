"""
MCP Security Platform — Authentication Router

Implements docs/API.md Section 2.9 (OIDC flows).

Endpoints:
  GET /api/v1/auth/oidc/login      — Initiate OIDC authorization code flow
  GET /api/v1/auth/oidc/callback   — OIDC callback; exchange code for tokens

Both endpoints are public (no auth required). They are part of the OIDC
integration point reserved per docs/ARCHITECTURE.md Section 8.1.

When OIDC_ENABLED=false, these endpoints return 503 with a helpful message.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings

router = APIRouter(prefix="/auth")


@router.get("/oidc/login")
async def oidc_login() -> RedirectResponse:
    """
    Initiate OIDC authorization code flow.
    Redirects to the configured OIDC provider authorization endpoint.
    Public endpoint — no authentication required.

    TODO (backend_dev): Implement OIDC code flow using python-jose or authlib.
      1. Build OIDC authorization URL with state + nonce
      2. Store state in Redis (short TTL for CSRF protection)
      3. Redirect to provider
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "OIDC_DISABLED",
                "message": "OIDC authentication is not enabled on this deployment.",
            },
        )
    raise HTTPException(status_code=501, detail="OIDC login not yet implemented.")


@router.get("/oidc/callback")
async def oidc_callback(
    code: str = "",
    state: str = "",
    error: str = "",
) -> JSONResponse:
    """
    OIDC authorization code callback.
    Exchanges code for tokens, resolves roles, returns access token.
    Public endpoint — OIDC provider handles authentication.

    TODO (backend_dev):
      1. Validate state against Redis-stored nonce (CSRF check)
      2. Exchange code for access token + ID token via OIDC provider token endpoint
      3. Validate ID token (signature, expiry, audience)
      4. Extract role claims per OIDC_ROLE_CLAIM_PATH
      5. Map claims to platform roles via oidc_role_mappings table
      6. Return {access_token, token_type, expires_in, roles}
    """
    if not settings.OIDC_ENABLED:
        raise HTTPException(
            status_code=503,
            detail={"code": "OIDC_DISABLED", "message": "OIDC is not enabled."},
        )
    if error:
        raise HTTPException(
            status_code=400,
            detail={"code": "OIDC_ERROR", "message": f"OIDC provider error: {error}"},
        )
    raise HTTPException(status_code=501, detail="OIDC callback not yet implemented.")
