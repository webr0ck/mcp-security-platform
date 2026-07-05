"""Admin LLM provider configuration (PRD-0005 R-1).

Endpoints (admin / platform_admin):
  GET  /api/v1/admin/llm         — effective config + whether a token is set
  PUT  /api/v1/admin/llm         — set non-secret fields (base_url/model/timeout/enabled)
  PUT  /api/v1/admin/llm/token   — set the API token (write-only; stored encrypted)
  DELETE /api/v1/admin/llm/token — remove the API token
  POST /api/v1/admin/llm/test    — bounded probe against the configured endpoint

The token is NEVER returned. Non-secret config in llm_config; token in
platform_secrets (KEK-encrypted). Mutations are HMAC-audited.
"""
from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.config import get_settings
from app.services import llm_config as llm_cfg
from app.services import platform_secrets
from app.services.admin_audit import emit_admin_config_event

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = {"admin", "platform_admin"}
_TOKEN_NAME = "llm-api"


def _require_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="admin or platform_admin role required")


async def _db():
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise HTTPException(status_code=503, detail="Database pool not available")
    return pool


class LlmUpdate(BaseModel):
    base_url: str | None = Field(default=None, max_length=500)
    model: str | None = Field(default=None, max_length=200)
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)
    enabled: bool | None = None


class TokenUpdate(BaseModel):
    token: str = Field(min_length=1, max_length=4000)


def _reject_insecure_base_url(base_url: str | None) -> None:
    """SI-4: in prod, refuse a plaintext http:// base_url to a non-loopback host."""
    if not base_url:
        return
    s = get_settings()
    env = (getattr(s, "ENVIRONMENT", "") or "").lower()
    if env in ("production", "staging") and base_url.startswith("http://"):
        host = base_url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        if host not in ("localhost", "127.0.0.1", "ollama"):
            raise HTTPException(
                status_code=400,
                detail="Plaintext http:// LLM endpoint to a non-loopback host is not allowed in prod.",
            )


@router.get("/api/v1/admin/llm")
async def get_llm(request: Request) -> dict:
    _require_admin(request)
    eff = await llm_cfg.effective(force=True)
    token_set = await platform_secrets.secret_exists(_TOKEN_NAME)
    return {
        "base_url": eff.base_url,
        "model": eff.model,
        "timeout_seconds": eff.timeout_seconds,
        "enabled": eff.enabled,
        "token_set": token_set,
    }


@router.put("/api/v1/admin/llm")
async def put_llm(body: LlmUpdate, request: Request) -> dict:
    _require_admin(request)
    _reject_insecure_base_url(body.base_url)
    actor = getattr(request.state, "client_id", "unknown-admin")
    pool = await _db()
    await pool.execute(
        "INSERT INTO llm_config (id, base_url, model, timeout_seconds, enabled, updated_by) "
        "VALUES (1, $1, $2, $3, COALESCE($4, true), $5) "
        "ON CONFLICT (id) DO UPDATE SET "
        "  base_url=COALESCE(EXCLUDED.base_url, llm_config.base_url), "
        "  model=COALESCE(EXCLUDED.model, llm_config.model), "
        "  timeout_seconds=COALESCE(EXCLUDED.timeout_seconds, llm_config.timeout_seconds), "
        "  enabled=COALESCE($4, llm_config.enabled), "
        "  updated_by=EXCLUDED.updated_by, updated_at=NOW()",
        body.base_url, body.model, body.timeout_seconds, body.enabled, actor,
    )
    llm_cfg.invalidate()
    await emit_admin_config_event(actor, "set_llm_config", "llm", {
        "base_url": body.base_url, "model": body.model,
        "timeout_seconds": body.timeout_seconds, "enabled": body.enabled,
    })
    return {"ok": True}


@router.put("/api/v1/admin/llm/token")
async def put_llm_token(body: TokenUpdate, request: Request) -> dict:
    _require_admin(request)
    actor = getattr(request.state, "client_id", "unknown-admin")
    try:
        await platform_secrets.set_secret(_TOKEN_NAME, body.token, actor)
    except Exception as exc:
        logger.warning("LLM token store failed: %s", exc)
        raise HTTPException(status_code=503, detail="Could not store token (KMS/Vault unavailable)")
    await emit_admin_config_event(actor, "set_llm_token", "llm", {"token_len": len(body.token)})
    return {"ok": True}


@router.delete("/api/v1/admin/llm/token")
async def delete_llm_token(request: Request) -> dict:
    _require_admin(request)
    actor = getattr(request.state, "client_id", "unknown-admin")
    await platform_secrets.delete_secret(_TOKEN_NAME)
    await emit_admin_config_event(actor, "delete_llm_token", "llm", {})
    return {"ok": True}


@router.post("/api/v1/admin/llm/test")
async def test_llm(request: Request) -> dict:
    """Bounded connectivity probe. Never echoes the token."""
    _require_admin(request)
    eff = await llm_cfg.effective(force=True)
    try:
        token = await llm_cfg.api_token()
    except Exception as exc:
        return {"ok": False, "error": f"token unobtainable: {exc}"}
    headers = {"Authorization": f"Bearer {token}"} if token else None
    try:
        async with httpx.AsyncClient(timeout=min(float(eff.timeout_seconds), 10.0)) as client:
            resp = await client.get(f"{eff.base_url}/api/tags", headers=headers)
        return {"ok": resp.status_code < 400, "status": resp.status_code, "token_used": bool(token)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200], "token_used": bool(token)}
