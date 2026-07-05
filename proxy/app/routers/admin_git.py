"""Admin git provider configuration (PRD-0005 R-2).

Endpoints (admin / platform_admin):
  GET    /api/v1/admin/git-providers            — list providers (token presence only)
  PUT    /api/v1/admin/git-providers/{provider}  — set host/account/enabled/allow_private
  PUT    /api/v1/admin/git-providers/{provider}/token   — set clone token (write-only)
  DELETE /api/v1/admin/git-providers/{provider}/token   — remove token

Only 'github' and 'bitbucket' are accepted providers. Enabling a private host
(allow_private) or setting a host that resolves to a private IP emits a WARN
audit event. The token is stored encrypted in platform_secrets; never returned.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.services import git_providers, platform_secrets
from app.services.admin_audit import emit_admin_config_event

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = {"admin", "platform_admin"}
_PROVIDERS = {"github", "bitbucket"}


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


class ProviderUpdate(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    clone_account: str | None = Field(default=None, max_length=255)
    enabled: bool = False
    allow_private: bool = False


class TokenUpdate(BaseModel):
    token: str = Field(min_length=1, max_length=4000)


@router.get("/api/v1/admin/git-providers")
async def list_providers(request: Request) -> dict:
    _require_admin(request)
    pool = await _db()
    rows = await pool.fetch(
        "SELECT provider, enabled, host, clone_account, allow_private, updated_at "
        "FROM git_providers ORDER BY provider"
    )
    out = []
    for r in rows:
        out.append({
            "provider": r["provider"], "enabled": r["enabled"], "host": r["host"],
            "clone_account": r["clone_account"], "allow_private": r["allow_private"],
            "token_set": await platform_secrets.secret_exists(f"git-{r['provider']}"),
        })
    return {"providers": out}


@router.put("/api/v1/admin/git-providers/{provider}")
async def put_provider(provider: str, body: ProviderUpdate, request: Request) -> dict:
    _require_admin(request)
    if provider not in _PROVIDERS:
        raise HTTPException(status_code=404, detail=f"unknown provider {provider!r}")
    actor = getattr(request.state, "client_id", "unknown-admin")

    # Validate the host now so a misconfiguration is caught at write time, not at
    # the first clone. If it resolves private, require allow_private (SSRF F-3).
    if body.enabled:
        try:
            git_providers.validate_host(body.host, body.allow_private)
        except git_providers.GitHostError as exc:
            raise HTTPException(status_code=400, detail=f"host validation failed: {exc}")

    pool = await _db()
    await pool.execute(
        "INSERT INTO git_providers (provider, enabled, host, clone_account, allow_private, updated_by) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (provider) DO UPDATE SET enabled=EXCLUDED.enabled, host=EXCLUDED.host, "
        "clone_account=EXCLUDED.clone_account, allow_private=EXCLUDED.allow_private, "
        "updated_by=EXCLUDED.updated_by, updated_at=NOW()",
        provider, body.enabled, body.host, body.clone_account, body.allow_private, actor,
    )
    await emit_admin_config_event(actor, "set_git_provider", provider, {
        "host": body.host, "enabled": body.enabled, "allow_private": body.allow_private,
    })
    if body.allow_private:
        # High-visibility: a private-host clone target is a deliberate SSRF-surface widening.
        await emit_admin_config_event(actor, "git_provider_allow_private", provider,
                                      {"host": body.host}, outcome="allow")
    return {"ok": True, "provider": provider}


@router.put("/api/v1/admin/git-providers/{provider}/token")
async def put_token(provider: str, body: TokenUpdate, request: Request) -> dict:
    _require_admin(request)
    if provider not in _PROVIDERS:
        raise HTTPException(status_code=404, detail=f"unknown provider {provider!r}")
    actor = getattr(request.state, "client_id", "unknown-admin")
    try:
        await platform_secrets.set_secret(f"git-{provider}", body.token, actor)
    except Exception as exc:
        logger.warning("git token store failed for %s: %s", provider, exc)
        raise HTTPException(status_code=503, detail="Could not store token (KMS/Vault unavailable)")
    await emit_admin_config_event(actor, "set_git_token", provider, {"token_len": len(body.token)})
    return {"ok": True}


@router.delete("/api/v1/admin/git-providers/{provider}/token")
async def delete_token(provider: str, request: Request) -> dict:
    _require_admin(request)
    if provider not in _PROVIDERS:
        raise HTTPException(status_code=404, detail=f"unknown provider {provider!r}")
    actor = getattr(request.state, "client_id", "unknown-admin")
    await platform_secrets.delete_secret(f"git-{provider}")
    await emit_admin_config_event(actor, "delete_git_token", provider, {})
    return {"ok": True}
