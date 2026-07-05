"""Admin editor for self-service wizard design prompts.

Endpoints:
  GET    /api/v1/admin/prompts           — list every prompt (default + effective)
  PUT    /api/v1/admin/prompts/{key}     — override a prompt's text
  DELETE /api/v1/admin/prompts/{key}     — remove override (revert to code default)

Role requirement: admin or platform_admin (mirrors admin_limits.py).
Mutations are recorded in the HMAC-signed audit chain via admin_audit.py.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.services import prompt_store
from app.services.admin_audit import emit_admin_config_event

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = {"admin", "platform_admin"}


def _require_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="admin or platform_admin role required")


class PromptUpdate(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


@router.get("/api/v1/admin/prompts")
async def list_prompts(request: Request) -> dict:
    _require_admin(request)
    return {"prompts": await prompt_store.list_prompts()}


def _validate_key(key: str) -> None:
    if key not in prompt_store.default_prompts():
        raise HTTPException(status_code=404, detail=f"unknown prompt key: {key}")


@router.put("/api/v1/admin/prompts/{key}")
async def put_prompt(key: str, body: PromptUpdate, request: Request) -> dict:
    _require_admin(request)
    _validate_key(key)
    actor = getattr(request.state, "client_id", "unknown-admin")
    try:
        await prompt_store.set_prompt(key, body.text, actor)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    await emit_admin_config_event(actor, "set_wizard_prompt", key, {"len": len(body.text)})
    return {"ok": True, "key": key}


@router.delete("/api/v1/admin/prompts/{key}")
async def delete_prompt(key: str, request: Request) -> dict:
    _require_admin(request)
    _validate_key(key)
    actor = getattr(request.state, "client_id", "unknown-admin")
    try:
        await prompt_store.reset_prompt(key)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    await emit_admin_config_event(actor, "reset_wizard_prompt", key, {})
    return {"ok": True, "key": key}
