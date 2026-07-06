"""
MCP Security Platform — OAuth provider profile catalog API (WP-A6, Finding 1)

Endpoints:
  GET    /api/v1/admin/oauth-provider-profiles              — list (optional ?status=)
  POST   /api/v1/admin/oauth-provider-profiles               — create draft (optionally
                                                                 running RFC 8414 discovery first)
  POST   /api/v1/admin/oauth-provider-profiles/discover       — RFC 8414 discovery preview,
                                                                 no DB write (wizard "test" step)
  POST   /api/v1/admin/oauth-provider-profiles/{id}/approve   — reviewer-approval gate
  POST   /api/v1/admin/oauth-provider-profiles/{id}/reject
  POST   /api/v1/wizard/recommend-provider-type               — Finding 1/2 wizard mapping,
                                                                 self-service (no admin role
                                                                 required — pure recommendation,
                                                                 no state change)

Role requirement for /admin/* routes: admin or platform_admin (mirrors admin_prompts.py).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.services import oauth_provider_profile as profile_svc

logger = logging.getLogger(__name__)
router = APIRouter()

_ADMIN_ROLES = {"admin", "platform_admin"}


def _require_admin(request: Request) -> None:
    roles = getattr(request.state, "client_roles", [])
    if not any(r in _ADMIN_ROLES for r in roles):
        raise HTTPException(status_code=403, detail="admin or platform_admin role required")


def _actor(request: Request) -> str:
    return getattr(request.state, "client_id", "unknown-admin")


class DiscoverRequest(BaseModel):
    issuer_or_metadata_url: str = Field(min_length=1, max_length=2048)


@router.post("/api/v1/admin/oauth-provider-profiles/discover")
async def discover(body: DiscoverRequest, request: Request) -> dict:
    """RFC 8414/OIDC metadata discovery preview — no DB write. Returns
    discovered=False (never an error) when no metadata document is reachable;
    the wizard falls back to manual endpoint entry in that case."""
    _require_admin(request)
    metadata = await profile_svc.discover_metadata(body.issuer_or_metadata_url)
    if metadata is None:
        return {"discovered": False}
    return {
        "discovered": True,
        "issuer": metadata.issuer,
        "authorization_endpoint": metadata.authorization_endpoint,
        "token_endpoint": metadata.token_endpoint,
        "jwks_uri": metadata.jwks_uri,
        "scopes_supported": metadata.scopes_supported,
        "token_endpoint_auth_methods_supported": metadata.token_endpoint_auth_methods_supported,
        "grant_types_supported": metadata.grant_types_supported,
        "metadata_url": metadata.metadata_url,
    }


class RecommendRequest(BaseModel):
    same_platform_idp: bool
    supports_authz_code: bool | None = None
    per_user: bool | None = None
    needs_api_key_or_basic: bool = False


@router.post("/api/v1/wizard/recommend-provider-type")
async def recommend_provider_type(body: RecommendRequest) -> dict:
    """Finding 1/2 wizard mapping — pure function, no auth gate beyond the
    standard authenticated-request requirement (no state change, no secrets)."""
    rec = profile_svc.recommend_provider_type(
        same_platform_idp=body.same_platform_idp,
        supports_authz_code=body.supports_authz_code,
        per_user=body.per_user,
        needs_api_key_or_basic=body.needs_api_key_or_basic,
    )
    return {
        "provider_type": rec.provider_type,
        "injection_mode": rec.injection_mode,
        "display_label": rec.display_label,
        "requires_admin_setup": rec.requires_admin_setup,
    }


class CreateProfileRequest(BaseModel):
    slug: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    display_name: str = Field(min_length=1, max_length=256)
    provider_type: str
    issuer_or_metadata_url: str | None = None  # if set, discovery runs before insert
    default_scopes: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=list)
    blocked_scopes: list[str] = Field(default_factory=list)
    token_audience_or_resource: str | None = None
    service_adapter: str | None = None
    supports_client_credentials: bool = False


@router.get("/api/v1/admin/oauth-provider-profiles")
async def list_profiles(request: Request, status: str | None = None) -> dict:
    _require_admin(request)
    async for db in get_db():
        rows = await profile_svc.list_profiles(db, status=status)
        return {"profiles": [_serialize(r) for r in rows]}
    return {"profiles": []}  # pragma: no cover — get_db always yields


@router.post("/api/v1/admin/oauth-provider-profiles")
async def create_profile(body: CreateProfileRequest, request: Request) -> dict:
    _require_admin(request)
    if body.provider_type not in profile_svc.PROVIDER_TYPES:
        raise HTTPException(status_code=422, detail=f"unknown provider_type: {body.provider_type!r}")

    metadata = None
    if body.issuer_or_metadata_url:
        metadata = await profile_svc.discover_metadata(body.issuer_or_metadata_url)
        # Discovery failure is NOT an error here (Finding 1: "A provider
        # without RFC 8414 metadata can still be configured manually") — the
        # profile is simply created with issuer/endpoints unset, and the
        # caller (wizard UI) is expected to prompt for manual entry next.

    async for db in get_db():
        try:
            profile = await profile_svc.create_draft_profile(
                db,
                slug=body.slug,
                display_name=body.display_name,
                provider_type=body.provider_type,
                created_by=_actor(request),
                metadata=metadata,
                default_scopes=body.default_scopes,
                allowed_scopes=body.allowed_scopes,
                blocked_scopes=body.blocked_scopes,
                token_audience_or_resource=body.token_audience_or_resource,
                service_adapter=body.service_adapter,
                supports_client_credentials=body.supports_client_credentials,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"profile": _serialize(profile), "discovery_applied": metadata is not None}
    raise HTTPException(status_code=503, detail="database unavailable")  # pragma: no cover


class ApproveRequest(BaseModel):
    high_risk_scopes_approved: bool = False


@router.post("/api/v1/admin/oauth-provider-profiles/{profile_id}/approve")
async def approve_profile(profile_id: str, body: ApproveRequest, request: Request) -> dict:
    _require_admin(request)
    async for db in get_db():
        try:
            profile = await profile_svc.approve_profile(
                db, profile_id, reviewer=_actor(request), high_risk_scopes_approved=body.high_risk_scopes_approved
            )
        except profile_svc.ProfileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except profile_svc.HighRiskScopeAckRequiredError as exc:
            raise HTTPException(status_code=422, detail={"code": "HIGH_RISK_SCOPE_ACK_REQUIRED", "message": str(exc)}) from exc
        except profile_svc.InvalidProfileStateTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"profile": _serialize(profile)}
    raise HTTPException(status_code=503, detail="database unavailable")  # pragma: no cover


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2000)


@router.post("/api/v1/admin/oauth-provider-profiles/{profile_id}/reject")
async def reject_profile(profile_id: str, body: RejectRequest, request: Request) -> dict:
    _require_admin(request)
    async for db in get_db():
        try:
            profile = await profile_svc.reject_profile(db, profile_id, reviewer=_actor(request), reason=body.reason)
        except profile_svc.ProfileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except profile_svc.InvalidProfileStateTransitionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {"profile": _serialize(profile)}
    raise HTTPException(status_code=503, detail="database unavailable")  # pragma: no cover


def _serialize(p: profile_svc.ProfileRow) -> dict:
    return {
        "id": p.id,
        "slug": p.slug,
        "display_name": p.display_name,
        "provider_type": p.provider_type,
        "issuer": p.issuer,
        "authorization_endpoint": p.authorization_endpoint,
        "token_endpoint": p.token_endpoint,
        "jwks_uri": p.jwks_uri,
        "metadata_url": p.metadata_url,
        "default_scopes": p.default_scopes,
        "allowed_scopes": p.allowed_scopes,
        "blocked_scopes": p.blocked_scopes,
        "token_audience_or_resource": p.token_audience_or_resource,
        "supports_pkce": p.supports_pkce,
        "supports_refresh_token": p.supports_refresh_token,
        "supports_client_credentials": p.supports_client_credentials,
        "service_adapter": p.service_adapter,
        "status": p.status,
        "created_by": p.created_by,
        "approved_by": p.approved_by,
    }
