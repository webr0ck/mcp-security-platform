"""
MCP Security Platform — dynamic per-server external OAuth adapter resolution
(WP-A3: CR-04 remainder)

The static adapter registry (adapters/registry.py) discovers exactly one
instance per Python module, configured from global Settings/env vars — right
for platform-wide integrations (m365, dex, bitbucket) but wrong for a
self-service-onboarded external OAuth server, where every server has its own
issuer/endpoints/client credentials.

resolve_external_oauth_adapter() is the generic equivalent: given a
server_registry.service_name, it looks up that SPECIFIC server's
reviewer-APPROVED config (server_registry.approved_upstream_idp_config —
never the submitter-requested upstream_idp_config; see WP-A2 /
docs/spec/01-authentication.md §4.5) and its admin-provisioned client_secret
from credential_store, and builds a GenericOAuthAdapter.

Fail-closed: returns None (never raises past this boundary for a "not
found"/"not configured" case) when the server has no approved config for
external_oauth_user_token, or the config is missing a required field, or no
client_secret has been provisioned — callers (routers/oauth.py, broker.py)
must treat None exactly like "no adapter registered".
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.credential_broker.adapters.generic_oauth import GenericOAuthAdapter

logger = logging.getLogger(__name__)

_REQUIRED_CONFIG_FIELDS = ("client_id", "authorization_endpoint", "token_endpoint")


async def _load_server_row(session: AsyncSession, service_name: str) -> dict[str, Any] | None:
    row = (
        await session.execute(
            text(
                """
                SELECT server_id, injection_mode, default_injection_mode,
                       approved_upstream_idp_config, approved_oauth_scopes
                FROM server_registry
                WHERE service_name = :svc AND status = 'approved' AND deleted_at IS NULL
                LIMIT 1
                """
            ),
            {"svc": service_name},
        )
    ).fetchone()
    return dict(row._mapping) if row else None


async def _find_credential_id(session: AsyncSession, server_id: str) -> tuple[str, str] | None:
    """
    The OAuth app's client_secret is a SERVICE-owned credential, admin-provisioned
    via the existing PUT /admin/credentials/{tool_id} endpoint (owner_type='service')
    against any one tool on this server — the exact same convention
    _inject_entra_client_credentials relies on (tool_registry.credential_id,
    resolved server-wide via server_registry.default_credential_id or a per-tool
    override). No new admin write path needed; this just finds whichever tool's
    credential_id was set.
    """
    row = (
        await session.execute(
            text(
                """
                SELECT t.tool_id, t.credential_id
                FROM tool_registry t
                WHERE t.server_id = :server_id AND t.credential_id IS NOT NULL
                      AND t.deleted_at IS NULL
                ORDER BY t.created_at ASC
                LIMIT 1
                """
            ),
            {"server_id": server_id},
        )
    ).fetchone()
    if row is None:
        return None
    return str(row.tool_id), str(row.credential_id)


async def resolve_external_oauth_adapter(
    service_name: str,
    db_factory,
    vault_client,
) -> GenericOAuthAdapter | None:
    """
    Build a GenericOAuthAdapter for `service_name` from its server_registry
    row's approved_upstream_idp_config, or return None if not eligible
    (no such server, not external_oauth_user_token mode, config incomplete,
    or no client_secret provisioned).

    `db_factory` is an async_sessionmaker (broker._db_factory / AsyncSessionLocal).
    `vault_client` is the broker's VaultKMSClient (broker.vault_client), passed
    to credential_storage.retrieve_credential the same way
    _inject_entra_client_credentials uses it.

    Fail-closed on infrastructure errors too: a DB/Vault outage here must
    result in "no adapter" (→ 404/"not enrolled"), never propagate a raw
    connection exception up through the enrollment page or broker.resolve.
    """
    try:
        return await _resolve_external_oauth_adapter_inner(service_name, db_factory, vault_client)
    except Exception as exc:
        logger.warning(
            "external_oauth adapter resolution failed for service=%s: %s", service_name, exc,
        )
        return None


async def _resolve_external_oauth_adapter_inner(
    service_name: str,
    db_factory,
    vault_client,
) -> GenericOAuthAdapter | None:
    async with db_factory() as session:
        row = await _load_server_row(session, service_name)
        if row is None:
            return None

        mode = row.get("injection_mode") or row.get("default_injection_mode") or "none"
        if mode != "external_oauth_user_token":
            return None

        config = row.get("approved_upstream_idp_config")
        if not config:
            logger.warning(
                "external_oauth adapter resolution: no approved_upstream_idp_config for "
                "service=%s (server_id=%s) — reviewer has not approved OAuth/IdP config "
                "under the WP-A2 model yet",
                service_name, row.get("server_id"),
            )
            return None

        missing = [f for f in _REQUIRED_CONFIG_FIELDS if not config.get(f)]
        if missing:
            logger.warning(
                "external_oauth adapter resolution: approved config for service=%s missing "
                "required field(s) %s — refusing to build an incomplete adapter",
                service_name, missing,
            )
            return None

        found = await _find_credential_id(session, str(row["server_id"]))

    if found is None:
        logger.warning(
            "external_oauth adapter resolution: no admin-provisioned client_secret "
            "found for service=%s (no tool_registry.credential_id set on any tool "
            "of this server); refusing to build an adapter that cannot authenticate",
            service_name,
        )
        return None
    tool_id, credential_id = found

    from app.services.credential_storage import retrieve_credential

    try:
        credential_dict = await retrieve_credential(
            credential_id=credential_id,
            user_sub="__service__",
            service=service_name,
            tool_id=tool_id,
            owner_type="service",
            vault_client=vault_client,
            db_pool=db_factory,
        )
    except KeyError:
        logger.warning(
            "external_oauth adapter resolution: credential_id %s not found in "
            "credential_store for service=%s", credential_id, service_name,
        )
        return None
    except Exception as exc:
        logger.warning(
            "external_oauth adapter resolution: credential_store retrieval failed "
            "for service=%s: %s", service_name, exc,
        )
        return None

    client_secret = credential_dict.get("client_secret") or credential_dict.get("secret")
    if not client_secret:
        logger.warning(
            "external_oauth adapter resolution: stored credential for service=%s has "
            "no client_secret/secret field; refusing to build an adapter that cannot "
            "authenticate", service_name,
        )
        return None

    redirect_uri = config.get("redirect_uri") or ""
    if not redirect_uri:
        from app.core.config import get_settings
        base = get_settings().PROXY_BASE_URL.rstrip("/")
        redirect_uri = f"{base}/auth/callback/{service_name}"

    return GenericOAuthAdapter(
        client_id=config["client_id"],
        client_secret=str(client_secret).strip(),
        redirect_uri=redirect_uri,
        scopes=list(row.get("approved_oauth_scopes") or config.get("scopes") or []),
        authorization_endpoint=config["authorization_endpoint"],
        token_endpoint=config["token_endpoint"],
        client_auth_method=config.get("client_auth_method") or "client_secret_post",
    )
