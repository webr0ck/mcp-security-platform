"""
MCP Security Platform — Credential Broker Factory

Assembles a CredentialBroker singleton from application settings and the
live Redis client. Called once from the app lifespan (main.py).

Returns None if VAULT_TOKEN is empty (Vault not configured in this deployment).
In that state, any tool with service_name + credential_approach set will
fail-closed via CredentialInjectionError in the invocation service.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

# Module-level import so patch("app.credential_broker.factory.AsyncSessionLocal")
# can replace the name in this module's namespace during tests.
# create_async_engine is lazy (no real connection until first use), so this is
# safe to import at module level without an active database.
from app.core.database import AsyncSessionLocal

if TYPE_CHECKING:
    from app.core.config import Settings

logger = logging.getLogger(__name__)


def build_broker(settings: "Settings", redis_client):
    """
    Build and return a CredentialBroker, or None if Vault is not configured.

    Args:
        settings: Application settings (from get_settings()).
        redis_client: Live async Redis client (from redis_pool.client).

    Returns:
        CredentialBroker instance, or None if VAULT_TOKEN is empty.
    """
    if not settings.VAULT_TOKEN:
        logger.warning(
            "VAULT_TOKEN is empty — credential broker disabled. "
            "Tools with service_name + credential_approach set will fail-closed."
        )
        return None

    from app.credential_broker.broker import CredentialBroker
    from app.credential_broker.kms import VaultKMSClient
    from app.credential_broker.session import SessionStore
    from app.credential_broker.adapters.gitea import GiteaAdapter
    from app.credential_broker.adapters.grafana import GrafanaAdapter
    from app.credential_broker.adapters.netbox import NetboxAdapter
    from app.credential_broker.adapters.m365 import M365Adapter

    kms = VaultKMSClient(
        addr=settings.VAULT_ADDR,
        token=settings.VAULT_TOKEN,
        ca_bundle=settings.VAULT_CA_BUNDLE or None,
    )
    session_store = SessionStore(redis_client, ttl=settings.BROKER_SESSION_TTL_SECONDS)

    approach_b_adapters: dict = {}
    approach_a_adapters: dict = {}

    if settings.GRAFANA_ADMIN_TOKEN:
        approach_b_adapters["grafana"] = GrafanaAdapter(
            base_url=settings.GRAFANA_BASE_URL,
            service_account_id=settings.GRAFANA_SERVICE_ACCOUNT_ID,
            admin_token=settings.GRAFANA_ADMIN_TOKEN,
        )

    if settings.NETBOX_ADMIN_TOKEN:
        approach_b_adapters["netbox"] = NetboxAdapter(
            base_url=settings.NETBOX_BASE_URL,
            admin_token=settings.NETBOX_ADMIN_TOKEN,
        )

    if settings.GITEA_ADMIN_TOKEN:
        approach_b_adapters["gitea"] = GiteaAdapter(
            admin_token=settings.GITEA_ADMIN_TOKEN,
        )

    # Approach A (per-user OAuth refresh): delegated Entra/M365 access. The
    # refresh token is stored encrypted per Keycloak sub at /auth/callback/m365;
    # broker._resolve_a() decrypts it and calls M365Adapter.refresh() per call to
    # mint a fresh DELEGATED Graph access token (acts as the signed-in user).
    if settings.ENTRA_CLIENT_ID and settings.ENTRA_CLIENT_SECRET:
        approach_a_adapters["m365"] = M365Adapter(
            client_id=settings.ENTRA_CLIENT_ID,
            client_secret=settings.ENTRA_CLIENT_SECRET,
            tenant_id=settings.ENTRA_TENANT_ID,
            redirect_uri=settings.ENTRA_REDIRECT_URI,
            scopes=settings.entra_scopes_list,
            token_url=settings.entra_token_url,
            auth_url=settings.entra_auth_url,
        )

    broker = CredentialBroker(
        session=session_store,
        kms=kms,
        db_factory=AsyncSessionLocal,
        approach_b_adapters=approach_b_adapters,
        approach_a_adapters=approach_a_adapters,
    )
    logger.info(
        "Credential broker initialized",
        extra={
            "adapters_b": list(approach_b_adapters),
            "adapters_a": list(approach_a_adapters),
        },
    )
    return broker
