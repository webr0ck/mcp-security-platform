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
from app.core.database import AsyncSessionLocal  # noqa: E402  (after TYPE_CHECKING guard)

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
    from app.credential_broker.adapters.grafana import GrafanaAdapter

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

    # Reference the module-level name so patch() replacements take effect in tests.
    import app.credential_broker.factory as _self
    broker = CredentialBroker(
        session=session_store,
        kms=kms,
        db_factory=_self.AsyncSessionLocal,
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
