"""
MCP Security Platform — Credential Broker Factory

Assembles a CredentialBroker singleton from application settings and the
live Redis client. Called once from the app lifespan (main.py).

Returns None if VAULT_TOKEN is empty (Vault not configured in this deployment).
In that state, any tool with service_name + credential_approach set will
fail-closed via CredentialInjectionError in the invocation service.

Adapter wiring is NOT hand-coded here. Each adapter module self-registers via
@register_adapter (see adapters/registry.py); build_adapters() discovers every
configured adapter and buckets it by approach. Adding a new credentialed MCP
server therefore requires NO edit to this file — drop an adapter module and
approve a server_registry row.
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
    from app.credential_broker.adapters.registry import build_adapters

    kms = VaultKMSClient(
        addr=settings.VAULT_ADDR,
        token=settings.VAULT_TOKEN,
        ca_bundle=settings.VAULT_CA_BUNDLE or None,
    )
    session_store = SessionStore(redis_client, ttl=settings.BROKER_SESSION_TTL_SECONDS)

    # Discover and instantiate every CONFIGURED adapter. Approach A (per-user
    # OAuth refresh, e.g. m365/bitbucket/dex) and Approach B (gateway-provisioned
    # tokens, e.g. grafana/netbox/gitea) are bucketed by each adapter's own
    # declared `approach`. Unconfigured adapters (missing `requires` settings)
    # are skipped — identical gating to the previous hand-written factory.
    approach_a_adapters, approach_b_adapters = build_adapters(settings)

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
