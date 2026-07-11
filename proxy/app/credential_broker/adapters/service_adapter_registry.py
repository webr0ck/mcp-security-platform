"""
MCP Security Platform — ServiceAdapter registry (WP-A6 Finding 3 completion)

Maps oauth_provider_profile.service_adapter slugs to ServiceAdapter
instances (app/credential_broker/adapters/service_adapter.py — the
post-enrollment-discovery/runtime-context contract). Distinct from
registry.py, which is the older Approach-A/B credential-adapter plugin
registry for a different concern (how a token is obtained/injected, not
what resource/tenant context a service needs after OAuth succeeds).

NULL/unknown slug resolves to GenericServiceAdapter — the "no extra
discovery needed" reference implementation — so every profile-backed
server has a usable adapter even before a service-specific one exists
(Finding 3's "adding a new OAuth service does not require modifying the
broker" acceptance criterion).
"""
from __future__ import annotations

from app.credential_broker.adapters.generic_service_adapter import GenericServiceAdapter
from app.credential_broker.adapters.service_adapter import ServiceAdapter

_SERVICE_ADAPTERS: dict[str, ServiceAdapter] = {
    "generic": GenericServiceAdapter(),
}


def get_service_adapter(slug: str | None) -> ServiceAdapter:
    """Never raises — an unknown or absent slug falls back to the generic
    no-discovery-needed adapter rather than blocking enrollment."""
    if slug is None:
        return _SERVICE_ADAPTERS["generic"]
    return _SERVICE_ADAPTERS.get(slug, _SERVICE_ADAPTERS["generic"])
