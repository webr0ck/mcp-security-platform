"""
MCP Security Platform — GenericServiceAdapter (WP-A6, Finding 3 reference implementation)

The "no extra discovery needed" ServiceAdapter: wraps the existing generic
OAuth substrate (generic_oauth.py / dynamic_external_oauth.py) with zero
service-specific behavior. This is the adapter that applies whenever
server_registry.oauth_provider_profile_id references a profile with
service_adapter=NULL (see V070) — the common case for a plain external
OAuth 2.0 API that doesn't need tenant/site/cloudId resolution.

Concretely demonstrates that "adding a new OAuth service does not require
modifying the broker if it has no API-specific discovery needs" (Finding 3
acceptance criterion): this class implements the full ServiceAdapter
contract using only information already present in a server's approved
config (api_base_url, if the admin supplied one) — no new adapter Python
module is needed for a plain OAuth API, only a new oauth_provider_profile
row (or a raw external_oauth_* submission).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from app.credential_broker.adapters.service_adapter import (
    DiscoveredResource,
    ProviderConfigError,
    RuntimeContext,
)

logger = logging.getLogger(__name__)

_PROBE_TIMEOUT_SECONDS = 10.0


class GenericServiceAdapter:
    """Reference ServiceAdapter implementation — see module docstring."""

    slug = "generic"
    display_name = "Generic OAuth 2.0 API (no service-specific discovery)"

    def required_oauth_fields(self) -> list[str]:
        # Nothing beyond the standard generic OAuth fields (issuer/client_id/
        # client_secret/scopes) already collected by the wizard for any
        # external_oauth_* submission.
        return []

    def default_scopes(self) -> list[str]:
        return []

    def validate_provider_config(self, config: dict[str, Any]) -> None:
        # api_base_url is optional here (verify_access()/safe_probe_endpoint()
        # degrade to a no-op when absent) — structurally, there is nothing
        # this adapter itself requires beyond what generic OAuth already
        # validates (issuer/client_id present — see server_onboarding.py).
        api_base_url = config.get("api_base_url")
        if api_base_url is not None and not isinstance(api_base_url, str):
            raise ProviderConfigError("api_base_url, if present, must be a string")

    async def post_enrollment_discovery(
        self, access_token: str, requested_config: dict[str, Any]
    ) -> list[DiscoveredResource]:
        # No service-specific discovery — this IS the "no extra discovery
        # needed" case the contract exists to make cheap.
        return []

    def select_resource(
        self, discovered_resources: list[DiscoveredResource], user_choice: str | None
    ) -> DiscoveredResource | None:
        return None

    def build_runtime_context(
        self, approved_config: dict[str, Any], selected_resource: DiscoveredResource | None
    ) -> RuntimeContext:
        return RuntimeContext(
            adapter=self.slug,
            api_base_url=approved_config.get("api_base_url"),
        )

    async def verify_access(self, access_token: str, runtime_context: RuntimeContext) -> bool:
        probe_url = self.safe_probe_endpoint(runtime_context)
        if probe_url is None:
            # Nothing to probe — not a failure. A plain OAuth API with no
            # configured api_base_url has no safe read-only endpoint this
            # adapter knows about; verification of the token itself is the
            # OAuth token-lifecycle's job (broker), not this adapter's.
            return True
        try:
            async with httpx.AsyncClient(timeout=_PROBE_TIMEOUT_SECONDS) as client:
                resp = await client.get(probe_url, headers={"Authorization": f"Bearer {access_token}"})
                return resp.status_code < 400
        except Exception as exc:
            logger.warning("GenericServiceAdapter.verify_access probe failed: %s", exc)
            return False

    def safe_probe_endpoint(self, runtime_context: RuntimeContext) -> str | None:
        return runtime_context.api_base_url
