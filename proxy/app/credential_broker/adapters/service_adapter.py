"""
MCP Security Platform — ServiceAdapter contract (WP-A6, Finding 3)

OAuth authenticates to an authorization server. It does not define the
resource API base URL, tenant/site/workspace identifiers, how to discover
the target account, which endpoint is safe for verification, or how the MCP
server should receive service context. A ServiceAdapter fills that gap for a
specific external service (Jira Cloud, a GitHub Enterprise instance, ...)
layered ON TOP of the generic OAuth substrate (generic_oauth.py,
dynamic_external_oauth.py) — the OAuth token lifecycle stays centralized in
the broker; adapters never see or store refresh tokens or client secrets.

Two implementations exist as of WP-A6:
  - GenericServiceAdapter (generic_service_adapter.py): the reference
    implementation for "no extra discovery needed" services — the common
    case where the OAuth access token alone is sufficient to call the
    upstream API with no resource/tenant resolution step.
  - A future jira_cloud adapter (Finding 4, explicitly NOT built by WP-A6)
    would resolve `cloudId` via Atlassian's accessible-resources endpoint.

Runtime context produced by build_runtime_context() is persisted to
server_registry.service_context (V070) — non-secret JSON, never a
credential. It's expected to be handed to the deployed MCP server as
config/env at deploy time (WP-B3), the same way any other non-secret
per-server setting would be.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class DiscoveredResource:
    """One candidate "account"/"site"/"tenant" a service adapter discovered
    after OAuth succeeded (e.g. one of several Jira Cloud sites the user has
    access to). `raw` carries the adapter-specific discovery payload verbatim
    for select_resource()/build_runtime_context() to use."""

    id: str
    display_name: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeContext:
    """The non-secret shape persisted to server_registry.service_context.
    `adapter` MUST match the adapter's own `slug` — this is what lets a
    future reader (deploy/verify worker, admin UI) know which adapter's
    contract produced this context without re-inspecting code."""

    adapter: str
    api_base_url: str | None = None
    resource_id: str | None = None
    resource_name: str | None = None
    resource_url: str | None = None
    verified_at: str | None = None  # ISO 8601, set by verify_access() callers

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "api_base_url": self.api_base_url,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_url": self.resource_url,
            "verified_at": self.verified_at,
        }


class ProviderConfigError(ValueError):
    """Raised by validate_provider_config() for a structurally invalid config.
    Fail-closed: an adapter MUST raise rather than silently accept a config
    it cannot actually use."""


@runtime_checkable
class ServiceAdapter(Protocol):
    """
    The Finding 3 contract. Every method is synchronous-signature-compatible
    with either sync or async implementations (concrete adapters use async
    where I/O is involved — see GenericServiceAdapter for the reference
    shape). A conforming adapter:

      - NEVER stores refresh tokens or client secrets (those live exclusively
        in credential_store, managed by the broker).
      - NEVER makes its own OAuth token requests — it receives an already-
        valid access_token from the broker/dispatcher and only calls the
        RESOURCE api with it.
      - Returns RuntimeContext (never raw credentials) from
        build_runtime_context().
    """

    slug: str
    display_name: str

    def required_oauth_fields(self) -> list[str]:
        """Field names the onboarding wizard must collect for this service
        beyond the generic OAuth ones (issuer/client_id/client_secret/scopes)
        — e.g. a Jira adapter might require none (cloudId is discovered, not
        collected); a hypothetical fixed-tenant adapter might require
        'tenant_id'."""
        ...

    def default_scopes(self) -> list[str]:
        """Scopes this service typically needs, used to pre-fill (not
        enforce — oauth_policy.py / oauth_provider_profile still govern
        enforcement) the onboarding wizard."""
        ...

    def validate_provider_config(self, config: dict[str, Any]) -> None:
        """Raises ProviderConfigError if `config` (the submitter/admin-
        supplied provider config, e.g. issuer/client_id/api_base_url) is
        structurally invalid for this adapter. Must not raise for I/O
        reasons (network calls do not belong here) — only structural/shape
        validation."""
        ...

    async def post_enrollment_discovery(
        self, access_token: str, requested_config: dict[str, Any]
    ) -> list[DiscoveredResource]:
        """Called once, immediately after OAuth enrollment succeeds (a fresh
        access_token is available). Returns whatever candidate resources this
        service exposes (e.g. Jira Cloud sites) — an empty list means "no
        discovery needed / nothing to choose", which is the GenericServiceAdapter
        case."""
        ...

    def select_resource(
        self, discovered_resources: list[DiscoveredResource], user_choice: str | None
    ) -> DiscoveredResource | None:
        """Given post_enrollment_discovery()'s output and an optional
        user-supplied choice (resource id), picks the one to persist. Returns
        None when there is nothing to select (0 or non-applicable
        discoveries)."""
        ...

    def build_runtime_context(
        self, approved_config: dict[str, Any], selected_resource: DiscoveredResource | None
    ) -> RuntimeContext:
        """Builds the RuntimeContext to persist to server_registry.service_context.
        MUST NOT include any secret value."""
        ...

    async def verify_access(self, access_token: str, runtime_context: RuntimeContext) -> bool:
        """Calls safe_probe_endpoint() with the given token and returns True
        only if the call succeeds in a way that proves the token is valid
        AND scoped to the right resource. Never mutates upstream state."""
        ...

    def safe_probe_endpoint(self, runtime_context: RuntimeContext) -> str | None:
        """Returns a read-only, side-effect-free URL suitable for
        verify_access() to call, or None if this adapter has no such
        endpoint (verify_access() should then just return True — nothing to
        probe, not a failure)."""
        ...
