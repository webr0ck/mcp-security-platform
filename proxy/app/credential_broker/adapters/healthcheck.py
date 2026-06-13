"""
MCP Security Platform — Adapter Healthcheck Interface

Provides healthcheck capability for upstream MCP servers during approval flow.
Each adapter implements a healthcheck() method that verifies the upstream is reachable.

Healthcheck failures raise HealthcheckFailed, which blocks server approval (422 response).
Timeout protection: 5-10 second HTTP timeouts per adapter.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

import httpx

from app.services.pinned_transport import PinnedIPTransport

logger = logging.getLogger(__name__)


class HealthcheckFailed(Exception):
    """
    Raised when adapter healthcheck fails (connection error, HTTP error, timeout).

    Carries the adapter name and error detail. Never surfaces raw error bodies
    to avoid leaking credentials or sensitive information.
    """

    def __init__(self, adapter_name: str, detail: str) -> None:
        self.adapter_name = adapter_name
        self.detail = detail
        super().__init__(f"Healthcheck failed for {adapter_name}: {detail}")


class HealthcheckAdapter(ABC):
    """Base class for healthcheck adapters."""

    def __init__(
        self,
        upstream_url: str,
        pinned_ip: str | None = None,
        original_hostname: str | None = None,
    ) -> None:
        self.upstream_url = upstream_url
        self.pinned_ip = pinned_ip
        self.original_hostname = original_hostname

    def _build_client(self, timeout: float) -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient.

        If pinned_ip and original_hostname are both set, the client uses
        PinnedIPTransport to prevent DNS re-resolution (TOCTOU rebind fix).
        Otherwise falls back to a plain client (backward compat).
        """
        if self.pinned_ip and self.original_hostname:
            transport = PinnedIPTransport(
                pinned_ip=self.pinned_ip,
                original_hostname=self.original_hostname,
            )
            return httpx.AsyncClient(transport=transport, timeout=timeout)
        return httpx.AsyncClient(timeout=timeout)

    @abstractmethod
    async def healthcheck(self) -> None:
        """
        Verify the upstream server is reachable.

        Raises HealthcheckFailed if the server is unreachable or unhealthy.
        """
        pass


class GiteaHealthcheck(HealthcheckAdapter):
    """
    Healthcheck for Gitea servers.

    Calls GET /api/v1/version and expects HTTP 200.
    Timeout: 5 seconds.
    """

    async def healthcheck(self) -> None:
        try:
            async with self._build_client(timeout=5.0) as client:
                url = f"{self.upstream_url.rstrip('/')}/api/v1/version"
                resp = await client.get(url)
                resp.raise_for_status()
        except httpx.TimeoutException as exc:
            raise HealthcheckFailed("gitea", f"Timeout after 5 seconds") from exc
        except httpx.HTTPStatusError as exc:
            raise HealthcheckFailed(
                "gitea",
                f"HTTP {exc.response.status_code}",
            ) from exc
        except Exception as exc:
            raise HealthcheckFailed("gitea", f"Connection failed: {type(exc).__name__}") from exc

        logger.debug("Gitea healthcheck passed for %s", self.upstream_url)


class M365Healthcheck(HealthcheckAdapter):
    """
    Healthcheck for M365/Graph servers.

    Calls GET /health and expects HTTP 200.
    Timeout: 10 seconds (M365 can be slower).
    """

    async def healthcheck(self) -> None:
        try:
            async with self._build_client(timeout=10.0) as client:
                url = f"{self.upstream_url.rstrip('/')}/health"
                resp = await client.get(url)
                resp.raise_for_status()
        except httpx.TimeoutException as exc:
            raise HealthcheckFailed("m365", f"Timeout after 10 seconds") from exc
        except httpx.HTTPStatusError as exc:
            raise HealthcheckFailed(
                "m365",
                f"HTTP {exc.response.status_code}",
            ) from exc
        except Exception as exc:
            raise HealthcheckFailed("m365", f"Connection failed: {type(exc).__name__}") from exc

        logger.debug("M365 healthcheck passed for %s", self.upstream_url)


def get_healthcheck(
    adapter_name: str,
    upstream_url: str,
    *,
    pinned_ip: str | None = None,
    original_hostname: str | None = None,
) -> HealthcheckAdapter:
    """
    Factory: return a healthcheck adapter instance.

    Args:
        adapter_name: Name of the adapter ('gitea', 'm365', etc.)
        upstream_url: Upstream server URL to healthcheck
        pinned_ip: Pre-validated IP to pin TCP connections to (TOCTOU fix).
            When provided together with original_hostname, the adapter uses
            PinnedIPTransport so DNS is never re-resolved at connect time.
        original_hostname: Original hostname for TLS SNI + Host header.
            Must be supplied alongside pinned_ip.

    Returns:
        HealthcheckAdapter instance

    Raises:
        ValueError: If adapter_name is unknown
    """
    if adapter_name == "gitea":
        return GiteaHealthcheck(upstream_url, pinned_ip=pinned_ip, original_hostname=original_hostname)
    elif adapter_name == "m365":
        return M365Healthcheck(upstream_url, pinned_ip=pinned_ip, original_hostname=original_hostname)
    else:
        raise ValueError(f"Unknown adapter: {adapter_name}")
