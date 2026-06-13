"""
Tests for TOCTOU DNS-rebind fix in healthcheck adapters.

These tests verify that:
1. Healthcheck adapters use PinnedIPTransport when pinned_ip is provided,
   preventing re-resolution of the hostname at connect time.
2. GiteaHealthcheck and M365Healthcheck accept pinned_ip/original_hostname
   constructor args (regression guard for the seam).
3. Partial args (only pinned_ip or only original_hostname) log a warning
   and fall back to a plain client.
"""
from __future__ import annotations

import unittest.mock

import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from app.credential_broker.adapters.healthcheck import (
    GiteaHealthcheck,
    M365Healthcheck,
    HealthcheckAdapter,
    get_healthcheck,
)
from app.services.pinned_transport import PinnedIPTransport


# ---------------------------------------------------------------------------
# Shared fixture: CapturingAsyncClient
# Subclasses httpx.AsyncClient and records the 'transport' kwarg passed to
# __init__, so tests can assert which transport was (or wasn't) injected.
# ---------------------------------------------------------------------------

_original_async_client = httpx.AsyncClient


class CapturingAsyncClient(_original_async_client):
    """httpx.AsyncClient subclass that records the transport kwarg on construction."""

    captured: list[object] = []

    def __init__(self, **kwargs: object) -> None:
        CapturingAsyncClient.captured.append(kwargs.get("transport"))
        super().__init__(**kwargs)


# ---------------------------------------------------------------------------
# Test 1 — TOCTOU rebind: PinnedIPTransport is used when pinned_ip is set
# ---------------------------------------------------------------------------

class TestTOCTOURebindPinning:
    """
    Verify that when a pinned_ip is provided, the healthcheck uses
    PinnedIPTransport rather than letting httpx re-resolve the hostname.
    """

    def setup_method(self) -> None:
        CapturingAsyncClient.captured = []

    @pytest.mark.asyncio
    async def test_gitea_healthcheck_uses_pinned_transport(self) -> None:
        """
        GiteaHealthcheck with pinned_ip must build its httpx client with
        PinnedIPTransport, not a plain client that re-resolves DNS.
        """
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(return_value=None)

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient", CapturingAsyncClient):
            with patch.object(CapturingAsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
                adapter = GiteaHealthcheck(
                    "http://gitea.example.com",
                    pinned_ip="1.2.3.4",
                    original_hostname="gitea.example.com",
                )
                await adapter.healthcheck()

        assert len(CapturingAsyncClient.captured) == 1, "httpx.AsyncClient must be constructed once"
        transport = CapturingAsyncClient.captured[0]
        assert isinstance(transport, PinnedIPTransport), (
            f"Expected PinnedIPTransport, got {type(transport).__name__!r}. "
            "Without pinning, a TTL-0 DNS flip can redirect the healthcheck to "
            "169.254.169.254 or vault:8200 (TOCTOU rebind)."
        )

    @pytest.mark.asyncio
    async def test_m365_healthcheck_uses_pinned_transport(self) -> None:
        """
        M365Healthcheck with pinned_ip must build its httpx client with
        PinnedIPTransport.
        """
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(return_value=None)

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient", CapturingAsyncClient):
            with patch.object(CapturingAsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
                adapter = M365Healthcheck(
                    "http://m365.example.com",
                    pinned_ip="1.2.3.4",
                    original_hostname="m365.example.com",
                )
                await adapter.healthcheck()

        assert len(CapturingAsyncClient.captured) == 1, "httpx.AsyncClient must be constructed once"
        transport = CapturingAsyncClient.captured[0]
        assert isinstance(transport, PinnedIPTransport), (
            f"Expected PinnedIPTransport, got {type(transport).__name__!r}."
        )

    @pytest.mark.asyncio
    async def test_gitea_no_pinned_ip_uses_plain_client(self) -> None:
        """
        Without pinned_ip, GiteaHealthcheck falls back to a plain httpx client
        (backward-compat: existing tests must not break).
        """
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(return_value=None)

        with patch("app.credential_broker.adapters.healthcheck.httpx.AsyncClient", CapturingAsyncClient):
            with patch.object(CapturingAsyncClient, "get", new_callable=AsyncMock, return_value=mock_response):
                adapter = GiteaHealthcheck("http://gitea.example.com")
                await adapter.healthcheck()

        assert len(CapturingAsyncClient.captured) == 1
        # No transport kwarg passed → None (plain client)
        assert CapturingAsyncClient.captured[0] is None, (
            "Without pinned_ip, no transport should be injected (backward compat)."
        )

    def test_partial_args_logs_warning_and_falls_back(self) -> None:
        """Only pinned_ip set (no original_hostname) → warning logged, plain client used."""
        adapter = GiteaHealthcheck("https://example.com", pinned_ip="1.2.3.4", original_hostname=None)
        with unittest.mock.patch("app.credential_broker.adapters.healthcheck.logger") as mock_logger:
            client = adapter._build_client(timeout=5.0)
        assert isinstance(client, httpx.AsyncClient)
        mock_logger.warning.assert_called_once()
        warning_msg = mock_logger.warning.call_args[0][0]
        assert "pinned_ip" in warning_msg or "original_hostname" in warning_msg


# ---------------------------------------------------------------------------
# Test 2 — Construction seam: adapters accept pinned_ip / original_hostname
# ---------------------------------------------------------------------------

class TestConstructionSeam:
    """
    Regression guard: GiteaHealthcheck and M365Healthcheck must accept
    pinned_ip and original_hostname constructor kwargs.

    If these tests break, the seam has been removed and the server_registry
    approve path can no longer inject IP pinning.
    """

    def test_gitea_healthcheck_accepts_pinned_ip_arg(self) -> None:
        adapter = GiteaHealthcheck(
            "http://gitea.example.com",
            pinned_ip="1.2.3.4",
            original_hostname="gitea.example.com",
        )
        assert adapter.pinned_ip == "1.2.3.4"
        assert adapter.original_hostname == "gitea.example.com"

    def test_m365_healthcheck_accepts_pinned_ip_arg(self) -> None:
        adapter = M365Healthcheck(
            "http://m365.example.com",
            pinned_ip="5.6.7.8",
            original_hostname="m365.example.com",
        )
        assert adapter.pinned_ip == "5.6.7.8"
        assert adapter.original_hostname == "m365.example.com"

    def test_gitea_healthcheck_no_pinned_ip_defaults(self) -> None:
        """Without args, pinned_ip and original_hostname default to None."""
        adapter = GiteaHealthcheck("http://gitea.example.com")
        assert adapter.pinned_ip is None
        assert adapter.original_hostname is None

    def test_m365_healthcheck_no_pinned_ip_defaults(self) -> None:
        adapter = M365Healthcheck("http://m365.example.com")
        assert adapter.pinned_ip is None
        assert adapter.original_hostname is None

    def test_get_healthcheck_factory_passes_pinned_ip_to_gitea(self) -> None:
        adapter = get_healthcheck(
            "gitea",
            "http://gitea.example.com",
            pinned_ip="1.2.3.4",
            original_hostname="gitea.example.com",
        )
        assert isinstance(adapter, GiteaHealthcheck)
        assert adapter.pinned_ip == "1.2.3.4"

    def test_get_healthcheck_factory_passes_pinned_ip_to_m365(self) -> None:
        adapter = get_healthcheck(
            "m365",
            "http://m365.example.com",
            pinned_ip="5.6.7.8",
            original_hostname="m365.example.com",
        )
        assert isinstance(adapter, M365Healthcheck)
        assert adapter.pinned_ip == "5.6.7.8"

    def test_get_healthcheck_factory_no_pinned_ip(self) -> None:
        """Factory without pinned_ip produces adapter with None values."""
        adapter = get_healthcheck("gitea", "http://gitea.example.com")
        assert adapter.pinned_ip is None
        assert adapter.original_hostname is None
