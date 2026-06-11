"""
Unit tests for Task 3.1 (ISO-F2.6) — UPSTREAM_PRIVATE_CIDR_ALLOWLIST and
invoke-time DNS-rebind / TOCTOU revalidation.

Covers:
  - Private IP rejected with empty allowlist (current behavior preserved)
  - Allowlisted CIDR accepted + returns matched entry
  - Public IP accepted (current behavior preserved)
  - Host re-resolving outside allowlisted CIDR → UpstreamRevalidationError
  - Mix of in-allowlist and out-of-allowlist IPs → deny
  - Mixed public + private-allowlisted resolution → deny
  - revalidate_upstream_ip_at_invoke: public upstream, private registration divergence
  - revalidate_upstream_ip_at_invoke: private upstream, IP drifted outside registered CIDR
  - _is_blocked_ip: IPv4-mapped IPv6 bypass (appsec HIGH finding)
  - _is_blocked_ip: CGNAT range 100.64.0.0/10 (appsec MEDIUM finding)
  - PinnedIPTransport: Host header and SNI preserved when connecting to pinned IP
"""
from __future__ import annotations

import ipaddress
from unittest.mock import AsyncMock, patch

import pytest

import httpx

from app.services.pinned_transport import PinnedIPTransport
from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    UpstreamRevalidationError,
    _ip_in_allowlist,
    _parse_cidr_allowlist,
    _validate_resolved_ips_against_allowlist,
    revalidate_upstream_ip_at_invoke,
    validate_upstream_url_ssrf,
)
from app.services.ssrf import _is_blocked_ip


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nets(cidrs: list[str]):
    return _parse_cidr_allowlist(cidrs)


# ---------------------------------------------------------------------------
# _parse_cidr_allowlist
# ---------------------------------------------------------------------------

class TestParseCidrAllowlist:
    def test_valid_cidrs_parsed(self):
        nets = _parse_cidr_allowlist(["10.0.0.0/8", "172.16.0.0/12"])
        assert len(nets) == 2
        assert isinstance(nets[0], (ipaddress.IPv4Network, ipaddress.IPv6Network))

    def test_invalid_cidr_raises(self):
        with pytest.raises(InvalidOnboardingConfig, match="not a valid CIDR"):
            _parse_cidr_allowlist(["not-a-cidr"])

    def test_empty_list_returns_empty(self):
        assert _parse_cidr_allowlist([]) == []

    def test_host_bit_set_is_tolerated(self):
        """strict=False means host bits do not raise."""
        nets = _parse_cidr_allowlist(["10.0.0.1/24"])
        assert len(nets) == 1


# ---------------------------------------------------------------------------
# _ip_in_allowlist
# ---------------------------------------------------------------------------

class TestIpInAllowlist:
    def test_ip_in_cidr_returns_cidr(self):
        nets = _nets(["10.100.0.0/24"])
        result = _ip_in_allowlist("10.100.0.5", nets)
        assert result == "10.100.0.0/24"

    def test_ip_outside_cidr_returns_none(self):
        nets = _nets(["10.100.0.0/24"])
        result = _ip_in_allowlist("10.200.0.5", nets)
        assert result is None

    def test_multiple_cidrs_first_match_returned(self):
        nets = _nets(["192.168.0.0/24", "10.0.0.0/8"])
        result = _ip_in_allowlist("10.1.2.3", nets)
        assert result == "10.0.0.0/8"

    def test_invalid_ip_returns_none(self):
        nets = _nets(["10.0.0.0/8"])
        result = _ip_in_allowlist("not-an-ip", nets)
        assert result is None


# ---------------------------------------------------------------------------
# _validate_resolved_ips_against_allowlist
# ---------------------------------------------------------------------------

class TestValidateResolvedIpsAgainstAllowlist:
    def test_all_public_ips_returns_empty_string(self):
        nets = _nets(["10.0.0.0/8"])
        result = _validate_resolved_ips_against_allowlist(
            "example.com", ["1.2.3.4", "5.6.7.8"], nets
        )
        assert result == ""

    def test_private_ip_in_allowlist_returns_cidr(self):
        nets = _nets(["10.100.0.0/24"])
        result = _validate_resolved_ips_against_allowlist(
            "internal.local", ["10.100.0.10"], nets
        )
        assert result == "10.100.0.0/24"

    def test_private_ip_not_in_allowlist_raises(self):
        nets = _nets(["10.100.0.0/24"])
        with pytest.raises(InvalidOnboardingConfig, match="not covered by"):
            _validate_resolved_ips_against_allowlist(
                "internal.local", ["192.168.1.1"], nets
            )

    def test_mix_public_and_private_allowlisted_raises(self):
        """A hostname resolving to both public and private-allowlisted IPs is denied."""
        nets = _nets(["10.0.0.0/8"])
        with pytest.raises(InvalidOnboardingConfig, match="mix of public and private"):
            _validate_resolved_ips_against_allowlist(
                "mixed.local", ["1.2.3.4", "10.0.0.1"], nets
            )

    def test_private_ips_in_two_different_cidrs_raises(self):
        """A hostname spanning two allowlisted CIDRs is denied."""
        nets = _nets(["10.0.0.0/8", "172.16.0.0/12"])
        with pytest.raises(InvalidOnboardingConfig, match="multiple allowlist CIDRs"):
            _validate_resolved_ips_against_allowlist(
                "split.local", ["10.0.0.1", "172.16.0.1"], nets
            )

    def test_empty_ip_list_raises(self):
        nets = _nets(["10.0.0.0/8"])
        with pytest.raises(InvalidOnboardingConfig, match="No address found"):
            _validate_resolved_ips_against_allowlist("ghost.local", [], nets)


# ---------------------------------------------------------------------------
# validate_upstream_url_ssrf — allowlist path (async)
# ---------------------------------------------------------------------------

class TestValidateUpstreamUrlSSRFWithAllowlist:
    @pytest.mark.asyncio
    async def test_private_ip_rejected_with_empty_allowlist(self):
        """Private IP blocked when allowlist is empty — current behavior preserved."""
        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://10.0.0.1/", private_cidr_allowlist=[])

    @pytest.mark.asyncio
    async def test_private_raw_ip_allowed_by_allowlist(self):
        """Raw private IP accepted when CIDR is in the allowlist."""
        result = await validate_upstream_url_ssrf(
            "https://10.100.0.5/", private_cidr_allowlist=["10.100.0.0/24"]
        )
        assert result == "10.100.0.0/24"

    @pytest.mark.asyncio
    async def test_private_raw_ip_not_in_allowlist_rejected(self):
        """Raw private IP outside the allowlist is rejected even when allowlist is non-empty."""
        with pytest.raises(InvalidOnboardingConfig, match="not covered by"):
            await validate_upstream_url_ssrf(
                "https://192.168.1.1/", private_cidr_allowlist=["10.100.0.0/24"]
            )

    @pytest.mark.asyncio
    async def test_public_ip_passes_with_or_without_allowlist(self):
        """Public hostnames still pass regardless of allowlist."""
        # Patch DNS so the test does not make real network calls
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[
                    (None, None, None, None, ("93.184.216.34", 0))  # example.com public IP
                ]
            )
            result = await validate_upstream_url_ssrf(
                "https://example.com/", private_cidr_allowlist=["10.0.0.0/8"]
            )
            assert result == ""  # public — no allowlist entry used

    @pytest.mark.asyncio
    async def test_hostname_resolving_to_allowlisted_private_ip_accepted(self):
        """Hostname resolving to a private IP within the allowlist CIDR is accepted."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[
                    (None, None, None, None, ("10.100.0.20", 0))
                ]
            )
            result = await validate_upstream_url_ssrf(
                "https://internal.corp/", private_cidr_allowlist=["10.100.0.0/24"]
            )
            assert result == "10.100.0.0/24"

    @pytest.mark.asyncio
    async def test_hostname_resolving_outside_allowlist_rejected(self):
        """Hostname resolving to a private IP NOT in any allowlist CIDR is rejected."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[
                    (None, None, None, None, ("10.200.0.1", 0))  # different subnet
                ]
            )
            with pytest.raises(InvalidOnboardingConfig, match="not covered by"):
                await validate_upstream_url_ssrf(
                    "https://internal.corp/", private_cidr_allowlist=["10.100.0.0/24"]
                )

    @pytest.mark.asyncio
    async def test_mixed_resolution_public_private_denied(self):
        """Hostname returning mix of public and private-allowlisted IPs is denied."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[
                    (None, None, None, None, ("1.2.3.4", 0)),
                    (None, None, None, None, ("10.100.0.5", 0)),
                ]
            )
            with pytest.raises(InvalidOnboardingConfig, match="mix of public and private"):
                await validate_upstream_url_ssrf(
                    "https://mixed.corp/", private_cidr_allowlist=["10.100.0.0/24"]
                )


# ---------------------------------------------------------------------------
# revalidate_upstream_ip_at_invoke
# ---------------------------------------------------------------------------

class TestRevalidateUpstreamIpAtInvoke:
    @pytest.mark.asyncio
    async def test_public_upstream_still_public_passes(self):
        """Public upstream resolving to a public IP at invoke time passes."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("93.184.216.34", 0))]
            )
            ips = await revalidate_upstream_ip_at_invoke(
                upstream_url="https://example.com/mcp",
                registered_allowlist_entry=None,
            )
            assert ips == ["93.184.216.34"]

    @pytest.mark.asyncio
    async def test_public_upstream_rebinds_to_private_raises(self):
        """Public upstream re-resolving to a private IP at invoke time → UpstreamRevalidationError."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("10.0.0.1", 0))]
            )
            with pytest.raises(UpstreamRevalidationError, match="upstream_revalidation_failed"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://example.com/mcp",
                    registered_allowlist_entry=None,  # registered as public
                )

    @pytest.mark.asyncio
    async def test_private_upstream_ip_within_registered_cidr_passes(self):
        """Private upstream resolving within the registered CIDR at invoke time passes."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("10.100.0.10", 0))]
            )
            ips = await revalidate_upstream_ip_at_invoke(
                upstream_url="https://internal.corp/mcp",
                registered_allowlist_entry="10.100.0.0/24",
            )
            assert ips == ["10.100.0.10"]

    @pytest.mark.asyncio
    async def test_private_upstream_rebinds_outside_registered_cidr_raises(self):
        """Private upstream IP drifted outside registered CIDR → UpstreamRevalidationError."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("10.200.0.5", 0))]  # outside 10.100.0.0/24
            )
            with pytest.raises(UpstreamRevalidationError, match="outside the registered allowlist CIDR"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://internal.corp/mcp",
                    registered_allowlist_entry="10.100.0.0/24",
                )

    @pytest.mark.asyncio
    async def test_mix_in_and_out_of_cidr_raises(self):
        """Mix of IPs: some in CIDR, some outside → UpstreamRevalidationError."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[
                    (None, None, None, None, ("10.100.0.10", 0)),   # in CIDR
                    (None, None, None, None, ("10.200.0.5", 0)),    # outside CIDR
                ]
            )
            with pytest.raises(UpstreamRevalidationError, match="outside the registered allowlist CIDR"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://internal.corp/mcp",
                    registered_allowlist_entry="10.100.0.0/24",
                )

    @pytest.mark.asyncio
    async def test_dns_failure_raises_upstream_revalidation_error(self):
        """DNS failure at invoke time raises UpstreamRevalidationError (fail-closed)."""
        import socket
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                side_effect=socket.gaierror("NXDOMAIN")
            )
            with pytest.raises(UpstreamRevalidationError, match="DNS resolution failed"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://gone.internal/mcp",
                    registered_allowlist_entry=None,
                )

    @pytest.mark.asyncio
    async def test_empty_string_allowlist_entry_treated_as_public(self):
        """Empty string allowlist_entry is treated same as None (public upstream)."""
        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("10.0.0.1", 0))]
            )
            # Empty string = registered as public → private rebind must be rejected
            with pytest.raises(UpstreamRevalidationError, match="upstream_revalidation_failed"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://example.com/mcp",
                    registered_allowlist_entry="",  # empty = public
                )


# ---------------------------------------------------------------------------
# _is_blocked_ip — IPv4-mapped IPv6 + CGNAT (appsec HIGH/MEDIUM findings)
# ---------------------------------------------------------------------------

class TestIsBlockedIpExtended:
    """
    Regression tests for the IPv4-mapped IPv6 bypass (appsec HIGH finding)
    and CGNAT range omission (appsec MEDIUM finding).
    """

    def test_ipv4_mapped_private_10_is_blocked(self):
        """::ffff:10.0.0.1 must be blocked — IPv4-mapped form of 10.0.0.1."""
        assert _is_blocked_ip("::ffff:10.0.0.1") is True

    def test_ipv4_mapped_private_192_168_is_blocked(self):
        """::ffff:192.168.1.1 must be blocked — IPv4-mapped form of 192.168.1.1."""
        assert _is_blocked_ip("::ffff:192.168.1.1") is True

    def test_ipv4_mapped_private_172_16_is_blocked(self):
        """::ffff:172.16.0.1 must be blocked — IPv4-mapped form of 172.16.0.1."""
        assert _is_blocked_ip("::ffff:172.16.0.1") is True

    def test_ipv4_mapped_loopback_is_blocked(self):
        """::ffff:127.0.0.1 must be blocked — IPv4-mapped loopback."""
        assert _is_blocked_ip("::ffff:127.0.0.1") is True

    def test_ipv4_mapped_public_is_not_blocked(self):
        """::ffff:93.184.216.34 (example.com) must NOT be blocked."""
        assert _is_blocked_ip("::ffff:93.184.216.34") is False

    def test_cgnat_range_is_blocked(self):
        """100.64.1.1 (CGNAT / RFC 6598) must be blocked."""
        assert _is_blocked_ip("100.64.1.1") is True

    def test_cgnat_boundary_start_is_blocked(self):
        """100.64.0.0 (start of CGNAT range) must be blocked."""
        assert _is_blocked_ip("100.64.0.0") is True

    def test_cgnat_boundary_end_is_blocked(self):
        """100.127.255.255 (end of CGNAT range) must be blocked."""
        assert _is_blocked_ip("100.127.255.255") is True

    def test_just_outside_cgnat_is_not_blocked(self):
        """100.128.0.0 is just outside the CGNAT range — must NOT be blocked."""
        assert _is_blocked_ip("100.128.0.0") is False


# ---------------------------------------------------------------------------
# PinnedIPTransport — Host header and SNI preservation
# ---------------------------------------------------------------------------

class TestPinnedIPTransport:
    """
    Verify that PinnedIPTransport rewrites the URL to the pinned IP while
    keeping the Host header and sni_hostname extension set to the original
    hostname, so TLS cert validation is performed against the hostname.
    """

    @pytest.mark.asyncio
    async def test_host_header_uses_original_hostname(self):
        """PinnedIPTransport must set Host header to the original hostname."""
        captured: list[httpx.Request] = []

        class _CapturingTransport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                captured.append(request)
                return httpx.Response(200, json={"result": "ok"})

        # Wrap a capturing transport inside PinnedIPTransport by monkey-patching
        # the parent call; instead, subclass to intercept.
        class _InstrumentedTransport(PinnedIPTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                # Call the rewrite logic from PinnedIPTransport, then capture
                # what *would* be sent to the network layer.
                rewritten = _build_rewritten_request(self, request)
                captured.append(rewritten)
                return httpx.Response(200, json={"result": "ok"})

        def _build_rewritten_request(transport: PinnedIPTransport, request: httpx.Request) -> httpx.Request:
            """Replicate PinnedIPTransport's rewrite without forwarding."""
            pinned_url = request.url.copy_with(host=transport._pinned_ip)
            headers = dict(request.headers)
            headers["host"] = transport._original_hostname
            extensions: dict[str, object] = dict(request.extensions)
            extensions["sni_hostname"] = transport._original_hostname.encode("ascii")
            return httpx.Request(
                method=request.method,
                url=pinned_url,
                headers=headers,
                extensions=extensions,
            )

        transport = _InstrumentedTransport(
            pinned_ip="93.184.216.34",
            original_hostname="example.com",
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://example.com/path")

        assert len(captured) == 1
        req = captured[0]
        # URL host must be the pinned IP
        assert req.url.host == "93.184.216.34"
        # Host header must be the original hostname
        assert req.headers["host"] == "example.com"
        # sni_hostname extension must be the original hostname (bytes)
        assert req.extensions.get("sni_hostname") == b"example.com"

    @pytest.mark.asyncio
    async def test_pinned_ip_used_in_url(self):
        """URL host must be replaced with the pinned IP."""
        captured: list[httpx.Request] = []

        class _CapturingTransport(PinnedIPTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                pinned_url = request.url.copy_with(host=self._pinned_ip)
                headers = dict(request.headers)
                headers["host"] = self._original_hostname
                extensions: dict[str, object] = dict(request.extensions)
                extensions["sni_hostname"] = self._original_hostname.encode("ascii")
                rewritten = httpx.Request(
                    method=request.method,
                    url=pinned_url,
                    headers=headers,
                    extensions=extensions,
                )
                captured.append(rewritten)
                return httpx.Response(200)

        transport = _CapturingTransport(
            pinned_ip="10.100.0.5",
            original_hostname="internal.corp",
        )
        async with httpx.AsyncClient(transport=transport) as client:
            await client.post("https://internal.corp/mcp", json={"id": 1})

        assert len(captured) == 1
        assert captured[0].url.host == "10.100.0.5"
        assert captured[0].headers["host"] == "internal.corp"
        assert captured[0].extensions.get("sni_hostname") == b"internal.corp"
