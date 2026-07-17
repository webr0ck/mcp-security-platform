"""
Unit tests for the SSRF legacy-gate/allowlist unification
(docs/design/ssrf-legacy-gate-unification.md).

Covers:
  - ssrf.py::validate_server_url's new `allowed_cidr` parameter (17-case
    design-doc test matrix, cases 1-12 + 15)
  - ssrf.py::_is_blocked_ip / _is_floor_blocked exemption + floor semantics
  - server_onboarding.py::_parse_cidr_allowlist floor-address rejection at
    parse time (appsec case a, first half)
  - server_onboarding.py::revalidate_upstream_ip_at_invoke floor check on the
    allowlisted branch (the CRITICAL pre-existing gap; appsec case a, second half)
  - IPv6-wrapped forms of an allowlisted IPv4 handled symmetrically (appsec case b)
  - mixed-family CIDR/IP membership doesn't false-negative (appsec case c)

Cases 13/14/16/17 from the design doc's matrix are end-to-end / different-
function concerns (discover_tools, invoke, approve_server, the invocation.py
fetch reorder) and are out of scope for this unit file — 13/14 need a live
lab server per the design doc's own qa note, 16 is unaffected-by-construction
(approve_server never calls validate_server_url), and 17 is exercised by
reading invocation.py directly (single fetch feeds both Step 3b and 3c).
"""
from __future__ import annotations

import ipaddress

import pytest

from app.services.ssrf import (
    SSRFError,
    _is_blocked_ip,
    _is_floor_blocked,
    validate_server_url,
)
from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    UpstreamRevalidationError,
    _parse_cidr_allowlist,
    revalidate_upstream_ip_at_invoke,
)


# ---------------------------------------------------------------------------
# Design-doc test matrix (validate_server_url + allowed_cidr)
# ---------------------------------------------------------------------------

class TestValidateServerUrlAllowedCidr:
    def test_case1_no_allowlist_public_passes(self):
        """#1: No allowlist entry, public IP → pass (unchanged)."""
        validate_server_url("https://93.184.216.34/")

    def test_case2_no_allowlist_private_blocked(self):
        """#2: No allowlist entry, private IP → SSRFError (unchanged baseline)."""
        with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
            validate_server_url("https://10.0.0.5/")

    def test_case3_allowlisted_private_ip_inside_entry_passes(self):
        """#3: Allowlisted private IP inside the registered CIDR → pass."""
        validate_server_url("https://100.64.3.9/", allowed_cidr="100.64.0.0/10")

    def test_case4_private_ip_outside_registered_entry_blocked(self):
        """#4: Private IP outside the registered entry → SSRFError."""
        with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
            validate_server_url("https://10.0.0.5/", allowed_cidr="100.64.0.0/10")

    def test_case5_metadata_ip_no_allowlist_blocked(self):
        """#5: Metadata IP, no allowlist → SSRFError."""
        with pytest.raises(SSRFError):
            validate_server_url("https://169.254.169.254/latest/meta-data/")

    def test_case6_metadata_ip_sloppy_allowlist_still_blocked(self):
        """#6: Metadata IP with a sloppy allowlist covering it (169.254.0.0/16)
        → SSRFError. The floor wins regardless of how broad the allowlist is."""
        with pytest.raises(SSRFError):
            validate_server_url(
                "https://169.254.169.254/", allowed_cidr="169.254.0.0/16"
            )

    def test_case7_metadata_smuggled_via_ipv6_mapped_still_blocked(self):
        """#7: Metadata IP smuggled via IPv4-mapped IPv6 form, allowlist set
        → SSRFError. Floor wins on the embedded v4."""
        with pytest.raises(SSRFError):
            validate_server_url(
                "https://[::ffff:169.254.169.254]/", allowed_cidr="::/0"
            )

    def test_case8_aws_ipv6_metadata_still_blocked(self):
        """#8: AWS IPv6 metadata, allowlist set → SSRFError. Floor wins."""
        with pytest.raises(SSRFError):
            validate_server_url(
                "https://[fd00:ec2::254]/", allowed_cidr="fd00::/8"
            )

    def test_case9_credentials_in_url_unaffected_by_exemption(self):
        """#9: Credentials in URL, allowlisted host → SSRFError (unaffected)."""
        with pytest.raises(SSRFError, match="credentials"):
            validate_server_url(
                "https://user:pass@100.64.3.9/", allowed_cidr="100.64.0.0/10"
            )

    def test_case10_http_scheme_non_dev_allowlisted_still_blocked(self):
        """#10: HTTP scheme, non-dev, allowlisted host → SSRFError (unaffected)."""
        with pytest.raises(SSRFError, match="HTTP scheme is not allowed"):
            validate_server_url(
                "http://100.64.3.9/", allowed_cidr="100.64.0.0/10"
            )

    def test_case11_malformed_allowed_cidr_fails_closed(self):
        """#11: Malformed stored allowed_cidr (data corruption) → SSRFError,
        fail closed."""
        with pytest.raises(SSRFError, match="not a valid CIDR"):
            validate_server_url("https://10.0.0.5/", allowed_cidr="not-a-cidr")

    def test_case12_mixed_dns_resolution_denied(self):
        """#12: Mixed DNS resolution — one IP inside the allowlist entry, one
        outside → SSRFError (existing per-IP DNS-loop logic still rejects)."""
        import socket
        from unittest.mock import patch

        resolved = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("100.64.3.9", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=resolved):
            with pytest.raises(SSRFError, match="blocked IP"):
                validate_server_url(
                    "https://mixed.internal/", allowed_cidr="100.64.0.0/10"
                )

    def test_case15_no_param_passed_still_strict(self):
        """#15 analogue (oauth_provider_profile-style call): no allowed_cidr
        passed at all → strict behaviour, private IP still denied."""
        with pytest.raises(SSRFError):
            validate_server_url("https://10.0.0.5/")


# ---------------------------------------------------------------------------
# Appsec case (a): CIDR containing a metadata address rejected at parse time
# AND floor-blocked at invoke time even if parsing were bypassed.
# ---------------------------------------------------------------------------

class TestMetadataFloorNeverExemptable:
    """
    Two-tier floor-overlap policy at parse time (lead decision, 2026-07-17,
    refining the original all-reject rule):
      - REJECT only when the entry is equal to or a subnet of a floor network
        (can only ever resolve inside the floor).
      - WARN + accept when a broader entry merely contains a floor address —
        the unconditional runtime floor check (ssrf.validate_server_url /
        revalidate_upstream_ip_at_invoke) still guarantees traffic to that
        address is blocked regardless of registration.
    """

    def test_parse_time_rejects_exact_metadata_v4_entry(self):
        """An entry that IS the metadata address itself (equal to the floor
        network) can only ever resolve to metadata — rejected."""
        with pytest.raises(InvalidOnboardingConfig, match="subnet of the cloud-metadata"):
            _parse_cidr_allowlist(["169.254.169.254/32"])

    def test_parse_time_rejects_exact_ecs_metadata_entry(self):
        with pytest.raises(InvalidOnboardingConfig, match="subnet of the cloud-metadata"):
            _parse_cidr_allowlist(["169.254.170.2/32"])

    def test_parse_time_rejects_exact_alibaba_metadata_entry(self):
        with pytest.raises(InvalidOnboardingConfig, match="subnet of the cloud-metadata"):
            _parse_cidr_allowlist(["100.100.100.200/32"])

    def test_parse_time_rejects_exact_aws_v6_metadata_entry(self):
        with pytest.raises(InvalidOnboardingConfig, match="subnet of the cloud-metadata"):
            _parse_cidr_allowlist(["fd00:ec2::254/128"])

    def test_parse_time_warns_but_allows_broad_cidr_covering_metadata_v4(self, caplog):
        """A broader entry that merely CONTAINS the metadata /32 (e.g. a
        sloppy /16) is registered anyway, with a loud WARNING — the runtime
        floor check is what actually blocks traffic to it."""
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["169.254.0.0/16"])
        assert len(nets) == 1
        assert any(
            "contains a cloud-metadata floor address" in r.message for r in caplog.records
        )

    def test_parse_time_warns_but_allows_narrow_cidr_covering_metadata_v4(self, caplog):
        """Even a /24 that happens to cover the metadata /32 is a CONTAINS
        case (not a SUBSET case) — warn + accept, not reject."""
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["169.254.169.0/24"])
        assert len(nets) == 1
        assert any(
            "contains a cloud-metadata floor address" in r.message for r in caplog.records
        )

    def test_parse_time_warns_but_allows_cidr_covering_ecs_metadata(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["169.254.170.0/24"])
        assert len(nets) == 1

    def test_parse_time_warns_but_allows_cidr_covering_alibaba_metadata(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["100.100.100.0/24"])
        assert len(nets) == 1

    def test_parse_time_warns_but_allows_cidr_covering_aws_v6_metadata(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["fd00:ec2::/32"])
        assert len(nets) == 1

    def test_parse_time_allows_ordinary_private_cidr(self):
        """A normal Tailscale/CGNAT-range entry with no metadata overlap parses fine
        and logs no floor-overlap warning."""
        nets = _parse_cidr_allowlist(["100.64.0.0/24"])
        assert len(nets) == 1

    def test_parse_time_warns_but_allows_full_cgnat_range_despite_alibaba_overlap(self, caplog):
        """Lead decision (2026-07-17): the full 100.64.0.0/10 CGNAT range —
        which the live lab legitimately runs (Tailscale) — technically
        contains the Alibaba metadata address 100.100.100.200. This is a
        CONTAINS case, not a SUBSET case, so it is registered with a loud
        WARNING rather than rejected. Hard-rejecting this range would
        re-break the exact onboarding path this change exists to fix; the
        unconditional runtime floor check is what actually blocks traffic to
        100.100.100.200 regardless of this entry."""
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["100.64.0.0/10"])
        assert len(nets) == 1
        assert any(
            "contains a cloud-metadata floor address" in r.message for r in caplog.records
        )
        assert any("100.100.100.200" in str(r.floor_address) for r in caplog.records if hasattr(r, "floor_address"))

    def test_parse_time_warns_but_allows_broad_v4_entry(self, caplog):
        """IPv4 entries broader than /24 are logged as a WARNING, not rejected
        — the live lab legitimately runs 10.89.0.0/16 and 100.64.0.0/10."""
        import logging
        with caplog.at_level(logging.WARNING, logger="app.services.server_onboarding"):
            nets = _parse_cidr_allowlist(["10.89.0.0/16"])
        assert len(nets) == 1
        assert any("broader than /24" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_revalidate_allowlisted_branch_blocks_metadata_ip(self):
        """CRITICAL regression: an allowlisted CIDR containing the metadata
        address must not let revalidate_upstream_ip_at_invoke pin credentialed
        requests to it. Simulate the pre-existing gap by constructing a
        registered CIDR wide enough to contain 169.254.169.254 (bypassing the
        parse-time rejection, as if it were a stale/legacy row) and confirm
        the invoke-time floor check still denies."""
        from unittest.mock import AsyncMock, patch

        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("169.254.169.254", 0))]
            )
            with pytest.raises(UpstreamRevalidationError, match="cloud-metadata"):
                await revalidate_upstream_ip_at_invoke(
                    upstream_url="https://legacy-wide.internal/mcp",
                    # Simulates a stale/legacy row that predates the parse-time
                    # rejection in _parse_cidr_allowlist — invoke-time must
                    # still fail closed.
                    registered_allowlist_entry="169.254.0.0/16",
                )

    @pytest.mark.asyncio
    async def test_revalidate_allowlisted_branch_still_passes_for_non_floor_ip(self):
        """Sanity: the floor check does not false-positive on an ordinary
        allowlisted private IP that is not a metadata address."""
        from unittest.mock import AsyncMock, patch

        with patch(
            "app.services.server_onboarding.asyncio.get_event_loop"
        ) as mock_loop:
            mock_loop.return_value.getaddrinfo = AsyncMock(
                return_value=[(None, None, None, None, ("100.64.3.9", 0))]
            )
            ips = await revalidate_upstream_ip_at_invoke(
                upstream_url="https://tailscale.internal/mcp",
                registered_allowlist_entry="100.64.0.0/10",
            )
            assert ips == ["100.64.3.9"]


# ---------------------------------------------------------------------------
# Appsec case (b): IPv6-wrapped forms of an allowlisted IPv4 handled
# symmetrically — not accidentally exempted, not inconsistently blocked.
# ---------------------------------------------------------------------------

class TestSymmetricIpv6WrappedExemption:
    def test_plain_v4_in_allowlist_exempted(self):
        allowed = ipaddress.ip_network("100.64.0.0/10")
        assert _is_blocked_ip("100.64.3.9", allowed) is False

    def test_ipv4_mapped_form_of_allowlisted_v4_exempted_symmetrically(self):
        """::ffff:100.64.3.9 wraps an allowlisted IPv4 — must be exempted the
        same way the plain v4 form is (symmetric treatment)."""
        allowed = ipaddress.ip_network("100.64.0.0/10")
        assert _is_blocked_ip("::ffff:100.64.3.9", allowed) is False

    def test_6to4_form_of_allowlisted_v4_exempted_symmetrically(self):
        """2002:6440:0309:: is the 6to4 wrapper for 100.64.3.9."""
        allowed = ipaddress.ip_network("100.64.0.0/10")
        assert _is_blocked_ip("2002:6440:0309::", allowed) is False

    def test_ipv4_mapped_form_of_non_allowlisted_v4_still_blocked(self):
        """::ffff:10.0.0.5 wraps a private IP OUTSIDE the allowlist — must
        stay blocked, not fall through as exempt."""
        allowed = ipaddress.ip_network("100.64.0.0/10")
        assert _is_blocked_ip("::ffff:10.0.0.5", allowed) is True

    def test_ipv4_mapped_metadata_never_exempted_even_with_wide_allowed_cidr(self):
        """::ffff:169.254.169.254 must stay blocked even if allowed_cidr is
        maximally permissive (::/0) — floor wins over any exemption."""
        allowed = ipaddress.ip_network("::/0")
        assert _is_blocked_ip("::ffff:169.254.169.254", allowed) is True
        assert _is_floor_blocked("::ffff:169.254.169.254") is True

    def test_validate_server_url_exempts_ipv6_mapped_allowlisted_form(self):
        """End-to-end: validate_server_url must accept an IPv4-mapped IPv6
        host literal when the embedded v4 is inside allowed_cidr."""
        validate_server_url(
            "https://[::ffff:100.64.3.9]/", allowed_cidr="100.64.0.0/10"
        )

    def test_validate_server_url_still_blocks_ipv6_mapped_non_allowlisted_form(self):
        with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
            validate_server_url(
                "https://[::ffff:10.0.0.5]/", allowed_cidr="100.64.0.0/10"
            )


# ---------------------------------------------------------------------------
# Appsec case (c): mixed-family CIDR/IP membership doesn't false-negative via
# Python ipaddress cross-version `in` semantics.
# ---------------------------------------------------------------------------

class TestMixedFamilyMembershipFailsClosed:
    def test_v4_address_against_v6_allowed_cidr_not_exempted(self):
        """A plain IPv4 private address checked against a v6-only allowed_cidr
        must NOT match (Python's ipaddress __contains__ returns False across
        families rather than raising) — must remain blocked, not silently
        pass through as "not applicable"."""
        allowed = ipaddress.ip_network("fd00:ec2::/32")  # AWS ULA-ish v6 range
        assert _is_blocked_ip("10.0.0.5", allowed) is True

    def test_v6_address_against_v4_allowed_cidr_not_exempted(self):
        allowed = ipaddress.ip_network("10.0.0.0/8")
        assert _is_blocked_ip("fc00::1", allowed) is True

    def test_validate_server_url_v4_host_with_v6_allowed_cidr_fails_closed(self):
        with pytest.raises(SSRFError, match="blocked private/reserved IP range"):
            validate_server_url(
                "https://10.0.0.5/", allowed_cidr="fd12:3456::/32"
            )

    def test_embedded_v4_matches_v4_allowed_cidr_even_though_wrapper_is_v6(self):
        """Sanity check that mixed-family logic doesn't over-correct: an
        IPv6-mapped wrapper's *embedded v4* correctly matches a v4
        allowed_cidr (this is the symmetric-exemption path, not a
        cross-family false negative)."""
        allowed = ipaddress.ip_network("100.64.0.0/10")
        assert _is_blocked_ip("::ffff:100.64.3.9", allowed) is False


# ---------------------------------------------------------------------------
# _is_floor_blocked — direct unit coverage
# ---------------------------------------------------------------------------

class TestIsFloorBlocked:
    def test_aws_gcp_azure_oci_metadata_v4(self):
        assert _is_floor_blocked("169.254.169.254") is True

    def test_ecs_metadata_v4(self):
        assert _is_floor_blocked("169.254.170.2") is True

    def test_alibaba_metadata_v4(self):
        assert _is_floor_blocked("100.100.100.200") is True

    def test_aws_metadata_v6(self):
        assert _is_floor_blocked("fd00:ec2::254") is True

    def test_ordinary_link_local_not_floor_blocked(self):
        """169.254.1.1 is ordinary link-local, not the metadata address —
        the floor is narrower than the full 169.254.0.0/16 block."""
        assert _is_floor_blocked("169.254.1.1") is False

    def test_ordinary_cgnat_not_floor_blocked(self):
        assert _is_floor_blocked("100.64.1.1") is False

    def test_public_ip_not_floor_blocked(self):
        assert _is_floor_blocked("93.184.216.34") is False


class TestDevModeHttpRawIpAllowlist:
    """QA finding 2026-07-17: the dev-mode http raw-IP gate ran before the
    allowlist exemption, re-blocking the exact plain-HTTP Tailscale-IP case
    this change exists to fix. The gate must honor allowed_cidr (floor still
    wins), while raw public IPs over http stay blocked."""

    def test_http_raw_allowlisted_private_ip_passes(self):
        validate_server_url(
            "http://100.101.102.103:8080/mcp",
            allow_http_localhost=True,
            allowed_cidr="100.64.0.0/10",
        )

    def test_http_raw_private_ip_without_allowlist_blocked(self):
        with pytest.raises(SSRFError):
            validate_server_url(
                "http://100.101.102.103:8080/mcp", allow_http_localhost=True
            )

    def test_http_raw_floor_ip_with_covering_cidr_blocked(self):
        with pytest.raises(SSRFError):
            validate_server_url(
                "http://169.254.169.254/latest/meta-data",
                allow_http_localhost=True,
                allowed_cidr="169.254.0.0/16",
            )

    def test_http_raw_public_ip_with_allowed_cidr_still_blocked(self):
        # allowed_cidr must not widen the dev-mode gate to public raw IPs
        # outside the registered CIDR.
        with pytest.raises(SSRFError):
            validate_server_url(
                "http://93.184.216.34/mcp",
                allow_http_localhost=True,
                allowed_cidr="100.64.0.0/10",
            )
