"""
Unit tests for proxy/app/services/server_onboarding.py — server onboarding validation.

Tests validate mode↔IdP combinations, SSRF checks, and upstream URL validation.
"""
from __future__ import annotations

import pytest

from app.services.server_onboarding import (
    InvalidOnboardingConfig,
    validate_mode_and_idp,
    validate_upstream_idp_config,
    validate_upstream_url_ssrf,
)


class TestValidateModeAndIdP:
    """Test mode↔IdP type combination validation."""

    def test_oauth_user_token_requires_gateway_idp(self):
        """oauth_user_token injection mode requires upstream_idp_type='gateway_idp'."""
        # Valid: gateway_idp
        validate_mode_and_idp("oauth_user_token", "gateway_idp", None)

    def test_oauth_user_token_rejects_other_idps(self):
        """oauth_user_token rejects entra, custom, etc."""
        with pytest.raises(InvalidOnboardingConfig, match="oauth_user_token.*gateway_idp"):
            validate_mode_and_idp("oauth_user_token", "entra", None)

        with pytest.raises(InvalidOnboardingConfig, match="oauth_user_token.*gateway_idp"):
            validate_mode_and_idp("oauth_user_token", "custom", None)

        with pytest.raises(InvalidOnboardingConfig, match="oauth_user_token.*gateway_idp"):
            validate_mode_and_idp("oauth_user_token", None, None)

    def test_entra_user_token_requires_entra_idp_with_config(self):
        """entra_user_token requires upstream_idp_type='entra' + config."""
        config = {
            "issuer": "https://login.microsoftonline.com/tenant/",
            "client_id": "app-id",
        }
        # Valid
        validate_mode_and_idp("entra_user_token", "entra", config)

    def test_entra_user_token_rejects_no_idp_type(self):
        """entra_user_token without idp_type raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/tenant/",
            "client_id": "app-id",
        }
        with pytest.raises(InvalidOnboardingConfig, match="entra_user_token.*entra"):
            validate_mode_and_idp("entra_user_token", None, config)

    def test_entra_user_token_rejects_wrong_idp_type(self):
        """entra_user_token with gateway_idp raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/tenant/",
            "client_id": "app-id",
        }
        with pytest.raises(InvalidOnboardingConfig, match="entra_user_token.*entra"):
            validate_mode_and_idp("entra_user_token", "gateway_idp", config)

    def test_entra_user_token_rejects_missing_config(self):
        """entra_user_token with entra IdP but no config raises."""
        with pytest.raises(InvalidOnboardingConfig, match="entra_user_token.*config"):
            validate_mode_and_idp("entra_user_token", "entra", None)

    def test_entra_client_credentials_requires_entra_idp_with_config(self):
        """entra_client_credentials requires upstream_idp_type='entra' + config."""
        config = {
            "issuer": "https://login.microsoftonline.com/tenant/",
            "client_id": "app-id",
        }
        # Valid
        validate_mode_and_idp("entra_client_credentials", "entra", config)

    def test_entra_client_credentials_rejects_no_idp_type(self):
        """entra_client_credentials without idp_type raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/tenant/",
            "client_id": "app-id",
        }
        with pytest.raises(InvalidOnboardingConfig, match="entra_client_credentials.*entra"):
            validate_mode_and_idp("entra_client_credentials", None, config)

    def test_entra_client_credentials_rejects_missing_config(self):
        """entra_client_credentials with entra IdP but no config raises."""
        with pytest.raises(InvalidOnboardingConfig, match="entra_client_credentials.*config"):
            validate_mode_and_idp("entra_client_credentials", "entra", None)

    def test_user_mode_accepts_no_idp(self):
        """user injection mode accepts None for upstream_idp_type."""
        validate_mode_and_idp("user", None, None)

    def test_user_mode_accepts_any_idp(self):
        """user injection mode with an IdP specified is also ok."""
        validate_mode_and_idp("user", "gateway_idp", None)
        validate_mode_and_idp("user", "entra", None)

    def test_service_account_mode_accepts_no_idp(self):
        """service_account injection mode accepts None for upstream_idp_type."""
        validate_mode_and_idp("service_account", None, None)

    def test_service_mode_accepts_no_idp(self):
        """service injection mode accepts None for upstream_idp_type."""
        validate_mode_and_idp("service", None, None)

    def test_none_mode_accepts_no_idp(self):
        """none injection mode accepts None for upstream_idp_type."""
        validate_mode_and_idp("none", None, None)

    def test_invalid_injection_mode_raises(self):
        """Unknown injection_mode raises InvalidOnboardingConfig."""
        with pytest.raises(InvalidOnboardingConfig, match="unknown injection_mode"):
            validate_mode_and_idp("invalid_mode", None, None)


class TestValidateUpstreamIdPConfig:
    """Test upstream IdP config validation."""

    def test_valid_entra_config(self):
        """Valid Entra config with issuer and client_id passes."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
            "client_id": "my-app-id",
        }
        validate_upstream_idp_config("entra", config)

    def test_valid_entra_config_with_scopes(self):
        """Valid Entra config with issuer, client_id, and scopes passes."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
            "client_id": "my-app-id",
            "scopes": ["User.Read", "Mail.Read"],
        }
        validate_upstream_idp_config("entra", config)

    def test_missing_issuer_raises(self):
        """Config without issuer raises."""
        config = {"client_id": "my-app-id"}
        with pytest.raises(InvalidOnboardingConfig, match="missing.*issuer"):
            validate_upstream_idp_config("entra", config)

    def test_missing_client_id_raises(self):
        """Config without client_id raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
        }
        with pytest.raises(InvalidOnboardingConfig, match="missing.*client_id"):
            validate_upstream_idp_config("entra", config)

    def test_empty_client_id_raises(self):
        """Config with empty client_id raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
            "client_id": "",
        }
        with pytest.raises(InvalidOnboardingConfig, match="client_id.*non-empty"):
            validate_upstream_idp_config("entra", config)

    def test_invalid_issuer_url_raises(self):
        """Config with invalid issuer URL format raises."""
        config = {
            "issuer": "not-a-url",
            "client_id": "my-app-id",
        }
        with pytest.raises(InvalidOnboardingConfig, match="issuer.*valid URI"):
            validate_upstream_idp_config("entra", config)

    def test_invalid_scopes_type_raises(self):
        """Config with non-list scopes raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
            "client_id": "my-app-id",
            "scopes": "User.Read",  # Should be list
        }
        with pytest.raises(InvalidOnboardingConfig, match="scopes.*list"):
            validate_upstream_idp_config("entra", config)

    def test_invalid_scope_element_raises(self):
        """Config with non-string scope element raises."""
        config = {
            "issuer": "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/",
            "client_id": "my-app-id",
            "scopes": ["User.Read", 123],  # 123 is not a string
        }
        with pytest.raises(InvalidOnboardingConfig, match="scopes.*strings"):
            validate_upstream_idp_config("entra", config)

    def test_config_none_or_empty_accepted(self):
        """None or empty config is acceptable (no validation)."""
        validate_upstream_idp_config("entra", None)
        validate_upstream_idp_config("entra", {})


class TestValidateUpstreamUrlSSRF:
    """Test upstream URL SSRF validation (async)."""

    @pytest.mark.asyncio
    async def test_valid_https_public_url_passes(self):
        """Valid public HTTPS URL passes."""
        await validate_upstream_url_ssrf("https://api.github.com/v1")

    @pytest.mark.asyncio
    async def test_private_ipv4_blocked(self):
        """Private IPv4 addresses are blocked."""
        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://10.0.0.1/")

        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://192.168.1.1/")

    @pytest.mark.asyncio
    async def test_cloud_metadata_blocked(self):
        """Cloud metadata endpoints are blocked."""
        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://169.254.169.254/latest/meta-data/")

    @pytest.mark.asyncio
    async def test_loopback_blocked(self):
        """Loopback addresses are blocked."""
        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://127.0.0.1/")

    @pytest.mark.asyncio
    async def test_ipv6_loopback_blocked(self):
        """IPv6 loopback is blocked."""
        with pytest.raises(InvalidOnboardingConfig, match="blocked.*private"):
            await validate_upstream_url_ssrf("https://[::1]/")

    @pytest.mark.asyncio
    async def test_dns_failure_raises(self):
        """DNS resolution failure raises (fail-closed Phase 3 hardening)."""
        # A hostname that will never resolve
        with pytest.raises(InvalidOnboardingConfig, match="DNS.*failed|cannot.*resolve"):
            await validate_upstream_url_ssrf("https://this-domain-definitely-does-not-exist-xyz.invalid/")

    @pytest.mark.asyncio
    async def test_invalid_url_raises(self):
        """Invalid URL format raises."""
        with pytest.raises(InvalidOnboardingConfig):
            await validate_upstream_url_ssrf("not-a-url")

    @pytest.mark.asyncio
    async def test_http_scheme_blocked(self):
        """HTTP (not HTTPS) is blocked for non-localhost."""
        with pytest.raises(InvalidOnboardingConfig, match="HTTPS"):
            await validate_upstream_url_ssrf("http://api.github.com/")

    @pytest.mark.asyncio
    async def test_url_with_credentials_blocked(self):
        """URLs with embedded credentials are blocked."""
        with pytest.raises(InvalidOnboardingConfig, match="credentials"):
            await validate_upstream_url_ssrf("https://user:pass@api.github.com/")

    @pytest.mark.asyncio
    async def test_no_hostname_raises(self):
        """URL without hostname raises."""
        with pytest.raises(InvalidOnboardingConfig):
            await validate_upstream_url_ssrf("https:///path/only")

    @pytest.mark.asyncio
    async def test_malformed_url_raises(self):
        """Malformed URLs raise."""
        with pytest.raises(InvalidOnboardingConfig):
            await validate_upstream_url_ssrf("ht!tp://[bad]")

    @pytest.mark.asyncio
    async def test_dns_resolution_success_with_valid_ip(self):
        """Valid URL that resolves to public IP passes (e.g., github.com)."""
        # github.com should always resolve to a public IP
        await validate_upstream_url_ssrf("https://github.com/")
