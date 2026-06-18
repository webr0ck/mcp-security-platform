# proxy/tests/unit/test_config_token_exchange.py
"""
Unit tests — S-2 (PRD-0002): token-exchange audience validator.

When KC_TOKEN_EXCHANGE_ENABLED=True, OIDC_AUDIENCE must be a single,
non-blank value REGARDLESS of ENVIRONMENT. The existing production/staging
validators skip development, leaving an audience-confusion fail-open in the
lab profile where case 4 (token exchange) runs. This validator closes it.

Run from proxy/:
    python3 -m pytest tests/unit/test_config_token_exchange.py -v
"""
from __future__ import annotations

import pytest


def _make_settings(**overrides):
    """Build Settings with all mandatory fields supplied, bypassing .env."""
    from app.core.config import Settings

    mandatory = dict(
        DB_PASSWORD="x",
        REDIS_PASSWORD="x",
        PROXY_SECRET_KEY="x",
        API_KEY_HMAC_KEY="x",
        SBOM_SIGNING_KEY="x",
        AUDIT_LOG_HMAC_KEY="x",
        WEBHOOK_SIGNING_KEY="x",
        MINIO_ROOT_USER="x",
        MINIO_ROOT_PASSWORD="x",
    )
    params = {**mandatory, **overrides, "_env_file": None}
    return Settings(**params)


# Minimum kwargs for the token-exchange scenario (development lab profile).
_EXCHANGE_BASE = dict(
    ENVIRONMENT="development",
    OIDC_ENABLED=True,
    KC_TOKEN_EXCHANGE_ENABLED=True,
)


def test_blank_audience_refused_when_exchange_enabled():
    with pytest.raises(ValueError, match="OIDC_AUDIENCE"):
        _make_settings(**_EXCHANGE_BASE, OIDC_AUDIENCE="", KC_TOKEN_EXCHANGE_AUDIENCE="lab-tickets")


def test_multi_audience_refused():
    with pytest.raises(ValueError, match="single"):
        _make_settings(**_EXCHANGE_BASE, OIDC_AUDIENCE="mcp-proxy lab-tickets", KC_TOKEN_EXCHANGE_AUDIENCE="lab-tickets")


def test_comma_audience_refused():
    with pytest.raises(ValueError, match="single"):
        _make_settings(**_EXCHANGE_BASE, OIDC_AUDIENCE="mcp-proxy,lab-tickets", KC_TOKEN_EXCHANGE_AUDIENCE="lab-tickets")


def test_single_audience_ok_in_development():
    s = _make_settings(**_EXCHANGE_BASE, OIDC_AUDIENCE="mcp-proxy", KC_TOKEN_EXCHANGE_AUDIENCE="lab-tickets")
    assert s.OIDC_AUDIENCE == "mcp-proxy"


def test_exchange_disabled_allows_blank_audience_in_dev():
    s = _make_settings(
        ENVIRONMENT="development",
        OIDC_ENABLED=True,
        KC_TOKEN_EXCHANGE_ENABLED=False,
        OIDC_AUDIENCE="",
    )
    assert s.KC_TOKEN_EXCHANGE_ENABLED is False
