from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.unit
def test_build_broker_returns_none_when_vault_token_empty():
    """Empty VAULT_TOKEN means no Vault configured — broker must not be built."""
    from app.credential_broker.factory import build_broker

    mock_settings = MagicMock()
    mock_settings.VAULT_TOKEN = ""

    result = build_broker(mock_settings, MagicMock())
    assert result is None


@pytest.mark.unit
def test_build_broker_returns_broker_for_valid_token():
    """A non-empty VAULT_TOKEN means Vault is configured — broker must be returned."""
    from app.credential_broker.factory import build_broker
    from app.credential_broker.broker import CredentialBroker

    mock_settings = MagicMock()
    mock_settings.VAULT_TOKEN = "hvs.real-vault-token"
    mock_settings.VAULT_ADDR = "https://vault:8200"
    mock_settings.VAULT_CA_BUNDLE = ""
    mock_settings.BROKER_SESSION_TTL_SECONDS = 28800
    mock_settings.GRAFANA_ADMIN_TOKEN = ""      # Grafana not configured — no adapter
    mock_settings.GRAFANA_BASE_URL = "http://grafana:3000"
    mock_settings.GRAFANA_SERVICE_ACCOUNT_ID = 1

    mock_redis = MagicMock()

    with patch("app.credential_broker.factory.AsyncSessionLocal") as mock_factory:
        result = build_broker(mock_settings, mock_redis)

    assert isinstance(result, CredentialBroker)
    # Adapter dict must be empty — GRAFANA_ADMIN_TOKEN was empty
    assert result._approach_b_adapters == {}


@pytest.mark.unit
def test_build_broker_registers_grafana_adapter_when_configured():
    """GRAFANA_ADMIN_TOKEN set → Grafana adapter must appear in approach_b_adapters."""
    from app.credential_broker.factory import build_broker
    from app.credential_broker.adapters.grafana import GrafanaAdapter

    mock_settings = MagicMock()
    mock_settings.VAULT_TOKEN = "hvs.real-vault-token"
    mock_settings.VAULT_ADDR = "https://vault:8200"
    mock_settings.VAULT_CA_BUNDLE = ""
    mock_settings.BROKER_SESSION_TTL_SECONDS = 28800
    mock_settings.GRAFANA_ADMIN_TOKEN = "glsa_admin-token"
    mock_settings.GRAFANA_BASE_URL = "http://grafana:3000"
    mock_settings.GRAFANA_SERVICE_ACCOUNT_ID = 1

    with patch("app.credential_broker.factory.AsyncSessionLocal"):
        result = build_broker(mock_settings, MagicMock())

    assert "grafana" in result._approach_b_adapters
    assert isinstance(result._approach_b_adapters["grafana"], GrafanaAdapter)
