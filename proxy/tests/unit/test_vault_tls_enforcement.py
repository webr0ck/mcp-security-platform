"""CB-002 regression: VAULT_ADDR must be https:// outside development."""
from __future__ import annotations

import pytest


def _settings(**overrides):
    from app.core.config import Settings
    return Settings(**overrides)


@pytest.mark.unit
def test_http_vault_allowed_in_development():
    s = _settings(ENVIRONMENT="development", VAULT_ADDR="http://vault:8200")
    assert s.VAULT_ADDR.startswith("http://")


# Use 'staging': it triggers the TLS validator but NOT the production-only
# placeholder-rejection validator, so this test isolates CB-002 cleanly.
@pytest.mark.unit
def test_http_vault_rejected_outside_development():
    with pytest.raises(ValueError, match="VAULT_ADDR must use https"):
        _settings(ENVIRONMENT="staging", VAULT_ADDR="http://vault:8200")


@pytest.mark.unit
def test_https_vault_accepted_outside_development():
    s = _settings(ENVIRONMENT="staging", VAULT_ADDR="https://vault:8200")
    assert s.VAULT_ADDR.startswith("https://")
