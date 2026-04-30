from __future__ import annotations
import pytest


def test_vault_settings_have_defaults():
    from app.core.config import Settings
    s = Settings(
        DB_PASSWORD="x", REDIS_PASSWORD="x",
        VAULT_ADDR="http://vault:8200",
        VAULT_TOKEN="dev-root-token",
        BROKER_MASTER_SECRET_PATH="secret/data/credential-broker",
    )
    assert s.VAULT_ADDR == "http://vault:8200"
    assert s.VAULT_TOKEN == "dev-root-token"


def test_entra_settings():
    from app.core.config import Settings
    s = Settings(
        DB_PASSWORD="x", REDIS_PASSWORD="x",
        VAULT_ADDR="http://vault:8200", VAULT_TOKEN="t",
        BROKER_MASTER_SECRET_PATH="secret/data/credential-broker",
        ENTRA_CLIENT_ID="client-id",
        ENTRA_CLIENT_SECRET="secret",
        ENTRA_TENANT_ID="tenant-id",
        ENTRA_REDIRECT_URI="https://gw.internal/auth/callback/m365",
        ENTRA_SCOPES="Mail.Read Calendars.Read",
    )
    assert s.ENTRA_CLIENT_ID == "client-id"
    assert s.entra_scopes_list == ["Mail.Read", "Calendars.Read"]
    assert "tenant-id" in s.entra_token_url
    assert "tenant-id" in s.entra_auth_url
