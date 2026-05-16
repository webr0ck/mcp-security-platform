from __future__ import annotations
import pytest

# Dummy values for all mandatory fields (no class-level defaults)
_REQUIRED = dict(
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


def test_vault_settings_defaults():
    """Verify the class-level defaults for vault settings without providing them."""
    from app.core.config import Settings
    s = Settings(**_REQUIRED)
    # CB-002: the secure default is https:// — the broker master secret must
    # never transit a plaintext channel. http:// is rejected outside dev.
    assert s.VAULT_ADDR == "https://vault:8200"
    assert s.VAULT_TOKEN == "change-me-in-production"
    assert s.BROKER_MASTER_SECRET_PATH == "secret/data/credential-broker"


def test_vault_settings_can_be_overridden():
    from app.core.config import Settings
    s = Settings(
        **_REQUIRED,
        VAULT_ADDR="http://custom-vault:8300",
        VAULT_TOKEN="my-real-token",
    )
    assert s.VAULT_ADDR == "http://custom-vault:8300"
    assert s.VAULT_TOKEN == "my-real-token"


def test_entra_settings():
    from app.core.config import Settings
    s = Settings(
        **_REQUIRED,
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
