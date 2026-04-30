"""
MCP Security Platform — Application Settings

All configuration is sourced from environment variables (via .env file in development).
No secrets are hardcoded here. See .env.example for all required variables.

Pydantic Settings v2 is used for typed config with automatic env var loading.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # =========================================================================
    # Deployment
    # =========================================================================
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    PLATFORM_VERSION: str = "1.0.0"

    # =========================================================================
    # PostgreSQL
    # =========================================================================
    DB_HOST: str = "db"
    DB_PORT: int = 5432
    DB_NAME: str = "mcp_security"
    DB_USER: str = "mcp_app"
    DB_PASSWORD: str
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    # =========================================================================
    # Redis
    # =========================================================================
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str
    REDIS_DB: int = 0
    REDIS_RATE_LIMIT_DB: int = 1

    @property
    def redis_url(self) -> str:
        return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # =========================================================================
    # Proxy Application
    # =========================================================================
    PROXY_HOST: str = "0.0.0.0"
    PROXY_PORT: int = 8000
    PROXY_WORKERS: int = 4
    PROXY_SECRET_KEY: str
    API_KEY_HMAC_KEY: str

    # =========================================================================
    # Signing Keys
    # =========================================================================
    SBOM_SIGNING_KEY: str
    AUDIT_LOG_HMAC_KEY: str
    WEBHOOK_SIGNING_KEY: str
    POLICY_SIGNING_KEY: str = ""
    POLICY_SIGNING_KEY_ID: str = "mcp-policy-signing-key-v1"

    # =========================================================================
    # OPA Sidecar
    # =========================================================================
    OPA_HOST: str = "opa"
    OPA_PORT: int = 8181
    OPA_TIMEOUT_SECONDS: int = 2

    @property
    def opa_url(self) -> str:
        return f"http://{self.OPA_HOST}:{self.OPA_PORT}"

    # =========================================================================
    # Ollama (Local LLM)
    # =========================================================================
    OLLAMA_HOST: str = "ollama"
    OLLAMA_PORT: int = 11434
    OLLAMA_MODEL: str = "llama3.2"
    OLLAMA_TIMEOUT_SECONDS: int = 30
    OLLAMA_HIGH_RISK_THRESHOLD: int = Field(default=70, ge=0, le=100)
    OLLAMA_CRITICAL_RISK_THRESHOLD: int = Field(default=90, ge=0, le=100)

    @property
    def ollama_base_url(self) -> str:
        return f"http://{self.OLLAMA_HOST}:{self.OLLAMA_PORT}"

    # =========================================================================
    # step-ca
    # =========================================================================
    STEP_CA_HOST: str = "step-ca"
    STEP_CA_PORT: int = 9000
    STEP_CA_FINGERPRINT: str = ""
    STEP_CA_MAX_TLS_DURATION: str = "24h"

    # =========================================================================
    # OIDC (Optional)
    # =========================================================================
    OIDC_ENABLED: bool = False
    OIDC_ISSUER_URL: str = ""
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_AUDIENCE: str = ""
    OIDC_ROLE_CLAIM_PATH: str = "roles"
    OIDC_REDIRECT_URI: str = ""

    # =========================================================================
    # MinIO / S3
    # =========================================================================
    MINIO_HOST: str = "minio"
    MINIO_PORT: int = 9000
    MINIO_ROOT_USER: str
    MINIO_ROOT_PASSWORD: str
    MINIO_AUDIT_BUCKET: str = "mcp-audit-archive"
    MINIO_RETENTION_DAYS: int = 90

    @property
    def minio_endpoint(self) -> str:
        return f"http://{self.MINIO_HOST}:{self.MINIO_PORT}"

    # =========================================================================
    # Grafana / Loki
    # =========================================================================
    LOKI_HOST: str = "loki"
    LOKI_PORT: int = 3100

    @property
    def loki_url(self) -> str:
        return f"http://{self.LOKI_HOST}:{self.LOKI_PORT}"

    # =========================================================================
    # Jira Integration (Optional)
    # =========================================================================
    JIRA_ENABLED: bool = False
    JIRA_BASE_URL: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_USER_EMAIL: str = ""
    JIRA_PROJECT_KEY: str = "MSEC"
    JIRA_WEBHOOK_SECRET: str = ""
    JIRA_ISSUE_TYPE: str = "Security Task"

    # =========================================================================
    # Artifactory Integration (Optional)
    # =========================================================================
    ARTIFACTORY_ENABLED: bool = False
    ARTIFACTORY_BASE_URL: str = ""
    ARTIFACTORY_REPO: str = "mcp-sbom-local"
    ARTIFACTORY_API_KEY: str = ""

    # =========================================================================
    # Rate Limiting (requests per minute per role)
    # =========================================================================
    RATE_LIMIT_ADMIN: int = 300
    RATE_LIMIT_AGENT: int = 120
    RATE_LIMIT_AUDITOR: int = 60
    RATE_LIMIT_READONLY: int = 30

    # =========================================================================
    # Outbound Webhooks (Optional)
    # =========================================================================
    WEBHOOK_ENABLED: bool = False
    WEBHOOK_TARGET_URL: str = ""
    WEBHOOK_EVENTS: str = "tool.quarantined,anomaly.detected,compliance.report.failed"

    # =========================================================================
    # Compliance Checker
    # =========================================================================
    COMPLIANCE_CRON_SCHEDULE: str = "0 2 * * *"
    COMPLIANCE_SAMPLE_SIZE: int = 1000
    COMPLIANCE_ALERT_WEBHOOK: str = "http://alertmanager:9093/api/v1/alerts"

    # =========================================================================
    # Credential Broker — KMS (HashiCorp Vault)
    # =========================================================================
    VAULT_ADDR: str = "http://vault:8200"
    VAULT_TOKEN: str = "dev-root-token"
    BROKER_MASTER_SECRET_PATH: str = "secret/data/credential-broker"

    # =========================================================================
    # Credential Broker — M365 / Entra
    # =========================================================================
    ENTRA_CLIENT_ID: str = ""
    ENTRA_CLIENT_SECRET: str = ""
    ENTRA_TENANT_ID: str = ""
    ENTRA_REDIRECT_URI: str = "https://localhost/auth/callback/m365"
    ENTRA_SCOPES: str = "Mail.Read Calendars.Read"

    @property
    def entra_scopes_list(self) -> list[str]:
        return self.ENTRA_SCOPES.split()

    @property
    def entra_token_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}/oauth2/v2.0/token"

    @property
    def entra_auth_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}/oauth2/v2.0/authorize"

    # =========================================================================
    # Credential Broker — Bitbucket
    # =========================================================================
    BITBUCKET_CLIENT_ID: str = ""
    BITBUCKET_CLIENT_SECRET: str = ""
    BITBUCKET_REDIRECT_URI: str = "https://localhost/auth/callback/bitbucket"
    BITBUCKET_AUTH_URL: str = "https://bitbucket.internal/site/oauth2/authorize"
    BITBUCKET_TOKEN_URL: str = "https://bitbucket.internal/site/oauth2/access_token"
    BITBUCKET_SCOPES: str = "repository:read pullrequest:read"

    @property
    def bitbucket_scopes_list(self) -> list[str]:
        return self.BITBUCKET_SCOPES.split()

    # =========================================================================
    # Credential Broker — Grafana
    # =========================================================================
    GRAFANA_BASE_URL: str = "http://grafana:3000"
    GRAFANA_SERVICE_ACCOUNT_ID: int = 1
    GRAFANA_ADMIN_TOKEN: str = ""

    # =========================================================================
    # Credential Broker — Netbox
    # =========================================================================
    NETBOX_BASE_URL: str = "http://netbox.internal"
    NETBOX_ADMIN_TOKEN: str = ""

    # =========================================================================
    # Credential Broker — Session
    # =========================================================================
    BROKER_SESSION_TTL_SECONDS: int = 28800
    BROKER_IDLE_TIMEOUT_SECONDS: int = 3600
    MCP_REGISTRY_PATH: str = "/app/mcps.yaml"

    # =========================================================================
    # OAuth state signing
    # =========================================================================
    OAUTH_STATE_SECRET: str = "change-me-in-production"

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def opa_policy_path(self) -> str:
        return "mcp/authz/allow"

    @property
    def opa_authz_url(self) -> str:
        return f"{self.opa_url}/v1/data/{self.opa_policy_path}"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance. Use this everywhere instead of Settings()."""
    return Settings()  # type: ignore[call-arg]


# Module-level alias for convenience (import settings from app.core.config)
settings: Settings = get_settings()
