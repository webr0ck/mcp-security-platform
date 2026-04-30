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
