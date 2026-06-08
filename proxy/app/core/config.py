"""
MCP Security Platform — Application Settings

All configuration is sourced from environment variables (via .env file in development).
No secrets are hardcoded here. See .env.example for all required variables.

Pydantic Settings v2 is used for typed config with automatic env var loading.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# Strings that we know are dev-only placeholders. If any of these reach a
# production runtime in a security-sensitive setting, we fail startup rather
# than silently authenticate / sign / decrypt with a well-known value.
_KNOWN_PLACEHOLDER_VALUES: frozenset[str] = frozenset({
    "change-me-in-production",
    "change-me",
    "lab-state-secret-change-me",
    "lab-root-token",
    "mcp-proxy-secret",
    "devpassword",
    "labpassword",
    "miniopassword",
    "",
})


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
    OPA_AUTH_TOKEN: str = ""  # Bearer token for OPA --authentication=token; empty = no auth (lab)

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
    # v3 typed principal namespace: CA identity label used in agent:{ca_id}:{cn}
    MTLS_CA_ID: str = "step-ca"

    # =========================================================================
    # OIDC / Keycloak (Optional)
    # =========================================================================
    OIDC_ENABLED: bool = False
    # v3 typed principal namespace: issuer label used in human:{issuer_id}:{sub}
    OIDC_ISSUER_ID: str = "keycloak"
    OIDC_ISSUER_URL: str = ""
    # Internal URL for proxy→IdP communication (JWKS, token endpoint).
    # Defaults to OIDC_ISSUER_URL if not set.
    OIDC_INTERNAL_URL: str = ""
    OIDC_INTERNAL_ISSUER_URL: str = ""  # Keycloak container-name URL (overrides OIDC_INTERNAL_URL)
    OIDC_CLIENT_ID: str = ""
    OIDC_CLIENT_SECRET: str = ""
    OIDC_AUDIENCE: str = ""
    OIDC_ROLE_CLAIM_PATH: str = "roles"
    OIDC_REDIRECT_URI: str = ""
    PROXY_BASE_URL: str = "http://localhost:8000"
    # When True, the OIDC callback URL is derived from the incoming request's
    # X-Forwarded-Host (gateway) or Host header instead of PROXY_BASE_URL.
    # PROXY_BASE_URL still wins when non-empty. Set True in the lab when the
    # proxy is reachable from multiple IPs (LAN + Tailscale). Keep False in
    # production where PROXY_BASE_URL must be explicitly configured.
    OIDC_TRUST_FORWARDED_HOST: bool = False
    # Comma-separated list of allowed Host/X-Forwarded-Host values when
    # OIDC_TRUST_FORWARDED_HOST=True (e.g. "localhost:8000,203.0.113.10:8000").
    # When non-empty, any derived host NOT in this list is rejected with 400
    # to prevent Host-header injection attacks. Empty = no allow-list check
    # (lab-only; not safe when the proxy is internet-exposed).
    PROXY_ALLOWED_HOSTS: str = ""

    # Session JWT (issued after Keycloak browser login; short-lived)
    SESSION_JWT_EXPIRE_SECONDS: int = 900      # 15 min default
    SESSION_COOKIE_SECURE: bool = False         # True in prod (HTTPS)
    SESSION_COOKIE_DOMAIN: str = "localhost"
    SESSION_COOKIE_NAME: str = "mcp_session"

    # RT-NEW-005 fix: shared secret Nginx must include in X-Gateway-Secret header.
    # X-Client-Cert-CN is only accepted when X-Gateway-Secret matches this value.
    # Empty string = mTLS CN auth disabled (safe default when unconfigured).
    # Set the same value in Nginx `proxy_set_header X-Gateway-Secret <value>` and here.
    GATEWAY_SHARED_SECRET: str = ""

    # Keycloak token exchange (service_account / oauth_user_token injection modes)
    KC_TOKEN_EXCHANGE_ENABLED: bool = False
    KC_TOKEN_EXCHANGE_AUDIENCE: str = ""        # default audience for KC token exchange

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
    VAULT_ADDR: str = "https://vault:8200"
    VAULT_TOKEN: str = "change-me-in-production"
    # Optional path to a CA bundle for verifying the Vault TLS certificate.
    # Empty string => use system trust store (httpx default verify=True).
    VAULT_CA_BUNDLE: str = ""
    BROKER_MASTER_SECRET_PATH: str = "secret/data/credential-broker"
    # CB-008: how long the broker may cache the Vault master secret in process
    # memory before it must be re-fetched (honours Vault rotation; bounds the
    # window a heap dump exposes the master).
    BROKER_MASTER_SECRET_TTL_SECONDS: int = 300

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
    # Credential Broker — Gitea (lab)
    # =========================================================================
    GITEA_ADMIN_TOKEN: str = ""

    # =========================================================================
    # Credential Broker — Dex (local lab OIDC IdP)
    # =========================================================================
    DEX_ISSUER_URL: str = "http://localhost:5556/dex"
    DEX_CLIENT_ID: str = "mcp-proxy"
    DEX_CLIENT_SECRET: str = "mcp-proxy-secret"
    DEX_REDIRECT_URI: str = "http://localhost:8000/auth/callback/dex"
    DEX_SCOPES: str = "openid profile email offline_access"

    @property
    def dex_scopes_list(self) -> list[str]:
        return self.DEX_SCOPES.split()

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

    @model_validator(mode="after")
    def _reject_placeholders_in_production(self) -> "Settings":
        """
        Fail startup if any security-sensitive secret still has a dev
        placeholder value in a production deployment. Catching this at
        config-load time is cheap and refuses to boot a server that would
        otherwise authenticate to Vault, sign SBOMs, or validate OAuth
        state with a well-known string.

        Also enforces the signed-only-runtime-policy non-negotiable
        (INV-012): in production the OPA bundle signing key must be set
        and OPA must be configured (separately) with the matching
        verification key.
        """
        if not self.is_production:
            return self

        sensitive_fields = (
            "PROXY_SECRET_KEY",
            "API_KEY_HMAC_KEY",
            "SBOM_SIGNING_KEY",
            "AUDIT_LOG_HMAC_KEY",
            "WEBHOOK_SIGNING_KEY",
            "POLICY_SIGNING_KEY",
            "VAULT_TOKEN",
            "OAUTH_STATE_SECRET",
            "DEX_CLIENT_SECRET",
            "DB_PASSWORD",
            "REDIS_PASSWORD",
            "MINIO_ROOT_PASSWORD",
        )
        bad = [
            name for name in sensitive_fields
            if str(getattr(self, name, "")).strip() in _KNOWN_PLACEHOLDER_VALUES
        ]
        if bad:
            raise ValueError(
                "Production startup blocked: the following secrets are unset "
                "or set to a known placeholder value: "
                + ", ".join(bad)
            )

        # Enforce minimum 32-byte length for all HMAC / signing keys.
        # A key shorter than 32 bytes provides near-zero security for HMAC-SHA256.
        _hmac_key_fields = (
            "PROXY_SECRET_KEY",
            "API_KEY_HMAC_KEY",
            "AUDIT_LOG_HMAC_KEY",
            "SBOM_SIGNING_KEY",
            "WEBHOOK_SIGNING_KEY",
        )
        short_keys = [
            name
            for name in _hmac_key_fields
            if len(str(getattr(self, name, "")).encode("utf-8")) < 32
        ]
        if short_keys:
            raise ValueError(
                "Production startup blocked: the following HMAC/signing keys are "
                "shorter than 32 bytes: "
                + ", ".join(short_keys)
                + ". Generate a suitable key with: "
                "python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )

        # Enforce OIDC_AUDIENCE is set when OIDC is enabled in production.
        # Without an audience constraint any valid JWT from the same Keycloak
        # realm authenticates, even tokens issued for unrelated clients.
        if self.OIDC_ENABLED and not self.OIDC_AUDIENCE.strip():
            raise ValueError(
                "Production startup blocked: OIDC_ENABLED=true but OIDC_AUDIENCE is "
                "empty. Set OIDC_AUDIENCE to the expected token audience (e.g. the "
                "proxy client_id) so that tokens issued for other clients are rejected."
            )

        # Enforce SESSION_COOKIE_SECURE in production to prevent session cookie
        # transmission over plain HTTP (downgrade / mixed-content attack surface).
        if not self.SESSION_COOKIE_SECURE:
            raise ValueError(
                "Production startup blocked: SESSION_COOKIE_SECURE must be True in "
                "production. Set SESSION_COOKIE_SECURE=true in your environment."
            )

        return self

    @model_validator(mode="after")
    def _enforce_vault_tls(self) -> "Settings":
        """
        CB-002: the Vault master secret protects every credential at rest.
        It must never transit a plaintext channel outside local development.
        Reject an http:// VAULT_ADDR in staging/production at config-load time.
        """
        if self.ENVIRONMENT != "development" and self.VAULT_ADDR.lower().startswith("http://"):
            raise ValueError(
                "VAULT_ADDR must use https:// outside development "
                f"(ENVIRONMENT={self.ENVIRONMENT}, VAULT_ADDR={self.VAULT_ADDR}). "
                "The credential-broker master secret cannot transit a plaintext channel."
            )
        return self

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def opa_policy_path(self) -> str:
        return "mcp/authz"

    @property
    def opa_authz_url(self) -> str:
        return f"{self.opa_url}/v1/data/{self.opa_policy_path}"


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance. Use this everywhere instead of Settings()."""
    return Settings()  # type: ignore[call-arg]


def __getattr__(name: str) -> object:
    if name == "settings":
        return get_settings()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
