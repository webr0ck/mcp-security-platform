"""
MCP Security Platform — Application Settings

All configuration is sourced from environment variables (via .env file in development).
No secrets are hardcoded here. See .env.example for all required variables.

Pydantic Settings v2 is used for typed config with automatic env var loading.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


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
    ENVIRONMENT: Literal["development", "staging", "production"] = "production"
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
    # DET-F1 / INV-005: when True, tool registration returns 503 if Ollama is
    # unreachable rather than falling back to static-only scoring.  Must be
    # True in production (enforced by the startup validator below).  Default
    # False in dev/staging to allow local development without a running Ollama.
    #
    # Operational consequence: tool registration is unavailable during Ollama
    # outages when this is True.  Tool *invocations* are unaffected — only
    # registration blocks.  See docs/ARCHITECTURE.md §5.4.
    REQUIRE_LLM_AUDIT: bool = False

    # PRD-0001 M2 — B-coarse taint floor (RFC-0001 §8.1). When True, a session
    # tainted by an untrusted (server trust_tier-derived) result is denied any
    # high-sensitivity / credential-injecting sink, enforced in invocation.py and
    # audited (INV-001). Default False so the control is dark until the V038
    # migration + server_registry.trust_tier JOIN on the tool-fetch query are in
    # place and the D1/D2 integration tests pass. Fail-closed when enabled.
    TAINT_FLOOR_ENABLED: bool = False

    # =========================================================================
    # Wazuh SIEM integration (AI attack detection)
    # =========================================================================
    # When WAZUH_SYSLOG_HOST is non-empty, each audit event is also emitted as
    # a UDP syslog datagram to the Wazuh manager (best-effort, never fail-closed).
    # Decoded by: deployments/poc/wazuh/decoders/mcp-audit-decoder.xml
    # Detected by: deployments/poc/wazuh/rules/0960-mcp-ai-attacks.xml
    WAZUH_SYSLOG_HOST: str = ""          # e.g. "lab-wazuh-manager" — empty = disabled
    WAZUH_SYSLOG_PORT: int = 514         # UDP syslog port on Wazuh manager

    # Trust envelope labeler (PRD-0001 M3 / RFC-0001)
    TRUST_ENVELOPE_ENABLED: bool = False
    # Layer B: MIME-style in-band advisory wrapper for non-conformant LLM consumers.
    # Advisory only — never the security boundary (RFC-0001 §3, P2).
    LAYER_B_ENABLED: bool = False
    LABELER_CERT_PATH: str = "/labeler/leaf.crt"
    LABELER_KEY_PATH: str = "/labeler/leaf.key"
    LABELER_SUB_CA_PATH: str = "/labeler/sub_ca.crt"

    # Trust envelope observer (W4.2) — passive verification log; never blocks
    TRUST_OBSERVER_ENABLED: bool = False

    # =========================================================================
    # Supply-chain re-scan freshness (Stage 3)
    # =========================================================================
    # SCAN_MAX_AGE_HOURS: how old last_rescanned_at may be before a server is
    # considered stale.  Default 168 h (7 days).
    # SCAN_FRESHNESS_ENFORCED: when True, a stale or never-rescanned server
    # blocks calls at invocation time.  Default True (fail closed) — the
    # rescan loop is proven and all lab servers carry a fresh
    # last_rescanned_at (PRD-2 / CR-11 remainder, 2026-07-06).
    # RESCAN_INTERVAL_HOURS: how often the background loop re-checks all
    # approved servers.  Default 24 h.
    SCAN_MAX_AGE_HOURS: int = 168
    SCAN_FRESHNESS_ENFORCED: bool = True
    RESCAN_INTERVAL_HOURS: int = 24

    # CR-08: POST /api/v1/servers (self-service direct registration) skips the
    # submission-scan/review funnel entirely — a server_owner-role caller goes
    # straight to an admin-approvable 'pending' row with no scan evidence.
    # Default false: direct registration requires platform_admin/admin only.
    # Flip true only for trusted labs/environments that intentionally rely on
    # server_owner self-registration without scanning.
    ALLOW_DIRECT_SERVER_REGISTRATION_FOR_NON_ADMIN: bool = False

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

    # CR-03: proxy-side allowlist of audiences the realm may mint a kc_token_exchange
    # token for (credential_broker/dispatcher.py). Deliberately env/config-driven,
    # NOT DB-driven — a malicious/buggy server_registry row must not be able to
    # widen what audiences can be minted. Comma-separated; defaults to the one lab
    # audience that previously lived hardcoded in dispatcher.py, so unset behavior
    # is unchanged.
    KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES: str = "lab-tickets"

    @property
    def kc_token_exchange_allowed_audiences_parsed(self) -> frozenset[str]:
        return frozenset(a.strip() for a in self.KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES.split(",") if a.strip())

    # WP-A2 (CR-13): scope-SET allowlist for service_account mode's `scope`
    # field (e.g. "openid"). Deliberately SEPARATE from
    # KC_TOKEN_EXCHANGE_ALLOWED_AUDIENCES above — service_account's scope is a
    # different validation shape (a set of OIDC scope strings) than
    # kc_token_exchange's audience (a single opaque string). Defaults to the
    # standard OIDC scopes every existing lab service_account tool already
    # uses (lab-gitea, lab-grafana-mcp, lab-wazuh), so unset behavior is
    # unchanged. Comma-separated.
    SERVICE_ACCOUNT_ALLOWED_SCOPES: str = "openid,profile,email"

    @property
    def service_account_allowed_scopes_parsed(self) -> frozenset[str]:
        return frozenset(s.strip() for s in self.SERVICE_ACCOUNT_ALLOWED_SCOPES.split(",") if s.strip())

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
    # SSRF / Private-Upstream Allowlist (Task 3.1, ISO-F2.6)
    # =========================================================================
    # Comma-separated list of CIDR ranges that private MCP server upstreams are
    # allowed to resolve into.  Default empty = current behaviour (all private
    # IPs are blocked — no change for deployments that don't use this feature).
    #
    # Example: "10.100.0.0/24,172.16.50.0/28"
    #
    # Security intent: only upstreams whose ALL resolved IPs fall within one of
    # these CIDRs (or are public) may be registered and called.  A hostname that
    # resolves to a MIX of allowlisted and non-allowlisted IPs is denied (the
    # most restrictive interpretation — prevents partial-rebind attacks).
    #
    # This value is also used at invocation time to re-validate the upstream
    # hostname before each call (DNS-rebind / TOCTOU mitigation).  See
    # proxy/app/services/server_onboarding.py :: revalidate_upstream_ip_at_invoke.
    UPSTREAM_PRIVATE_CIDR_ALLOWLIST: str = ""

    @property
    def upstream_private_cidr_allowlist_parsed(self) -> list[str]:
        """Return the allowlist as a list of CIDR strings, filtering blanks."""
        return [c.strip() for c in self.UPSTREAM_PRIVATE_CIDR_ALLOWLIST.split(",") if c.strip()]

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
    # KV-v2 API read path for the broker master secret. MUST match where the
    # secret is actually seeded: lab/seeder/seed.py writes "secret/data/mcp/
    # broker-master" and .env.lab.example sets the same. The previous default
    # ("secret/data/credential-broker") pointed at an unseeded path, so any
    # deployment that did not explicitly set BROKER_MASTER_SECRET_PATH got a
    # Vault 404 → KMSError → every user/entra credential injection failed.
    BROKER_MASTER_SECRET_PATH: str = "secret/data/mcp/broker-master"
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
    # Optional explicit endpoint overrides. Empty (default) = derive the real
    # login.microsoftonline.com URLs from ENTRA_TENANT_ID. The lab points these
    # at lab-mock-idp so entra_user_token works without a real Entra tenant
    # (PRD-0002 Case 1 mock flow).
    ENTRA_TOKEN_URL: str = ""
    ENTRA_AUTH_URL: str = ""

    @property
    def entra_scopes_list(self) -> list[str]:
        return self.ENTRA_SCOPES.split()

    @property
    def entra_token_url(self) -> str:
        return self.ENTRA_TOKEN_URL or f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}/oauth2/v2.0/token"

    @property
    def entra_auth_url(self) -> str:
        return self.ENTRA_AUTH_URL or f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}/oauth2/v2.0/authorize"

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
    # Credential Broker — Jira (WP-A3 / CR-04 fast-follow, D2 droppable)
    #
    # Distinct from JIRA_API_TOKEN et al. above — those are for the platform's
    # OWN outbound Jira notifications (filing security tickets from CR-13's
    # oauth_policy findings etc., basic-auth API-token style). These are for
    # the per-user OAuth 2.0 3LO adapter (credential_broker/adapters/jira.py)
    # that lets an onboarded Jira MCP tool act AS the signed-in user.
    # =========================================================================
    JIRA_OAUTH_CLIENT_ID: str = ""
    JIRA_OAUTH_CLIENT_SECRET: str = ""
    JIRA_OAUTH_REDIRECT_URI: str = "https://localhost/auth/callback/jira"
    JIRA_OAUTH_SCOPES: str = "read:jira-work write:jira-work offline_access"

    @property
    def jira_oauth_scopes_list(self) -> list[str]:
        return self.JIRA_OAUTH_SCOPES.split()

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
    # DEX_ISSUER_URL: browser-facing URL (used to build the /auth redirect sent
    #   to the user's browser). Set to the external/LAN address in multi-host labs.
    # DEX_INTERNAL_ISSUER_URL: server-to-server URL (used by the proxy container
    #   to POST to /token). Defaults to DEX_ISSUER_URL; override when the proxy
    #   can reach Dex via an internal hostname (e.g. http://lab-dex:5556/dex).
    DEX_ISSUER_URL: str = "http://localhost:5556/dex"
    DEX_INTERNAL_ISSUER_URL: str = ""
    DEX_CLIENT_ID: str = "mcp-proxy"
    DEX_CLIENT_SECRET: str = "mcp-proxy-secret"
    DEX_REDIRECT_URI: str = "http://localhost:8000/auth/callback/dex"
    DEX_SCOPES: str = "openid profile email offline_access"

    @property
    def dex_scopes_list(self) -> list[str]:
        return self.DEX_SCOPES.split()

    @property
    def dex_internal_issuer_url(self) -> str:
        """Internal issuer URL for server-to-server calls (token exchange)."""
        return self.DEX_INTERNAL_ISSUER_URL or self.DEX_ISSUER_URL

    # =========================================================================
    # Credential Broker — Session
    # =========================================================================
    BROKER_SESSION_TTL_SECONDS: int = 28800
    BROKER_IDLE_TIMEOUT_SECONDS: int = 3600

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

        # AUTH-F7 / F-001: the gateway shared secret is what makes the
        # X-Client-Cert-CN identity header trustworthy.  Nginx injects it via
        # `proxy_set_header X-Gateway-Secret <secret>` and `_is_trusted_proxy`
        # rejects any request that doesn't present it (fail-closed).  An empty
        # secret in production would silently disable that check — mTLS CN auth
        # would accept no identity and a direct-to-proxy caller's forged header
        # would be the only thing standing between it and a CN.  Refuse to start
        # rather than boot fail-open (project invariant: no fail-open path).
        if not self.GATEWAY_SHARED_SECRET.strip():
            raise ValueError(
                "Production startup blocked: GATEWAY_SHARED_SECRET is empty. It must "
                "match the value Nginx injects as the `X-Gateway-Secret` header so the "
                "proxy can verify that `X-Client-Cert-CN` identity headers originate "
                "from the gateway (F-001). Without it the mTLS CN auth path is silently "
                "disabled. Generate one with: "
                "python3 -c \"import secrets; print(secrets.token_hex(32))\""
            )

        # DET-F1 / INV-005: REQUIRE_LLM_AUDIT must be True in production.
        # An attacker who can DoS Ollama at registration time would otherwise
        # downgrade the auditor to static-regex-only at reduced (0.4×) weight.
        # In production the correct fail-closed posture is to refuse registration
        # (503) rather than accept a degraded audit decision.
        #
        # Operational consequence: tool registration is unavailable during Ollama
        # outages in production.  Tool invocations are NOT affected.
        # See docs/ARCHITECTURE.md §5.4 for runbook guidance.
        if not self.REQUIRE_LLM_AUDIT:
            raise ValueError(
                "Production startup blocked: REQUIRE_LLM_AUDIT must be True in "
                "production. Set REQUIRE_LLM_AUDIT=true in your environment. "
                "When True, tool registration returns 503 during Ollama outages "
                "rather than accepting a degraded (static-only) audit result. "
                "Tool invocations are not affected by this setting."
            )

        return self

    @model_validator(mode="after")
    def _enforce_staging_parity(self) -> "Settings":
        """
        AUTH-F5 / Task 1.8: staging must enforce the same OIDC audience and
        session-cookie security constraints as production.  Development is
        intentionally excluded to allow local testing without HTTPS or a real
        Keycloak audience.

        The "require when OIDC_ENABLED=true outside development" rule applies
        to both OIDC_AUDIENCE and SESSION_COOKIE_SECURE — both are audience/
        transport-integrity controls that are meaningless to skip in staging
        (staging is where pre-production validation happens and must mirror
        the production threat model).
        """
        if self.ENVIRONMENT != "staging":
            return self

        # OIDC_AUDIENCE in staging — same rationale as production.
        if self.OIDC_ENABLED and not self.OIDC_AUDIENCE.strip():
            raise ValueError(
                "Staging startup blocked: OIDC_ENABLED=true but OIDC_AUDIENCE is "
                "empty. Staging must enforce the same audience constraint as "
                "production. Set OIDC_AUDIENCE to the expected token audience."
            )

        # SESSION_COOKIE_SECURE in staging — staging must use HTTPS.
        if not self.SESSION_COOKIE_SECURE:
            raise ValueError(
                "Staging startup blocked: SESSION_COOKIE_SECURE must be True in "
                "staging. Set SESSION_COOKIE_SECURE=true in your environment."
            )

        return self

    @model_validator(mode="after")
    def _enforce_token_exchange_audience(self) -> "Settings":
        """
        S-2 (PRD-0002): when KC token exchange is enabled, OIDC_AUDIENCE must be
        a single, non-blank value REGARDLESS of ENVIRONMENT. The existing
        production/staging audience validators skip development, which is exactly
        the lab profile where case 4 (token exchange) runs — leaving an
        audience-confusion fail-open. This closes it.
        """
        if not (self.OIDC_ENABLED and self.KC_TOKEN_EXCHANGE_ENABLED):
            return self
        aud = self.OIDC_AUDIENCE.strip()
        if not aud:
            raise ValueError(
                "Startup blocked: KC_TOKEN_EXCHANGE_ENABLED=true requires a non-blank "
                "OIDC_AUDIENCE (single value) so verify_aud is enforced even in development."
            )
        if "," in aud or " " in aud:
            raise ValueError(
                "Startup blocked: OIDC_AUDIENCE must be a single audience when token "
                f"exchange is enabled; got multi-value {aud!r}."
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
    def is_staging(self) -> bool:
        return self.ENVIRONMENT == "staging"

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


def get_rate_limit_for_roles(roles: list[str], settings: "Settings") -> int:
    """Most-permissive per-role rate limit (requests/min). Fallback: most restrictive."""
    role_map = {
        "admin": settings.RATE_LIMIT_ADMIN,
        "platform_admin": settings.RATE_LIMIT_ADMIN,
        "agent": settings.RATE_LIMIT_AGENT,
        "auditor": settings.RATE_LIMIT_AUDITOR,
        "viewer": settings.RATE_LIMIT_READONLY,
    }
    if not roles:
        return settings.RATE_LIMIT_READONLY
    return max((role_map.get(r, settings.RATE_LIMIT_READONLY) for r in roles),
               default=settings.RATE_LIMIT_READONLY)


def __getattr__(name: str) -> object:
    if name == "settings":
        return get_settings()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
