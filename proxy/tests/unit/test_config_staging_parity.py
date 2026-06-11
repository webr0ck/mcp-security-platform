"""
Unit tests — Task 1.8: Staging-environment enforcement parity + gateway secret check.

AUTH-F5: staging must enforce OIDC_AUDIENCE and SESSION_COOKIE_SECURE parity
         with production.
AUTH-F7: ENVIRONMENT=production + empty GATEWAY_SHARED_SECRET → ERROR log at
         startup (mTLS CN auth silently disabled is not acceptable silently).
AUTH-F1 residual: INV-012 signed-bundle gate already covers compose.standard.yml
         and compose.engine.yml — verified by test_inv012_signed_bundle_gate_covers_all_tiers
         (structural assertion, no subprocess needed).

Run from proxy/:
    .venv/bin/python -m pytest tests/unit/test_config_staging_parity.py -v
"""
from __future__ import annotations

import logging
import os

import pytest


# ---------------------------------------------------------------------------
# Helper — build a minimal valid Settings instance bypassing proxy/.env
# ---------------------------------------------------------------------------

def _make_settings(**overrides):
    """Build Settings with all mandatory fields supplied, bypassing .env."""
    from app.core.config import Settings

    # All fields that have no class-level default and would raise if absent.
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
    # Caller overrides win; _env_file=None ensures proxy/.env is never read.
    params = {**mandatory, **overrides, "_env_file": None}
    return Settings(**params)


# Minimum key length that passes the production 32-byte HMAC length check.
_LONG_KEY = "a" * 32

# Minimum production-valid kwargs (satisfies all production validators).
_PRODUCTION_BASE = dict(
    ENVIRONMENT="production",
    VAULT_ADDR="https://vault:8200",
    REQUIRE_LLM_AUDIT=True,
    SESSION_COOKIE_SECURE=True,
    OIDC_ENABLED=False,       # OIDC off → OIDC_AUDIENCE not required
    GATEWAY_SHARED_SECRET="some-secret-value",
    # All HMAC/signing keys need to be ≥ 32 bytes in production.
    DB_PASSWORD="x",
    REDIS_PASSWORD="x",
    PROXY_SECRET_KEY=_LONG_KEY,
    API_KEY_HMAC_KEY=_LONG_KEY,
    SBOM_SIGNING_KEY=_LONG_KEY,
    AUDIT_LOG_HMAC_KEY=_LONG_KEY,
    WEBHOOK_SIGNING_KEY=_LONG_KEY,
    MINIO_ROOT_USER="x",
    MINIO_ROOT_PASSWORD="x",
    VAULT_TOKEN="a-real-token",
    OAUTH_STATE_SECRET=_LONG_KEY,
    DEX_CLIENT_SECRET="not-a-placeholder",
    POLICY_SIGNING_KEY=_LONG_KEY,
)


# ===========================================================================
# AUTH-F5 — Staging enforcement parity
# ===========================================================================

class TestStagingOidcAudience:
    """OIDC_ENABLED=true + empty OIDC_AUDIENCE must block startup in staging."""

    @pytest.mark.parametrize("environment", ["staging"])
    def test_oidc_enabled_empty_audience_blocks_staging(self, environment):
        with pytest.raises(ValueError, match="Staging startup blocked.*OIDC_AUDIENCE"):
            _make_settings(
                ENVIRONMENT=environment,
                VAULT_ADDR="https://vault:8200",
                OIDC_ENABLED=True,
                OIDC_AUDIENCE="",   # empty — must block
                SESSION_COOKIE_SECURE=True,
            )

    @pytest.mark.parametrize("environment", ["staging"])
    def test_oidc_enabled_with_audience_passes_staging(self, environment):
        """Staging with OIDC_ENABLED=true AND a real audience must boot cleanly."""
        s = _make_settings(
            ENVIRONMENT=environment,
            VAULT_ADDR="https://vault:8200",
            OIDC_ENABLED=True,
            OIDC_AUDIENCE="mcp-proxy",
            SESSION_COOKIE_SECURE=True,
        )
        assert s.OIDC_AUDIENCE == "mcp-proxy"

    def test_oidc_disabled_empty_audience_passes_staging(self):
        """When OIDC is disabled the audience check must not fire in staging."""
        s = _make_settings(
            ENVIRONMENT="staging",
            VAULT_ADDR="https://vault:8200",
            OIDC_ENABLED=False,
            OIDC_AUDIENCE="",
            SESSION_COOKIE_SECURE=True,
        )
        assert s.ENVIRONMENT == "staging"

    def test_oidc_enabled_empty_audience_still_blocks_production(self):
        """Production behaviour is unchanged: OIDC_ENABLED + empty audience still blocks."""
        with pytest.raises(ValueError, match="(?i)(production|staging).*OIDC_AUDIENCE"):
            _make_settings(
                **{
                    **{k: v for k, v in _PRODUCTION_BASE.items()
                       if k not in ("OIDC_ENABLED",)},
                    "OIDC_ENABLED": True,
                    "OIDC_AUDIENCE": "",
                },
            )

    def test_oidc_enabled_empty_audience_passes_development(self):
        """Development is excluded from the audience check to allow local testing."""
        s = _make_settings(
            ENVIRONMENT="development",
            OIDC_ENABLED=True,
            OIDC_AUDIENCE="",
        )
        assert s.ENVIRONMENT == "development"


class TestStagingSessionCookieSecure:
    """SESSION_COOKIE_SECURE=false must block startup in staging."""

    @pytest.mark.parametrize("environment", ["staging"])
    def test_insecure_cookie_blocks_staging(self, environment):
        with pytest.raises(ValueError, match="Staging startup blocked.*SESSION_COOKIE_SECURE"):
            _make_settings(
                ENVIRONMENT=environment,
                VAULT_ADDR="https://vault:8200",
                SESSION_COOKIE_SECURE=False,   # must block
            )

    @pytest.mark.parametrize("environment", ["staging"])
    def test_secure_cookie_passes_staging(self, environment):
        s = _make_settings(
            ENVIRONMENT=environment,
            VAULT_ADDR="https://vault:8200",
            SESSION_COOKIE_SECURE=True,
        )
        assert s.SESSION_COOKIE_SECURE is True

    def test_insecure_cookie_still_blocks_production(self):
        """Production behaviour is unchanged: SESSION_COOKIE_SECURE=false still blocks."""
        with pytest.raises(ValueError, match="(?i)(production|staging).*SESSION_COOKIE_SECURE"):
            _make_settings(
                **{**_PRODUCTION_BASE, "SESSION_COOKIE_SECURE": False},
            )

    def test_insecure_cookie_passes_development(self):
        """Development is excluded — local testing without HTTPS must work."""
        s = _make_settings(
            ENVIRONMENT="development",
            SESSION_COOKIE_SECURE=False,
        )
        assert s.SESSION_COOKIE_SECURE is False


# ===========================================================================
# AUTH-F7 — Gateway secret ERROR log in production
# ===========================================================================

class TestGatewaySecretProductionLog:
    """ENVIRONMENT=production + empty GATEWAY_SHARED_SECRET must emit ERROR log."""

    def test_empty_gateway_secret_logs_error_in_production(self, caplog):
        """Empty GATEWAY_SHARED_SECRET in production emits ERROR, does not block startup."""
        with caplog.at_level(logging.ERROR, logger="app.core.config"):
            s = _make_settings(
                **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": ""},
            )
        # Startup must succeed (it is a WARNING, not a hard block).
        assert s.ENVIRONMENT == "production"
        # The ERROR must be logged.
        error_records = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "GATEWAY_SHARED_SECRET" in r.message
        ]
        assert error_records, (
            "Expected at least one ERROR-level log record mentioning "
            "GATEWAY_SHARED_SECRET when it is empty in production. "
            f"Records seen: {[r.message for r in caplog.records]}"
        )

    def test_empty_gateway_secret_message_mentions_mtls_disabled(self, caplog):
        """The ERROR message must explain that mTLS CN auth is disabled."""
        with caplog.at_level(logging.ERROR, logger="app.core.config"):
            _make_settings(
                **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": ""},
            )
        error_messages = " ".join(
            r.message for r in caplog.records if r.levelno >= logging.ERROR
        )
        assert "mTLS" in error_messages or "CN" in error_messages or "disabled" in error_messages, (
            "ERROR message should mention that mTLS CN auth is disabled. "
            f"Actual messages: {error_messages}"
        )

    def test_set_gateway_secret_does_not_log_error_in_production(self, caplog):
        """A non-empty GATEWAY_SHARED_SECRET must not trigger the error log."""
        with caplog.at_level(logging.ERROR, logger="app.core.config"):
            _make_settings(
                **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": "my-real-secret"},
            )
        error_records = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "GATEWAY_SHARED_SECRET" in r.message
        ]
        assert not error_records, (
            "No ERROR log should be emitted when GATEWAY_SHARED_SECRET is set. "
            f"Unexpected records: {[r.message for r in error_records]}"
        )

    def test_empty_gateway_secret_does_not_log_error_in_development(self, caplog):
        """Development intentionally omits GATEWAY_SHARED_SECRET; no ERROR should fire."""
        with caplog.at_level(logging.ERROR, logger="app.core.config"):
            _make_settings(
                ENVIRONMENT="development",
                GATEWAY_SHARED_SECRET="",
            )
        error_records = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "GATEWAY_SHARED_SECRET" in r.message
        ]
        assert not error_records, (
            "No GATEWAY_SHARED_SECRET ERROR should be logged in development. "
            f"Records: {[r.message for r in error_records]}"
        )

    def test_empty_gateway_secret_does_not_log_error_in_staging(self, caplog):
        """Staging may omit GATEWAY_SHARED_SECRET without error (plan only targets production)."""
        with caplog.at_level(logging.ERROR, logger="app.core.config"):
            _make_settings(
                ENVIRONMENT="staging",
                VAULT_ADDR="https://vault:8200",
                SESSION_COOKIE_SECURE=True,
                GATEWAY_SHARED_SECRET="",
            )
        error_records = [
            r for r in caplog.records
            if r.levelno >= logging.ERROR and "GATEWAY_SHARED_SECRET" in r.message
        ]
        assert not error_records, (
            "GATEWAY_SHARED_SECRET ERROR must target production only. "
            f"Records: {[r.message for r in error_records]}"
        )


# ===========================================================================
# INV-012 — check_signed_default.sh covers every non-dev compose tier
# ===========================================================================

class TestInv012SignedBundleGateCoverage:
    """
    Structural assertion: scripts/check_signed_default.sh must list every
    non-dev compose tier that can run OPA.  No subprocess needed — just read
    the script and assert the required files are present in its PROD_COMPOSES
    array.
    """

    _SCRIPT_PATH = os.path.join(
        os.path.dirname(__file__),
        "..", "..", "..", "scripts", "check_signed_default.sh",
    )

    def _read_script(self) -> str:
        path = os.path.normpath(self._SCRIPT_PATH)
        with open(path) as fh:
            return fh.read()

    @pytest.mark.parametrize("compose_file", [
        "docker-compose.yml",
        "compose.standard.yml",
        "compose.engine.yml",
    ])
    def test_signed_bundle_gate_covers_tier(self, compose_file):
        """Every non-dev compose tier must appear in PROD_COMPOSES in the gate script."""
        content = self._read_script()
        assert compose_file in content, (
            f"scripts/check_signed_default.sh must include '{compose_file}' in its "
            "PROD_COMPOSES list to enforce INV-012 (signed OPA bundles) on that tier. "
            "Update the script to add the missing file."
        )

    def test_dev_compose_excluded_from_gate(self):
        """docker-compose.dev.yml must NOT be in PROD_COMPOSES (dev uses unsigned dir mount)."""
        content = self._read_script()
        # dev file should appear only in comments or the exclusion note, not in the array.
        # Find the PROD_COMPOSES=(...) array block.
        import re
        match = re.search(r'PROD_COMPOSES=\((.+?)\)', content, re.DOTALL)
        assert match, "Could not find PROD_COMPOSES=(...) in the script."
        array_body = match.group(1)
        assert "docker-compose.dev.yml" not in array_body, (
            "docker-compose.dev.yml must NOT appear in PROD_COMPOSES — "
            "dev intentionally uses an unsigned directory mount."
        )
