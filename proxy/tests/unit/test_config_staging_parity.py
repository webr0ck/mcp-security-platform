"""
Unit tests — Task 1.8: Staging-environment enforcement parity + gateway secret check.

AUTH-F5: staging must enforce OIDC_AUDIENCE and SESSION_COOKIE_SECURE parity
         with production.
AUTH-F7 / F-001: ENVIRONMENT=production + empty GATEWAY_SHARED_SECRET → startup
         is BLOCKED (raises). The gateway secret is what makes X-Client-Cert-CN
         identity trustworthy; an empty secret would silently disable that check,
         so production fails closed rather than booting fail-open.
AUTH-F1 residual: INV-012 signed-bundle gate already covers compose.standard.yml
         and compose.engine.yml — verified by test_inv012_signed_bundle_gate_covers_all_tiers
         (structural assertion, no subprocess needed).

Run from proxy/:
    .venv/bin/python -m pytest tests/unit/test_config_staging_parity.py -v
"""
from __future__ import annotations

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
# AUTH-F7 / F-001 — Gateway secret REQUIRED in production (fail-closed)
# ===========================================================================

class TestGatewaySecretProductionFailClosed:
    """ENVIRONMENT=production + empty GATEWAY_SHARED_SECRET must BLOCK startup.

    The gateway shared secret is what lets the proxy verify that an
    X-Client-Cert-CN identity header originated from Nginx (F-001). An empty
    secret in production would silently disable that check, so startup must
    fail closed (raise) rather than boot with mTLS CN auth disabled.
    """

    def test_empty_gateway_secret_blocks_production(self):
        """Empty GATEWAY_SHARED_SECRET in production must raise, not boot."""
        with pytest.raises(
            ValueError,
            match="(?i)production startup blocked.*GATEWAY_SHARED_SECRET",
        ):
            _make_settings(
                **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": ""},
            )

    def test_block_message_explains_f001_reason(self):
        """The block message must explain the F-001 identity-trust reason."""
        with pytest.raises(ValueError) as exc_info:
            _make_settings(
                **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": ""},
            )
        msg = str(exc_info.value)
        assert (
            "F-001" in msg
            or "X-Gateway-Secret" in msg
            or "X-Client-Cert-CN" in msg
        ), f"Block message should explain the F-001 identity-trust reason. Got: {msg}"

    def test_set_gateway_secret_boots_in_production(self):
        """A non-empty GATEWAY_SHARED_SECRET must let production boot cleanly."""
        s = _make_settings(
            **{**_PRODUCTION_BASE, "GATEWAY_SHARED_SECRET": "my-real-secret"},
        )
        assert s.GATEWAY_SHARED_SECRET == "my-real-secret"

    def test_empty_gateway_secret_passes_development(self):
        """Development intentionally omits GATEWAY_SHARED_SECRET; must not block."""
        s = _make_settings(
            ENVIRONMENT="development",
            GATEWAY_SHARED_SECRET="",
        )
        assert s.ENVIRONMENT == "development"

    def test_empty_gateway_secret_passes_staging(self):
        """Staging may omit GATEWAY_SHARED_SECRET (the hard block targets production)."""
        s = _make_settings(
            ENVIRONMENT="staging",
            VAULT_ADDR="https://vault:8200",
            SESSION_COOKIE_SECURE=True,
            GATEWAY_SHARED_SECRET="",
        )
        assert s.ENVIRONMENT == "staging"


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
