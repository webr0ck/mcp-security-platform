"""
Tests for scripts/check_network_isolation.py — F-001 isolation gate.

Each test loads a YAML fixture directly (no compose binary needed) so the
suite is runnable offline and without a container runtime.  The tests
exercise the check functions in isolation by passing pre-parsed dicts.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

# Make the scripts/ package importable from the repo root
_SCRIPTS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(_SCRIPTS_DIR))
from check_network_isolation import (
    _check_mcp_isolation,
    _check_egress_proxy,
    _check_gateway_secret_env_file_scope,
    _is_credential_var,
    _is_mcp_service,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> dict:
    return yaml.safe_load((FIXTURES / name).read_text())


# ---------------------------------------------------------------------------
# Unit: helpers
# ---------------------------------------------------------------------------

class TestIsCredentialVar:
    def test_postgres_prefix(self):
        assert _is_credential_var("POSTGRES_PASSWORD")
        assert _is_credential_var("POSTGRES_USER")

    def test_redis_password(self):
        assert _is_credential_var("REDIS_PASSWORD")

    def test_dsn_suffix(self):
        assert _is_credential_var("DATABASE_URL")
        assert _is_credential_var("DB_DSN")
        assert _is_credential_var("MY_DATABASE_URL")

    def test_benign(self):
        assert not _is_credential_var("HOST")
        assert not _is_credential_var("PORT")
        assert not _is_credential_var("LOG_LEVEL")
        assert not _is_credential_var("GITEA_URL")


class TestIsMcpService:
    def test_mcp_prefix(self):
        assert _is_mcp_service("mcp-netbox")
        assert _is_mcp_service("mcp-echo")

    def test_lab_mcp_prefix(self):
        assert _is_mcp_service("lab-mcp-notes")
        assert _is_mcp_service("lab-mcp-gitea")

    def test_non_mcp(self):
        assert not _is_mcp_service("proxy")
        assert not _is_mcp_service("redis")
        assert not _is_mcp_service("lab-grafana")


# ---------------------------------------------------------------------------
# Integration: fixture compose files
# ---------------------------------------------------------------------------

class TestPassingFixture:
    def test_no_violations(self):
        c = _load("passing_lab.yml")
        fails: list[str] = []
        _check_mcp_isolation(c, "passing_lab.yml", fails)
        assert fails == [], f"Unexpected violations in passing fixture: {fails}"


class TestViolatesInternalNet:
    def test_detects_internal_net_violation(self):
        c = _load("violates_internal_net.yml")
        fails: list[str] = []
        _check_mcp_isolation(c, "test", fails)
        # Should catch the internal-net violation for lab-mcp-bad
        assert any("internal-net" in f and "lab-mcp-bad" in f for f in fails), \
            f"Expected internal-net violation not found in: {fails}"


class TestViolatesBackendNet:
    def test_detects_backend_net_violation(self):
        c = _load("violates_backend_net.yml")
        fails: list[str] = []
        _check_mcp_isolation(c, "test", fails)
        assert any("proxy-redis-net" in f or "platform backend" in f for f in fails), \
            f"Expected backend-net violation not found in: {fails}"


class TestViolatesCredentialEnv:
    def test_detects_credential_env_violation(self):
        c = _load("violates_credential_env.yml")
        fails: list[str] = []
        _check_mcp_isolation(c, "test", fails)
        assert any("REDIS_PASSWORD" in f or "credential env" in f for f in fails), \
            f"Expected credential-env violation not found in: {fails}"


class TestViolatesPairwiseNet:
    def test_detects_pairwise_net_violation(self):
        c = _load("violates_pairwise_net.yml")
        fails: list[str] = []
        _check_mcp_isolation(c, "test", fails)
        assert any("pairwise" in f or "rogue-service" in f for f in fails), \
            f"Expected pairwise-net violation not found in: {fails}"


class TestEgressProxy:
    def test_clean_egress_proxy(self):
        c = {
            "services": {
                "squid": {
                    "image": "ubuntu/squid:latest",
                    "networks": {"egress-net": None},
                    "volumes": [
                        "./squid/allowed-sites.txt:/etc/squid/allowed-sites.txt:ro"
                    ],
                }
            },
            "networks": {"egress-net": {"driver": "bridge", "internal": True}},
        }
        fails: list[str] = []
        _check_egress_proxy(c, "test", fails)
        assert fails == [], f"Unexpected egress-proxy violations: {fails}"

    def test_egress_proxy_on_platform_net(self):
        c = {
            "services": {
                "squid": {
                    "image": "ubuntu/squid:latest",
                    "networks": {"egress-net": None, "proxy-db-net": None},
                    "volumes": [
                        "./squid/allowed-sites.txt:/etc/squid/allowed-sites.txt:ro"
                    ],
                }
            },
            "networks": {
                "egress-net": {"driver": "bridge"},
                "proxy-db-net": {"driver": "bridge", "internal": True},
            },
        }
        fails: list[str] = []
        _check_egress_proxy(c, "test", fails)
        assert any("proxy-db-net" in f for f in fails), \
            f"Expected platform-net violation for egress-proxy not found: {fails}"

    def test_egress_proxy_config_not_ro(self):
        c = {
            "services": {
                "squid": {
                    "image": "ubuntu/squid:latest",
                    "networks": {"egress-net": None},
                    "volumes": [
                        "./squid/allowed-sites.txt:/etc/squid/allowed-sites.txt"  # no :ro
                    ],
                }
            },
            "networks": {"egress-net": {"driver": "bridge", "internal": True}},
        }
        fails: list[str] = []
        _check_egress_proxy(c, "test", fails)
        assert any("read-only" in f for f in fails), \
            f"Expected read-only violation for egress-proxy config not found: {fails}"


class TestGatewaySecretEnvFileScope:
    """S4: GATEWAY_SHARED_SECRET must not be leaked via .env env_file to non-proxy services."""

    def _compose_with_env_file(self, svc_name: str, env_files: list[str]) -> dict:
        """Build a minimal compose dict with proxy and one additional service."""
        return {
            "services": {
                "proxy": {
                    "image": "mcp-proxy:local",
                    "networks": {"gateway-net": None},
                    "env_file": [".env"],
                },
                svc_name: {
                    "image": "alpine:3.20",
                    "networks": {"observability-net": None},
                    "env_file": env_files,
                },
            },
        }

    def test_non_proxy_service_with_dotenv_fails(self):
        """A non-proxy service with .env in env_file must be caught by the gate."""
        c = self._compose_with_env_file("alertmanager-config-renderer", [".env"])
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "test.yml", fails)
        assert any(
            "alertmanager-config-renderer" in f and "S4" in f for f in fails
        ), f"Expected S4 violation for alertmanager-config-renderer not found: {fails}"

    def test_non_proxy_service_without_dotenv_passes(self):
        """A non-proxy service that does NOT have .env must pass the gate."""
        c = self._compose_with_env_file("alertmanager-config-renderer", [".env.alertmanager"])
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "test.yml", fails)
        assert not any("alertmanager-config-renderer" in f for f in fails), \
            f"Unexpected S4 failure: {fails}"

    def test_non_proxy_service_no_env_file_passes(self):
        """A non-proxy service with no env_file at all must pass the gate."""
        c = {
            "services": {
                "proxy": {
                    "image": "mcp-proxy:local",
                    "env_file": [".env"],
                },
                "minio-init": {
                    "image": "minio/mc:latest",
                    "environment": {"MINIO_ROOT_USER": "admin"},
                },
            }
        }
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "test.yml", fails)
        assert fails == [], f"Unexpected S4 failure for no-env_file service: {fails}"

    def test_proxy_with_dotenv_passes(self):
        """The proxy service itself is allowed to have .env — must not be flagged."""
        c = {
            "services": {
                "proxy": {
                    "image": "mcp-proxy:local",
                    "env_file": [".env"],
                },
            }
        }
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "test.yml", fails)
        assert fails == [], f"proxy should be allowed to have .env: {fails}"

    def test_skips_when_no_proxy_service(self):
        """Lab overlays without a proxy service must be silently skipped."""
        c = {
            "services": {
                "lab-mcp-notes": {
                    "image": "lab-notes:local",
                    "env_file": [".env"],
                },
            }
        }
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "podman-compose.lab.yml", fails)
        assert fails == [], \
            f"Gate should skip lab overlays without proxy service: {fails}"

    def test_multiple_violators_all_caught(self):
        """All non-proxy services with .env must be reported — not just the first."""
        c = {
            "services": {
                "proxy": {"image": "mcp-proxy:local", "env_file": [".env"]},
                "minio-init": {"image": "minio/mc:latest", "env_file": [".env"]},
                "compliance-checker": {"image": "mcp-cc:latest", "env_file": [".env"]},
            }
        }
        fails: list[str] = []
        _check_gateway_secret_env_file_scope(c, "test.yml", fails)
        assert len(fails) == 2, \
            f"Expected 2 violations (minio-init + compliance-checker), got: {fails}"
        names = " ".join(fails)
        assert "minio-init" in names and "compliance-checker" in names, \
            f"Both violators should appear in fails: {fails}"
