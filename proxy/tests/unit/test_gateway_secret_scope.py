"""
S4 — GATEWAY_SHARED_SECRET scope test.

Asserts that the three non-edge containers that do NOT need GATEWAY_SHARED_SECRET
do not have `.env` in their `env_file` list.  Any container that can read `.env`
can read GATEWAY_SHARED_SECRET, which is sufficient to forge admin CNs via
`_is_trusted_proxy` in proxy/app/middleware/auth.py.

Containers intentionally allowed to read .env:
  - proxy   (legitimate: uses GATEWAY_SHARED_SECRET directly)

Containers that must NOT receive .env:
  - alertmanager-config-renderer  (needs only ALERT_WEBHOOK_URL vars)
  - minio-init                    (needs only MinIO vars)
  - compliance-checker            (needs DB + MinIO vars)
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_COMPOSE_FILE = Path(__file__).parents[3] / "docker-compose.yml"

# Containers that must NOT have .env in their env_file
_NO_ENV_FILE_SERVICES = (
    "alertmanager-config-renderer",
    "minio-init",
    "compliance-checker",
)


def _env_files_for_service(service_def: dict) -> list[str]:
    """Return the list of env_file paths declared for a service."""
    raw = service_def.get("env_file")
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    # List of strings or dicts (compose v3.9+ dict form: {path: ..., required: ...})
    result = []
    for entry in raw:
        if isinstance(entry, str):
            result.append(entry)
        elif isinstance(entry, dict):
            result.append(entry.get("path", ""))
    return result


@pytest.fixture(scope="module")
def compose() -> dict:
    assert _COMPOSE_FILE.exists(), f"docker-compose.yml not found at {_COMPOSE_FILE}"
    return yaml.safe_load(_COMPOSE_FILE.read_text())


class TestGatewaySecretScope:
    """S4: GATEWAY_SHARED_SECRET must not be exposed to non-edge containers."""

    @pytest.mark.parametrize("svc_name", _NO_ENV_FILE_SERVICES)
    def test_service_present_in_compose(self, compose: dict, svc_name: str) -> None:
        """Sanity-check: the service must exist so the scope test is meaningful."""
        services = compose.get("services", {})
        assert svc_name in services, (
            f"Service '{svc_name}' not found in docker-compose.yml. "
            "Either the service was renamed or the test needs updating."
        )

    @pytest.mark.parametrize("svc_name", _NO_ENV_FILE_SERVICES)
    def test_no_dotenv_in_env_file(self, compose: dict, svc_name: str) -> None:
        """
        The service must NOT have '.env' in its env_file list.

        Any service with env_file: ['.env'] receives ALL variables defined in .env,
        including GATEWAY_SHARED_SECRET.  Non-edge containers must use explicit
        `environment:` keys instead, scoping only what they actually need.
        """
        services = compose.get("services", {})
        svc = services.get(svc_name, {})
        env_files = _env_files_for_service(svc)
        assert ".env" not in env_files, (
            f"Service '{svc_name}' has '.env' in env_file ({env_files}). "
            "This exposes GATEWAY_SHARED_SECRET to a container that does not need it. "
            "Remove '.env' from env_file and declare only the required vars explicitly "
            "in the environment: block."
        )

    @pytest.mark.parametrize("svc_name", _NO_ENV_FILE_SERVICES)
    def test_no_inline_gateway_secret(self, compose: dict, svc_name: str) -> None:
        """
        Belt-and-suspenders: service must not declare GATEWAY_SHARED_SECRET inline.
        """
        services = compose.get("services", {})
        svc = services.get(svc_name, {})
        env = svc.get("environment") or {}
        env_names: list[str]
        if isinstance(env, list):
            env_names = [e.split("=", 1)[0] for e in env]
        else:
            env_names = list(env.keys())
        assert "GATEWAY_SHARED_SECRET" not in env_names, (
            f"Service '{svc_name}' declares GATEWAY_SHARED_SECRET in environment:. "
            "This container does not need the secret."
        )

    def test_proxy_retains_dotenv(self, compose: dict) -> None:
        """
        Regression guard: the proxy service must KEEP '.env' in its env_file.
        Removing it would break the legitimate use of GATEWAY_SHARED_SECRET.
        """
        proxy = compose.get("services", {}).get("proxy", {})
        env_files = _env_files_for_service(proxy)
        assert ".env" in env_files, (
            "proxy service must have '.env' in env_file. "
            "GATEWAY_SHARED_SECRET is legitimately used there."
        )
