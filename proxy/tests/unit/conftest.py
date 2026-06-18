"""
Unit test conftest — sets dummy env vars before any module-level imports
so that pydantic Settings validation doesn't fail in tests that don't
need real credentials.

Also sets _SKIP_AUDIT_DB_WRITE = True so that _emit_audit_event skips the
DB INSERT in unit tests (no real DB available).  This replaces the fragile
type-guard (non-UUID event_id / non-str sha256_hash) that previously
gated the INSERT as an emergent side-effect of mock return values.

Integration tests in tests/integration/ do NOT use this conftest and run
against a real DB — they must NOT set this flag.
"""
from __future__ import annotations
import os
from unittest.mock import AsyncMock, patch

import pytest

_DEFAULTS = {
    "ENVIRONMENT": "development",
    "DB_PASSWORD": "test",
    "REDIS_PASSWORD": "test",
    "PROXY_SECRET_KEY": "test",
    "API_KEY_HMAC_KEY": "test",
    "SBOM_SIGNING_KEY": "test",
    "AUDIT_LOG_HMAC_KEY": "test",
    "WEBHOOK_SIGNING_KEY": "test",
    "MINIO_ROOT_USER": "test",
    "MINIO_ROOT_PASSWORD": "test",
}

for _k, _v in _DEFAULTS.items():
    os.environ.setdefault(_k, _v)


def pytest_configure(config: object) -> None:  # noqa: ANN001
    """
    Set the audit DB-write skip flag for the entire unit test session.
    Imported lazily to avoid module-import errors before env vars are set.
    """
    try:
        import app.services.invocation as _inv
        _inv._SKIP_AUDIT_DB_WRITE = True
    except Exception:
        # Module may not be importable at configure time (e.g. missing deps);
        # individual test fixtures will set the flag directly if needed.
        pass


@pytest.fixture(autouse=True)
def _stub_invocation_redis_calls():
    """
    Unit-test defaults: patch Redis-dependent and network-dependent functions in
    invocation.py so that unit tests don't need a live Redis connection or DNS.

    - _get_recent_calls_for_opa → [] (Task 1.7: fail-closed anomaly window fetch)
    - _lookup_profile_with_cache → None (Task 1.10: fail-closed profile lookup)
      None means "no profile row" = no restriction = default allow
    - revalidate_upstream_ip_at_invoke → returns ["127.0.0.1"] (Task 3.1: invoke-time
      DNS-rebind revalidation — no-op in unit tests since upstream URLs are fake
      hostnames that will never resolve.  Tests that specifically exercise the
      revalidation logic (test_upstream_validator.py) patch DNS themselves and do
      NOT rely on this stub.)

    Tests that specifically verify these behaviors override these stubs by patching
    the same targets themselves within the test body. pytest's test-level patches
    take priority over autouse fixture-level patches.
    """
    try:
        with patch(
            "app.services.invocation._get_recent_calls_for_opa",
            new=AsyncMock(return_value=[]),
        ), patch(
            "app.services.invocation._lookup_profile_with_cache",
            new=AsyncMock(return_value=None),
        ), patch(
            "app.services.server_onboarding.revalidate_upstream_ip_at_invoke",
            new=AsyncMock(return_value=["127.0.0.1"]),
        ):
            yield
    except (AttributeError, ModuleNotFoundError):
        # Module not yet loaded or function not yet present — let the test proceed.
        yield
