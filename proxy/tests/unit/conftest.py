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
def _stub_get_recent_calls_for_opa():
    """
    Unit-test default: patch _get_recent_calls_for_opa to return [] so that
    invocation.py unit tests don't need a live Redis connection.

    Task 1.7 added a fail-closed Redis read before OPA evaluation; without this
    stub every invoke_tool unit test would 503 on Redis not initialized.

    Tests that specifically verify recent_calls behavior (test_anomaly_rego_wire.py)
    override this by patching 'app.services.invocation._get_recent_calls_for_opa'
    themselves within the test body. pytest's fixture system gives test-level patches
    priority over autouse fixtures.
    """
    try:
        with patch(
            "app.services.invocation._get_recent_calls_for_opa",
            new=AsyncMock(return_value=[]),
        ):
            yield
    except (AttributeError, ModuleNotFoundError):
        # Module not yet loaded or function not yet present — let the test proceed.
        yield
