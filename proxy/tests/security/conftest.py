"""Security test fixtures."""
from __future__ import annotations

import pytest


def pytest_configure(config: object) -> None:  # noqa: ANN001
    """Skip audit DB writes — security tests run without a real DB."""
    try:
        import app.services.invocation as _inv
        _inv._SKIP_AUDIT_DB_WRITE = True
    except Exception:
        pass


@pytest.fixture
def compose_opa_signed():
    """Tampered-bundle integration fixture — not yet implemented.

    This fixture requires:
      1. A running podman lab (podman-compose up -d).
      2. sign_policy_bundle.sh to generate bundle.tar.gz.
      3. Byte-flipping bundle.tar.gz to simulate tampering.
      4. Restarting the OPA container with the tampered bundle.

    Until the fixture is implemented, test_tampered_bundle_rejected is
    skipped at collection time via @pytest.mark.integration on the test
    combined with the missing fixture guard here.
    """
    pytest.skip("compose_opa_signed fixture not yet implemented — requires full lab setup")
