"""Shared fixtures + markers for the RFC-0002 verification suite.

Markers (registered here so `pytest -m ...` works without warnings):
  oracle      — pure spec-logic test against spec_oracle.py (no gateway, always runs)
  substrate   — exercises the REAL implemented RFC-0001 libs (labeler/verifier/taint)
  live        — requires a running proxy on $RFC0002_PROXY_URL (auto-skipped if down)
  conformance — RFC-0002 §4–§6 gateway integration; skips until implemented
"""
from __future__ import annotations

import os
import urllib.request

import pytest

from ._pki import make_pki  # noqa: F401  (re-exported for convenience)

PROXY_URL = os.environ.get("RFC0002_PROXY_URL", "http://localhost:8000")


def pytest_configure(config: pytest.Config) -> None:
    for name, desc in (
        ("oracle", "pure RFC-0002 spec-logic test (no gateway)"),
        ("substrate", "exercises the implemented RFC-0001 libs (no containers)"),
        ("live", "requires a running proxy (auto-skipped if unavailable)"),
        ("conformance", "RFC-0002 §4-6 gateway integration (skips until implemented)"),
        ("redteam", "tracks a known vulnerability; passes while bug persists, fails when fixed"),
    ):
        config.addinivalue_line("markers", f"{name}: {desc}")


@pytest.fixture
def pki():
    """A fresh sub-CA + valid labeler leaf for the test (15-min TTL)."""
    return make_pki()


@pytest.fixture
def verifier(pki):
    """A TrustVerifier pinned to the fixture sub-CA."""
    from app.services.trust_verifier import TrustVerifier

    _sub_ca_key, sub_ca, _leaf_key, _leaf = pki
    return TrustVerifier(sub_ca_cert=sub_ca)


# ── Live proxy auto-detection ────────────────────────────────────────────────

def _proxy_health(url: str = PROXY_URL, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/health", timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except Exception:
        return False


@pytest.fixture(scope="session")
def live_proxy_url() -> str:
    """Skip any 'live' test unless a proxy is actually answering /health."""
    if not _proxy_health():
        pytest.skip(
            f"no live proxy at {PROXY_URL} — start the lab "
            f"(see RFC-0002-verification-plan.md §5) or set RFC0002_PROXY_URL"
        )
    return PROXY_URL
