"""Unit tests — F-001 gateway-shared-secret trust boundary (runtime check).

`_is_trusted_proxy` is the gate that decides whether the proxy will honour a
gateway-set `X-Client-Cert-CN` identity header. F-001: that header must only be
trusted when it arrives from Nginx, which proves itself by injecting the shared
`X-Gateway-Secret`. These tests assert the gate is **fail-closed** — a forged,
missing, or mismatched secret is rejected, and only the exact configured secret
is trusted.

NOTE on the autouse patch: ``conftest.py`` installs an autouse fixture that
patches ``app.middleware.auth._is_trusted_proxy`` to always return True (so
in-process ASGI tests that bypass Nginx still authenticate). That patch would
mask the very behaviour under test here, so we capture the REAL function object
at import time — rebinding the module attribute later does not affect this local
reference — and drive ``settings`` via a stub to vary the configured secret.

Run from proxy/:
    .venv/bin/python -m pytest tests/unit/test_gateway_secret_trust.py -v
"""
from __future__ import annotations

import os

# Importing app.middleware.auth instantiates the global Settings() (auth.py does
# `from app.core.config import settings`). The ENVIRONMENT default is "production",
# which would trip the production secret-completeness validators on a bare import.
# Test runners (make test / CI) already set a non-production ENVIRONMENT; force it
# here too so this module imports cleanly standalone. The value is irrelevant to
# the assertions below — every test stubs `auth.settings` directly.
os.environ.setdefault("ENVIRONMENT", "development")

from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402

from app.middleware import auth  # noqa: E402
# Bind the genuine function NOW, before the conftest autouse fixture patches the
# module attribute at test runtime. This reference stays pointed at real code.
from app.middleware.auth import _is_trusted_proxy as real_is_trusted_proxy  # noqa: E402


def _request_with(headers: dict) -> SimpleNamespace:
    """Minimal stand-in — _is_trusted_proxy only calls request.headers.get(...)."""
    return SimpleNamespace(headers=headers)


@pytest.fixture
def set_gateway_secret(monkeypatch):
    """Set the proxy's configured GATEWAY_SHARED_SECRET via a settings stub.

    Replacing the module-level ``settings`` object avoids any pydantic
    frozen/validate-on-assignment concerns with mutating the real instance.
    """
    def _set(value: str) -> None:
        monkeypatch.setattr(
            auth, "settings", SimpleNamespace(GATEWAY_SHARED_SECRET=value)
        )
    return _set


def test_secret_unset_disables_cn_trust(set_gateway_secret):
    """Lab mode (no secret configured): the CN header is never trusted."""
    set_gateway_secret("")
    req = _request_with({"X-Client-Cert-CN": "admin", "X-Gateway-Secret": "anything"})
    assert real_is_trusted_proxy(req) is False


def test_secret_set_but_header_absent_is_rejected(set_gateway_secret):
    """A direct-to-proxy caller cannot present the secret -> fail closed."""
    set_gateway_secret("s3cr3t-from-nginx")
    req = _request_with({"X-Client-Cert-CN": "admin"})  # no X-Gateway-Secret
    assert real_is_trusted_proxy(req) is False


def test_secret_set_but_header_mismatch_is_rejected(set_gateway_secret):
    """A forged/guessed secret must not be accepted."""
    set_gateway_secret("s3cr3t-from-nginx")
    req = _request_with({"X-Client-Cert-CN": "admin", "X-Gateway-Secret": "wrong"})
    assert real_is_trusted_proxy(req) is False


def test_correct_secret_is_trusted(set_gateway_secret):
    """Only the exact gateway secret makes the request trusted."""
    set_gateway_secret("s3cr3t-from-nginx")
    req = _request_with({"X-Gateway-Secret": "s3cr3t-from-nginx"})
    assert real_is_trusted_proxy(req) is True


def test_empty_provided_secret_with_configured_secret_is_rejected(set_gateway_secret):
    """An explicitly-empty X-Gateway-Secret header is still a rejection."""
    set_gateway_secret("s3cr3t-from-nginx")
    req = _request_with({"X-Client-Cert-CN": "admin", "X-Gateway-Secret": ""})
    assert real_is_trusted_proxy(req) is False
