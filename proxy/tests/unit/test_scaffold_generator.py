"""
Unit tests — scaffold_generator.py (WP-A6 Finding 5).

Covers: kc_token_exchange scaffolds get a real jwt_validator.py (issuer/
audience/expiry/signature validation, not just mcphub_sdk's X-User-Sub
trust), pre-filled with the platform's real issuer/JWKS URI; the audience
is never pre-filled (only known at admin-approval time); other modes are
unaffected.
"""
from __future__ import annotations

import pytest

from app.services.scaffold_generator import generate_scaffold

pytestmark = pytest.mark.unit


def test_kc_token_exchange_scaffold_includes_jwt_validator():
    files = generate_scaffold(
        "acme-mcp", "kc_token_exchange",
        issuer="https://kc.example/realms/mcp",
        jwks_uri="https://kc.example/realms/mcp/protocol/openid-connect/certs",
    )
    assert "jwt_validator.py" in files
    validator = files["jwt_validator.py"]
    assert 'KC_ISSUER = os.environ.get("KC_ISSUER", "https://kc.example/realms/mcp")' in validator
    assert "https://kc.example/realms/mcp/protocol/openid-connect/certs" in validator
    # Audience must NEVER be pre-filled — only known at reviewer-approval time.
    assert 'KC_AUDIENCE = os.environ.get("KC_AUDIENCE", "")' in validator
    assert "pyjwt[crypto]" in files["requirements.txt"]


def test_kc_token_exchange_server_calls_validate_token():
    files = generate_scaffold("acme-mcp", "kc_token_exchange")
    assert "from jwt_validator import TokenValidationError, validate_token" in files["server.py"]
    assert "validate_token(token)" in files["server.py"]


def test_kc_token_exchange_validates_via_middleware_not_just_example_tool():
    """M-01 (2026-07-11 audit): validation must run for every request at the
    middleware layer — a second custom @srv.tool() a developer adds cannot
    accidentally skip it the way a per-tool-only call could."""
    files = generate_scaffold("acme-mcp", "kc_token_exchange")
    server_code = files["server.py"]
    assert "class _TokenValidationMiddleware(BaseHTTPMiddleware):" in server_code
    assert "srv.app.add_middleware(_TokenValidationMiddleware)" in server_code
    # the middleware itself must be the one invoking validate_token, before
    # add_middleware — not just inside example_tool
    middleware_body = server_code.split("class _TokenValidationMiddleware")[1].split("srv.app.add_middleware")[0]
    assert "validate_token(token)" in middleware_body


@pytest.mark.parametrize("mode", ["service", "user", "entra_user_token", "none", "oauth_user_token"])
def test_non_kc_modes_get_no_jwt_validator(mode):
    files = generate_scaffold("acme-mcp", mode)
    assert "jwt_validator.py" not in files
    assert "pyjwt" not in files["requirements.txt"]


def test_jwt_validator_fails_closed_without_configured_audience():
    """Regression: a scaffold deployed without KC_AUDIENCE set must reject
    every token rather than silently skip audience validation."""
    import importlib.util
    import sys

    files = generate_scaffold(
        "acme-mcp", "kc_token_exchange",
        issuer="https://kc.example/realms/mcp",
        jwks_uri="https://kc.example/realms/mcp/protocol/openid-connect/certs",
    )
    spec = importlib.util.spec_from_loader("acme_jwt_validator_test", loader=None)
    module = importlib.util.module_from_spec(spec)
    exec(compile(files["jwt_validator.py"], "jwt_validator.py", "exec"), module.__dict__)

    with pytest.raises(module.TokenValidationError, match="KC_AUDIENCE"):
        module.validate_token("some-token")
