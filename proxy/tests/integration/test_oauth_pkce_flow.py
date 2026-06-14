"""
OAuth 2.1 PKCE end-to-end flow tests.

These tests verify the full zero-credential MCP client flow:

  1. Discovery chain:   POST /mcp (no creds) → 401 → fetch resource metadata
                        → fetch server metadata → dynamic registration
  2. Token exchange:    POST to Keycloak token endpoint with PKCE
  3. Authenticated MCP: Use KC token as Bearer to hit /mcp

Requirements:
  - KEYCLOAK_URL (or OIDC_ISSUER_URL from .env)
  - Keycloak realm "mcp" with a "claude-code" public client and test user
  - PROXY_BASE_URL pointing at the running proxy
  - KC_TEST_USER / KC_TEST_PASSWORD for resource-owner-password flow (test-only)

Set KC_STACK_RUNNING=1 to enable. Skipped in CI unless that var is set.

For purely automated OAuth testing (no browser), we use Keycloak's
resource owner password credentials grant (ROPC) — the same user/pass
that would be entered in the browser, but directly at the token endpoint.
This is permitted for Keycloak "direct access" grant types in test realms.

NOTE: ROPC is NOT used in production MCP flows (which use PKCE + browser).
      It is used here only to automate the "user has authenticated" step.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import urllib.parse

import pytest
import httpx

# ---------------------------------------------------------------------------
# Fixtures / skip guard
# ---------------------------------------------------------------------------

KC_STACK_RUNNING = os.environ.get("KC_STACK_RUNNING", "").lower() in ("1", "true", "yes")
PROXY_BASE_URL = os.environ.get("PROXY_BASE_URL", "http://localhost:8000").rstrip("/")
KC_URL = os.environ.get("KC_URL", "http://localhost:8082")
KC_REALM = os.environ.get("KC_REALM", "mcp")
KC_TEST_USER = os.environ.get("KC_TEST_USER", "testuser")
KC_TEST_PASSWORD = os.environ.get("KC_TEST_PASSWORD", "testpass")
KC_CLIENT_ID = "claude-code"


def skip_unless_kc(fn):
    return pytest.mark.skipif(
        not KC_STACK_RUNNING,
        reason="KC_STACK_RUNNING not set — Keycloak integration tests skipped",
    )(fn)


# ---------------------------------------------------------------------------
# PKCE helpers (mirrors what MCP clients do)
# ---------------------------------------------------------------------------

def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256)."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def _token_endpoint() -> str:
    return f"{KC_URL}/realms/{KC_REALM}/protocol/openid-connect/token"


def _ropc_token(scope: str = "openid profile email roles") -> dict:
    """Fetch a token via ROPC — automation stand-in for the browser login step."""
    resp = httpx.post(
        _token_endpoint(),
        data={
            "grant_type": "password",
            "client_id": KC_CLIENT_ID,
            "username": KC_TEST_USER,
            "password": KC_TEST_PASSWORD,
            "scope": scope,
        },
    )
    assert resp.status_code == 200, f"ROPC failed: {resp.text}"
    return resp.json()


# ---------------------------------------------------------------------------
# Test: discovery chain
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestOAuthDiscoveryChain:
    """Verify the full zero-credential bootstrap chain."""

    @skip_unless_kc
    def test_unauthenticated_mcp_returns_401(self):
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 401

    @skip_unless_kc
    def test_401_includes_resource_metadata_hint(self):
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 401
        www_auth = r.headers.get("WWW-Authenticate", "")
        assert "resource_metadata" in www_auth.lower() or "bearer" in www_auth.lower()

    @skip_unless_kc
    def test_protected_resource_metadata_reachable(self):
        r = httpx.get(f"{PROXY_BASE_URL}/.well-known/oauth-protected-resource")
        assert r.status_code == 200
        body = r.json()
        assert len(body["authorization_servers"]) >= 1

    @skip_unless_kc
    def test_authorization_server_metadata_reachable(self):
        r = httpx.get(f"{PROXY_BASE_URL}/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        body = r.json()
        assert "token_endpoint" in body
        assert "registration_endpoint" in body

    @skip_unless_kc
    def test_dynamic_registration_returns_claude_code(self):
        r = httpx.post(
            f"{PROXY_BASE_URL}/oauth/register",
            json={"redirect_uris": ["http://localhost:8765/callback"]},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["client_id"] == "claude-code"
        assert "client_secret" not in body
        assert body["token_endpoint_auth_method"] == "none"

    @skip_unless_kc
    def test_server_metadata_token_endpoint_is_keycloak(self):
        r = httpx.get(f"{PROXY_BASE_URL}/.well-known/oauth-authorization-server")
        body = r.json()
        token_ep = body["token_endpoint"]
        assert "openid-connect/token" in token_ep


# ---------------------------------------------------------------------------
# Test: token acquisition via ROPC (automates the "user logs in" step)
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestTokenAcquisition:
    """ROPC simulates the browser login — tests KC is wired correctly."""

    @skip_unless_kc
    def test_ropc_returns_access_token(self):
        tokens = _ropc_token()
        assert "access_token" in tokens
        assert tokens["token_type"].lower() == "bearer"

    @skip_unless_kc
    def test_ropc_token_includes_realm_roles(self):
        tokens = _ropc_token(scope="openid roles")
        import base64, json as _json
        # Decode JWT body without verifying sig (we only care about claim presence)
        payload_b64 = tokens["access_token"].split(".")[1]
        padding = 4 - len(payload_b64) % 4
        payload = _json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * padding))
        # Keycloak puts realm roles under realm_access.roles
        assert "realm_access" in payload or "roles" in payload

    @skip_unless_kc
    def test_pkce_verifier_challenge_pair_valid(self):
        """Sanity check our PKCE helpers match the S256 spec."""
        verifier, challenge = _pkce_pair()
        digest = hashlib.sha256(verifier.encode()).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert challenge == expected


# ---------------------------------------------------------------------------
# Test: authenticated /mcp access with token
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestAuthenticatedMcpAccess:
    """After ROPC-acquired token, the MCP endpoint must accept it."""

    @skip_unless_kc
    def test_bearer_token_allows_mcp_tools_list(self):
        tokens = _ropc_token()
        access_token = tokens["access_token"]
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            headers={"Authorization": f"Bearer {access_token}"},
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        # 200 or a valid JSON-RPC response (not 401)
        assert r.status_code != 401, f"Token was rejected: {r.text[:200]}"

    @skip_unless_kc
    def test_expired_or_invalid_token_returns_401(self):
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.INVALID.SIGNATURE"},
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 401

    @skip_unless_kc
    def test_token_without_bearer_prefix_rejected(self):
        tokens = _ropc_token()
        access_token = tokens["access_token"]
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            headers={"Authorization": access_token},  # missing "Bearer "
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# How to run with Keycloak live:
#
#   KC_STACK_RUNNING=1 \
#   PROXY_BASE_URL=http://localhost:8000 \
#   KC_URL=http://localhost:8082 \
#   KC_TEST_USER=<user> KC_TEST_PASSWORD=<pass> \
#   python -m pytest proxy/tests/integration/test_oauth_pkce_flow.py -v
#
# Create the test user in Keycloak admin console:
#   Realm: mcp → Users → Add user → testuser
#   Set password (non-temporary) → Credentials tab
#   Ensure "claude-code" client has "Direct Access Grants" enabled
# ---------------------------------------------------------------------------
