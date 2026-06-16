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
KC_TEST_USER = os.environ.get("KC_TEST_USER", "alice")
KC_TEST_PASSWORD = os.environ.get("KC_TEST_PASSWORD", "")  # set via KC_TEST_PASSWORD env var
# lab-test is the ROPC client (directAccessGrantsEnabled=true); claude-code is PKCE-only (public)
KC_ROPC_CLIENT = "lab-test"
KC_ROPC_SECRET = os.environ.get("KC_LAB_TEST_SECRET", "-lab-test-secret")
KC_CLIENT_ID = "claude-code"  # used in discovery chain tests only


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


def _ropc_token(scope: str = "openid profile email roles", username: str | None = None, password: str | None = None) -> dict:
    """Fetch a token via ROPC using lab-test client (automation stand-in for browser login).

    Uses lab-test client (directAccessGrantsEnabled=true) — NOT claude-code (PKCE-only).
    KC_URL must match OIDC_ISSUER_URL so that iss claim passes proxy validation.
    """
    resp = httpx.post(
        _token_endpoint(),
        data={
            "grant_type": "password",
            "client_id": KC_ROPC_CLIENT,
            "client_secret": KC_ROPC_SECRET,
            "username": username or KC_TEST_USER,
            "password": password or KC_TEST_PASSWORD,
            "scope": scope,
        },
    )
    assert resp.status_code == 200, f"ROPC failed: {resp.text}"
    return resp.json()


def _token_claims(token_str: str) -> dict:
    """Decode JWT payload without signature verification (test utility only)."""
    import base64 as _b64
    import json as _json
    payload_b64 = token_str.split(".")[1]
    padding = 4 - len(payload_b64) % 4
    return _json.loads(_b64.urlsafe_b64decode(payload_b64 + "=" * padding))


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
        payload = _token_claims(tokens["access_token"])
        # Keycloak puts realm roles under realm_access.roles
        assert "realm_access" in payload or "roles" in payload

    @skip_unless_kc
    def test_ropc_token_audience_includes_mcp_proxy(self):
        """lab-test client must have audience-mcp-proxy mapper wired."""
        tokens = _ropc_token()
        payload = _token_claims(tokens["access_token"])
        aud = payload.get("aud", "")
        aud_list = [aud] if isinstance(aud, str) else aud
        assert "mcp-proxy" in aud_list, f"aud does not include mcp-proxy: {aud}"

    @skip_unless_kc
    def test_ropc_token_issuer_matches_oidc_config(self):
        """iss in token must match OIDC_ISSUER_URL so proxy validation passes."""
        tokens = _ropc_token()
        payload = _token_claims(tokens["access_token"])
        expected_iss = f"{KC_URL}/realms/{KC_REALM}"
        assert payload.get("iss") == expected_iss, (
            f"Issuer mismatch: token has '{payload.get('iss')}', expected '{expected_iss}'. "
            f"Ensure KC_URL matches OIDC_ISSUER_URL and Keycloak frontendUrl is set."
        )

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

    @skip_unless_kc
    def test_alice_sees_meta_tools_and_registry(self):
        """Admin alice must see all 5 meta-tools plus at least some registry tools."""
        tokens = _ropc_token()
        r = httpx.post(
            f"{PROXY_BASE_URL}/mcp",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        )
        assert r.status_code == 200
        tools = r.json().get("result", {}).get("tools", [])
        names = {t["name"] for t in tools}
        meta_tools = {"platform_info", "security_pulse_summary", "list_registered_tools",
                      "enrollment_status", "invoke_tool"}
        assert meta_tools.issubset(names), f"Missing meta-tools: {meta_tools - names}"
        assert len(tools) >= 15, f"Expected ≥15 tools for alice admin, got {len(tools)}"

    @skip_unless_kc
    def test_refresh_token_flow(self):
        """ROPC should return a refresh_token; using it must yield a fresh access_token."""
        tokens = _ropc_token(scope="openid roles offline_access")
        refresh_token = tokens.get("refresh_token")
        assert refresh_token, "No refresh_token in ROPC response (add offline_access scope)"

        r = httpx.post(
            _token_endpoint(),
            data={
                "grant_type": "refresh_token",
                "client_id": KC_ROPC_CLIENT,
                "client_secret": KC_ROPC_SECRET,
                "refresh_token": refresh_token,
            },
        )
        assert r.status_code == 200, f"Token refresh failed: {r.text}"
        refreshed = r.json()
        assert "access_token" in refreshed
        assert refreshed["access_token"] != tokens["access_token"], "Refresh should yield new token"


# ---------------------------------------------------------------------------
# How to run with Keycloak live (full automated OAuth test — no browser):
#
#   KC_STACK_RUNNING=1 \
#   PROXY_BASE_URL=http://localhost:8000 \
#   KC_URL=http://localhost:8082 \
#   KC_TEST_USER=alice \
#   KC_TEST_PASSWORD=<DEX_ALICE_PASSWORD from .env> \
#   python -m pytest proxy/tests/integration/test_oauth_pkce_flow.py -v
#
# KC_URL must be the same address used in OIDC_ISSUER_URL (.env) so that the
# iss claim in ROPC tokens matches what the proxy validates against.
#
# Shortcut via Makefile:
#   make test-oauth     (sets the right env vars from .env automatically)
#
# How ROPC automation works:
#   - lab-test client (directAccessGrantsEnabled=true) issues tokens directly.
#   - This replaces the browser PKCE popup for CI/automated tests.
#   - The claude-code public client (PKCE-only) is still used in production flows.
#   - NEVER add directAccessGrantsEnabled to claude-code or mcp-proxy clients.
# ---------------------------------------------------------------------------
