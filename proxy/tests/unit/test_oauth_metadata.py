"""
OAuth 2.1 / MCP discovery endpoint tests.

Coverage:
  - /.well-known/oauth-protected-resource (RFC 9728)
  - /.well-known/oauth-authorization-server (RFC 8414 / MCP §4.2)
  - POST /oauth/register (RFC 7591 bridge — always returns "claude-code" public client)
  - _validate_redirect_uri(): scheme + hostname guard
  - Zero-credential flow: 401 WWW-Authenticate header carries resource_metadata

These tests do NOT require Keycloak; the IdP discovery is mocked.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# App bootstrap (mirrors other unit tests in this repo)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def client():
    from app.main import app
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


# ---------------------------------------------------------------------------
# /.well-known/oauth-protected-resource (RFC 9728)
# ---------------------------------------------------------------------------

class TestProtectedResourceMetadata:
    def test_returns_200(self, client):
        r = client.get("/.well-known/oauth-protected-resource")
        assert r.status_code == 200

    def test_has_required_fields(self, client):
        r = client.get("/.well-known/oauth-protected-resource")
        body = r.json()
        assert "resource" in body
        assert "authorization_servers" in body
        assert "bearer_methods_supported" in body

    def test_authorization_servers_is_list(self, client):
        r = client.get("/.well-known/oauth-protected-resource")
        assert isinstance(r.json()["authorization_servers"], list)
        assert len(r.json()["authorization_servers"]) >= 1

    def test_bearer_methods_includes_header(self, client):
        body = client.get("/.well-known/oauth-protected-resource").json()
        assert "header" in body["bearer_methods_supported"]

    def test_includes_issuer(self, client):
        # Codex >=0.143 (rmcp PR896 / openai/codex#31573) fails OAuth with
        # "missing required issuer" against a protected-resource metadata
        # document that omits "issuer". RFC 9728 doesn't mandate it, but this
        # is the minimal platform-side accommodation (WS-5).
        # OIDC_ISSUER_URL is unset in this test environment (no .env.lab), so
        # patch it to a realistic value — production always sets it.
        with patch("app.routers.oauth_metadata.settings.OIDC_ISSUER_URL", "http://keycloak.test/realms/mcp"):
            body = client.get("/.well-known/oauth-protected-resource").json()
        assert body.get("issuer"), "protected-resource metadata must carry a non-empty issuer"

    def test_issuer_present_on_resource_scoped_variant(self, client):
        with patch("app.routers.oauth_metadata.settings.OIDC_ISSUER_URL", "http://keycloak.test/realms/mcp"):
            body = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert body.get("issuer")

    def test_issuer_addition_does_not_disturb_existing_fields(self, client):
        # Additive-only change: resource/authorization_servers/bearer_methods_supported
        # must be untouched so Claude Code's existing flow doesn't regress.
        body = client.get("/.well-known/oauth-protected-resource").json()
        assert "resource" in body
        assert isinstance(body["authorization_servers"], list) and len(body["authorization_servers"]) == 1
        assert body["bearer_methods_supported"] == ["header"]


# ---------------------------------------------------------------------------
# /.well-known/oauth-authorization-server (RFC 8414)
# ---------------------------------------------------------------------------

class TestAuthorizationServerMetadata:
    def _mock_fetch(self):
        return {
            "issuer": "http://keycloak.test/realms/mcp",
            "authorization_endpoint": "http://keycloak.test/realms/mcp/protocol/openid-connect/auth",
            "token_endpoint": "http://keycloak.test/realms/mcp/protocol/openid-connect/token",
            "jwks_uri": "http://keycloak.test/realms/mcp/protocol/openid-connect/certs",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email", "roles", "offline_access"],
        }

    def test_returns_200(self, client):
        with patch("app.routers.oauth_metadata._fetch_idp_discovery", AsyncMock(return_value=self._mock_fetch())):
            r = client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200

    def test_injects_registration_endpoint(self, client):
        with patch("app.routers.oauth_metadata._fetch_idp_discovery", AsyncMock(return_value=self._mock_fetch())):
            body = client.get("/.well-known/oauth-authorization-server").json()
        assert "registration_endpoint" in body
        assert body["registration_endpoint"].endswith("/oauth/register")

    def test_pkce_s256_advertised(self, client):
        with patch("app.routers.oauth_metadata._fetch_idp_discovery", AsyncMock(return_value=self._mock_fetch())):
            body = client.get("/.well-known/oauth-authorization-server").json()
        assert body["code_challenge_methods_supported"] == ["S256"]

    def test_scopes_filtered_to_claude_code_client(self, client):
        # Should NOT include realm-wide scopes; only the set enabled for claude-code.
        with patch("app.routers.oauth_metadata._fetch_idp_discovery", AsyncMock(return_value=self._mock_fetch())):
            body = client.get("/.well-known/oauth-authorization-server").json()
        for scope in body["scopes_supported"]:
            assert scope in {"openid", "profile", "email", "roles", "offline_access"}

    def test_fallback_when_idp_unavailable(self, client):
        # If Keycloak is unreachable, proxy returns minimal fallback (not 500).
        with patch("app.routers.oauth_metadata._fetch_idp_discovery", AsyncMock(return_value={})):
            r = client.get("/.well-known/oauth-authorization-server")
        assert r.status_code == 200
        body = r.json()
        assert "token_endpoint" in body
        assert "registration_endpoint" in body


# ---------------------------------------------------------------------------
# POST /oauth/register (RFC 7591 bridge)
# ---------------------------------------------------------------------------

class TestDynamicClientRegistration:
    """Rate-limiter is mocked to always allow so tests don't share a counter."""

    @pytest.fixture(autouse=True)
    def _bypass_rate_limit(self):
        with patch(
            "app.routers.oauth_metadata._check_register_rate_limit",
            AsyncMock(return_value=True),
        ):
            yield

    def test_returns_201_with_empty_body(self, client):
        r = client.post("/oauth/register", json={})
        assert r.status_code == 201

    def test_returns_claude_code_client_id(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert body["client_id"] == "claude-code"

    def test_no_client_secret_returned(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert "client_secret" not in body

    def test_token_endpoint_auth_method_is_none(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert body["token_endpoint_auth_method"] == "none"

    def test_pkce_s256_in_registration_response(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert "S256" in body["code_challenge_methods_supported"]

    def test_echoes_valid_https_redirect_uris(self, client):
        uris = ["https://app.example.com/callback", "https://localhost:3000/cb"]
        body = client.post("/oauth/register", json={"redirect_uris": uris}).json()
        assert body["redirect_uris"] == uris

    def test_echoes_http_loopback_redirect_uris(self, client):
        uris = ["http://localhost:8080/callback", "http://127.0.0.1:9000/cb"]
        body = client.post("/oauth/register", json={"redirect_uris": uris}).json()
        assert body["redirect_uris"] == uris

    def test_rejects_javascript_scheme(self, client):
        r = client.post("/oauth/register", json={"redirect_uris": ["javascript:alert(1)"]})
        assert r.status_code == 422

    def test_rejects_data_uri_scheme(self, client):
        r = client.post("/oauth/register", json={"redirect_uris": ["data:text/html,<h1>x</h1>"]})
        assert r.status_code == 422

    def test_rejects_file_scheme(self, client):
        r = client.post("/oauth/register", json={"redirect_uris": ["file:///etc/passwd"]})
        assert r.status_code == 422

    def test_rejects_http_non_loopback(self, client):
        r = client.post("/oauth/register", json={"redirect_uris": ["http://evil.com/steal"]})
        assert r.status_code == 422

    def test_rejects_http_with_internal_host(self, client):
        # Prevents open-redirect to internal services via HTTP.
        r = client.post("/oauth/register", json={"redirect_uris": ["http://internal-svc:8080/cb"]})
        assert r.status_code == 422

    def test_grant_types_includes_authorization_code(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert "authorization_code" in body["grant_types"]

    def test_scope_includes_openid(self, client):
        body = client.post("/oauth/register", json={}).json()
        assert "openid" in body["scope"]


# ---------------------------------------------------------------------------
# 401 challenge — unauthenticated /mcp request must include resource_metadata
# ---------------------------------------------------------------------------

class TestUnauthenticatedMcpChallenge:
    def test_unauthenticated_returns_401(self, client):
        r = client.post("/mcp", json={"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        assert r.status_code in (401, 403)

    def test_401_has_www_authenticate_header(self, client):
        r = client.post("/mcp", json={"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        if r.status_code == 401:
            assert "WWW-Authenticate" in r.headers


# ---------------------------------------------------------------------------
# _validate_redirect_uri unit tests (direct import)
# ---------------------------------------------------------------------------

class TestValidateRedirectUri:
    def _validate(self, uri: str):
        from app.routers.oauth_metadata import _validate_redirect_uri
        _validate_redirect_uri(uri)

    def test_accepts_https(self):
        self._validate("https://example.com/callback")

    def test_accepts_http_localhost(self):
        self._validate("http://localhost:8080/cb")

    def test_accepts_http_127(self):
        self._validate("http://127.0.0.1:4000/cb")

    def test_rejects_http_non_loopback(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self._validate("http://attacker.com/steal")
        assert exc_info.value.status_code == 422

    def test_rejects_custom_scheme(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            self._validate("myapp://callback")
        assert exc_info.value.status_code == 422

    def test_rejects_javascript_scheme(self):
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            self._validate("javascript:void(0)")
