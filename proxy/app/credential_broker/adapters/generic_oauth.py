"""
MCP Security Platform — Generic external OAuth 2.0 adapter (WP-A3: CR-04 remainder)

Unlike m365.py/dex.py/bitbucket.py (each a statically env-var-configured
adapter for exactly one external IdP), GenericOAuthAdapter is parameterized
entirely at construction time from a SERVER's reviewer-approved IdP config
(server_registry.approved_upstream_idp_config, set by WP-A2's approval gate)
— so onboarding a new external OAuth server (e.g. a customer's own Atlassian
Jira Cloud instance, a SaaS product's OAuth app) requires zero new Python
module or env var, just an onboarding submission + reviewer approval.

Same approach-A interface as every other per-user adapter in this package
(build_auth_url/exchange_code/refresh) so it drops into the existing broker
resolution path (credential_broker/broker.py::_resolve_a) and enrollment flow
(routers/oauth.py) unchanged.

NOT registered via @register_adapter — it has no static, always-the-same
configuration to discover at import time. Instances are built per-server by
adapters/dynamic_external_oauth.py::resolve_external_oauth_adapter, which
reads server_registry.approved_upstream_idp_config (never the submitter-
requested upstream_idp_config directly — see docs/spec/01-authentication.md
§4.5) and the server's admin-provisioned client_secret from credential_store.

client_auth_method (CR-13's requested-vs-approved policy dimension) controls
how the client credentials are sent to the token endpoint:
  - "client_secret_post" (default): client_id/client_secret as form fields.
  - "client_secret_basic": HTTP Basic auth header, client_id/secret NOT in
    the form body (some IdPs, e.g. Atlassian, require this).
"""
from __future__ import annotations

import base64
import logging
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class GenericOAuthAdapter:
    """
    Generic OAuth 2.0 authorization_code + refresh_token flow (RFC 6749),
    for any external IdP that isn't Keycloak (kc_token_exchange) or Entra
    (entra_user_token). Does NOT provision tokens autonomously — enrollment
    is driven by routers/oauth.py, identical to every other approach-A
    adapter in this package.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        authorization_endpoint: str,
        token_endpoint: str,
        client_auth_method: str = "client_secret_post",
    ) -> None:
        if client_auth_method not in ("client_secret_post", "client_secret_basic"):
            raise ValueError(f"unsupported client_auth_method: {client_auth_method!r}")
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._client_auth_method = client_auth_method

    def build_auth_url(self, state: str, code_challenge: str | None = None) -> str:
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
        }
        if code_challenge:  # CB-011: PKCE S256
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self._authorization_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str | None = None
    ) -> tuple[str, str, int]:
        """Exchange authorization_code for (access_token, refresh_token, expires_in)."""
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(self._scopes),
        }
        if code_verifier:  # CB-011: PKCE
            payload["code_verifier"] = code_verifier
        return await self._post_token(payload)

    async def refresh(self, refresh_token: str) -> tuple[str, str, int]:
        """Use refresh_token to get a new (access_token, refresh_token, expires_in)."""
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": " ".join(self._scopes),
        }
        return await self._post_token(payload)

    def _auth_kwargs(self, payload: dict) -> dict:
        """client_auth_method dispatch: client_secret_post puts creds in the form
        body; client_secret_basic sends them as an HTTP Basic Authorization
        header instead (and MUST NOT also be present in the body)."""
        if self._client_auth_method == "client_secret_basic":
            token = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
            return {"headers": {"Authorization": f"Basic {token}"}, "data": payload}
        return {"data": {**payload, "client_id": self._client_id, "client_secret": self._client_secret}}

    async def _post_token(self, payload: dict) -> tuple[str, str, int]:
        from app.credential_broker.adapters.base import TokenExchangeError

        kwargs = self._auth_kwargs(payload)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(self._token_endpoint, **kwargs)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # CB-010: never surface exc.response.text (may echo
                # client_secret / partial token from the IdP error body).
                raise TokenExchangeError("external_oauth", exc.response.status_code) from None
            data = resp.json()
        # Some IdPs (e.g. rotating-refresh-token providers) omit refresh_token
        # on a refresh-grant response when the old one is still valid —
        # matches dex.py's .get() defensive pattern.
        refresh_token: str = data.get("refresh_token", "")
        return data["access_token"], refresh_token, int(data.get("expires_in", 3600))
