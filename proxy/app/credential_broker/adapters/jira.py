"""
MCP Security Platform — Atlassian Jira Cloud OAuth 2.0 3LO adapter
(WP-A3: CR-04 fast-follow, D2 = droppable — not a finalisation blocker)

Statically-registered, platform-wide adapter (env-var configured), same
shape as m365.py/dex.py/bitbucket.py — this is the Jira-specific instance the
issue sketch calls out by name; the generic mechanism (any OTHER external
IdP, self-service-onboarded per server) is adapters/generic_oauth.py +
dynamic_external_oauth.py, built separately in this same package.

Known simplification (droppable-scope, documented rather than silently
dropped): real Jira Cloud API calls additionally require a `cloudId`,
resolved via a separate `GET https://api.atlassian.com/oauth/token/
accessible-resources` call using the freshly-minted access_token, then
prefixing API paths with `/ex/jira/{cloudId}/...`. That resolution step is
NOT implemented here — this adapter only handles the OAuth token
lifecycle (authorize/exchange/refresh) that credential_broker/broker.py's
approach-A flow needs. A tool wired to injection_mode='oauth_user_token'-like
per-user Jira access gets a valid Atlassian access_token injected; resolving
it to a specific site's cloudId is left to the downstream Jira MCP tool
implementation (it already needs to know its own site), not the platform.
"""
from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)

# Atlassian's OAuth 2.0 (3LO) endpoints — fixed, not tenant-specific (unlike
# Entra's per-tenant URL). https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/
_AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
_TOKEN_URL = "https://auth.atlassian.com/oauth/token"


class JiraAdapter:
    """
    Handles Atlassian Jira Cloud OAuth 2.0 3LO authorization_code flow.
    Mirrors BitbucketAdapter/M365Adapter's interface for broker compatibility.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes

    def build_auth_url(
        self, state: str, code_challenge: str | None = None, redirect_uri: str | None = None
    ) -> str:
        """redirect_uri override: see M365Adapter.build_auth_url for why."""
        params = {
            "audience": "api.atlassian.com",
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri or self._redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
            # prompt=consent per Atlassian's docs — otherwise a returning user
            # who already granted access silently skips the consent screen,
            # which would bypass this platform's own D1 consent-page gate.
            "prompt": "consent",
        }
        if code_challenge:  # CB-011: PKCE S256
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{_AUTHORIZE_URL}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str | None = None, redirect_uri: str | None = None
    ) -> tuple[str, str, int]:
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": redirect_uri or self._redirect_uri,
        }
        if code_verifier:  # CB-011: PKCE
            payload["code_verifier"] = code_verifier
        return await self._post_token(payload)

    async def refresh(self, refresh_token: str) -> tuple[str, str, int]:
        payload = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
        }
        return await self._post_token(payload)

    async def _post_token(self, payload: dict) -> tuple[str, str, int]:
        from app.credential_broker.adapters.base import TokenExchangeError

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(_TOKEN_URL, json=payload)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # CB-010: never surface exc.response.text (may echo
                # client_secret / partial token from the IdP error body).
                raise TokenExchangeError("jira", exc.response.status_code) from None
            data = resp.json()
        # Atlassian rotates refresh tokens on every use (offline_access) —
        # always present on a successful response, unlike Dex's optional field.
        return data["access_token"], data["refresh_token"], int(data["expires_in"])


# --- Adapter plugin registration (see adapters/registry.py) ----------------
from app.credential_broker.adapters.registry import register_adapter


@register_adapter(
    name="jira", approach="A", requires=("JIRA_OAUTH_CLIENT_ID", "JIRA_OAUTH_CLIENT_SECRET")
)
def _build_from_settings(settings):
    return JiraAdapter(
        client_id=settings.JIRA_OAUTH_CLIENT_ID,
        client_secret=settings.JIRA_OAUTH_CLIENT_SECRET,
        redirect_uri=settings.JIRA_OAUTH_REDIRECT_URI,
        scopes=settings.jira_oauth_scopes_list,
    )
