from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class DexAdapter:
    """
    Handles Dex local OIDC authorization_code flow.
    Does NOT provision tokens autonomously — enrollment is driven by oauth.py router.
    Provides: build_auth_url(), exchange_code(), refresh().
    """

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        internal_issuer_url: str = "",
    ) -> None:
        self._issuer_url = issuer_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        # Auth URL uses the browser-facing issuer; token URL uses the internal
        # one so the proxy container can reach Dex without going through the host.
        _internal = internal_issuer_url or issuer_url
        self._token_url = f"{_internal}/token"
        self._auth_url = f"{issuer_url}/auth"

    def build_auth_url(self, state: str, code_challenge: str | None = None) -> str:
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": self._redirect_uri,
            "scope": " ".join(self._scopes),
            "state": state,
            # NOTE: response_mode is an MSAL/Entra extension — NOT part of
            # standard OIDC/RFC 6749. Dex does not support it; omit to avoid
            # sending an unrecognised parameter that could confuse Dex or
            # future IdP swaps.
        }
        if code_challenge:  # CB-011: PKCE S256 (Dex supports it natively)
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self._auth_url}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str | None = None
    ) -> tuple[str, str, int]:
        """Exchange authorization_code for (access_token, refresh_token, expires_in)."""
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
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
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": refresh_token,
            "scope": " ".join(self._scopes),
        }
        return await self._post_token(payload)

    async def _post_token(self, payload: dict) -> tuple[str, str, int]:
        from app.credential_broker.adapters.base import TokenExchangeError

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(self._token_url, data=payload)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # CB-010: never surface exc.response.text (may echo
                # client_secret / partial token from the IdP error body).
                raise TokenExchangeError("dex", exc.response.status_code) from None
            data = resp.json()
        # Dex only returns refresh_token when offline_access scope is granted
        # AND the server's issuer config allows refresh tokens. Use .get() to
        # avoid KeyError when the server omits the field (e.g., short-lived
        # sessions without offline_access or server-side refresh disabled).
        refresh_token: str = data.get("refresh_token", "")
        return data["access_token"], refresh_token, int(data["expires_in"])


# --- Adapter plugin registration (see adapters/registry.py) ----------------
from app.credential_broker.adapters.registry import register_adapter


@register_adapter(
    name="dex", approach="A", requires=("DEX_CLIENT_ID", "DEX_CLIENT_SECRET")
)
def _build_from_settings(settings):
    return DexAdapter(
        issuer_url=settings.DEX_ISSUER_URL,
        client_id=settings.DEX_CLIENT_ID,
        client_secret=settings.DEX_CLIENT_SECRET,
        redirect_uri=settings.DEX_REDIRECT_URI,
        scopes=settings.dex_scopes_list,
        internal_issuer_url=settings.dex_internal_issuer_url,
    )
