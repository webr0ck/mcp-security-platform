from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class BitbucketAdapter:
    """
    Handles Bitbucket OAuth2 authorization_code flow.
    Mirrors M365Adapter interface for broker compatibility.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str],
        auth_url: str,
        token_url: str,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._auth_url = auth_url
        self._token_url = token_url

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
        return f"{self._auth_url}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str | None = None
    ) -> tuple[str, str, int]:
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._redirect_uri,
        }
        if code_verifier:  # CB-011: PKCE
            payload["code_verifier"] = code_verifier
        return await self._post_token(payload)

    async def refresh(self, refresh_token: str) -> tuple[str, str, int]:
        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        return await self._post_token(payload)

    async def _post_token(self, payload: dict) -> tuple[str, str, int]:
        from app.credential_broker.adapters.base import TokenExchangeError

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._token_url,
                data=payload,
                auth=(self._client_id, self._client_secret),
            )
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # CB-010: never surface exc.response.text (may echo
                # client_secret / partial token from the IdP error body).
                raise TokenExchangeError("bitbucket", exc.response.status_code) from None
            data = resp.json()
        return data["access_token"], data["refresh_token"], int(data["expires_in"])
