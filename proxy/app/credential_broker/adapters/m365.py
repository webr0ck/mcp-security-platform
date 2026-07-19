from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


class M365Adapter:
    """
    Handles Entra ID OAuth2 authorization_code flow with delegated permissions.
    Does NOT provision tokens autonomously — enrollment is driven by oauth.py router.
    Provides: build_auth_url(), exchange_code(), refresh().
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        tenant_id: str,
        redirect_uri: str,
        scopes: list[str],
        token_url: str,
        auth_url: str,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._tenant_id = tenant_id
        self._redirect_uri = redirect_uri
        self._scopes = scopes
        self._token_url = token_url
        self._auth_url = auth_url

    def build_auth_url(
        self, state: str, code_challenge: str | None = None, redirect_uri: str | None = None
    ) -> str:
        """redirect_uri override: enrollment can be reached from any host the
        proxy is exposed on (LAN IP, Tailscale, localhost) — see
        app.core.public_url.derive_public_base_url. Azure enforces an exact
        match against the app registration's redirect URI allowlist, so the
        SAME value used here must be reused verbatim in exchange_code() below
        (the caller persists it alongside the flow state for that reason).
        Falls back to the static configured redirect_uri when not given."""
        params = {
            "client_id": self._client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri or self._redirect_uri,
            "scope": " ".join(self._scopes) + " offline_access",
            "state": state,
            "response_mode": "query",
        }
        if code_challenge:  # CB-011: PKCE S256
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"
        return f"{self._auth_url}?{urlencode(params)}"

    async def exchange_code(
        self, code: str, code_verifier: str | None = None, redirect_uri: str | None = None
    ) -> tuple[str, str, int]:
        """Exchange authorization_code for (access_token, refresh_token, expires_in).
        redirect_uri must be the EXACT value passed to build_auth_url for this
        same flow — Microsoft rejects a mismatch.

        No client_secret here — live-verified against this platform's Azure app
        registration: it returns AADSTS700025 ("Client is public so neither
        'client_assertion' nor 'client_secret' should be presented") for this
        delegated/PKCE flow's redirect_uri, even though the SAME client_id/
        secret work fine for the separate app-only client_credentials grant
        (a confidential-client flow) — Azure treats the two grant types under
        different client-type rules for one registration. PKCE (code_verifier)
        is this flow's actual proof of possession, not a secret.
        """
        payload = {
            "grant_type": "authorization_code",
            "client_id": self._client_id,
            "code": code,
            "redirect_uri": redirect_uri or self._redirect_uri,
            "scope": " ".join(self._scopes) + " offline_access",
        }
        if code_verifier:  # CB-011: PKCE
            payload["code_verifier"] = code_verifier
        return await self._post_token(payload)

    async def refresh(self, refresh_token: str) -> tuple[str, str, int]:
        """Use refresh_token to get a new (access_token, refresh_token, expires_in).
        No client_secret — same public-client rule as exchange_code() above."""
        payload = {
            "grant_type": "refresh_token",
            "client_id": self._client_id,
            "refresh_token": refresh_token,
            "scope": " ".join(self._scopes) + " offline_access",
        }
        return await self._post_token(payload)

    async def _post_token(self, payload: dict) -> tuple[str, str, int]:
        from app.credential_broker.adapters.base import TokenExchangeError

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(self._token_url, data=payload)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as exc:
                # CB-010: never surface exc.response.text in the raised
                # exception/API response (may echo client_secret / partial
                # token from the IdP error body) — but DO log the AADSTS
                # error code server-side only (podman logs, never reaches
                # the caller): Microsoft's error_description is standardized
                # diagnostic text (e.g. "AADSTS7000215: Invalid client secret
                # is provided."), not a secret, and is the only way to tell
                # "bad secret" apart from "redirect_uri mismatch" apart from
                # "code already used" without guessing.
                try:
                    _body = exc.response.json()
                    logger.error(
                        "m365 token endpoint rejected request: status=%s error=%s description=%s",
                        exc.response.status_code, _body.get("error"), _body.get("error_description"),
                    )
                except Exception:
                    logger.error("m365 token endpoint rejected request: status=%s (non-JSON body)", exc.response.status_code)
                raise TokenExchangeError("m365", exc.response.status_code) from None
            data = resp.json()
        return data["access_token"], data["refresh_token"], int(data["expires_in"])


# --- Adapter plugin registration (see adapters/registry.py) ----------------
from app.credential_broker.adapters.registry import register_adapter


@register_adapter(
    name="m365", approach="A", requires=("ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET")
)
def _build_from_settings(settings):
    return M365Adapter(
        client_id=settings.ENTRA_CLIENT_ID,
        client_secret=settings.ENTRA_CLIENT_SECRET,
        tenant_id=settings.ENTRA_TENANT_ID,
        redirect_uri=settings.ENTRA_REDIRECT_URI,
        scopes=settings.entra_scopes_list,
        token_url=settings.entra_token_url,
        auth_url=settings.entra_auth_url,
    )
