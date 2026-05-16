from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone, timedelta

import httpx

from app.credential_broker.adapters.base import BaseAdapter
from app.credential_broker.models import Token

logger = logging.getLogger(__name__)


class NetboxAdapter(BaseAdapter):
    """
    Creates per-user tokens via Netbox admin API.
    sub_to_username: callable that maps passport user_sub to Netbox username.
    Default mapping: strip domain from email (alice@corp.com -> alice).
    """

    def __init__(
        self,
        base_url: str,
        admin_token: str,
        sub_to_username: Callable[[str], str] | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "Authorization": f"Token {admin_token}",
            "Content-Type": "application/json",
        }
        self._sub_to_username = sub_to_username or (lambda sub: sub.split("@")[0])

    async def provision(self, user_sub: str, session_id: str) -> Token:
        username = self._sub_to_username(user_sub)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=28800)
        payload = {
            "user": username,
            "description": f"mcp-session-{session_id}",
            "expires": expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/users/tokens/",
                json=payload,
                headers=self._headers,
            )
            resp.raise_for_status()
            data = resp.json()

        return Token(value=data["key"], expires_at=expires_at, token_id=str(data["id"]))

    async def revoke(self, token_id: str) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(
                f"{self._base_url}/api/users/tokens/{token_id}/",
                headers=self._headers,
            )
            resp.raise_for_status()
        logger.info("netbox_token_revoked", extra={"token_id": token_id})
