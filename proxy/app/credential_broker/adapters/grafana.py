from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

import httpx

from app.credential_broker.adapters.base import BaseAdapter
from app.credential_broker.models import Token

logger = logging.getLogger(__name__)


class GrafanaAdapter(BaseAdapter):
    """
    Creates per-user named tokens on a Grafana service account.
    Token name: mcp-{user_sub}-{session_id} (truncated to 100 chars).
    TTL matches BROKER_SESSION_TTL_SECONDS.
    """

    def __init__(self, base_url: str, service_account_id: int, admin_token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._sa_id = service_account_id
        self._headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    async def provision(self, user_sub: str, session_id: str) -> Token:
        name = f"mcp-{user_sub}-{session_id}"[:100]
        url = f"{self._base_url}/api/serviceaccounts/{self._sa_id}/tokens"
        payload = {"name": name, "role": "Viewer", "secondsToLive": 28800}

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers=self._headers)
            resp.raise_for_status()
            data = resp.json()

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=28800)
        return Token(value=data["key"], expires_at=expires_at, token_id=str(data["id"]))

    async def revoke(self, token_id: str) -> None:
        url = f"{self._base_url}/api/serviceaccounts/{self._sa_id}/tokens/{token_id}"
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.delete(url, headers=self._headers)
            resp.raise_for_status()
        logger.info("grafana_token_revoked", extra={"token_id": token_id})
