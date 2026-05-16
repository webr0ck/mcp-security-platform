from __future__ import annotations

from app.credential_broker.adapters.base import BaseAdapter
from app.credential_broker.models import Token


class ApproachB:
    """Auto-provision per-user tokens; never persist to DB."""

    def __init__(self, adapter: BaseAdapter) -> None:
        self._adapter = adapter

    async def resolve(self, user_sub: str, session_id: str) -> Token:
        return await self._adapter.provision(user_sub=user_sub, session_id=session_id)

    async def revoke(self, token_id: str) -> None:
        await self._adapter.revoke(token_id)
