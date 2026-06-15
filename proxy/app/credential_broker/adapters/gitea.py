from __future__ import annotations

from datetime import datetime, timezone, timedelta

from app.credential_broker.adapters.base import BaseAdapter
from app.credential_broker.models import Token


class GiteaAdapter(BaseAdapter):
    """
    Injects a shared Gitea admin token for all users (shared service account pattern).
    The token is static — provision() always returns it; revoke() is a no-op.
    """

    def __init__(self, admin_token: str) -> None:
        self._token = admin_token

    async def provision(self, user_sub: str, session_id: str) -> Token:
        return Token(
            value=self._token,
            expires_at=datetime.now(timezone.utc) + timedelta(days=3650),
            token_id="static",
        )

    async def revoke(self, token_id: str) -> None:
        pass  # static token — nothing to revoke


# --- Adapter plugin registration (see adapters/registry.py) ----------------
from app.credential_broker.adapters.registry import register_adapter


@register_adapter(name="gitea", approach="B", requires=("GITEA_ADMIN_TOKEN",))
def _build_from_settings(settings):
    return GiteaAdapter(admin_token=settings.GITEA_ADMIN_TOKEN)
