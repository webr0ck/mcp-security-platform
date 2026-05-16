from __future__ import annotations
from abc import ABC, abstractmethod
from app.credential_broker.models import Token


class TokenExchangeError(Exception):
    """
    CB-010 / INV-002: raised when an OAuth token endpoint returns an error.

    Carries ONLY the HTTP status code — never the raw IdP response body, which
    can echo client secrets or partial tokens and would otherwise propagate
    into the default 500 handler / structured logs unredacted.
    """

    def __init__(self, service: str, status_code: int) -> None:
        self.service = service
        self.status_code = status_code
        super().__init__(f"{service} token endpoint returned HTTP {status_code}")


class BaseAdapter(ABC):
    """Interface all Approach B adapters must implement."""

    @abstractmethod
    async def provision(self, user_sub: str, session_id: str) -> Token:
        """Create a user-scoped token in the downstream service."""

    @abstractmethod
    async def revoke(self, token_id: str) -> None:
        """Delete the token from the downstream service."""
