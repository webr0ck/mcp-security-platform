from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class Token:
    """Represents a short-lived downstream access token."""
    value: str
    expires_at: datetime
    token_id: str

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def zero(self) -> None:
        """Overwrite value in-place — best-effort in CPython."""
        object.__setattr__(self, "value", "")


@dataclass
class CredentialResult:
    """What broker.resolve() returns to the invocation service."""
    token: str
    expires_at: datetime
    approach: str      # "A" or "B"
    service: str
    token_id: str | None = None

    def zero(self) -> None:
        object.__setattr__(self, "token", "")


@dataclass
class StoredCredential:
    """Row shape for credential_store table (Approach A only)."""
    user_sub: str
    service: str
    encrypted_blob: bytes
