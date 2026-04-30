"""
MCP Security Platform — API Key Pydantic Models

Used for API key creation and metadata retrieval.
Raw key values are NEVER returned after the initial create response.
Only key_id, key_prefix, and metadata are exposed in subsequent reads.

Per ARCHITECTURE.md §12 and INV-008: no secrets in persisted records.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class APIKeyCreate(BaseModel):
    """Request body for API key creation (admin-only operation)."""

    client_id: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=255)
    expires_at: datetime | None = None


class APIKeyCreateResponse(BaseModel):
    """
    Response from API key creation.
    The raw_key field is returned ONCE and never stored.
    After this response, only the hash is kept.
    """

    key_id: UUID
    client_id: str
    raw_key: str  # Shown once; never stored or retrievable again
    key_prefix: str  # First 12 chars for identification
    description: str | None = None
    created_at: datetime
    expires_at: datetime | None = None


class APIKey(BaseModel):
    """
    API key metadata record.
    raw_key is NEVER included in this model — only key_id and prefix.
    """

    key_id: UUID
    client_id: str
    key_prefix: str
    description: str | None = None
    created_by: str
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked: bool = False
    revoked_at: datetime | None = None
    created_at: datetime
