"""Effective LLM provider configuration (PRD-0005 R-1).

Merges env defaults (config.py OLLAMA_*) with admin overrides in the llm_config
table (absent row => env, SI-2). The API token lives in platform_secrets under
name 'llm-api' and is fetched separately.

SI-6 (no silent unauthenticated downgrade): api_token() distinguishes
  - no token configured  -> returns None (local ollama; call without auth)
  - token configured but unobtainable (Vault down / decrypt fail) -> raises
Callers (auditor.py) MUST treat a raise as "LLM unavailable", never send the
request unauthenticated.
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from app.core.config import get_settings
from app.services import platform_secrets

_LLM_TOKEN_NAME = "llm-api"

_CACHE_TTL = 30.0
_cache: "LlmSettings | None" = None
_cache_at: float = 0.0


@dataclass(frozen=True)
class LlmSettings:
    base_url: str
    model: str
    timeout_seconds: int
    enabled: bool


def _env_defaults() -> LlmSettings:
    s = get_settings()
    return LlmSettings(
        base_url=s.ollama_base_url,
        model=s.OLLAMA_MODEL,
        timeout_seconds=s.OLLAMA_TIMEOUT_SECONDS,
        enabled=True,
    )


async def effective(force: bool = False) -> LlmSettings:
    """Env defaults overlaid with the llm_config row; 30s cache."""
    global _cache, _cache_at
    now = time.monotonic()
    if not force and _cache is not None and (now - _cache_at) < _CACHE_TTL:
        return _cache
    base = _env_defaults()
    try:
        from app.core.asyncpg_pool import asyncpg_pool
        pool = asyncpg_pool.get()
        if pool is not None:
            row = await pool.fetchrow(
                "SELECT base_url, model, timeout_seconds, enabled FROM llm_config WHERE id=1"
            )
            if row is not None:
                base = LlmSettings(
                    base_url=row["base_url"] or base.base_url,
                    model=row["model"] or base.model,
                    timeout_seconds=row["timeout_seconds"] or base.timeout_seconds,
                    enabled=row["enabled"] if row["enabled"] is not None else base.enabled,
                )
    except Exception:
        # Fail to env defaults (SI-2) — never a silent insecure fallback.
        pass
    _cache, _cache_at = base, now
    return base


async def api_token() -> str | None:
    """Return the configured LLM API token, or None if none is configured.

    Raises (KMSError / InvalidTag / RuntimeError) if a token row EXISTS but
    cannot be decrypted — SI-6: the caller must treat that as unavailable, not
    fall back to an unauthenticated request.
    """
    if not await platform_secrets.secret_exists(_LLM_TOKEN_NAME):
        return None
    return await platform_secrets.get_secret(_LLM_TOKEN_NAME)


def invalidate() -> None:
    global _cache_at
    _cache_at = 0.0
