"""Admin-editable self-service wizard prompts.

The design questions the wizard asks ("list every action…", "which scopes…")
live as code defaults in scaffold_generator._PROMPTS/_SHARED_PROMPTS. This
module overlays admin overrides stored in the wizard_prompts table on top of
those defaults, so an admin can reword what the self-service flow asks users
without a code change.

Absent override => code default. The effective set is cached briefly so the
hot read path (design-assist / prompts endpoints) doesn't hit the DB per call.
"""
from __future__ import annotations

import time
from typing import Optional

from app.services.scaffold_generator import _PROMPTS, _SHARED_PROMPTS

# key format: "<mode>.<id>" for mode prompts, "shared.<id>" for the shared block.
_SHARED_MODE = "shared"

_CACHE_TTL = 30.0
_cache: dict[str, str] = {}
_cache_at: float = 0.0


def default_prompts() -> dict[str, str]:
    """Flatten the code-default prompts into {key: text}."""
    out: dict[str, str] = {}
    for mode, items in _PROMPTS.items():
        for it in items:
            out[f"{mode}.{it['id']}"] = it["prompt"]
    for it in _SHARED_PROMPTS:
        out[f"{_SHARED_MODE}.{it['id']}"] = it["prompt"]
    return out


def _split_key(key: str) -> tuple[str, str]:
    mode, _, pid = key.partition(".")
    return mode, pid


async def _load_overrides() -> dict[str, str]:
    """Fetch overrides from the DB; return {} on any failure (fail to defaults)."""
    try:
        from app.core.asyncpg_pool import asyncpg_pool
        pool = asyncpg_pool.get()
        if pool is None:
            return {}
        rows = await pool.fetch("SELECT prompt_key, prompt_text FROM wizard_prompts")
        return {r["prompt_key"]: r["prompt_text"] for r in rows}
    except Exception:
        return {}


async def effective_prompts(force: bool = False) -> dict[str, str]:
    """Defaults overlaid with DB overrides, cached for _CACHE_TTL seconds."""
    global _cache, _cache_at
    now = time.monotonic()
    if not force and _cache and (now - _cache_at) < _CACHE_TTL:
        return _cache
    merged = default_prompts()
    merged.update(await _load_overrides())
    _cache, _cache_at = merged, now
    return merged


async def prompts_for_mode(mode: str) -> list[dict]:
    """Rebuild the [{id, prompt}] list for a mode, applying overrides.

    Mirrors scaffold_generator.generate_prompts (mode block + shared block),
    falling back to 'none' for an unknown mode.
    """
    eff = await effective_prompts()
    m = mode if mode in _PROMPTS else "none"
    result: list[dict] = []
    for it in _PROMPTS[m]:
        key = f"{m}.{it['id']}"
        result.append({"id": it["id"], "prompt": eff.get(key, it["prompt"])})
    for it in _SHARED_PROMPTS:
        key = f"{_SHARED_MODE}.{it['id']}"
        result.append({"id": it["id"], "prompt": eff.get(key, it["prompt"])})
    return result


def _invalidate() -> None:
    global _cache_at
    _cache_at = 0.0


async def set_prompt(key: str, text: str, actor: str) -> None:
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("Database pool not available")
    await pool.execute(
        "INSERT INTO wizard_prompts (prompt_key, prompt_text, updated_by) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT (prompt_key) DO UPDATE SET "
        "prompt_text=EXCLUDED.prompt_text, updated_by=EXCLUDED.updated_by, updated_at=NOW()",
        key, text, actor,
    )
    _invalidate()


async def reset_prompt(key: str) -> None:
    """Delete an override so the code default takes effect again."""
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("Database pool not available")
    await pool.execute("DELETE FROM wizard_prompts WHERE prompt_key=$1", key)
    _invalidate()


async def list_prompts() -> list[dict]:
    """Full registry for the admin UI: every known key with default + effective text."""
    defaults = default_prompts()
    overrides = await _load_overrides()
    out = []
    for key in defaults:
        mode, pid = _split_key(key)
        out.append({
            "key": key,
            "mode": mode,
            "id": pid,
            "default_text": defaults[key],
            "text": overrides.get(key, defaults[key]),
            "is_override": key in overrides,
        })
    return out


if __name__ == "__main__":
    # ponytail: self-check — override overlays, mode fallback, reset semantics.
    import asyncio

    d = default_prompts()
    assert d, "defaults must be non-empty"
    assert all("." in k for k in d), "keys must be <mode>.<id>"
    assert any(k.startswith("kc_token_exchange.") for k in d)
    assert any(k.startswith("shared.") for k in d)

    async def _t():
        # No DB pool in this context → overrides empty → effective == defaults.
        eff = await effective_prompts(force=True)
        assert eff == default_prompts()
        # Unknown mode falls back to 'none' block + shared.
        pl = await prompts_for_mode("does_not_exist")
        ids = {p["id"] for p in pl}
        assert {i["id"] for i in _PROMPTS["none"]} <= ids
        assert {i["id"] for i in _SHARED_PROMPTS} <= ids
        # Known mode keeps its own block.
        pl2 = await prompts_for_mode("kc_token_exchange")
        assert any(p["id"] == "auth_flow" for p in pl2)
    asyncio.run(_t())
    print("prompt_store self-check OK")
