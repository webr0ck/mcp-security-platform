"""Fail-closed per-principal taint store for the B-coarse floor (PRD-0001 M2).

INV-015 discipline, and the deliberate INVERSE of the `mcp_session:*` cache
(`invocation.py:_get_or_create_session`, which fails OPEN):

  * read error / unavailable store  -> treat as TAINTED (deny high sinks)
  * write failure                   -> raise, so the caller fails the in-flight
                                       request closed (write-before-forward)

The store keys on `client_id` — the logical identity (e.g. "alice@corp") that is
stable across all auth methods. Using `principal_id` (which encodes the auth method
prefix: "human:oidc-issuer:alice" vs "human:apikey:alice") would allow taint evasion
by switching from an OIDC JWT to an API key for the same account (LOGIC-005).

A distinct `mcp_taint:` namespace ensures it is never confused with the fail-open
session cache.

The Redis-pool plumbing lives in the thin `*_for_principal` wrappers; the core
`is_tainted` / `mark_tainted` take the client explicitly so the fail-closed branching
is unit-testable without Redis.
"""

from __future__ import annotations

import hashlib
import logging

logger = logging.getLogger(__name__)

# Taint persists for the logical session. Generous TTL so it does not clear
# mid-session. NOTE (appsec L-2): RFC §8.1 says "on expiry, re-derive as tainted";
# this B-coarse store instead lets a key simply expire to clean after a long idle,
# because without a true session model there is nothing to re-derive from. Accepted
# for M1/M2: the window is the full TTL, and a long-idle session re-deriving clean is
# a deliberate availability trade-off, not a mid-session reset. A learned/derived
# session model is future work.
DEFAULT_TAINT_TTL_SECONDS = 3600


class TaintStoreError(Exception):
    """Raised when the taint bit cannot be durably written (caller must 500)."""


def taint_key(client_id: str) -> str:
    """Namespaced, hashed key keyed on logical identity (client_id), not auth method.

    Using client_id (stable across OIDC/API-key/session) prevents taint evasion by
    switching auth methods (LOGIC-005 fix). Distinct from the fail-open
    `mcp_session:` cache.
    """
    digest = hashlib.sha256(client_id.encode()).hexdigest()[:16]
    return f"mcp_taint:{digest}"


async def is_tainted(client, client_id: str | None) -> bool:
    """True if the identity's session is tainted. Fail-CLOSED: unknown -> True."""
    if client_id is None:
        logger.warning("Taint check with no client_id; failing closed (tainted)")
        return True
    if client is None:
        logger.warning("Taint store unavailable on read; failing closed (tainted)")
        return True
    try:
        value = await client.get(taint_key(client_id))
    except Exception as exc:  # noqa: BLE001 - any read failure must fail closed
        logger.warning("Taint store read failed; failing closed (tainted): %s", exc)
        return True
    return value is not None


async def mark_tainted(
    client, client_id: str | None, ttl: int = DEFAULT_TAINT_TTL_SECONDS
) -> None:
    """Durably set the taint bit. Raises TaintStoreError if it cannot be written."""
    if client_id is None:
        raise TaintStoreError("no client_id to taint; failing closed")
    if client is None:
        raise TaintStoreError("taint store unavailable; cannot mark tainted")
    try:
        await client.setex(taint_key(client_id), ttl, b"1")
    except Exception as exc:  # noqa: BLE001
        raise TaintStoreError(f"taint write failed: {exc}") from exc


# --- thin production wrappers (pull the shared Redis pool) ----------------------

def _pool_client():
    """Return the shared Redis client, or None if the pool is not initialized.

    `redis_pool.client` RAISES when uninitialized rather than returning None, so we
    catch that and hand None to the fail-closed core (is_tainted -> tainted,
    mark_tainted -> raise). A never-initialized pool must never read as "clean".
    """
    from app.core.redis_client import redis_pool

    try:
        return redis_pool.client
    except Exception:  # noqa: BLE001 - uninitialized pool -> fail closed
        return None


async def is_tainted_for_principal(client_id: str | None) -> bool:
    return await is_tainted(_pool_client(), client_id)


async def mark_tainted_for_principal(
    client_id: str | None, ttl: int = DEFAULT_TAINT_TTL_SECONDS
) -> None:
    await mark_tainted(_pool_client(), client_id, ttl)
