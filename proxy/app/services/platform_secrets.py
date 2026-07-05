"""Platform-level encrypted secrets (PRD-0005 R-1 / SI-1).

Stores non-user, non-tool secrets (the LLM API token, git service-account
tokens) encrypted with the SAME KEK/AES-256-GCM primitive the credential broker
uses for user credentials — but NOT via the tool-bound credential_store path
(which requires a tool_id). The blob is salt||nonce||ciphertext+tag; the KEK
comes from Vault (spec §2.1), derived for a fixed non-user platform key-domain.

A platform secret is bound by AAD to (user_sub='__platform__', service=name),
so a blob cannot be swapped between names or lifted into a user credential row.

Fail-closed: if Vault/KEK is unreachable, get_secret raises KMSError — callers
decide what that means (e.g. the LLM auditor treats it as llm_unavailable, never
a silent unauthenticated call — SI-6).
"""
from __future__ import annotations

import logging

from app.credential_broker.approaches import approach_a
from app.credential_broker.kms import load_master_secret_standalone

logger = logging.getLogger(__name__)

# Fixed non-user principal for the platform key-domain. Distinct from any real
# user_sub, so the HKDF info + AAD domain-separate platform secrets from user
# credentials (a user KEK can never decrypt a platform blob and vice-versa).
_PLATFORM_SUB = "__platform__"
_OWNER_TYPE = "platform"


async def set_secret(name: str, value: str, actor: str) -> None:
    """Encrypt and upsert a platform secret. Raises KMSError if Vault is down."""
    master = await load_master_secret_standalone()
    try:
        blob = approach_a.encrypt(
            value, _PLATFORM_SUB, master,
            service=name, tool_id=None, owner_type=_OWNER_TYPE,
        )
    finally:
        _zero(master)
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("Database pool not available")
    await pool.execute(
        "INSERT INTO platform_secrets (name, blob, updated_by) VALUES ($1, $2, $3) "
        "ON CONFLICT (name) DO UPDATE SET blob=EXCLUDED.blob, "
        "updated_by=EXCLUDED.updated_by, updated_at=NOW()",
        name, blob, actor,
    )


async def get_secret(name: str) -> str | None:
    """Return the decrypted secret, or None if no row exists.

    Raises KMSError if the row exists but Vault/KEK is unreachable, and
    cryptography.exceptions.InvalidTag on a tampered/mismatched blob — callers
    MUST treat either as "secret unavailable", never fall back to no-secret
    (SI-6: no silent unauthenticated downgrade for a configured secret).
    """
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("Database pool not available")
    row = await pool.fetchrow("SELECT blob FROM platform_secrets WHERE name=$1", name)
    if row is None:
        return None
    master = await load_master_secret_standalone()
    try:
        return approach_a.decrypt(
            bytes(row["blob"]), _PLATFORM_SUB, master,
            service=name, tool_id=None, owner_type=_OWNER_TYPE,
        )
    finally:
        _zero(master)


async def secret_exists(name: str) -> bool:
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        return False
    row = await pool.fetchrow("SELECT 1 FROM platform_secrets WHERE name=$1", name)
    return row is not None


async def delete_secret(name: str) -> None:
    from app.core.asyncpg_pool import asyncpg_pool
    pool = asyncpg_pool.get()
    if pool is None:
        raise RuntimeError("Database pool not available")
    await pool.execute("DELETE FROM platform_secrets WHERE name=$1", name)


def _zero(b) -> None:
    try:
        for i in range(len(b)):
            b[i] = 0
    except (TypeError, AttributeError):
        pass  # immutable bytes — best-effort only


if __name__ == "__main__":
    # ponytail: self-check — the crypto round-trips and AAD binds the name.
    # No Vault here, so use a raw 32-byte master directly against approach_a.
    import os
    m = bytearray(os.urandom(32))
    blob = approach_a.encrypt("s3cr3t-token", _PLATFORM_SUB, m,
                              service="llm-api", tool_id=None, owner_type=_OWNER_TYPE)
    assert approach_a.decrypt(blob, _PLATFORM_SUB, m, service="llm-api",
                              tool_id=None, owner_type=_OWNER_TYPE) == "s3cr3t-token"
    # Wrong service (name) must fail to decrypt — AAD binding holds.
    try:
        approach_a.decrypt(blob, _PLATFORM_SUB, m, service="git-bitbucket",
                           tool_id=None, owner_type=_OWNER_TYPE)
        raise SystemExit("FAIL: blob decrypted under the wrong name")
    except Exception:
        pass
    print("platform_secrets self-check OK")
