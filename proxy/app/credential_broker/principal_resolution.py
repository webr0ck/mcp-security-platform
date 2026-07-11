"""
MCP Security Platform — CR-10 (WP-A1) typed-principal credential dual-read.

`credential_store` (V006/V011) historically keyed every per-user row by a bare
Keycloak `user_sub`. That collides an OIDC human, an API-key caller, and an
mTLS agent that happen to share the same subject string onto the same
credential set — the exact bug this module exists to close.

Migration strategy (V062): additive `principal_type` column, dual-read at
lookup time, no big-bang rewrite of existing rows.

  1. Typed lookup: `user_sub == principal_id` (e.g. "human:kc-realm:alice").
     This is the ONLY key new enrollments ever write under (see
     routers/oauth.py::callback).
  2. Bare-sub fallback: `user_sub == <bare subject>`. Only reached when (1)
     misses — i.e. a pre-CR-10 row. The fallback is gated: the row's
     `principal_type` (or the inferred-legacy default of "human" when the
     column is NULL, since credential_store pre-CR-10 was only ever populated
     by OIDC/session human enrollment flows) MUST match the caller's
     principal_type. A mismatch is NEVER treated as a match — it raises
     CrossTypePrincipalFallbackDenied so the caller can turn it into an
     audited deny (see services/invocation.py's dispatch_credential_injection
     except block).

Fail-closed by construction: any lookup that cannot determine a safe owner
returns None (not enrolled) or raises (cross-type denial) — never silently
matches across principal types.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Rows written before CR-10 have no recorded principal_type. credential_store
# was, prior to this package, only ever populated by OIDC/session human
# enrollment flows (/auth/enroll/*, /auth/callback/*) — so the safe inference
# for a NULL principal_type column is "human", never a wildcard match.
_INFERRED_LEGACY_PRINCIPAL_TYPE = "human"


class CrossTypePrincipalMismatch(RuntimeError):
    """
    Raised when a typed-principal lookup misses and the bare-sub fallback row
    belongs to a DIFFERENT principal type than the caller.

    This is an internal signal only — callers in dispatcher.py catch it and
    re-raise as dispatcher.CrossTypePrincipalFallbackDenied (a
    CredentialInjectionError subclass) so it flows through the existing
    audited-deny exception handling in services/invocation.py. Kept separate
    from that public exception to avoid a circular import (dispatcher.py
    imports resolve_credential_owner from this module).

    Callers MUST treat this as a deny + audit event — never a silent match.
    """

    def __init__(self, bare_sub: str, caller_type: str, row_type: str, service: str) -> None:
        self.bare_sub = bare_sub
        self.caller_type = caller_type
        self.row_type = row_type
        self.service = service
        # INV-002: bare_sub may be a real subject identifier — kept out of the
        # message only insofar as it already appears in DB query params/logs
        # elsewhere at the same trust level (not a secret; a subject, not a token).
        super().__init__(
            f"cross_type_principal_mismatch: service={service!r} "
            f"caller_type={caller_type!r} row_type={row_type!r}"
        )


@dataclass(frozen=True)
class ResolvedCredentialOwner:
    """The credential_store.user_sub value to use for decrypt/update AAD."""

    owner_key: str
    matched_typed: bool  # True: matched via principal_id. False: bare-sub dual-read.


async def resolve_credential_owner(
    session,
    *,
    principal_id: str | None,
    principal_type: str | None,
    bare_sub: str,
    service: str,
) -> ResolvedCredentialOwner | None:
    """
    CR-10 dual-read credential owner resolution for owner_type='user' rows.

    Args:
        session: an open SQLAlchemy AsyncSession/connection (caller-managed).
        principal_id: the typed principal id (e.g. "human:kc-realm:alice"),
            or None if the caller could not be typed (fails back to bare-sub
            lookup with legacy-inference immediately in that case).
        principal_type: 'human' | 'agent' | ... — the caller's type. Treated
            as "human" if None (matches the legacy-inference default so
            untyped callers behave exactly as pre-CR-10 code did).
        bare_sub: the plain subject string (client_id) — the pre-CR-10 key.
        service: credential_store.service value.

    Returns:
        ResolvedCredentialOwner if a row was found (matched_typed indicates
        which key matched), or None if neither lookup finds a row.

    Raises:
        CrossTypePrincipalMismatch: bare-sub row exists but its principal_type
            does not match the caller's — never silently matched.
    """
    from sqlalchemy import text

    caller_type = principal_type or _INFERRED_LEGACY_PRINCIPAL_TYPE

    if principal_id:
        row = await session.execute(
            text(
                "SELECT 1 FROM credential_store "
                "WHERE user_sub = :sub AND service = :svc "
                "AND (owner_type = 'user' OR owner_type IS NULL) LIMIT 1"
            ),
            {"sub": principal_id, "svc": service},
        )
        if row.fetchone() is not None:
            return ResolvedCredentialOwner(owner_key=principal_id, matched_typed=True)

    if principal_id == bare_sub:
        # No distinct bare-sub form to fall back to — already tried above.
        return None

    row = await session.execute(
        text(
            "SELECT principal_type FROM credential_store "
            "WHERE user_sub = :sub AND service = :svc "
            "AND (owner_type = 'user' OR owner_type IS NULL) LIMIT 1"
        ),
        {"sub": bare_sub, "svc": service},
    )
    record = row.fetchone()
    if record is None:
        return None

    row_type = record.principal_type or _INFERRED_LEGACY_PRINCIPAL_TYPE
    if row_type != caller_type:
        logger.warning(
            "credential dual-read: cross-type fallback denied",
            extra={
                "service": service,
                "caller_type": caller_type,
                "row_type": row_type,
            },
        )
        raise CrossTypePrincipalMismatch(bare_sub, caller_type, row_type, service)

    return ResolvedCredentialOwner(owner_key=bare_sub, matched_typed=False)
