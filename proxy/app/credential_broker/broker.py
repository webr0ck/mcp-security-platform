from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker

from app.credential_broker.kms import VaultKMSClient
from app.credential_broker.models import CredentialResult
from app.credential_broker.session import SessionStore
from app.credential_broker.approaches.approach_a import decrypt, encrypt

logger = logging.getLogger(__name__)


class CredentialBroker:
    """
    Central orchestrator. Called by invocation service before every tool call.

    Approach B: check session cache -> provision if miss -> cache -> return token.
    Approach A: check DB for encrypted refresh_token -> decrypt with KEK ->
                use refresh_token to get fresh access_token -> return token.
    """

    def __init__(
        self,
        session: SessionStore,
        kms: VaultKMSClient,
        db_factory: async_sessionmaker,
        approach_b_adapters: dict,
        approach_a_adapters: dict,
    ) -> None:
        self._session = session
        self._kms = kms
        self._db_factory = db_factory
        self._approach_b_adapters = approach_b_adapters
        self._approach_a_adapters = approach_a_adapters
        # CB-008: held in a bytearray so it can be explicitly overwritten;
        # re-fetched after a TTL so Vault rotation is honoured and the
        # window a heap dump exposes the master is bounded.
        self._master_secret: bytearray | None = None
        self._master_secret_fetched_at: datetime | None = None

    @property
    def vault_client(self) -> "VaultKMSClient":
        """Public accessor used by dispatcher helpers (entra_client_credentials path)."""
        return self._kms

    @property
    def db_pool(self) -> "async_sessionmaker":
        """Public accessor used by dispatcher helpers (entra_client_credentials path)."""
        return self._db_factory

    @staticmethod
    def _zero(buf: bytearray | None) -> None:
        if buf:
            for i in range(len(buf)):
                buf[i] = 0

    async def _get_master_secret(self) -> bytes:
        from app.core.config import get_settings
        settings = get_settings()
        ttl = timedelta(seconds=settings.BROKER_MASTER_SECRET_TTL_SECONDS)
        now = datetime.now(timezone.utc)

        expired = (
            self._master_secret_fetched_at is None
            or now - self._master_secret_fetched_at >= ttl
        )
        if self._master_secret is None or expired:
            fresh = await self._kms.get_master_secret(settings.BROKER_MASTER_SECRET_PATH)
            # Overwrite the previous copy before dropping the reference.
            self._zero(self._master_secret)
            self._master_secret = bytearray(fresh)
            self._master_secret_fetched_at = now
        return bytes(self._master_secret)

    async def resolve(
        self,
        user_sub: str,
        service: str,
        session_id: str,
        approach: str,
        principal_id: str | None = None,
        principal_type: str | None = None,
    ) -> CredentialResult:
        if approach == "B":
            return await self._resolve_b(user_sub, service, session_id)
        if approach == "A":
            return await self._resolve_a(
                user_sub, service, session_id,
                principal_id=principal_id, principal_type=principal_type,
            )
        raise ValueError(f"Unknown approach: {approach}")

    async def _resolve_b(self, user_sub: str, service: str, session_id: str) -> CredentialResult:
        cached = await self._session.get(session_id, service)
        if cached:
            exp = datetime.fromisoformat(cached["expires_at"])
            if exp > datetime.now(timezone.utc):
                return CredentialResult(
                    token=cached["value"],
                    expires_at=exp,
                    approach="B",
                    service=service,
                    token_id=cached.get("token_id"),
                )

        adapter = self._approach_b_adapters[service]
        token = await adapter.provision(user_sub=user_sub, session_id=session_id)
        await self._session.save(
            session_id=session_id,
            service=service,
            token=token.value,
            token_id=token.token_id,
            expires_at=token.expires_at,
            approach="B",
        )
        return CredentialResult(
            token=token.value,
            expires_at=token.expires_at,
            approach="B",
            service=service,
            token_id=token.token_id,
        )

    async def _resolve_a(
        self,
        user_sub: str,
        service: str,
        session_id: str,
        principal_id: str | None = None,
        principal_type: str | None = None,
    ) -> CredentialResult:
        from sqlalchemy import text
        from app.credential_broker.principal_resolution import resolve_credential_owner

        async with self._db_factory() as db:
            # CR-10 (WP-A1): resolve the owner key via the typed-principal
            # dual-read (typed key first, bare-sub fallback gated to
            # same-type). Raises CrossTypePrincipalMismatch — NOT caught here,
            # propagated to the caller (dispatcher._inject_entra_user_token)
            # so it becomes an audited deny, never a silent match.
            resolved = await resolve_credential_owner(
                db,
                principal_id=principal_id,
                principal_type=principal_type,
                bare_sub=user_sub,
                service=service,
            )
            # Enrollment check MUST precede the KMS/Vault master-secret fetch. An
            # unenrolled caller has to receive an actionable CredentialNotEnrolledError
            # (→ "log in first" prompt) even when Vault is unreachable. Fetching the
            # master secret first would surface a generic KMSError on a Vault outage
            # and mask the real "not enrolled" signal — the m365-graph vs dex-calendar
            # divergence this ordering fixes.
            if resolved is None:
                raise CredentialNotEnrolledError(user_sub=user_sub, service=service)

            owner_key = resolved.owner_key
            row = await db.execute(
                text("SELECT encrypted_blob FROM credential_store WHERE user_sub=:sub AND service=:svc"),
                {"sub": owner_key, "svc": service},
            )
            record = row.fetchone()
            if record is None:
                # Row vanished between the resolve check and this SELECT (race) —
                # treat identically to "never enrolled" rather than raising a
                # confusing AttributeError on record.encrypted_blob.
                raise CredentialNotEnrolledError(user_sub=user_sub, service=service)

            master = await self._get_master_secret()

            # Pass full four-field AAD to match _make_aad() contract (FIND-010 / INV-013).
            # owner_type is always "user" on this path (service credentials use approach_a
            # via decrypt_credential, not this broker method). AAD/KEK derivation uses
            # owner_key — the row's ACTUAL user_sub (typed principal_id for new rows,
            # bare sub for a same-type legacy dual-read row) — since that is the value
            # encrypt() was originally called with for this row.
            refresh_token = decrypt(
                bytes(record.encrypted_blob),
                owner_key,
                master,
                service=service,
                tool_id=None,
                owner_type="user",
            )
            adapter = self._approach_a_adapters[service]
            access_token, new_refresh, expires_in = await adapter.refresh(refresh_token)

            new_encrypted = encrypt(
                new_refresh,
                owner_key,
                master,
                service=service,
                tool_id=None,
                owner_type="user",
            )
            await db.execute(
                text(
                    "UPDATE credential_store SET encrypted_blob=:blob WHERE user_sub=:sub AND service=:svc"
                ),
                {"blob": new_encrypted, "sub": owner_key, "svc": service},
            )
            await db.commit()

        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        return CredentialResult(
            token=access_token,
            expires_at=expires_at,
            approach="A",
            service=service,
        )


class CredentialNotEnrolledError(Exception):
    def __init__(self, user_sub: str, service: str) -> None:
        self.user_sub = user_sub
        self.service = service
        super().__init__(f"User {user_sub} not enrolled for {service}. OAuth enrollment required.")
