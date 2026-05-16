"""CB-008: master secret is cached with a TTL, re-fetched, and zeroed."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.credential_broker.broker import CredentialBroker


def _broker(kms):
    return CredentialBroker(
        session=MagicMock(), kms=kms, db=MagicMock(),
        approach_b_adapters={}, approach_a_adapters={},
    )


@pytest.mark.unit
async def test_master_secret_cached_within_ttl():
    kms = MagicMock()
    kms.get_master_secret = AsyncMock(return_value=b"SECRET-v1")
    b = _broker(kms)

    assert await b._get_master_secret() == b"SECRET-v1"
    assert await b._get_master_secret() == b"SECRET-v1"
    kms.get_master_secret.assert_awaited_once()  # cached, not re-fetched


@pytest.mark.unit
async def test_master_secret_refetched_after_ttl_and_old_zeroed():
    kms = MagicMock()
    kms.get_master_secret = AsyncMock(side_effect=[b"SECRET-v1", b"SECRET-v2"])
    b = _broker(kms)

    assert await b._get_master_secret() == b"SECRET-v1"
    old_buf = b._master_secret  # keep a reference to the live bytearray
    assert bytes(old_buf) == b"SECRET-v1"

    # Simulate TTL expiry.
    b._master_secret_fetched_at = datetime.now(timezone.utc) - timedelta(hours=1)

    assert await b._get_master_secret() == b"SECRET-v2"  # rotation honoured
    assert kms.get_master_secret.await_count == 2
    assert bytes(old_buf) == b"\x00" * len(old_buf)  # old copy wiped
