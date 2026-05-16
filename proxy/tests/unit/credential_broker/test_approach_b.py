from __future__ import annotations
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock


@pytest.mark.unit
async def test_approach_b_provision_calls_adapter():
    from app.credential_broker.approaches.approach_b import ApproachB
    from app.credential_broker.models import Token

    future = datetime.now(timezone.utc) + timedelta(hours=8)
    mock_adapter = AsyncMock()
    mock_adapter.provision = AsyncMock(
        return_value=Token(value="provisioned-token", expires_at=future, token_id="tid-1")
    )

    b = ApproachB(adapter=mock_adapter)
    token = await b.resolve(user_sub="user@corp", session_id="sess-1")

    mock_adapter.provision.assert_awaited_once_with(user_sub="user@corp", session_id="sess-1")
    assert token.value == "provisioned-token"


@pytest.mark.unit
async def test_approach_b_revoke_calls_adapter():
    from app.credential_broker.approaches.approach_b import ApproachB

    mock_adapter = AsyncMock()
    mock_adapter.revoke = AsyncMock()

    b = ApproachB(adapter=mock_adapter)
    await b.revoke(token_id="tid-1")

    mock_adapter.revoke.assert_awaited_once_with("tid-1")
