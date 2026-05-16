from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

def _mock_client(post_resp=None, delete_resp=None):
    mc = AsyncMock()
    mc.__aenter__ = AsyncMock(return_value=mc)
    mc.__aexit__ = AsyncMock(return_value=False)
    if post_resp:
        mc.post = AsyncMock(return_value=post_resp)
    if delete_resp:
        mc.delete = AsyncMock(return_value=delete_resp)
    return mc

@pytest.mark.unit
async def test_netbox_provision_uses_username_mapping():
    from app.credential_broker.adapters.netbox import NetboxAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = AsyncMock()
    mock_resp.json = MagicMock(return_value={"id": 99, "key": "netbox-token-xyz"})

    with patch("app.credential_broker.adapters.netbox.httpx.AsyncClient") as cls:
        cls.return_value = _mock_client(post_resp=mock_resp)
        adapter = NetboxAdapter(
            base_url="http://netbox.internal",
            admin_token="admin-tok",
            sub_to_username=lambda sub: sub.split("@")[0],
        )
        token = await adapter.provision(user_sub="alice@corp.com", session_id="sess-1")

    assert token.value == "netbox-token-xyz"
    assert token.token_id == "99"

@pytest.mark.unit
async def test_netbox_revoke_deletes_token():
    from app.credential_broker.adapters.netbox import NetboxAdapter

    mock_resp = AsyncMock()
    mock_resp.raise_for_status = AsyncMock()

    with patch("app.credential_broker.adapters.netbox.httpx.AsyncClient") as cls:
        mc = _mock_client(delete_resp=mock_resp)
        cls.return_value = mc
        adapter = NetboxAdapter(
            base_url="http://netbox.internal",
            admin_token="admin-tok",
            sub_to_username=lambda sub: sub.split("@")[0],
        )
        await adapter.revoke("99")
        mc.delete.assert_awaited_once()
