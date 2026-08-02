"""
P1-2 at the MCP meta-tool seam.

profiles.py bars machine tokens from mutating profiles (_assert_not_service_account),
reached via _assert_may_write on the REST routes. But the meta-tool handlers
_handle_enable_mcp_server / _handle_disable_mcp_server call _upsert_profile_row
DIRECTLY and never reach that guard.

That was latent, not live: no service account in the lab held any role in those tools'
_roles set. It became reachable the moment `agent` was added there so agent-only MCP
clients could recover their own profile — the lab's `self-service` and
`svc-mcp-agent` accounts both hold `agent`.

The escalation P1-2 exists to stop: automated credential compromise -> the compromised
service account self-enables MCP servers -> scope expansion.

Reading your own profile (get_my_profile) mutates nothing and is deliberately NOT blocked.
"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.routers.mcp_server import (
    _handle_disable_mcp_server,
    _handle_enable_mcp_server,
    _sa_blocked_for_profile_mutation,
)

MUTATING = [
    ("enable_mcp_server", _handle_enable_mcp_server),
    ("disable_mcp_server", _handle_disable_mcp_server),
]


def _req(*, is_service_account: bool, client_id: str = "svc-bot@lab.local"):
    return SimpleNamespace(
        state=SimpleNamespace(
            is_service_account=is_service_account,
            client_id=client_id,
            client_roles=["agent"],
        )
    )


class TestPredicate:
    def test_service_account_is_blocked(self):
        assert _sa_blocked_for_profile_mutation(_req(is_service_account=True)) is not None

    def test_human_is_not_blocked(self):
        assert _sa_blocked_for_profile_mutation(_req(is_service_account=False)) is None

    def test_missing_flag_is_treated_as_human(self):
        # Absent flag must not fail closed into blocking every human caller; the
        # middleware always sets it, and defaulting to "blocked" would break the
        # normal path on any request that skipped it.
        assert _sa_blocked_for_profile_mutation(SimpleNamespace(state=SimpleNamespace())) is None

    def test_message_names_the_remedy_and_leaks_nothing(self):
        out = _sa_blocked_for_profile_mutation(_req(is_service_account=True))
        text = out["text"]
        assert "administrator" in text.lower()
        assert "svc-bot@lab.local" not in text, "must not echo the caller id back"


class TestHandlersRefuseServiceAccounts:
    @pytest.mark.parametrize("name,handler", MUTATING, ids=[n for n, _ in MUTATING])
    @pytest.mark.asyncio
    async def test_service_account_cannot_mutate_its_own_profile(self, name, handler):
        # The assertion that matters: the DB writer is never reached. Asserting only
        # on the returned text would pass even if the write had already happened.
        with patch("app.routers.profiles._upsert_profile_row", new_callable=AsyncMock) as upsert, \
             patch("app.routers.profiles._assert_mcp_exists", new_callable=AsyncMock), \
             patch("app.routers.profiles._get_profile_row", new_callable=AsyncMock, return_value=None), \
             patch("app.routers.profiles._invalidate_profile_cache", new_callable=AsyncMock):
            result = await handler({"server_name": "echo-basic"}, _req(is_service_account=True))

        upsert.assert_not_awaited(), f"{name} wrote to the profile for a service account"
        assert "service account" in result["text"].lower()

    @pytest.mark.parametrize("name,handler", MUTATING, ids=[n for n, _ in MUTATING])
    @pytest.mark.asyncio
    async def test_human_agent_can_still_mutate_its_own_profile(self, name, handler):
        # The whole point of granting `agent` these tools — a human agent-role caller
        # must still be able to recover. A guard that blocks everyone is not a fix.
        with patch("app.routers.profiles._upsert_profile_row", new_callable=AsyncMock) as upsert, \
             patch("app.routers.profiles._assert_mcp_exists", new_callable=AsyncMock), \
             patch("app.routers.profiles._get_profile_row", new_callable=AsyncMock, return_value=None), \
             patch("app.routers.profiles._invalidate_profile_cache", new_callable=AsyncMock):
            result = await handler(
                {"server_name": "echo-basic"},
                _req(is_service_account=False, client_id="bob@corp"),
            )

        upsert.assert_awaited_once()
        assert "service account" not in result["text"].lower()


class TestRoleGrants:
    def test_agent_can_reach_the_recovery_tools(self):
        from app.routers.mcp_server import _TOOLS
        roles = {t["name"]: t["_roles"] for t in _TOOLS}
        for tool in ("get_my_profile", "enable_mcp_server", "disable_mcp_server"):
            assert "agent" in roles[tool], (
                f"{tool} must be reachable by agent — an agent-only MCP client "
                f"otherwise has no way to inspect or restore its own profile"
            )

    def test_viewer_is_not_granted_mutating_tools(self):
        # viewer is read-only by design (parallel to auditor). It may read its
        # profile but must not change it.
        from app.routers.mcp_server import _TOOLS
        roles = {t["name"]: t["_roles"] for t in _TOOLS}
        assert "viewer" in roles["get_my_profile"]
        assert "viewer" not in roles["enable_mcp_server"]
        assert "viewer" not in roles["disable_mcp_server"]
