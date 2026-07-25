"""
Deny-dominant profile resolution (2026-07-25).

Regression tests for two authorization defects found against the live lab:

  F6 — named-profile restrictions were hidden-but-callable. The only writer of named
       bindings writes `profile_mcp_bindings`; the invoke path read
       `mcp_profiles WHERE profile_uuid=`, which no writer populates. Every named
       restriction resolved to "no row" -> allow, while discovery correctly hid the
       tool. Hidden in the UI, callable over the wire.

  F7 — binding ANY active profile shed the caller's own per-identity restrictions,
       because resolution was an if/else (named REPLACED legacy) rather than a merge.

The merge is a pure function so the security-critical precedence rule is directly
assertable without a DB.
"""
import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.services.invocation import merge_profile_deny_dominant as merge

# tests/unit/conftest.py has an autouse fixture that stubs
# app.services.invocation._lookup_profile_with_cache to AsyncMock(return_value=None)
# so unit tests don't need Redis. Binding the real function HERE, at import time,
# keeps a reference to the original object: the fixture rebinds the module
# attribute, not this name. Calls made through _REAL_RESOLVER therefore execute
# the real body, while the inner _lookup_profile_source it calls still resolves
# through the module global and stays patchable per-test.
from app.services.invocation import _lookup_profile_with_cache as _REAL_RESOLVER


class TestNoRestriction:
    def test_both_absent_is_unrestricted(self):
        assert merge(None, None) is None

    def test_only_legacy_present_is_returned_verbatim(self):
        legacy = {"enabled": False, "allowed_functions": None}
        assert merge(legacy, None) == legacy

    def test_only_named_present_is_returned_verbatim(self):
        named = {"enabled": False, "allowed_functions": None}
        assert merge(None, named) == named


class TestDenyDominance:
    """Either side saying False must win. This is the F7 fix."""

    def test_legacy_deny_survives_a_permissive_named_profile(self):
        # F7 REGRESSION: alice is denied 'ping' per-identity, then attaches
        # X-MCP-Profile pointing at a profile that permits it. Pre-fix this
        # returned enabled=True and the call succeeded.
        legacy = {"enabled": False, "allowed_functions": None}
        named = {"enabled": True, "allowed_functions": None}
        assert merge(legacy, named)["enabled"] is False

    def test_named_deny_survives_a_permissive_legacy_profile(self):
        # F6 REGRESSION: profile 'readonly-demo' disables approve_submission.
        legacy = {"enabled": True, "allowed_functions": None}
        named = {"enabled": False, "allowed_functions": None}
        assert merge(legacy, named)["enabled"] is False

    def test_both_enabled_stays_enabled(self):
        legacy = {"enabled": True, "allowed_functions": None}
        named = {"enabled": True, "allowed_functions": None}
        assert merge(legacy, named)["enabled"] is True

    def test_missing_enabled_key_defaults_to_allowed_not_denied(self):
        # Absent key means "this source expresses no opinion", not "deny".
        # A source that wants to deny says so explicitly.
        assert merge({}, {})["enabled"] is True


class TestAllowedFunctionsNarrowing:
    """A named profile narrows the function allowlist; it never widens it."""

    def test_intersection_when_both_restrict(self):
        legacy = {"enabled": True, "allowed_functions": ["read", "write", "list"]}
        named = {"enabled": True, "allowed_functions": ["read", "list", "delete"]}
        out = merge(legacy, named)
        assert out["enabled"] is True
        assert out["allowed_functions"] == ["read", "list"]  # order follows legacy
        assert "delete" not in out["allowed_functions"], "named must not ADD a function"

    def test_single_restricting_side_is_applied(self):
        legacy = {"enabled": True, "allowed_functions": ["read"]}
        named = {"enabled": True, "allowed_functions": None}
        assert merge(legacy, named)["allowed_functions"] == ["read"]

        legacy2 = {"enabled": True, "allowed_functions": None}
        named2 = {"enabled": True, "allowed_functions": ["read"]}
        assert merge(legacy2, named2)["allowed_functions"] == ["read"]

    def test_neither_restricting_is_unrestricted(self):
        legacy = {"enabled": True, "allowed_functions": None}
        named = {"enabled": True, "allowed_functions": []}
        assert merge(legacy, named)["allowed_functions"] is None

    def test_disjoint_allowlists_deny_entirely(self):
        # The fail-open this guards: authz.rego triggers the function restriction
        # only on `count(input.profile.allowed_functions) > 0`. Returning an empty
        # intersection as [] would read as "unrestricted" and permit EVERY function,
        # which is the exact opposite of what two disjoint allowlists mean.
        legacy = {"enabled": True, "allowed_functions": ["read"]}
        named = {"enabled": True, "allowed_functions": ["write"]}
        out = merge(legacy, named)
        assert out["enabled"] is False, "disjoint allowlists must deny, not open up"
        assert out["allowed_functions"] == []


class TestNoWideningInvariant:
    """Property: merging can only ever remove access, never grant it."""

    @pytest.mark.parametrize(
        "legacy,named",
        [
            ({"enabled": True, "allowed_functions": ["a", "b"]}, {"enabled": True, "allowed_functions": ["b", "c"]}),
            ({"enabled": False, "allowed_functions": None}, {"enabled": True, "allowed_functions": ["a"]}),
            ({"enabled": True, "allowed_functions": ["a"]}, {"enabled": False, "allowed_functions": None}),
            ({"enabled": True, "allowed_functions": None}, {"enabled": True, "allowed_functions": ["a"]}),
            ({"enabled": True, "allowed_functions": ["a"]}, {"enabled": True, "allowed_functions": ["b"]}),
        ],
    )
    def test_merge_never_grants_what_a_side_denied(self, legacy, named):
        out = merge(legacy, named)
        assert out is not None

        # enabled never becomes True if either side said False
        if not legacy.get("enabled", True) or not named.get("enabled", True):
            assert out["enabled"] is False

        # no function appears in the result that a restricting side excluded
        for side in (legacy, named):
            fns = side.get("allowed_functions") or []
            if fns and out.get("allowed_functions"):
                assert set(out["allowed_functions"]) <= set(fns), (
                    f"merge widened the allowlist beyond {fns}"
                )


class TestResolverSourcesTheRightTables:
    """Which table/key the resolver actually reads — the F6 root cause."""

    @pytest.mark.asyncio
    async def test_named_path_reads_the_table_the_writer_writes(self):
        # F6 REGRESSION. The only writer of named bindings is
        # routers/profiles.py::_upsert_profile_mcp_binding -> profile_mcp_bindings.
        # Invoke used to read `mcp_profiles WHERE profile_uuid=`, a column no writer
        # populates, so every named restriction resolved to "no row" -> allow while
        # discovery correctly hid the tool: hidden in the UI, callable over the wire.
        p_uuid = str(uuid.uuid4())
        calls: list[dict] = []

        async def spy(**kw):
            calls.append(kw)
            return None

        with patch("app.services.invocation._lookup_profile_source", side_effect=spy), \
             patch("app.services.invocation._named_profile_has_any_binding",
                   new=AsyncMock(return_value=False)):
            await _REAL_RESOLVER("user@corp", "tool-x", profile_uuid=p_uuid)

        by_table = {c["table"]: c for c in calls}
        assert "profile_mcp_bindings" in by_table, (
            f"named lookup must read profile_mcp_bindings, got {set(by_table)}"
        )
        assert "mcp_profiles" in by_table, "legacy source must still be consulted"

        assert by_table["profile_mcp_bindings"]["key_column"] == "profile_id"
        assert by_table["profile_mcp_bindings"]["key_value"] == p_uuid
        # The legacy source must key on the BARE client_id — the key the writer and
        # the invoke gate both use. Discovery used to key on principal_id
        # ("human:{issuer}:{sub}"), matched nothing, and filtered nothing.
        assert by_table["mcp_profiles"]["key_column"] == "profile_id"
        assert by_table["mcp_profiles"]["key_value"] == "user@corp"

    @pytest.mark.asyncio
    async def test_legacy_source_consulted_even_when_a_profile_is_bound(self):
        # F7 REGRESSION: resolution used to be an if/else, so a bound named profile
        # REPLACED the legacy rules and any caller could shed their own restrictions
        # with one X-MCP-Profile header.
        # The named side must return a PERMISSIVE ROW, not None. With None the old
        # `named if named is not None else legacy` fell through to legacy and looked
        # correct — this test passed against the bug until mutation testing caught it.
        # An explicit enabled=True binding is what actually distinguishes the two.
        async def spy(**kw):
            if kw["table"] == "mcp_profiles":
                return {"enabled": False, "allowed_functions": None}   # legacy DENIES
            return {"enabled": True, "allowed_functions": None}        # named ALLOWS

        with patch("app.services.invocation._lookup_profile_source", side_effect=spy), \
             patch("app.services.invocation._named_profile_has_any_binding",
                   new=AsyncMock(return_value=False)):
            out = await _REAL_RESOLVER("user@corp", "tool-x", profile_uuid=str(uuid.uuid4()))

        assert out is not None and out["enabled"] is False, (
            "a bound named profile must not override a legacy deny — this is the "
            "one-header privilege escalation (F7)"
        )

    @pytest.mark.asyncio
    async def test_no_profile_uuid_skips_the_named_source(self):
        calls: list[dict] = []

        async def spy(**kw):
            calls.append(kw)
            return None

        with patch("app.services.invocation._lookup_profile_source", side_effect=spy):
            await _REAL_RESOLVER("user@corp", "tool-x", profile_uuid=None)

        assert [c["table"] for c in calls] == ["mcp_profiles"]

    @pytest.mark.asyncio
    async def test_configured_named_profile_default_denies_an_unbound_tool(self):
        # A profile with >=1 binding anywhere has not granted a tool it has no row for.
        async def spy(**kw):
            return None  # no row from either source

        with patch("app.services.invocation._lookup_profile_source", side_effect=spy), \
             patch("app.services.invocation._named_profile_has_any_binding",
                   new=AsyncMock(return_value=True)):
            out = await _REAL_RESOLVER("user@corp", "tool-x", profile_uuid=str(uuid.uuid4()))

        assert out is not None and out["enabled"] is False

    @pytest.mark.asyncio
    async def test_unconfigured_named_profile_stays_default_allow(self):
        # Zero bindings = freshly created profile; must not be bricked before an
        # admin adds the first binding.
        async def spy(**kw):
            return None

        with patch("app.services.invocation._lookup_profile_source", side_effect=spy), \
             patch("app.services.invocation._named_profile_has_any_binding",
                   new=AsyncMock(return_value=False)):
            out = await _REAL_RESOLVER("user@corp", "tool-x", profile_uuid=str(uuid.uuid4()))

        assert out is None
