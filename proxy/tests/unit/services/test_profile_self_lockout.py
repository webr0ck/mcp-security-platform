"""
Self-lockout guard + deny remediation (2026-07-25, Stage 2).

F2 — self-service `disable_mcp` could disable the very tools needed to undo it.
     Observed in the lab: a sweep wrote 37 disable rows in 1.4s including
     get_profile, enable_mcp and enable_function. The principal (an admin — there
     is deliberately no role bypass on the profile gate) could then neither see
     nor restore their own access.

F4 — a deny that only names its rule ("mcp_disabled_for_profile") is a dead end
     for the caller, which for this platform is usually an LLM agent.
"""
import pytest

from app.routers.profiles import _RECOVERY_MCPS, would_self_lockout
from app.services.policy import deny_remediation


class TestSelfLockoutGuard:
    @pytest.mark.parametrize("tool", sorted(_RECOVERY_MCPS))
    def test_disabling_own_recovery_tool_is_blocked(self, tool):
        assert would_self_lockout("alice@corp", tool, False, "alice@corp") is True

    @pytest.mark.parametrize("tool", sorted(_RECOVERY_MCPS))
    def test_enabling_a_recovery_tool_is_always_fine(self, tool):
        assert would_self_lockout("alice@corp", tool, True, "alice@corp") is False

    def test_disabling_an_ordinary_tool_is_fine(self):
        assert would_self_lockout("alice@corp", "echo-basic", False, "alice@corp") is False

    def test_admin_may_restrict_another_principal(self):
        # Legitimate policy, NOT a lockout: the admin can still reverse it, so the
        # target is never stranded. Blocking this would remove a real capability.
        assert would_self_lockout("bob@corp", "enable_mcp", False, "admin@corp") is False

    def test_admin_disabling_their_OWN_recovery_tool_is_still_blocked(self):
        # The lab case exactly: alice holds `admin` and locked herself out. Role is
        # irrelevant — what matters is that the actor is the subject.
        assert would_self_lockout("alice@corp", "enable_mcp", False, "alice@corp") is True

    def test_recovery_set_covers_both_inspect_and_undo(self):
        # A set that can undo but not inspect (or vice versa) is not a recovery path:
        # you would be able to fix only what you could already name.
        assert "get_profile" in _RECOVERY_MCPS, "must be able to INSPECT what is disabled"
        assert "enable_mcp" in _RECOVERY_MCPS, "must be able to UNDO a server disable"
        assert "enable_function" in _RECOVERY_MCPS, "must be able to UNDO a function disable"


class TestDenyRemediation:
    def test_profile_deny_explains_how_to_undo(self):
        help_text = deny_remediation(["mcp_disabled_for_profile"])
        assert help_text is not None
        # Must name the tools that actually work, not the ones that are disabled.
        # get_profile/enable_mcp are exactly what a denied caller CANNOT call.
        assert "get_my_profile" in help_text
        assert "enable_mcp_server" in help_text

    def test_named_profile_case_is_mentioned(self):
        # A caller restricted via X-MCP-Profile cannot self-serve at all, so telling
        # them to "enable it" without that caveat sends them in a loop.
        assert "administrator" in deny_remediation(["mcp_disabled_for_profile"])

    def test_decorated_reason_still_resolves(self):
        # Reasons can arrive suffixed, e.g. "taint_floor:required_integrity=3".
        assert deny_remediation(["mcp_disabled_for_profile:tool=x"]) is not None

    def test_unknown_reason_returns_none_not_filler(self):
        # Generic filler ("contact your administrator") trains agents and humans to
        # ignore the field entirely, which costs more than an absent field.
        assert deny_remediation(["some_future_rule"]) is None
        assert deny_remediation([]) is None
        assert deny_remediation(None) is None

    def test_first_recognised_reason_wins(self):
        out = deny_remediation(["unknown_rule", "function_not_allowed_for_profile"])
        assert out is not None and "enable_function" in out
