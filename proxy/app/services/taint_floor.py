"""B-coarse taint-floor decision core (PRD-0001 M2 / SPEC-0001 §8.1).

Pure, deterministic, services-free security logic. The Redis taint store
(`taint_store.py`) and the `invocation.py` gate wire these together; keeping the
decisions here makes them unit-testable without Postgres/Redis/OPA.

Binary integrity model (SPEC-0001 §4.1):
    SEP-1913 trust_tier rank  -> binary integrity
        untrustedPublic = 0   -> 0 (untrusted)
        trustedPublic   = 1   -> 0 (untrusted)
        internal        = 2   -> 1 (trusted)
        user            = 3   -> 1 (trusted)
        system          = 4   -> 1 (trusted)
    Unknown / NULL / out-of-range -> 0 (fail-closed, INV-003).

The taint floor (RFC §8.1): a session is *tainted* once it ingests any result
whose binary integrity is 0; a tainted session is denied any tool whose
`required_integrity >= 1` (deny-on-unknown, since unclassified tools default to 1).
"""

from __future__ import annotations

# The lowest SEP-1913 rank considered "trusted" in the binary collapse (internal).
_TRUSTED_FLOOR_RANK = 2

# Injection modes that broker a credential to the upstream call. Anything not in
# this set (i.e. "none") is non-injecting. Listed explicitly rather than `!= none`
# so an unknown/garbage mode fails CLOSED (treated as injecting -> bumps the floor).
_NON_INJECTING_MODES = frozenset({"none"})


def binary_integrity(trust_tier: int | None) -> int:
    """Collapse a SEP-1913 trust_tier rank to binary integrity {0,1}, fail-closed."""
    if trust_tier is None:
        return 0
    if trust_tier >= _TRUSTED_FLOOR_RANK:
        return 1
    return 0


def result_taints_session(trust_tier: int | None) -> bool:
    """True if a result from a server at this trust_tier taints the session."""
    return binary_integrity(trust_tier) == 0


def effective_injection_mode(tool_mode: str | None, server_default: str | None) -> str:
    """Resolve the injection mode for the SAFETY bump, fail-closed in BOTH directions.

    A credential can be brokered to the upstream if EITHER the tool-level mode OR the
    server default is injecting (depending on how the dispatcher resolves a given call,
    V032). For the safety bump we must therefore treat the call as injecting if *either*
    side is non-'none' — returning the first injecting mode found, else 'none'. This is
    strictly conservative: it can only over-bump (fail-closed), never let a
    credential-injecting tool slip through as a low sink in either resolution direction.
    """
    for mode in (tool_mode, server_default):
        if mode is not None and mode not in _NON_INJECTING_MODES:
            return mode
    return "none"


def effective_required_integrity(tool_required_integrity: int, injection: str | None) -> int:
    """Bump a credential-injecting tool's floor to >=1 (it can never be a low sink).

    Closes the round-1 credential-injection bypass: a tainted session must not reach
    a Vault-brokered upstream call even if the tool was classified low. Unknown modes
    fail closed (treated as injecting).
    """
    mode = injection or "none"
    if mode in _NON_INJECTING_MODES:
        return tool_required_integrity
    return max(tool_required_integrity, 1)


def taint_floor_decision(*, tainted: bool, required_integrity: int) -> str:
    """The binary B-coarse rule: deny a high sink in a tainted session.

    Returns "deny" or "allow". `tainted` is resolved fail-closed by the caller
    (store error or unknown -> True).
    """
    if tainted and required_integrity >= 1:
        return "deny"
    return "allow"


# The two Phase-0 taint-floor actions (PRD-0010). "block" hard-denies (raises
# TaintFloorDenyError); "notify" allows-with-disclaimer. Kept as a pair so the
# invocation gate and its tests share one source of truth.
TAINT_ACTION_BLOCK = "block"
TAINT_ACTION_NOTIFY = "notify"


def resolve_taint_action(decision: str, mode: str) -> str:
    """Map a taint_floor_decision + configured mode to the effective action.

    decision "allow"  -> "" (no action; the call proceeds normally, no notice).
    decision "deny" + mode "enforce" -> "block" (raise TaintFloorDenyError, fail-closed).
    decision "deny" + mode "notify"  -> "notify" (allow-with-disclaimer, Phase-0 default).

    Only "enforce" enforces; ANY other mode string (incl. garbage) degrades to notify.
    That is deliberate: this control is dark-launched, so an operator typo must not
    silently start denying production traffic. The SECURITY fail-closed lives in the
    decision (deny-on-unknown-taint); the MODE only chooses block-vs-notify once denied.
    """
    if decision != "deny":
        return ""
    return TAINT_ACTION_BLOCK if mode == "enforce" else TAINT_ACTION_NOTIFY
