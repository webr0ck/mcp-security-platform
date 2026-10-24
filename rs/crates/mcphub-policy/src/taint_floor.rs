//! B-coarse taint-floor decision core — direct port of
//! `proxy/app/services/taint_floor.py` (PRD-0001 M2 / SPEC-0001 §8.1).
//!
//! Pure, deterministic, I/O-free. The Redis-backed taint store and the
//! `invoke` gate live elsewhere (`mcphub-store`, `mcphub-gateway`); this
//! module is the decision core those wire together, kept unit-testable on
//! its own exactly like the Python original.

/// The lowest SEP-1913 rank considered "trusted" in the binary collapse
/// (internal). Values below this collapse to untrusted (0).
const TRUSTED_FLOOR_RANK: u8 = 2;

/// Injection modes that do NOT broker a credential upstream. Anything not
/// in this set — including an unrecognized mode string — is treated as
/// injecting, so an unknown mode fails closed (bumps the floor) rather than
/// silently passing through as safe.
fn is_non_injecting(mode: &str) -> bool {
    mode == "none"
}

/// Collapse a SEP-1913 trust_tier rank to binary integrity {0,1}, fail-closed
/// on `None`/unknown.
pub fn binary_integrity(trust_tier: Option<u8>) -> u8 {
    match trust_tier {
        None => 0,
        Some(t) if t >= TRUSTED_FLOOR_RANK => 1,
        Some(_) => 0,
    }
}

/// True if a result from a server at this trust_tier taints the session.
pub fn result_taints_session(trust_tier: Option<u8>) -> bool {
    binary_integrity(trust_tier) == 0
}

/// Resolve the injection mode for the safety bump: injecting if EITHER the
/// tool-level mode or the server default is injecting. Strictly conservative
/// — can only over-bump (fail-closed), never under-bump.
pub fn effective_injection_mode(tool_mode: Option<&str>, server_default: Option<&str>) -> String {
    for mode in [tool_mode, server_default].into_iter().flatten() {
        if !is_non_injecting(mode) {
            return mode.to_string();
        }
    }
    "none".to_string()
}

/// Bump a credential-injecting tool's floor to >=1 (it can never be a low
/// sink). Unknown/garbage modes fail closed (treated as injecting).
pub fn effective_required_integrity(tool_required_integrity: u8, injection: Option<&str>) -> u8 {
    let mode = injection.unwrap_or("none");
    if is_non_injecting(mode) {
        tool_required_integrity
    } else {
        tool_required_integrity.max(1)
    }
}

/// The binary B-coarse rule: deny a high sink in a tainted session.
/// `tainted` must already be resolved fail-closed by the caller (store
/// error or unknown -> true).
pub fn taint_floor_decision(tainted: bool, required_integrity: u8) -> Decision {
    if tainted && required_integrity >= 1 {
        Decision::Deny
    } else {
        Decision::Allow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// The two Phase-0 taint-floor actions (PRD-0010).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintAction {
    /// No action; the call proceeds normally, no notice.
    None,
    /// Hard-deny (fail-closed).
    Block,
    /// Allow-with-disclaimer (Phase-0 default).
    Notify,
}

/// Map a `taint_floor_decision` + configured mode to the effective action.
/// Only `mode == "enforce"` enforces; any other mode string (including
/// garbage) degrades to notify — deliberate, since this control is
/// dark-launched and an operator typo must not silently start denying
/// production traffic. The SECURITY fail-closed lives in the decision
/// (deny-on-unknown-taint, upstream of this function); `mode` only chooses
/// block-vs-notify once a deny has already been decided.
pub fn resolve_taint_action(decision: Decision, mode: &str) -> TaintAction {
    if decision != Decision::Deny {
        return TaintAction::None;
    }
    if mode == "enforce" {
        TaintAction::Block
    } else {
        TaintAction::Notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_trust_tier_is_untrusted() {
        assert_eq!(binary_integrity(None), 0);
        assert!(result_taints_session(None));
    }

    #[test]
    fn trusted_floor_boundary() {
        assert_eq!(binary_integrity(Some(1)), 0);
        assert_eq!(binary_integrity(Some(2)), 1);
        assert_eq!(binary_integrity(Some(4)), 1);
    }

    #[test]
    fn unknown_injection_mode_fails_closed_to_injecting() {
        // "none" is the only non-injecting mode; anything else — including
        // garbage — bumps the floor.
        assert_eq!(effective_required_integrity(0, Some("weird_mode")), 1);
        assert_eq!(effective_required_integrity(0, Some("none")), 0);
        assert_eq!(effective_required_integrity(0, None), 0);
    }

    #[test]
    fn injecting_tool_never_a_low_sink() {
        assert_eq!(effective_required_integrity(0, Some("bearer_header")), 1);
    }

    #[test]
    fn either_side_injecting_bumps_the_floor() {
        assert_eq!(effective_injection_mode(Some("none"), Some("bearer_header")), "bearer_header");
        assert_eq!(effective_injection_mode(Some("bearer_header"), Some("none")), "bearer_header");
        assert_eq!(effective_injection_mode(Some("none"), Some("none")), "none");
        assert_eq!(effective_injection_mode(None, None), "none");
    }

    #[test]
    fn tainted_session_denies_high_sink() {
        assert_eq!(taint_floor_decision(true, 1), Decision::Deny);
        assert_eq!(taint_floor_decision(true, 0), Decision::Allow);
        assert_eq!(taint_floor_decision(false, 1), Decision::Allow);
    }

    #[test]
    fn only_enforce_mode_blocks_garbage_mode_notifies() {
        assert_eq!(resolve_taint_action(Decision::Deny, "enforce"), TaintAction::Block);
        assert_eq!(resolve_taint_action(Decision::Deny, "notify"), TaintAction::Notify);
        assert_eq!(resolve_taint_action(Decision::Deny, "typo-mode"), TaintAction::Notify);
        assert_eq!(resolve_taint_action(Decision::Allow, "enforce"), TaintAction::None);
    }
}
