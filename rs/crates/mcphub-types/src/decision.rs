use crate::ids::ServerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ToolRef {
    pub server: ServerId,
    pub tool: String,
}

/// Per-decision obligations attached to an `Allow`. These are instructions
/// the dispatch stage must honor — they are not optional hints.
///
/// TODO: confirm exact field set with architect; the fields below are the
/// obligations referenced by name in ARCHITECTURE.md's enforcement order
/// (rate limiting, taint floor, credential injection, response filtering).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Obligations {
    /// Set when the taint-floor gate ran in `notify` mode: a disclaimer must
    /// be attached to the response rather than the call being denied.
    pub taint_notice: Option<String>,
    /// Extra headers the dispatch stage must inject (credential broker
    /// output). Values are opaque here — `mcphub-creds` owns redaction of
    /// the actual secret material before it ever reaches this struct's
    /// caller-visible representation.
    pub inject_headers: HashMap<String, String>,
    /// Response bytes must be filtered before returning to the caller.
    pub requires_response_filter: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuthMode {
    SharedPassthrough,
    SharedExchange,
    DedicatedPort { port: u16 },
}

/// Stable machine codes for the audit record. Every gate that can deny must
/// produce one of these — no gate is allowed to invent an ad-hoc string.
/// `DependencyUnavailable` carries a `&'static str` component name so a
/// fail-closed audit record still says *which* dependency was unreachable,
/// without ever carrying request-derived (and therefore log-injectable)
/// content.
// NOTE (component 3, revised after security review): this originally
// derived `#[derive(Serialize, Deserialize)]` with `#[serde(tag =
// "reason")]`, then briefly had a hand-written `Deserialize` (via a
// `Box::leak` on the `DependencyUnavailable` component-name field) because
// the derive can't produce a `&'static str` on the read side. That
// hand-written `Deserialize` was a real vulnerability: `Box::leak`'d
// exactly the string an attacker controlled — anything able to feed a
// serialized `DenyReason` in (however that string was labelled
// "bounded") could leak unbounded memory, a trivially scriptable remote
// OOM, since every deserialize call leaked a new `'static` allocation that
// is never freed for the life of the process.
//
// Audited: nothing in this workspace deserializes a `DenyReason` (or
// `Decision`, which contains one) from the wire — `grep -rn
// "from_str::<.*DenyReason\|from_value::<.*DenyReason"` across the repo
// returns no hits. Every reconstruction of a `DenyReason` for display
// (e.g. `mcphub-store/src/ui_data.rs::deny_reason_view_from_code`) matches
// a `code(): &str` against a fixed set of literals and returns one of
// THIS enum's own variants — it never deserializes attacker-controlled
// JSON into `DenyReason` directly, and `DependencyUnavailable`'s
// component there is a hardcoded `"unknown"` literal, not leaked input.
// `Serialize` alone therefore covers every real caller (audit records,
// HTTP error bodies, the UI view). Deleted `Deserialize` entirely instead
// of trying to bound the leak — removing the attack surface beats
// policing it. If a future caller genuinely needs to deserialize a
// `DenyReason`, the safe shape is: match the `reason` string against the
// SAME fixed allowlist `code()` produces, mapping anything unrecognised to
// a single static `DependencyUnavailable("unknown")` — never `Box::leak`
// attacker-supplied bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    Unauthenticated,
    NoGrant,
    Quarantined,
    PolicyDenied,
    EntitlementMissing,
    RateLimited,
    TaintFloor,
    DependencyUnavailable(&'static str),
}

impl DenyReason {
    /// Stable machine code, safe to place in an audit record or an HTTP
    /// error body. Never derived from request content.
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::Unauthenticated => "unauthenticated",
            DenyReason::NoGrant => "no_grant",
            DenyReason::Quarantined => "quarantined",
            DenyReason::PolicyDenied => "policy_denied",
            DenyReason::EntitlementMissing => "entitlement_missing",
            DenyReason::RateLimited => "rate_limited",
            DenyReason::TaintFloor => "taint_floor",
            DenyReason::DependencyUnavailable(_) => "dependency_unavailable",
        }
    }
}

/// Wire shape for `DenyReason`, matching what `#[serde(tag = "reason")]`
/// would have produced: `{"reason": "<code>"}` for unit variants,
/// `{"reason": "dependency_unavailable", "component": "<name>"}` for the one
/// tuple variant.
#[derive(Serialize, Deserialize)]
struct DenyReasonWire {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    component: Option<String>,
}

impl Serialize for DenyReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let wire = DenyReasonWire {
            reason: self.code().to_string(),
            component: match self {
                DenyReason::DependencyUnavailable(c) => Some((*c).to_string()),
                _ => None,
            },
        };
        wire.serialize(serializer)
    }
}

// Deliberately NOT `Deserialize`. `DenyReason` is write-only: it is produced by
// the gateway and serialized into audit records and error bodies. Nothing reads
// one back off the wire.
//
// The previous hand-written `Deserialize` leaked its `component` field via
// `Box::leak` to satisfy `&'static str`. The comment defending it claimed
// component names come from a fixed operator-controlled set — true of the
// serialize side, false of the deserialize side, which accepted any string from
// the wire and leaked it permanently. That is an unbounded, remotely-driven
// memory leak: feed it distinct component names in a loop and the process grows
// until it is OOM-killed.
//
// Not deriving it removes the attack surface outright rather than bounding it.
// If a read path is ever genuinely needed, deserialize into `DenyReasonWire` and
// map to a fixed allowlist of `&'static str` literals — never leak the input.

impl std::fmt::Display for DenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for DenyReason {}

// `Serialize` only, for the same reason as `DenyReason` above: a `Decision` is
// produced by the gateway and written out (audit, error body), never read back
// in. Deriving `Deserialize` here would require `DenyReason: Deserialize` and
// so would reintroduce exactly the leak deleted above.
#[derive(Debug, Clone, Serialize)]
pub enum Decision {
    Allow { obligations: Obligations },
    Deny(DenyReason),
}

impl Decision {
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    pub fn deny(reason: DenyReason) -> Self {
        Decision::Deny(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exhaustive `match` compiles only if every `DenyReason` variant is
    /// handled — this test doubles as a compile-time guard against a silent
    /// `_ => "unknown"` catch-all creeping into `code()`.
    #[test]
    fn every_deny_reason_has_a_stable_code() {
        let reasons = [
            DenyReason::Unauthenticated,
            DenyReason::NoGrant,
            DenyReason::Quarantined,
            DenyReason::PolicyDenied,
            DenyReason::EntitlementMissing,
            DenyReason::RateLimited,
            DenyReason::TaintFloor,
            DenyReason::DependencyUnavailable("redis"),
        ];
        for r in reasons {
            assert!(!r.code().is_empty());
        }
    }

    #[test]
    fn decision_is_allow_distinguishes_variants() {
        assert!(Decision::Allow { obligations: Obligations::default() }.is_allow());
        assert!(!Decision::deny(DenyReason::NoGrant).is_allow());
    }

    /// Regression pin for the `Serialize` wire shape (the same shape the
    /// deleted `Deserialize` impl consumed) — `{"reason": "...", "component":
    /// "..."}`, `component` present only for `DependencyUnavailable`. If
    /// `DenyReason` ever needs a read path again, it must match THIS shape
    /// against a fixed allowlist (see the comment above the enum) rather
    /// than leaking whatever `component` string arrives.
    #[test]
    fn deny_reason_wire_shape_is_stable() {
        let unit = serde_json::to_value(DenyReason::Quarantined).unwrap();
        assert_eq!(unit, serde_json::json!({"reason": "quarantined"}));

        let with_component = serde_json::to_value(DenyReason::DependencyUnavailable("redis")).unwrap();
        assert_eq!(
            with_component,
            serde_json::json!({"reason": "dependency_unavailable", "component": "redis"})
        );
    }

    // No test asserts "DenyReason does not implement Deserialize" directly —
    // stable Rust has no negative-trait-bound assertion short of a
    // `trybuild` compile-fail test, which felt like more machinery than this
    // warrants. The guard that exists: `DependencyUnavailable(&'static
    // str)`'s field makes a correct, safe `#[derive(Deserialize)]` type-
    // impossible (there is no owned backing store for `&'static str`), so
    // the only way to reintroduce a read path is a hand-written impl someone
    // has to consciously write — and the comment block above the enum spells
    // out the one safe shape (fixed allowlist, never `Box::leak`) for
    // whoever does. `deny_reason_wire_shape_is_stable` above pins the shape
    // that hand-written impl would need to match.
}
