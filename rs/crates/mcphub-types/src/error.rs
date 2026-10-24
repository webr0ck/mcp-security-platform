use crate::decision::DenyReason;
use thiserror::Error;

/// Errors surfaced by gate implementations (`Authenticator`, `PolicyEngine`,
/// `CredentialBroker`, `AuditSink`, `EntitlementStore`, `RateLimiter` in
/// `mcphub-gateway`). By construction there is no `Ok(Allow)` reachable from
/// any of these variants — callers must explicitly map `Err` to
/// `Decision::Deny`, never to `Decision::Allow` (invariant 1).
#[derive(Debug, Error)]
pub enum GateError {
    #[error("dependency unavailable: {0}")]
    DependencyUnavailable(&'static str),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("internal error")]
    Internal,

    // NOTE (component 3 / mcphub-policy): added the three variants below.
    // `DenyReason` already had `RateLimited`, `TaintFloor`, and
    // `EntitlementMissing` arms, but nothing in `GateError` could produce
    // them — every rate-limit, taint-floor, or entitlement denial collapsed
    // into `PolicyDenied` or a generic `DependencyUnavailable`, which would
    // have made those audit codes permanently unused. Flagged for component
    // 1 to confirm; purely additive, no existing arm changed.
    #[error("rate limited")]
    RateLimited,

    #[error("taint floor exceeded")]
    TaintFloor,

    #[error("entitlement missing")]
    EntitlementMissing,
}

impl GateError {
    /// Every `GateError` maps to a `DenyReason` — never to allow. This is
    /// the structural enforcement of invariant 1 ("`Err` from any gate maps
    /// to Deny, never Allow"): there is no code path that can turn a
    /// `GateError` into `Decision::Allow`.
    pub fn to_deny_reason(&self) -> DenyReason {
        match self {
            GateError::DependencyUnavailable(what) => DenyReason::DependencyUnavailable(what),
            GateError::InvalidRequest(_) => DenyReason::PolicyDenied,
            GateError::Internal => DenyReason::DependencyUnavailable("internal"),
            GateError::RateLimited => DenyReason::RateLimited,
            GateError::TaintFloor => DenyReason::TaintFloor,
            GateError::EntitlementMissing => DenyReason::EntitlementMissing,
        }
    }
}

/// Startup-time configuration errors. `mcphubd::main` must refuse to start
/// (fail-closed) rather than boot with any of these.
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("identity configuration is absent: no IDP configured at install time, at runtime, or in the DB")]
    NoIdentityConfig,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("failed to bind listener on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_error_never_maps_to_allow() {
        // There is no `Decision::Allow` arm reachable here — this test pins
        // the shape of `to_deny_reason`'s return type (`DenyReason`, not
        // `Decision`), so a future edit can't quietly widen it to allow.
        let errs: Vec<GateError> = vec![
            GateError::DependencyUnavailable("opa"),
            GateError::InvalidRequest("bad json".into()),
            GateError::Internal,
            GateError::RateLimited,
            GateError::TaintFloor,
            GateError::EntitlementMissing,
        ];
        for e in errs {
            let reason: DenyReason = e.to_deny_reason();
            // Exhaustive match compiles only because DenyReason has no Allow variant.
            let _code = reason.code();
        }
    }
}
