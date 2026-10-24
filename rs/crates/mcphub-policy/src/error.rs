use mcphub_types::GateError;
use thiserror::Error;

/// Errors internal to `mcphub-policy`. Every variant maps to a `GateError`
/// (never to a bare "allow"), so the fail-closed contract at the
/// `mcphub-gateway` trait boundary holds regardless of which of these fires.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy bundle failed signature verification: {0}")]
    BundleSignatureInvalid(String),

    #[error("policy bundle is malformed: {0}")]
    BundleMalformed(String),

    #[error("no policy bundle has been loaded")]
    NotLoaded,

    #[error("policy data has never been synced")]
    DataNeverSynced,

    #[error("policy data is stale (older than the configured max age)")]
    DataStale,

    #[error("rego evaluation failed: {0}")]
    Eval(String),
}

impl PolicyError {
    /// Every failure mode here is a dependency/config problem, never a
    /// legitimate "this request is invalid" — so all of them map to
    /// `DependencyUnavailable`, which `GateError::to_deny_reason` in turn
    /// maps to `DenyReason::DependencyUnavailable`. This keeps the audit
    /// trail honest: "policy denied this call" (an authz decision) and
    /// "the policy engine was unusable" (an outage) are different facts and
    /// must not be conflated.
    pub fn to_gate_error(&self) -> GateError {
        match self {
            PolicyError::BundleSignatureInvalid(_) => {
                GateError::DependencyUnavailable("policy_bundle_signature")
            }
            PolicyError::BundleMalformed(_) => GateError::DependencyUnavailable("policy_bundle"),
            PolicyError::NotLoaded => GateError::DependencyUnavailable("policy_engine_not_loaded"),
            PolicyError::DataNeverSynced => {
                GateError::DependencyUnavailable("policy_data_never_synced")
            }
            PolicyError::DataStale => GateError::DependencyUnavailable("policy_data_stale"),
            PolicyError::Eval(_) => GateError::DependencyUnavailable("policy_eval"),
        }
    }
}
