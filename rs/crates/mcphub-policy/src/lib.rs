//! `mcphub-policy` — in-process Rego policy evaluation (`regorus`), the
//! discovery==invoke entitlement predicate, the taint-floor decision core,
//! and per-client rate limiting. Component 3's first of two crates (see
//! `mcphub-creds` for the credential broker).
//!
//! No network hop to a sidecar OPA: `authz.rego` is embedded, signature
//! verified at bundle-load time, compiled once, and evaluated in-process —
//! see `engine::RegorusPolicyEngine`.

#![forbid(unsafe_code)]

pub mod anomaly_score;
pub mod bundle;
pub mod cache;
pub mod engine;
pub mod entitlement;
pub mod error;
pub mod rate_limit;
pub mod taint_floor;

pub use bundle::PolicyBundle;
pub use engine::RegorusPolicyEngine;
pub use entitlement::{GrantResolver, GrantsSource, InMemoryCatalog, InMemoryGrants, ToolCatalog};
pub use error::PolicyError;
pub use rate_limit::GovernorRateLimiter;
