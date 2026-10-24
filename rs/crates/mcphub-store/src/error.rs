//! `StoreError` — the single error type every fallible `mcphub-store`
//! operation returns. By construction there is no `Ok`-on-failure path: a
//! Postgres error, a redis error, and a schema-check failure all become
//! `Err(StoreError)`, and callers in `mcphub-gateway` map that to
//! `Decision::Deny` (never `Allow`) per invariant 1.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("postgres error: {0}")]
    Db(#[from] sqlx::Error),

    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("schema check failed: {0}")]
    SchemaCheckFailed(String),

    #[error("migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("row not found")]
    NotFound,

    #[error("invariant violation: {0}")]
    InvariantViolation(String),

    /// Reconstructed, fan-out-friendly classification for a failure that
    /// happened once (e.g. in the audit group-commit writer task) and
    /// must be reported to N independent callers, each via its own
    /// `oneshot` — `sqlx::Error`/`redis::RedisError` are not `Clone`, so
    /// the original error can't be sent more than once. `dependency` and
    /// `message` ARE cheaply cloneable, so each recipient gets a fresh
    /// `StoreError` carrying the same classification and text, not a
    /// clone of the original.
    #[error("dependency unavailable ({dependency}): {message}")]
    DependencyUnavailable { dependency: &'static str, message: String },
}

/// Every `StoreError` maps to a `mcphub_types::GateError`, which in turn
/// maps only to `DenyReason` — never `Decision::Allow`. This is the
/// structural link between "the database/redis is unhappy" and "the
/// request is denied" (ARCHITECTURE.md invariant 1).
impl From<StoreError> for mcphub_types::GateError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Db(_) | StoreError::Migration(_) => {
                mcphub_types::GateError::DependencyUnavailable("postgres")
            }
            StoreError::Redis(_) => mcphub_types::GateError::DependencyUnavailable("redis"),
            StoreError::Serialization(_) => mcphub_types::GateError::Internal,
            StoreError::SchemaCheckFailed(_) => {
                mcphub_types::GateError::DependencyUnavailable("postgres")
            }
            StoreError::NotFound => mcphub_types::GateError::InvalidRequest("not found".into()),
            StoreError::InvariantViolation(msg) => mcphub_types::GateError::InvalidRequest(msg),
            StoreError::DependencyUnavailable { dependency, .. } => {
                mcphub_types::GateError::DependencyUnavailable(dependency)
            }
        }
    }
}
