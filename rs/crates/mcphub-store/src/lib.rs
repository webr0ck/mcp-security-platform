//! `mcphub-store` — Postgres (sqlx, runtime queries, rustls) + redis
//! (`ConnectionManager`) + the audit sink for the MCP security gateway.
//!
//! Fail-closed throughout (`rs/ARCHITECTURE.md` invariant 1): every public
//! function returns `Result`, and `StoreError` has a defined mapping onto
//! `mcphub_types::GateError` (see `error.rs`) which itself only ever maps
//! to `Decision::Deny`. There is no code path in this crate that turns a
//! Postgres or redis failure into a default/empty success value.

#![forbid(unsafe_code)]

pub mod audit;
pub mod audit_verify;
pub mod error;
pub mod hash;
pub mod migrate;
pub mod pool;
pub mod redis_store;
pub mod repo;
pub mod security;
pub mod ui_data;

// `pub`, gated by the `testing` feature (not bare `#[cfg(test)]`, which
// would make this module invisible to OTHER crates' test builds — `cfg(test)`
// only applies to this crate's own `cargo test`): other crates' tests (e.g.
// `mcphub-selfservice`) need the same throwaway-migrated-database helper
// rather than reimplementing it — one bootstrap helper, not N copies to
// keep in sync.
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use audit::{AuditRecord, AuditSink, Outcome, PgRedisAuditSink};
pub use audit_verify::{verify_chain, ChainVerifyReport};
pub use security::assert_non_privileged_connection;
pub use error::StoreError;
pub use pool::PoolConfig;
pub use redis_store::RedisStore;
pub use ui_data::PgUiData;
