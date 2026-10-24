//! Repository functions: one module per table family. All queries are
//! runtime (`sqlx::query` / `sqlx::query_as` with turbofish or explicit
//! row types), never the compile-time `query!`/`query_as!` macros — the
//! workspace contract requires the build to succeed with no `DATABASE_URL`
//! set (see `rs/ARCHITECTURE.md`'s pinned-deps list: "macros off").

pub mod credentials;
pub mod grants;
pub mod idp;
pub mod profiles;
pub mod quarantine;
pub mod rate_limit;
pub mod roles;
pub mod servers;
pub mod tools;
