//! Test-only helpers for spinning up an isolated database per test against
//! a live Postgres instance. Not compiled into non-test builds.
//!
//! Point `TEST_DATABASE_URL` at an admin connection (a database the test
//! user can `CREATE DATABASE` against — typically the server's default
//! `postgres` database). Each helper creates a uniquely named database,
//! so tests can run concurrently without clobbering each other's schema
//! state. Falls back to `postgres://postgres:test@localhost:55432/postgres`
//! (the throwaway container documented in this crate's test report) when
//! the env var is unset.

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

fn admin_database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:test@localhost:55432/postgres".to_string())
}

/// Creates a fresh, empty database (no migrations applied) and returns a
/// pool connected to it. Used by tests that need to exercise `migrate::run`
/// / `migrate::check` themselves.
pub async fn test_pool_fresh() -> PgPool {
    let admin_url = admin_database_url();
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .expect("connect to admin database for test setup");

    let db_name = format!("mcphub_test_{}", uuid::Uuid::new_v4().simple());
    admin_pool
        .execute(format!("CREATE DATABASE \"{db_name}\"").as_str())
        .await
        .expect("create throwaway test database");

    let base = url::strip_db(&admin_url);
    let test_url = format!("{base}/{db_name}");

    PgPoolOptions::new()
        .max_connections(5)
        .connect(&test_url)
        .await
        .expect("connect to fresh test database")
}

/// Creates a fresh database AND applies every migration. Used by tests
/// that just need a ready-to-use schema (the common case).
pub async fn test_pool_migrated() -> PgPool {
    let pool = test_pool_fresh().await;
    crate::migrate::run(&pool).await.expect("apply migrations to test database");
    pool
}

/// Tiny helper: strip the trailing `/dbname` (and any query string) off a
/// Postgres URL, leaving `postgres://user:pass@host:port`.
mod url {
    pub fn strip_db(url: &str) -> String {
        let without_query = url.split('?').next().unwrap_or(url);
        match without_query.rfind('/') {
            // Only strip if the slash comes after the scheme's "//".
            Some(idx) if idx > without_query.find("//").map(|i| i + 1).unwrap_or(0) => {
                without_query[..idx].to_string()
            }
            _ => without_query.to_string(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn strips_trailing_database_name() {
            assert_eq!(
                strip_db("postgres://user:pass@localhost:55432/postgres"),
                "postgres://user:pass@localhost:55432"
            );
        }

        #[test]
        fn leaves_url_without_db_untouched() {
            assert_eq!(
                strip_db("postgres://user:pass@localhost:55432"),
                "postgres://user:pass@localhost:55432"
            );
        }
    }
}
