//! Migration runner. `run()` applies pending migrations; `check()` is the
//! `--check` mode wired into the `mcphubd` binary's startup path — it
//! refuses to proceed (returns `Err`) if the schema is dirty (a prior
//! migration failed partway) or behind (migrations exist that have not
//! been applied), without applying anything itself. This is the
//! fail-closed complement to `run()`: an operator who wants "start only if
//! the schema is exactly what this binary expects" gets that via `check`,
//! never an implicit auto-apply.

use crate::error::StoreError;
use sqlx::PgPool;
use std::collections::BTreeSet;

/// Embeds `rs/migrations/` at compile time. Path is relative to this
/// crate's `Cargo.toml` (`rs/crates/mcphub-store/`).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Apply all pending migrations. Safe to call on every startup — already
/// applied migrations are skipped (idempotent).
pub async fn run(pool: &PgPool) -> Result<(), StoreError> {
    MIGRATOR.run(pool).await?;
    Ok(())
}

/// Refuse to start unless the schema is exactly up to date: every
/// migration in `MIGRATOR` has a corresponding successful row in
/// `_sqlx_migrations`, and no applied migration is marked `success = false`
/// (dirty). Does not apply anything.
pub async fn check(pool: &PgPool) -> Result<(), StoreError> {
    let applied: Vec<(i64, bool)> = match sqlx::query_as::<_, (i64, bool)>(
        "SELECT version, success FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(sqlx::Error::Database(db_err)) if db_err.code().as_deref() == Some("42P01") => {
            // undefined_table: migrations have never been run against this database.
            return Err(StoreError::SchemaCheckFailed(
                "no _sqlx_migrations table — database has never been migrated".into(),
            ));
        }
        Err(e) => return Err(e.into()),
    };

    if let Some((dirty_version, _)) = applied.iter().find(|(_, success)| !success) {
        return Err(StoreError::SchemaCheckFailed(format!(
            "migration {dirty_version} is dirty (a prior run failed partway through)"
        )));
    }

    let applied_versions: BTreeSet<i64> = applied.iter().map(|(v, _)| *v).collect();
    for migration in MIGRATOR.iter() {
        if !applied_versions.contains(&migration.version) {
            return Err(StoreError::SchemaCheckFailed(format!(
                "migration {} ({}) has not been applied — database is behind this binary",
                migration.version, migration.description
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_fresh;

    #[tokio::test]
    #[ignore = "requires a live Postgres; set TEST_DATABASE_URL and run with `cargo test -- --ignored`"]
    async fn check_fails_before_run_and_passes_after() {
        let pool = test_pool_fresh().await;

        // Fresh database, migrations not yet applied: check must refuse.
        let before = check(&pool).await;
        assert!(before.is_err(), "check() must fail on an unmigrated database");

        run(&pool).await.expect("run() should apply cleanly");

        let after = check(&pool).await;
        assert!(after.is_ok(), "check() must pass once every migration is applied: {after:?}");
    }

    /// Mutation proof for D7's down-migration fix: reverting all the way
    /// back through 0003_audit must NOT destroy `audit_events`. Before the
    /// fix, `0003_audit.down.sql` was `DROP TABLE IF EXISTS audit_events`
    /// — a single `sqlx migrate revert` (looped down to version 0, as this
    /// test does) would have silently erased the entire compliance ledger.
    /// Now it must fail loudly instead, and the table must still exist and
    /// still contain whatever was in it.
    #[tokio::test]
    #[ignore = "requires a live Postgres; set TEST_DATABASE_URL and run with `cargo test -- --ignored`"]
    async fn reverting_all_migrations_refuses_to_destroy_the_audit_ledger() {
        use crate::testing::test_pool_migrated;

        let pool = test_pool_migrated().await;

        // Prove there's something in the table this whole exercise is
        // protecting, not just an empty shell.
        sqlx::query(
            "INSERT INTO audit_events (event_id, event_ts, request_id, principal_id, tool_name, \
             outcome, sha256_hash, redacted_fields, chain_id, chain_seq) VALUES \
             (gen_random_uuid(), now(), 'req-1', 'alice', 'echo', 'allow', repeat('a', 64), \
             '{}'::jsonb, gen_random_uuid(), 0)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let revert_all = MIGRATOR.undo(&pool, 0).await;
        assert!(
            revert_all.is_err(),
            "reverting down through 0003_audit must fail (refuse to destroy the ledger), not succeed"
        );

        // The table — and the row inserted above — must still be there.
        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM audit_events")
            .fetch_one(&pool)
            .await
            .expect("audit_events must still exist after the refused revert");
        assert!(count.0 >= 1, "the row inserted before the revert attempt must still be present");
    }
}
