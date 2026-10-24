//! Runtime privilege assertions (D7): the append-only guarantee on
//! `audit_events` (triggers + `0004_ops.up.sql`'s GRANT/REVOKE model) is
//! decoration if the process that actually connects at runtime is a
//! superuser or the table's owner — both can `TRUNCATE`, `DROP TABLE`, or
//! `ALTER TABLE ... DISABLE TRIGGER ALL` regardless of any GRANT/REVOKE,
//! because ownership (and superuser status) bypasses the privilege system
//! entirely. `bin/mcphubd`'s `tests/e2e.rs`-style startup and this crate's
//! own `testing::test_pool_migrated` both connect as the migration-running
//! superuser today — fine for tests and for running migrations, never fine
//! for the connection the gateway serves traffic on.
//!
//! Call [`assert_non_privileged_connection`] once, right after connecting
//! the production pool and right after `migrate::check` (which legitimately
//! needs elevated privileges and must keep using its own connection/role —
//! do NOT call this assertion before migrations run). See this crate's
//! handoff report for the exact `bin/mcphubd` wiring this requires.

use crate::error::StoreError;
use sqlx::PgPool;

/// Fails closed (`Err`) if the connected role is a superuser OR owns
/// `audit_events`. Either condition means the privilege model in
/// `0004_ops.up.sql` (SELECT/INSERT only, UPDATE/DELETE explicitly
/// revoked, no TRUNCATE grant) is not actually being enforced against
/// this connection — the role could bypass it entirely.
pub async fn assert_non_privileged_connection(pool: &PgPool) -> Result<(), StoreError> {
    let (current_user, is_superuser): (String, bool) =
        sqlx::query_as("SELECT current_user::text, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)")
            .fetch_one(pool)
            .await?;

    if is_superuser {
        return Err(StoreError::InvariantViolation(format!(
            "refusing to serve traffic: connected role '{current_user}' is a Postgres superuser, \
             which bypasses every GRANT/REVOKE on audit_events (TRUNCATE, DISABLE TRIGGER, DROP \
             TABLE all become available) — connect as a dedicated non-superuser application role instead"
        )));
    }

    let owner: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE relname = 'audit_events' AND relkind = 'r'",
    )
    .fetch_optional(pool)
    .await?;

    match owner {
        Some(owner) if owner == current_user => Err(StoreError::InvariantViolation(format!(
            "refusing to serve traffic: connected role '{current_user}' OWNS audit_events, which \
             bypasses every GRANT/REVOKE the same way superuser does (owners may TRUNCATE, DISABLE \
             TRIGGER, and DROP their own tables regardless of any REVOKE) — connect as mcphub_app \
             (or an equivalent non-owner application role) instead"
        ))),
        Some(_) | None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_migrated;

    /// Mutation proof (D7): `testing::test_pool_migrated` connects as the
    /// admin/superuser role by construction (see its own doc comment) —
    /// this is exactly the "decorative privilege model" scenario the
    /// assertion exists to catch, so it must fail here. If this assertion
    /// were ever weakened to a no-op, this test would start passing
    /// wrongly (i.e. it pins the "must reject" behavior, not just "must
    /// compile").
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn superuser_or_owner_connection_is_rejected() {
        let pool = test_pool_migrated().await;
        let result = assert_non_privileged_connection(&pool).await;
        assert!(
            result.is_err(),
            "the migration-running connection is the table owner (and typically superuser too) — \
             it must be rejected, not silently accepted"
        );
    }

    /// The positive case: a role that is neither superuser nor the table
    /// owner, with exactly the 0004_ops.up.sql grant shape, must pass —
    /// and must then be structurally unable to TRUNCATE/ALTER/DROP
    /// audit_events, proving the privilege model (not just the assertion)
    /// actually holds once a real non-privileged role is used.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn least_privilege_role_passes_and_cannot_bypass_append_only() {
        let admin_pool = test_pool_migrated().await;

        // mcphub_app is created NOLOGIN by 0004_ops.up.sql; deployment
        // tooling grants LOGIN + a real password out of band (see that
        // migration's comment). For this test we do the same thing
        // deploy-time tooling would, scoped to this throwaway database.
        sqlx::query("ALTER ROLE mcphub_app WITH LOGIN PASSWORD 'test-only-password'")
            .execute(&admin_pool)
            .await
            .unwrap();

        // Discover which throwaway database test_pool_migrated created so
        // we can open a second pool, as mcphub_app, against the SAME db.
        let (db_name,): (String,) = sqlx::query_as("SELECT current_database()").fetch_one(&admin_pool).await.unwrap();

        let admin_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:test@localhost:55432/postgres".to_string());
        let base = admin_url.split('/').take(3).collect::<Vec<_>>().join("/");
        let app_url = format!("{base}/{db_name}").replacen("postgres:test@", "mcphub_app:test-only-password@", 1);

        let app_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&app_url)
            .await
            .expect("connect as mcphub_app");

        assert!(
            assert_non_privileged_connection(&app_pool).await.is_ok(),
            "mcphub_app is neither superuser nor table owner — it must pass"
        );

        // D7's actual claim: even connected as the "app" role, none of the
        // three bypass vectors work.
        let truncate = sqlx::query("TRUNCATE audit_events").execute(&app_pool).await;
        assert!(truncate.is_err(), "mcphub_app must not be able to TRUNCATE audit_events");

        let disable_trigger =
            sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER ALL").execute(&app_pool).await;
        assert!(disable_trigger.is_err(), "mcphub_app must not be able to disable audit_events's triggers");

        let drop_table = sqlx::query("DROP TABLE audit_events").execute(&app_pool).await;
        assert!(drop_table.is_err(), "mcphub_app must not be able to drop audit_events");

        // And the append-only trigger itself still holds for this role
        // (belt-and-braces: even if a future migration accidentally
        // re-granted UPDATE/DELETE to mcphub_app, the trigger — which
        // fires regardless of role — still blocks it).
        let update = sqlx::query("UPDATE audit_events SET outcome = 'deny' WHERE 1=0").execute(&app_pool).await;
        assert!(update.is_err(), "UPDATE on audit_events must be blocked for mcphub_app");
    }

    /// D7's TRUNCATE vector specifically: row-level triggers (the original
    /// BEFORE UPDATE/DELETE guards from 0003_audit.up.sql) never fire for
    /// TRUNCATE — only a `FOR EACH STATEMENT` trigger can intercept it
    /// (added in 0006_audit_hardening.up.sql). This test proves the
    /// STATEMENT-LEVEL trigger itself is what's blocking TRUNCATE — it
    /// runs as the migration-owning admin/superuser connection (which
    /// bypasses every GRANT/REVOKE), so a privilege-based explanation is
    /// ruled out; only the trigger firing explains the rejection.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn truncate_is_blocked_even_for_a_privileged_connection() {
        let pool = test_pool_migrated().await;

        let result = sqlx::query("TRUNCATE audit_events").execute(&pool).await;
        assert!(
            result.is_err(),
            "TRUNCATE must be rejected by trg_audit_events_no_truncate even for a role that has \
             every table privilege — only a disabled/dropped trigger would let this through"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("append-only") || err.contains("restrict_violation") || err.to_lowercase().contains("truncate"),
            "rejection should be attributable to the append-only guard, not some unrelated failure: {err}"
        );
    }

    /// Mutation proof (D7): disabling the trigger — the exact bypass a
    /// table-owner-level attacker would use — makes TRUNCATE succeed
    /// again. This is the "revert and confirm red" counterpart to the
    /// test above: it proves the previous test's rejection really does
    /// come from the trigger (drop/disable it, and the guard is gone),
    /// not from some other unrelated constraint.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disabling_the_truncate_trigger_reopens_the_vector_it_closes() {
        let pool = test_pool_migrated().await;

        sqlx::query("ALTER TABLE audit_events DISABLE TRIGGER trg_audit_events_no_truncate")
            .execute(&pool)
            .await
            .unwrap();

        let result = sqlx::query("TRUNCATE audit_events").execute(&pool).await;
        assert!(
            result.is_ok(),
            "with the guard trigger disabled, TRUNCATE succeeds — confirming the trigger (not \
             something else) is what blocks it when enabled"
        );
    }
}
