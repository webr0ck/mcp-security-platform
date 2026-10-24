//! `profiles` — per-(principal, mcp_name) self-service opt-out, narrowing
//! (never widening) whatever `grants` already permits. See
//! 0013_profiles.up.sql for the full data-model rationale and the
//! grants-vs-profiles composition rule.

use crate::error::StoreError;
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProfileRow {
    pub enabled: bool,
    /// NULL = unrestricted (every function allowed). See the migration's
    /// doc comment — this is an allowlist, never a denylist.
    pub allowed_functions: Option<Vec<String>>,
}

/// `None` means no explicit row exists — the caller must apply the default
/// (enabled=true, allowed_functions=None/unrestricted), mirroring the
/// Python platform's `_get_profile_row` contract exactly (absence of a row
/// is not itself a denial).
pub async fn get_profile(pool: &PgPool, principal_id: &str, mcp_name: &str) -> Result<Option<ProfileRow>, StoreError> {
    let row = sqlx::query_as::<_, ProfileRow>(
        "SELECT enabled, allowed_functions FROM profiles WHERE principal_id = $1 AND mcp_name = $2",
    )
    .bind(principal_id)
    .bind(mcp_name)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// True when this write would strand `changed_by` with no tool left to
/// inspect or undo it: disabling `_SELF_SERVICE_MCP_NAME` (or narrowing its
/// recovery functions) for yourself, with no admin-role bypass — an admin
/// who does this to their own principal is locked out exactly like anyone
/// else, matching the Python platform's `would_self_lockout` (an admin
/// restricting ANOTHER principal's profile is legitimate policy and stays
/// allowed, since that principal isn't the one who lost their own recovery
/// path).
///
/// Scoped to `enabled=false` writes on the self-service MCP itself — a
/// function-level narrowing that excludes a recovery function is caught by
/// the caller passing the post-narrowing `allowed_functions` and checking
/// membership itself (see `mcphub-selfservice::profile_tools`), since this
/// function only sees the coarse enable/disable axis.
pub fn would_self_lockout(principal_id: &str, mcp_name: &str, enabled: bool, changed_by: &str) -> bool {
    !enabled && mcp_name == SELF_SERVICE_MCP_NAME && changed_by == principal_id
}

/// The self-service MCP's own registry name — kept here (not just in
/// `mcphub-selfservice`) because the guard this constant feeds
/// (`would_self_lockout`) is centralized in this crate precisely so every
/// future writer of `profiles` (not just today's one caller) gets it for
/// free. Mirrors the Python platform's documented reasoning verbatim: "11
/// call sites... route through this function — guarding each caller would
/// leave the next one unprotected."
pub const SELF_SERVICE_MCP_NAME: &str = "self-service";

/// Recovery functions: the tools a principal needs to inspect and undo a
/// profile restriction on the self-service MCP itself. Narrowing
/// `allowed_functions` to exclude any of these, for yourself, is the
/// function-level half of the self-lockout guard — see
/// `mcphub-selfservice::profile_tools::disable_function` for where this is
/// actually checked (that layer has product knowledge and the target
/// function name in hand well before an `upsert_profile` call is made).
pub const RECOVERY_FUNCTIONS: &[&str] = &["get_profile", "enable_mcp", "enable_function"];

/// Insert or update a profile row. Refuses a coarse-grained self-lockout
/// (see `would_self_lockout`) — enforced here, not just at the caller, so
/// no future write path can bypass it by mistake.
pub async fn upsert_profile(
    pool: &PgPool,
    principal_id: &str,
    mcp_name: &str,
    enabled: bool,
    allowed_functions: Option<&[String]>,
    updated_by: &str,
) -> Result<(), StoreError> {
    if would_self_lockout(principal_id, mcp_name, enabled, updated_by) {
        return Err(StoreError::InvariantViolation(format!(
            "refusing to disable {mcp_name:?} in {principal_id}'s own profile: it holds their own recovery tools"
        )));
    }

    sqlx::query(
        r#"
        INSERT INTO profiles (principal_id, mcp_name, enabled, allowed_functions, updated_by)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (principal_id, mcp_name) DO UPDATE SET
            enabled           = EXCLUDED.enabled,
            allowed_functions = EXCLUDED.allowed_functions,
            updated_by        = EXCLUDED.updated_by
        "#,
    )
    .bind(principal_id)
    .bind(mcp_name)
    .bind(enabled)
    .bind(allowed_functions)
    .bind(updated_by)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_lockout_blocks_own_disable_of_self_service_mcp() {
        assert!(would_self_lockout(SELF_SERVICE_MCP_NAME, SELF_SERVICE_MCP_NAME, false, SELF_SERVICE_MCP_NAME));
    }

    #[test]
    fn self_lockout_allows_other_mcps() {
        assert!(!would_self_lockout("bob", "some-other-mcp", false, "bob"));
    }

    #[test]
    fn self_lockout_allows_enabling() {
        assert!(!would_self_lockout("bob", SELF_SERVICE_MCP_NAME, true, "bob"));
    }

    #[test]
    fn self_lockout_allows_admin_disabling_someone_elses_profile() {
        // changed_by (the admin) != principal_id (the target) — not self-directed.
        assert!(!would_self_lockout("someone-else", SELF_SERVICE_MCP_NAME, false, "admin-1"));
    }

    #[cfg(test)]
    mod live_db {
        use super::super::*;
        use crate::testing::test_pool_migrated;

        #[tokio::test]
        #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
        async fn upsert_then_get_roundtrips() {
            let pool = test_pool_migrated().await;
            upsert_profile(&pool, "alice", "some-mcp", false, Some(&["read".to_string()]), "alice").await.unwrap();
            let row = get_profile(&pool, "alice", "some-mcp").await.unwrap().unwrap();
            assert!(!row.enabled);
            assert_eq!(row.allowed_functions, Some(vec!["read".to_string()]));
        }

        #[tokio::test]
        #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
        async fn upsert_rejects_self_lockout_and_leaves_no_row() {
            let pool = test_pool_migrated().await;
            let err = upsert_profile(&pool, "bob", SELF_SERVICE_MCP_NAME, false, None, "bob").await.unwrap_err();
            assert!(matches!(err, StoreError::InvariantViolation(_)), "expected InvariantViolation, got {err:?}");
            assert!(get_profile(&pool, "bob", SELF_SERVICE_MCP_NAME).await.unwrap().is_none());
        }

        #[tokio::test]
        #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
        async fn admin_can_disable_self_service_for_another_principal() {
            let pool = test_pool_migrated().await;
            upsert_profile(&pool, "carol", SELF_SERVICE_MCP_NAME, false, None, "admin-1").await.unwrap();
            let row = get_profile(&pool, "carol", SELF_SERVICE_MCP_NAME).await.unwrap().unwrap();
            assert!(!row.enabled);
        }
    }
}
