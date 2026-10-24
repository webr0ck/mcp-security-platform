//! `role_grants` — principal -> `mcphub_types::Role` resolution.

use crate::error::StoreError;
use mcphub_types::Role;
use sqlx::PgPool;
use std::collections::HashSet;

pub fn role_to_db(role: Role) -> &'static str {
    role.as_str()
}

pub fn role_from_db(s: &str) -> Option<Role> {
    match s {
        "super_admin" => Some(Role::SuperAdmin),
        "server_owner" => Some(Role::ServerOwner),
        "security_analyst" => Some(Role::SecurityAnalyst),
        "employee" => Some(Role::Employee),
        _ => None,
    }
}

/// HOT: resolved once per authenticated request (identity resolution step).
pub async fn resolve_roles(pool: &PgPool, principal_id: &str, issuer: &str) -> Result<Vec<Role>, StoreError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT role::text FROM role_grants
        WHERE principal_id = $1 AND issuer = $2
          AND (expires_at IS NULL OR expires_at > now())
        "#,
    )
    .bind(principal_id)
    .bind(issuer)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().filter_map(|(r,)| role_from_db(&r)).collect())
}

/// Writes a `role_grants` row. `known_issuers` must be the caller's current
/// set of CONFIGURED issuer strings (every `IdpConfig.issuer` — the same
/// set `mcphub_identity::registry::IssuerRegistry` was built from; this
/// crate deliberately does not depend on `mcphub-identity`, so the caller —
/// `bin/mcphubd`, which owns wiring and already holds the registry — passes
/// it in rather than this crate re-deriving or duplicating it). An `issuer`
/// not in that set is rejected: a `role_grants` row for an issuer nobody
/// configured can never be resolved by `resolve_roles` (which is scoped to
/// a token's already-validated `(sub, issuer)`), so it is dead data at best
/// — and at worst, if `idp_configs` gains that issuer later, a "role_grants
/// row for a not-yet-configured issuer" quietly reanimates into a live
/// grant with no fresh operator review of that grant.
///
/// This does NOT enforce `IdpConfig::max_assertable_role` — the ceiling
/// lives in config this crate has no visibility into (it isn't persisted
/// in `idp_configs` at all yet; see `bin/mcphubd/src/idp_store.rs`'s
/// TODO), so a DB-level (or even application-level, inside this function)
/// ceiling check isn't possible here without duplicating or importing that
/// config. The ceiling is enforced at READ time instead, in
/// `StoreAuthenticator::authenticate` via
/// `mcphub_identity::claims::apply_ceiling` — every grant, however
/// written, is re-checked against the issuer's current ceiling on every
/// authenticated request, which also means a ceiling lowered after a grant
/// was written takes effect immediately rather than only at the next grant.
pub async fn grant_role(
    pool: &PgPool,
    principal_id: &str,
    issuer: &str,
    role: Role,
    granted_by: &str,
    known_issuers: &HashSet<String>,
) -> Result<(), StoreError> {
    if !known_issuers.contains(issuer) {
        return Err(StoreError::InvariantViolation(format!(
            "refusing to grant role for issuer {issuer:?}: not a configured IDP"
        )));
    }

    sqlx::query(
        r#"
        INSERT INTO role_grants (principal_id, issuer, role, granted_by)
        VALUES ($1, $2, $3::role_enum, $4)
        ON CONFLICT (principal_id, issuer, role) DO UPDATE
            SET granted_by = EXCLUDED.granted_by
        "#,
    )
    .bind(principal_id)
    .bind(issuer)
    .bind(role_to_db(role))
    .bind(granted_by)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_migrated;

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn grant_then_resolve_roundtrips() {
        let pool = test_pool_migrated().await;
        let known = HashSet::from(["https://idp.example.com".to_string()]);
        grant_role(&pool, "alice", "https://idp.example.com", Role::Employee, "admin-1", &known)
            .await
            .unwrap();

        let roles = resolve_roles(&pool, "alice", "https://idp.example.com").await.unwrap();
        assert_eq!(roles, vec![Role::Employee]);
    }

    /// The write-side half of the ceiling-bypass fix: `grant_role` must
    /// refuse to write a `role_grants` row for an issuer nobody configured.
    /// Without this, `role_grants` is a second, unauthenticated-adjacent
    /// path to minting a role for an issuer string an attacker (or a bug)
    /// picked, entirely independent of the `IssuerRegistry` every token
    /// must resolve against to authenticate at all.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn grant_role_rejects_unconfigured_issuer() {
        let pool = test_pool_migrated().await;
        let known = HashSet::from(["https://idp.example.com".to_string()]);

        let err = grant_role(&pool, "mallory", "https://attacker.example.com", Role::SuperAdmin, "admin-1", &known)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::InvariantViolation(_)), "expected InvariantViolation, got {err:?}");

        let roles = resolve_roles(&pool, "mallory", "https://attacker.example.com").await.unwrap();
        assert!(roles.is_empty(), "rejected grant must not have been written");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn expired_grant_is_not_resolved() {
        let pool = test_pool_migrated().await;
        sqlx::query(
            r#"INSERT INTO role_grants (principal_id, issuer, role, granted_by, expires_at)
               VALUES ($1, $2, 'employee', 'admin-1', now() - interval '1 hour')"#,
        )
        .bind("bob")
        .bind("https://idp.example.com")
        .execute(&pool)
        .await
        .unwrap();

        let roles = resolve_roles(&pool, "bob", "https://idp.example.com").await.unwrap();
        assert!(roles.is_empty());
    }

    /// The authz-bug regression test the team lead asked for: two
    /// completely different real-world identities can share the same raw
    /// `sub` value if they're minted by two different IDPs (`sub` is only
    /// unique *within* one issuer's namespace). `resolve_roles` is the
    /// function `invoke()` must call for enforcement — it MUST be scoped
    /// by `(principal_id, issuer)` together, never by `principal_id` alone,
    /// or a SuperAdmin grant on one IDP would leak to an Employee on
    /// another IDP who happens to share the same `sub` string.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn same_sub_under_different_issuers_does_not_leak_roles() {
        let pool = test_pool_migrated().await;
        let known = HashSet::from(["https://idp-a.example.com".to_string(), "https://idp-b.example.com".to_string()]);

        // Two distinct identities, same `sub`, different issuers.
        grant_role(&pool, "shared-sub", "https://idp-a.example.com", Role::SuperAdmin, "admin-1", &known)
            .await
            .unwrap();
        grant_role(&pool, "shared-sub", "https://idp-b.example.com", Role::Employee, "admin-2", &known)
            .await
            .unwrap();

        let roles_a = resolve_roles(&pool, "shared-sub", "https://idp-a.example.com").await.unwrap();
        let roles_b = resolve_roles(&pool, "shared-sub", "https://idp-b.example.com").await.unwrap();

        assert_eq!(roles_a, vec![Role::SuperAdmin], "idp-a's identity must see only its own grant");
        assert_eq!(roles_b, vec![Role::Employee], "idp-b's identity must see only its own grant");
        assert!(!roles_b.contains(&Role::SuperAdmin), "idp-b's employee must NOT inherit idp-a's SuperAdmin grant");
        assert!(!roles_a.contains(&Role::Employee), "idp-a's super-admin listing must not be polluted by idp-b's grant");

        // A third issuer with no grants at all for this sub must resolve empty.
        let roles_c = resolve_roles(&pool, "shared-sub", "https://idp-c.example.com").await.unwrap();
        assert!(roles_c.is_empty());
    }
}
