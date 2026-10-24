//! `servers` — the MCP server registry.
//!
//! `dedicated_port` lives on `idp_configs`, not here (see
//! `0009_dedicated_port_to_idp.up.sql` — resolved in mcphub-identity's
//! favour: the port publishes ONE IDP's metadata, so servers sharing an
//! IDP share its port rather than each getting their own identical
//! listener). `ServerRow.dedicated_port` below is still populated — via a
//! `LEFT JOIN idp_configs` — so `bin/mcphubd::listeners::
//! spawn_dedicated_listeners` (which reads `server.dedicated_port`
//! directly) keeps working unmodified: "the port this server's dedicated
//! listener binds to" is still a well-defined per-server value, it's just
//! sourced from the server's IDP now instead of a column on `servers`
//! itself.

use crate::error::StoreError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ServerRow {
    pub server_id: Uuid,
    pub name: String,
    pub upstream_url: String,
    pub status: String,
    pub owner_principal_id: String,
    pub auth_mode: String,
    /// Sourced from this server's `idp_configs.dedicated_port` (via join),
    /// not a `servers` column. `None` for any server without an `idp_id`
    /// or whose IDP has no dedicated port assigned.
    pub dedicated_port: Option<i32>,
    pub idp_id: Option<Uuid>,
    pub allowed_cidr: Option<String>,
}

const SERVER_ROW_SELECT: &str = r#"
    SELECT s.server_id, s.name, s.upstream_url, s.status::text, s.owner_principal_id,
           s.auth_mode::text, i.dedicated_port, s.idp_id, s.allowed_cidr
    FROM servers s
    LEFT JOIN idp_configs i ON i.idp_id = s.idp_id AND i.deleted_at IS NULL
"#;

/// HOT: the ingress gate reads this on every invoke ("is the server this
/// tool belongs to enabled?"). Served by `idx_servers_status`.
pub async fn get_active_server(pool: &PgPool, server_id: Uuid) -> Result<Option<ServerRow>, StoreError> {
    let sql = format!("{SERVER_ROW_SELECT} WHERE s.server_id = $1 AND s.deleted_at IS NULL");
    let row = sqlx::query_as::<_, ServerRow>(&sql).bind(server_id).fetch_optional(pool).await?;

    Ok(row)
}

/// All approved, non-deleted servers. Added for `mcphubd`'s
/// `EntitlementStore::list_visible` wiring (component 1 integration): the
/// discovery listing has to enumerate every server a grant could apply to,
/// not just one. Same active-row predicate as `get_active_server`, just
/// unscoped by id.
pub async fn list_active_servers(pool: &PgPool) -> Result<Vec<ServerRow>, StoreError> {
    let sql = format!("{SERVER_ROW_SELECT} WHERE s.deleted_at IS NULL AND s.status = 'approved'");
    let rows = sqlx::query_as::<_, ServerRow>(&sql).fetch_all(pool).await?;

    Ok(rows)
}

/// Defense-in-depth auditor/startup check (team-lead review: "decide
/// whether [the dedicated_port invariant] is a DB constraint or a startup
/// check, and make it fail closed either way"). The `0009` migration's
/// triggers already make this state unreachable through normal SQL — this
/// query exists for the same reason `security::
/// assert_non_privileged_connection` exists alongside the audit_events
/// triggers: a privileged connection can bypass triggers (`ALTER TABLE
/// ... DISABLE TRIGGER`), so a belt-and-braces check that doesn't rely on
/// triggers having fired is worth having wherever this crate's caller
/// wants an extra startup-time assertion. Returns the server_ids of every
/// active `dedicated_port` server whose IDP does not currently have a
/// dedicated port — i.e. exactly the misconfiguration the triggers exist
/// to prevent. An empty result is the only "healthy" answer.
pub async fn find_dedicated_port_misconfigurations(pool: &PgPool) -> Result<Vec<Uuid>, StoreError> {
    let rows: Vec<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT s.server_id
        FROM servers s
        LEFT JOIN idp_configs i ON i.idp_id = s.idp_id AND i.deleted_at IS NULL
        WHERE s.deleted_at IS NULL
          AND s.auth_mode = 'dedicated_port'
          AND (i.idp_id IS NULL OR i.dedicated_port IS NULL)
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn register_server(
    pool: &PgPool,
    name: &str,
    upstream_url: &str,
    owner_principal_id: &str,
) -> Result<Uuid, StoreError> {
    let (server_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO servers (name, upstream_url, owner_principal_id)
        VALUES ($1, $2, $3)
        RETURNING server_id
        "#,
    )
    .bind(name)
    .bind(upstream_url)
    .bind(owner_principal_id)
    .fetch_one(pool)
    .await?;

    Ok(server_id)
}

pub async fn approve_server(pool: &PgPool, server_id: Uuid, approved_by: &str) -> Result<(), StoreError> {
    let result = sqlx::query(
        r#"
        UPDATE servers
        SET status = 'approved', approved_at = now(), approved_by = $2
        WHERE server_id = $1 AND deleted_at IS NULL
        "#,
    )
    .bind(server_id)
    .bind(approved_by)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Explicit, admin-only opt-in: exempts this server's upstream from the SSRF
/// gate's public-upstream-only default for the given CIDR. `None` clears the
/// exemption. Never set implicitly by registration — see 0007's migration
/// comment.
pub async fn set_allowed_cidr(pool: &PgPool, server_id: Uuid, allowed_cidr: Option<&str>) -> Result<(), StoreError> {
    let result = sqlx::query("UPDATE servers SET allowed_cidr = $2 WHERE server_id = $1 AND deleted_at IS NULL")
        .bind(server_id)
        .bind(allowed_cidr)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_migrated;

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn register_then_approve_roundtrips() {
        let pool = test_pool_migrated().await;
        let server_id = register_server(&pool, "test-server", "https://upstream.example.com", "owner-1")
            .await
            .unwrap();

        let before = get_active_server(&pool, server_id).await.unwrap().unwrap();
        assert_eq!(before.status, "pending");

        approve_server(&pool, server_id, "admin-1").await.unwrap();

        let after = get_active_server(&pool, server_id).await.unwrap().unwrap();
        assert_eq!(after.status, "approved");
    }

    async fn seed_idp_with_port(pool: &PgPool, name: &str, port: Option<i32>) -> Uuid {
        let idp_id = crate::repo::idp::upsert_idp(
            pool,
            name,
            &format!("https://{name}.example.com"),
            None,
            "mcphub",
            &[],
            false,
            false,
        )
        .await
        .unwrap();
        if let Some(p) = port {
            crate::repo::idp::set_dedicated_port(pool, idp_id, Some(p)).await.unwrap();
        }
        idp_id
    }

    async fn set_dedicated_port_mode(pool: &PgPool, server_id: Uuid, idp_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE servers SET idp_id = $2, auth_mode = 'dedicated_port' WHERE server_id = $1")
            .bind(server_id)
            .bind(idp_id)
            .execute(pool)
            .await
            .map(|_| ())
    }

    /// Mutation proof for the cross-table invariant (trigger a): a server
    /// cannot declare `auth_mode = 'dedicated_port'` pointing at an IDP
    /// that has no dedicated_port assigned.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn server_cannot_go_dedicated_port_without_an_idp_port() {
        let pool = test_pool_migrated().await;
        let server_id = register_server(&pool, "srv-no-port", "https://upstream.example.com", "owner-1")
            .await
            .unwrap();
        let idp_id = seed_idp_with_port(&pool, "idp-no-port", None).await;

        let result = set_dedicated_port_mode(&pool, server_id, idp_id).await;
        assert!(result.is_err(), "declaring dedicated_port auth against an IDP with no port must be rejected");
    }

    /// The healthy path: a server pointing at an IDP that DOES have a
    /// dedicated port succeeds, and `ServerRow.dedicated_port` (sourced
    /// via the join, not a `servers` column) reflects the IDP's port.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn server_dedicated_port_is_sourced_from_its_idp() {
        let pool = test_pool_migrated().await;
        let server_id = register_server(&pool, "srv-with-port", "https://upstream.example.com", "owner-1")
            .await
            .unwrap();
        let idp_id = seed_idp_with_port(&pool, "idp-with-port", Some(9001)).await;

        set_dedicated_port_mode(&pool, server_id, idp_id).await.unwrap();

        let row = get_active_server(&pool, server_id).await.unwrap().unwrap();
        assert_eq!(row.dedicated_port, Some(9001));
        assert_eq!(row.auth_mode, "dedicated_port");

        assert!(find_dedicated_port_misconfigurations(&pool).await.unwrap().is_empty());
    }

    /// Mutation proof for the cross-table invariant (trigger b): clearing
    /// an IDP's dedicated_port while an active server still depends on it
    /// for dedicated_port auth must be rejected — this is the exact
    /// scenario the review flagged: "a server declaring dedicated-port
    /// auth with no port to serve it on must not silently fall back to
    /// the shared listener."
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn clearing_a_still_depended_on_idp_port_is_rejected() {
        let pool = test_pool_migrated().await;
        let server_id = register_server(&pool, "srv-dependent", "https://upstream.example.com", "owner-1")
            .await
            .unwrap();
        let idp_id = seed_idp_with_port(&pool, "idp-dependent", Some(9002)).await;
        set_dedicated_port_mode(&pool, server_id, idp_id).await.unwrap();

        let result = crate::repo::idp::set_dedicated_port(&pool, idp_id, None).await;
        assert!(result.is_err(), "clearing a dedicated_port a live server still depends on must be rejected");

        // The server's effective port must still be exactly what it was —
        // no silent fallback occurred.
        let row = get_active_server(&pool, server_id).await.unwrap().unwrap();
        assert_eq!(row.dedicated_port, Some(9002));
    }

    /// Team-lead's uniqueness requirement: two IDPs must never share a
    /// dedicated_port, enforced by the DB (`uq_idp_configs_dedicated_port_active`),
    /// not the allocator.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn two_idps_cannot_share_a_dedicated_port() {
        let pool = test_pool_migrated().await;
        seed_idp_with_port(&pool, "idp-a", Some(9003)).await;
        let idp_b = seed_idp_with_port(&pool, "idp-b", None).await;

        let result = crate::repo::idp::set_dedicated_port(&pool, idp_b, Some(9003)).await;
        assert!(result.is_err(), "two IDPs sharing the same dedicated_port must be rejected by the DB");
    }

    /// `find_dedicated_port_misconfigurations` is the defense-in-depth
    /// check for a privileged connection bypassing the triggers directly
    /// (same threat model as D7's audit_events guard) — prove it actually
    /// detects the bad state when the triggers are disabled to construct
    /// one.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn find_dedicated_port_misconfigurations_detects_a_trigger_bypassed_bad_state() {
        let pool = test_pool_migrated().await;
        let server_id = register_server(&pool, "srv-bypassed", "https://upstream.example.com", "owner-1")
            .await
            .unwrap();
        let idp_id = seed_idp_with_port(&pool, "idp-bypassed", Some(9004)).await;
        set_dedicated_port_mode(&pool, server_id, idp_id).await.unwrap();

        // Simulate a privileged bypass: disable the guard trigger, clear
        // the port anyway (exactly what the trigger normally prevents),
        // re-enable it.
        sqlx::query("ALTER TABLE idp_configs DISABLE TRIGGER trg_idp_configs_check_dedicated_port_still_referenced")
            .execute(&pool)
            .await
            .unwrap();
        crate::repo::idp::set_dedicated_port(&pool, idp_id, None).await.unwrap();
        sqlx::query("ALTER TABLE idp_configs ENABLE TRIGGER trg_idp_configs_check_dedicated_port_still_referenced")
            .execute(&pool)
            .await
            .unwrap();

        let misconfigured = find_dedicated_port_misconfigurations(&pool).await.unwrap();
        assert_eq!(misconfigured, vec![server_id], "the bypassed bad state must be detected by the auditor query");
    }
}
