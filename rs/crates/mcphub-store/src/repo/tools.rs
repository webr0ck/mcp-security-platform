//! `tool_registry` — ONE ROW PER TOOL, unique on `(name, version)`.
//!
//! Non-negotiable: rows are never hard-deleted. `upsert_tool` is the only
//! sanctioned write path for tool metadata changes — it always
//! `ON CONFLICT (name, version) DO UPDATE`s rather than deleting and
//! re-inserting, and `disable_tool` soft-deletes via `deleted_at` +
//! `status = 'disabled'`. `hard_delete_is_blocked` below exists purely as
//! a regression test: it MUST fail.

use crate::error::StoreError;
use crate::hash::sha256_hex;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ToolRow {
    pub tool_id: Uuid,
    pub server_id: Uuid,
    pub name: String,
    pub version: String,
    pub description: String,
    pub schema: serde_json::Value,
    pub digest: String,
    pub status: String,
    pub risk_score: Option<i16>,
    pub risk_level: Option<String>,
    pub deleted_at: Option<time::OffsetDateTime>,
}

/// Content-addressable digest over the immutable identity of a tool
/// version: `(name, version, description, schema)`. This is the value a
/// caller can pin against — `tool_id` is the stable surrogate FK used
/// everywhere else (audit_events, grants), `digest` is the
/// content-verification companion.
pub fn compute_digest(name: &str, version: &str, description: &str, schema: &serde_json::Value) -> String {
    let canonical = serde_json::json!({
        "name": name,
        "version": version,
        "description": description,
        "schema": schema,
    });
    // serde_json's default map type sorts keys (no `preserve_order`
    // feature enabled workspace-wide), so this is stable regardless of
    // caller-supplied JSON key order inside `schema`... EXCEPT `schema`'s
    // own nested object key order is preserved as parsed unless it too
    // went through a sorting pass; canonicalize by round-tripping through
    // a `BTreeMap`-backed `Value` via `serde_json::to_vec` is what
    // actually sorts, so re-serializing here is what makes this stable.
    let bytes = serde_json::to_vec(&canonical).expect("Value serialization cannot fail");
    sha256_hex(&bytes)
}

/// Upsert on `(name, version)` — the ONLY write path for tool metadata.
/// A re-registration of an existing (name, version) updates in place
/// (including clearing `deleted_at` if it had been soft-deleted) rather
/// than creating a duplicate row or requiring a delete-then-insert dance.
pub async fn upsert_tool(
    pool: &PgPool,
    server_id: Uuid,
    name: &str,
    version: &str,
    description: &str,
    schema: &serde_json::Value,
    registered_by: &str,
) -> Result<Uuid, StoreError> {
    let digest = compute_digest(name, version, description, schema);

    // D12: `risk_level` is nullable in the schema (needed so an
    // administrator can later apply a scan/review result), but a NULL
    // makes `grants.max_risk_level` inert for that tool on the
    // enforcement side (see bin/mcphubd's entitlement gate) — NULL was
    // effectively "no risk ceiling applies". Every tool registered
    // through this, the ONLY sanctioned write path, now gets an explicit
    // fail-closed default ('critical', the strictest tier) at INSERT
    // time. Deliberately NOT set on the ON CONFLICT UPDATE branch: a
    // re-registration of an existing (name, version) must not clobber a
    // risk_level an admin/scanner already set to something less strict —
    // only the very first insert needs the safety-net default.
    const DEFAULT_RISK_LEVEL: &str = "critical";

    let (tool_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO tool_registry (server_id, name, version, description, schema, digest, registered_by, risk_level)
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
        ON CONFLICT (name, version) DO UPDATE SET
            server_id     = EXCLUDED.server_id,
            description   = EXCLUDED.description,
            schema        = EXCLUDED.schema,
            digest        = EXCLUDED.digest,
            registered_by = EXCLUDED.registered_by,
            status        = 'active',
            deleted_at    = NULL
        RETURNING tool_id
        "#,
    )
    .bind(server_id)
    .bind(name)
    .bind(version)
    .bind(description)
    .bind(schema)
    .bind(&digest)
    .bind(registered_by)
    .bind(DEFAULT_RISK_LEVEL)
    .fetch_one(pool)
    .await?;

    Ok(tool_id)
}

/// The only sanctioned removal path: soft-delete, never `DELETE FROM`.
pub async fn disable_tool(pool: &PgPool, tool_id: Uuid) -> Result<(), StoreError> {
    let result = sqlx::query(
        r#"UPDATE tool_registry SET status = 'disabled', deleted_at = now() WHERE tool_id = $1"#,
    )
    .bind(tool_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// Sets/clears the per-tool RBAC floor (migration 0012). `None` clears it
/// back to "no per-tool role requirement" (the default for every row).
///
/// NOT called from any admin HTTP route today — same pattern
/// `repo::roles::grant_role` has (no admin route calls it either): the
/// write path exists and is tested, but there is currently no way for an
/// operator to reach it except direct DB access or a future admin
/// endpoint. Flagging this explicitly rather than letting it be
/// rediscovered per-feature.
pub async fn set_required_role(pool: &PgPool, tool_id: Uuid, required_role: Option<mcphub_types::Role>) -> Result<(), StoreError> {
    let role_str = required_role.map(crate::repo::roles::role_to_db);
    let result = sqlx::query("UPDATE tool_registry SET required_role = $2::role_enum WHERE tool_id = $1")
        .bind(tool_id)
        .bind(role_str)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// HOT: served by `idx_tool_registry_server_active`. This is the exact
/// query both `tools/list` AND the `tools/call` entitlement check must
/// use — ARCHITECTURE.md invariant 3 ("discovery == invoke") depends on
/// both call sites sharing this one function rather than two independent
/// WHERE clauses that could drift apart.
pub async fn list_active_tools_for_server(pool: &PgPool, server_id: Uuid) -> Result<Vec<ToolRow>, StoreError> {
    let rows = sqlx::query_as::<_, ToolRow>(
        r#"
        SELECT tool_id, server_id, name, version, description, schema, digest, status::text,
               risk_score, risk_level, deleted_at
        FROM tool_registry
        WHERE server_id = $1 AND deleted_at IS NULL AND status = 'active'
        "#,
    )
    .bind(server_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_migrated;

    async fn seed_server(pool: &PgPool) -> Uuid {
        let (server_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO servers (name, upstream_url, owner_principal_id) VALUES ($1, $2, $3) RETURNING server_id",
        )
        .bind(format!("srv-{}", Uuid::new_v4()))
        .bind("https://upstream.example.com")
        .bind("owner-1")
        .fetch_one(pool)
        .await
        .unwrap();
        server_id
    }

    #[test]
    fn compute_digest_is_deterministic_and_order_independent_for_top_level_keys() {
        let schema = serde_json::json!({"type": "object"});
        let a = compute_digest("echo", "1.0.0", "desc", &schema);
        let b = compute_digest("echo", "1.0.0", "desc", &schema);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn compute_digest_changes_with_version() {
        let schema = serde_json::json!({"type": "object"});
        let a = compute_digest("echo", "1.0.0", "desc", &schema);
        let b = compute_digest("echo", "2.0.0", "desc", &schema);
        assert_ne!(a, b);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn upsert_on_name_version_updates_in_place_not_duplicate() {
        let pool = test_pool_migrated().await;
        let server_id = seed_server(&pool).await;
        let schema = serde_json::json!({"type": "object"});

        let id1 = upsert_tool(&pool, server_id, "echo", "1.0.0", "v1 description", &schema, "reg-1")
            .await
            .unwrap();
        let id2 = upsert_tool(&pool, server_id, "echo", "1.0.0", "v2 description (updated)", &schema, "reg-2")
            .await
            .unwrap();

        assert_eq!(id1, id2, "same (name, version) must upsert the same row, not create a new one");

        let count: (i64,) = sqlx::query_as("SELECT count(*) FROM tool_registry WHERE name = 'echo' AND version = '1.0.0'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 1, "exactly one row must exist for this (name, version)");

        let row: (String,) = sqlx::query_as("SELECT description FROM tool_registry WHERE tool_id = $1")
            .bind(id1)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, "v2 description (updated)");
    }

    /// Mutation proof (D12): before the fix, `upsert_tool` never bound
    /// `risk_level`, so every newly registered tool had NULL there —
    /// silently disabling `grants.max_risk_level` for that tool on the
    /// enforcement side. This pins "every tool registered through the
    /// sanctioned path gets a non-NULL, fail-closed default".
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn newly_registered_tool_gets_a_fail_closed_default_risk_level() {
        let pool = test_pool_migrated().await;
        let server_id = seed_server(&pool).await;
        let schema = serde_json::json!({});

        let tool_id = upsert_tool(&pool, server_id, "risky", "1.0.0", "d", &schema, "reg-1").await.unwrap();

        let row: (Option<String>,) = sqlx::query_as("SELECT risk_level FROM tool_registry WHERE tool_id = $1")
            .bind(tool_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0.as_deref(), Some("critical"), "a freshly registered tool must not have NULL risk_level");
    }

    /// A re-registration (upsert of an existing (name, version)) must NOT
    /// clobber a risk_level an admin/scanner already downgraded from the
    /// default — only the very first insert gets the safety-net value.
    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn re_registration_does_not_overwrite_an_already_set_risk_level() {
        let pool = test_pool_migrated().await;
        let server_id = seed_server(&pool).await;
        let schema = serde_json::json!({});

        let tool_id = upsert_tool(&pool, server_id, "scanned", "1.0.0", "d", &schema, "reg-1").await.unwrap();
        sqlx::query("UPDATE tool_registry SET risk_level = 'low' WHERE tool_id = $1")
            .bind(tool_id)
            .execute(&pool)
            .await
            .unwrap();

        let tool_id_again =
            upsert_tool(&pool, server_id, "scanned", "1.0.0", "d2 (re-registered)", &schema, "reg-2").await.unwrap();
        assert_eq!(tool_id, tool_id_again);

        let row: (Option<String>,) = sqlx::query_as("SELECT risk_level FROM tool_registry WHERE tool_id = $1")
            .bind(tool_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0.as_deref(), Some("low"), "re-registration must preserve an already-set risk_level");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disable_then_reregister_clears_soft_delete() {
        let pool = test_pool_migrated().await;
        let server_id = seed_server(&pool).await;
        let schema = serde_json::json!({});

        let tool_id = upsert_tool(&pool, server_id, "notes", "1.0.0", "d", &schema, "reg-1").await.unwrap();
        disable_tool(&pool, tool_id).await.unwrap();

        let visible = list_active_tools_for_server(&pool, server_id).await.unwrap();
        assert!(visible.is_empty(), "disabled tool must not appear in the active list");

        let tool_id_again = upsert_tool(&pool, server_id, "notes", "1.0.0", "d2", &schema, "reg-2").await.unwrap();
        assert_eq!(tool_id, tool_id_again);

        let visible_after = list_active_tools_for_server(&pool, server_id).await.unwrap();
        assert_eq!(visible_after.len(), 1, "re-registration must clear the soft delete");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn hard_delete_is_blocked() {
        let pool = test_pool_migrated().await;
        let server_id = seed_server(&pool).await;
        let schema = serde_json::json!({});
        let tool_id = upsert_tool(&pool, server_id, "will-not-delete", "1.0.0", "d", &schema, "reg-1")
            .await
            .unwrap();

        let result = sqlx::query("DELETE FROM tool_registry WHERE tool_id = $1")
            .bind(tool_id)
            .execute(&pool)
            .await;

        assert!(result.is_err(), "hard DELETE on tool_registry must be rejected by the immutability guard");

        // The row must still exist afterward — the guard didn't just error,
        // it actually prevented the delete.
        let still_there: (i64,) = sqlx::query_as("SELECT count(*) FROM tool_registry WHERE tool_id = $1")
            .bind(tool_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(still_there.0, 1);
    }
}
