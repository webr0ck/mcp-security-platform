//! `grants` — per-principal tool/tag entitlements (the RBAC gate's data
//! source). See 0002_grants_credentials.up.sql for the hot-query rationale.

use crate::error::StoreError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct GrantRow {
    pub allowed_tools: Vec<String>,
    pub allowed_tags: Vec<String>,
    pub max_risk_level: String,
}

/// HOT: read on every invoke's RBAC step. `server_id = NULL` rows are
/// platform-wide grants (e.g. super-admin tooling) and are unioned with
/// any server-scoped grant for the same principal.
pub async fn resolve_grants(
    pool: &PgPool,
    principal_id: &str,
    server_id: Uuid,
) -> Result<Vec<GrantRow>, StoreError> {
    let rows = sqlx::query_as::<_, GrantRow>(
        r#"
        SELECT allowed_tools, allowed_tags, max_risk_level
        FROM grants
        WHERE principal_id = $1 AND (server_id = $2 OR server_id IS NULL)
        "#,
    )
    .bind(principal_id)
    .bind(server_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// Every grant row, principal_id attached. Added for `mcphubd`'s policy-data
/// sync wiring (component 1 integration): `mcphub-policy`'s `authz.rego`
/// expects a flat `data.mcp_grants[client_id]` map that is not server-scoped,
/// while this table's grants ARE server-scoped — there is no single query
/// that answers "this principal's grant" without picking a server. Callers
/// aggregate across servers themselves; see `mcphubd`'s policy wiring.
pub async fn list_all_grants(pool: &PgPool) -> Result<Vec<(String, GrantRow)>, StoreError> {
    let rows: Vec<(String, Vec<String>, Vec<String>, String)> = sqlx::query_as(
        r#"SELECT principal_id, allowed_tools, allowed_tags, max_risk_level FROM grants"#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(principal_id, allowed_tools, allowed_tags, max_risk_level)| {
            (principal_id, GrantRow { allowed_tools, allowed_tags, max_risk_level })
        })
        .collect())
}

pub async fn upsert_grant(
    pool: &PgPool,
    principal_id: &str,
    server_id: Option<Uuid>,
    allowed_tools: &[String],
    allowed_tags: &[String],
    max_risk_level: &str,
    granted_by: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        r#"
        INSERT INTO grants (principal_id, server_id, allowed_tools, allowed_tags, max_risk_level, granted_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (principal_id, server_id) DO UPDATE SET
            allowed_tools  = EXCLUDED.allowed_tools,
            allowed_tags   = EXCLUDED.allowed_tags,
            max_risk_level = EXCLUDED.max_risk_level,
            granted_by     = EXCLUDED.granted_by
        "#,
    )
    .bind(principal_id)
    .bind(server_id)
    .bind(allowed_tools)
    .bind(allowed_tags)
    .bind(max_risk_level)
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
    async fn platform_wide_and_server_scoped_grants_both_resolve() {
        let pool = test_pool_migrated().await;
        let (server_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO servers (name, upstream_url, owner_principal_id) VALUES ($1, $2, $3) RETURNING server_id",
        )
        .bind(format!("srv-{}", Uuid::new_v4()))
        .bind("https://upstream.example.com")
        .bind("owner-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        upsert_grant(&pool, "alice", None, &["platform_info".into()], &[], "low", "admin-1")
            .await
            .unwrap();
        upsert_grant(&pool, "alice", Some(server_id), &["echo".into()], &[], "medium", "admin-1")
            .await
            .unwrap();

        let rows = resolve_grants(&pool, "alice", server_id).await.unwrap();
        assert_eq!(rows.len(), 2);
    }
}
