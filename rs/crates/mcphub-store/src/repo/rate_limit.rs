//! `rate_limit_config` — per-principal overrides of the role-default rate
//! limit and anomaly-cutoff sensitivity. Absence of a row means "use the
//! role default", resolved by `mcphub-policy`, not here.

use crate::error::StoreError;
use sqlx::PgPool;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RateLimitConfigRow {
    pub rate_limit_rpm: Option<i32>,
    pub anomaly_sensitivity: String,
}

/// HOT: rate-limit / anomaly-cutoff gate, one lookup per invoke.
pub async fn get_override(pool: &PgPool, principal_id: &str) -> Result<Option<RateLimitConfigRow>, StoreError> {
    let row = sqlx::query_as::<_, RateLimitConfigRow>(
        r#"SELECT rate_limit_rpm, anomaly_sensitivity FROM rate_limit_config WHERE principal_id = $1"#,
    )
    .bind(principal_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

pub async fn set_override(
    pool: &PgPool,
    principal_id: &str,
    rate_limit_rpm: Option<i32>,
    anomaly_sensitivity: &str,
    updated_by: &str,
) -> Result<(), StoreError> {
    sqlx::query(
        r#"
        INSERT INTO rate_limit_config (principal_id, rate_limit_rpm, anomaly_sensitivity, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (principal_id) DO UPDATE SET
            rate_limit_rpm      = EXCLUDED.rate_limit_rpm,
            anomaly_sensitivity = EXCLUDED.anomaly_sensitivity,
            updated_by          = EXCLUDED.updated_by
        "#,
    )
    .bind(principal_id)
    .bind(rate_limit_rpm)
    .bind(anomaly_sensitivity)
    .bind(updated_by)
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
    async fn absence_means_no_override() {
        let pool = test_pool_migrated().await;
        assert!(get_override(&pool, "nobody").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn set_then_get_roundtrips() {
        let pool = test_pool_migrated().await;
        set_override(&pool, "alice", Some(500), "lenient", "admin-1").await.unwrap();
        let row = get_override(&pool, "alice").await.unwrap().unwrap();
        assert_eq!(row.rate_limit_rpm, Some(500));
        assert_eq!(row.anomaly_sensitivity, "lenient");
    }
}
