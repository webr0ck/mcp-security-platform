//! `quarantine_events` — the Postgres source of truth backing the
//! `redis::RedisStore` quarantine-flag cache. The quarantine gate should
//! prefer the redis flag on the hot path and fall back to this table (or
//! treat a redis miss/error as "ask Postgres", never as "assume clear" —
//! fail-closed) when it needs an authoritative answer or a reason string.

use crate::error::StoreError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineTarget {
    Server,
    Tool,
}

impl QuarantineTarget {
    fn as_str(self) -> &'static str {
        match self {
            QuarantineTarget::Server => "server",
            QuarantineTarget::Tool => "tool",
        }
    }
}

/// HOT: quarantine gate, authoritative-path lookup. Served by
/// `idx_quarantine_events_open`.
pub async fn is_quarantined(
    pool: &PgPool,
    target_type: QuarantineTarget,
    target_id: Uuid,
) -> Result<Option<String>, StoreError> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT reason FROM quarantine_events
        WHERE target_type = $1::quarantine_target_enum AND target_id = $2 AND released_at IS NULL
        ORDER BY quarantined_at DESC
        LIMIT 1
        "#,
    )
    .bind(target_type.as_str())
    .bind(target_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|(reason,)| reason))
}

pub async fn quarantine(
    pool: &PgPool,
    target_type: QuarantineTarget,
    target_id: Uuid,
    reason: &str,
    quarantined_by: &str,
) -> Result<Uuid, StoreError> {
    let (id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO quarantine_events (target_type, target_id, reason, quarantined_by)
        VALUES ($1::quarantine_target_enum, $2, $3, $4)
        RETURNING quarantine_id
        "#,
    )
    .bind(target_type.as_str())
    .bind(target_id)
    .bind(reason)
    .bind(quarantined_by)
    .fetch_one(pool)
    .await?;

    Ok(id)
}

pub async fn release(
    pool: &PgPool,
    target_type: QuarantineTarget,
    target_id: Uuid,
    released_by: &str,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        r#"
        UPDATE quarantine_events
        SET released_at = now(), released_by = $3
        WHERE target_type = $1::quarantine_target_enum AND target_id = $2 AND released_at IS NULL
        "#,
    )
    .bind(target_type.as_str())
    .bind(target_id)
    .bind(released_by)
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
    async fn quarantine_then_release_roundtrips() {
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

        assert!(is_quarantined(&pool, QuarantineTarget::Server, server_id).await.unwrap().is_none());

        quarantine(&pool, QuarantineTarget::Server, server_id, "suspicious traffic", "analyst-1")
            .await
            .unwrap();
        assert_eq!(
            is_quarantined(&pool, QuarantineTarget::Server, server_id).await.unwrap(),
            Some("suspicious traffic".to_string())
        );

        release(&pool, QuarantineTarget::Server, server_id, "analyst-2").await.unwrap();
        assert!(is_quarantined(&pool, QuarantineTarget::Server, server_id).await.unwrap().is_none());
    }
}
