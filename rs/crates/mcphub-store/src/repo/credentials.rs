//! `credentials` — AES-256-GCM sealed material for the credential broker.
//! This module stores/retrieves ciphertext + nonce + AAD + key_version;
//! it never sees plaintext or the KEK. Sealing/unsealing is `mcphub-creds`'
//! job (component 3) — this is intentionally a dumb blob store with a
//! `(principal_id, server_id, purpose)` lookup key.

use crate::error::StoreError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub credential_id: Uuid,
    pub key_version: i32,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
}

/// HOT: credential injection dispatch step, one lookup per invoke that
/// needs injection. Served by `idx_credentials_active`.
pub async fn get_active_credential(
    pool: &PgPool,
    principal_id: &str,
    server_id: Uuid,
    purpose: &str,
) -> Result<Option<CredentialRow>, StoreError> {
    let row = sqlx::query_as::<_, CredentialRow>(
        r#"
        SELECT credential_id, key_version, nonce, ciphertext, aad
        FROM credentials
        WHERE principal_id = $1 AND server_id = $2 AND purpose = $3 AND revoked_at IS NULL
        "#,
    )
    .bind(principal_id)
    .bind(server_id)
    .bind(purpose)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_credential(
    pool: &PgPool,
    principal_id: &str,
    server_id: Uuid,
    purpose: &str,
    key_version: i32,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Uuid, StoreError> {
    let (credential_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO credentials (principal_id, server_id, purpose, key_version, nonce, ciphertext, aad)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (principal_id, server_id, purpose) DO UPDATE SET
            key_version = EXCLUDED.key_version,
            nonce       = EXCLUDED.nonce,
            ciphertext  = EXCLUDED.ciphertext,
            aad         = EXCLUDED.aad,
            revoked_at  = NULL
        RETURNING credential_id
        "#,
    )
    .bind(principal_id)
    .bind(server_id)
    .bind(purpose)
    .bind(key_version)
    .bind(nonce)
    .bind(ciphertext)
    .bind(aad)
    .fetch_one(pool)
    .await?;

    Ok(credential_id)
}

/// Full revocation: unlike `tool_registry`, `credentials` permits hard
/// DELETE — see 0002_grants_credentials.up.sql's comment on why.
pub async fn hard_delete_credential(pool: &PgPool, credential_id: Uuid) -> Result<(), StoreError> {
    let result = sqlx::query("DELETE FROM credentials WHERE credential_id = $1")
        .bind(credential_id)
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
    async fn upsert_then_get_then_hard_delete_roundtrips() {
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

        let credential_id = upsert_credential(
            &pool, "alice", server_id, "upstream_token", 1, b"nonce12bytes", b"ciphertext-bytes", b"aad-bytes",
        )
        .await
        .unwrap();

        let row = get_active_credential(&pool, "alice", server_id, "upstream_token")
            .await
            .unwrap()
            .expect("credential must be present");
        assert_eq!(row.credential_id, credential_id);
        assert_eq!(row.ciphertext, b"ciphertext-bytes");

        hard_delete_credential(&pool, credential_id).await.unwrap();

        let after = get_active_credential(&pool, "alice", server_id, "upstream_token").await.unwrap();
        assert!(after.is_none(), "hard delete must be permitted and take effect for credentials");
    }
}
