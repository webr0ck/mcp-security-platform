//! `idp_configs` — runtime-settable IDP configuration. Startup wiring
//! reads all active rows; the admin API (`POST /api/v1/admin/idps`,
//! super-admin only) writes through `upsert_idp`.

use crate::error::StoreError;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdpConfigRow {
    pub idp_id: Uuid,
    pub name: String,
    pub issuer: String,
    pub discovery_url: Option<String>,
    pub client_id: String,
    pub client_secret_credential_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub supports_token_exchange: bool,
    pub is_platform_idp: bool,
    /// The RFC 9728/RFC 8414 dedicated listener port for this IDP, if any
    /// (`0009_dedicated_port_to_idp.up.sql` — moved here from `servers`).
    /// `None` means this IDP has no dedicated listener; every server
    /// pointing at it must use `shared_passthrough`/`shared_exchange`.
    pub dedicated_port: Option<i32>,
}

/// Read at startup: "if the DB is unreachable at startup, boot from the
/// file config; if neither is present, refuse to start" (ARCHITECTURE.md).
/// Callers are expected to treat `Err` here as "DB unreachable" and fall
/// back to file config themselves — this function does not do that
/// fallback (it has no access to the file config).
pub async fn list_active_idps(pool: &PgPool) -> Result<Vec<IdpConfigRow>, StoreError> {
    let rows = sqlx::query_as::<_, IdpConfigRow>(
        r#"
        SELECT idp_id, name, issuer, discovery_url, client_id, client_secret_credential_id,
               scopes, supports_token_exchange, is_platform_idp, dedicated_port
        FROM idp_configs
        WHERE deleted_at IS NULL
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

/// `dedicated_port` is the RFC 9728/RFC 8414 listener port for this IDP
/// (`None` = no dedicated listener). NOT set on the `ON CONFLICT DO
/// UPDATE` branch — matches this crate's convention elsewhere (see
/// `repo::tools::upsert_tool`'s `risk_level`) of never letting a
/// re-registration silently clobber an operationally-significant value
/// that isn't part of what the caller is re-registering; port assignment
/// is Ansible's job (per the review), not this upsert's.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_idp(
    pool: &PgPool,
    name: &str,
    issuer: &str,
    discovery_url: Option<&str>,
    client_id: &str,
    scopes: &[String],
    supports_token_exchange: bool,
    is_platform_idp: bool,
) -> Result<Uuid, StoreError> {
    let (idp_id,): (Uuid,) = sqlx::query_as(
        r#"
        INSERT INTO idp_configs (name, issuer, discovery_url, client_id, scopes, supports_token_exchange, is_platform_idp)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (name) WHERE deleted_at IS NULL DO UPDATE SET
            issuer                  = EXCLUDED.issuer,
            discovery_url           = EXCLUDED.discovery_url,
            client_id               = EXCLUDED.client_id,
            scopes                  = EXCLUDED.scopes,
            supports_token_exchange = EXCLUDED.supports_token_exchange,
            is_platform_idp         = EXCLUDED.is_platform_idp
        RETURNING idp_id
        "#,
    )
    .bind(name)
    .bind(issuer)
    .bind(discovery_url)
    .bind(client_id)
    .bind(scopes)
    .bind(supports_token_exchange)
    .bind(is_platform_idp)
    .fetch_one(pool)
    .await?;

    Ok(idp_id)
}

/// Sets (or clears, with `None`) the dedicated listener port for an IDP.
/// The `0009` migration's `uq_idp_configs_dedicated_port_active` index and
/// `trg_idp_configs_check_dedicated_port_still_referenced` trigger are the
/// actual enforcement — this function just performs the UPDATE and lets
/// their errors (unique violation / dependent-server violation) surface
/// as `StoreError::Db`, fail-closed.
pub async fn set_dedicated_port(pool: &PgPool, idp_id: Uuid, dedicated_port: Option<i32>) -> Result<(), StoreError> {
    let result = sqlx::query("UPDATE idp_configs SET dedicated_port = $2 WHERE idp_id = $1 AND deleted_at IS NULL")
        .bind(idp_id)
        .bind(dedicated_port)
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
    async fn upsert_and_list_roundtrips() {
        let pool = test_pool_migrated().await;
        upsert_idp(&pool, "keycloak-platform", "https://kc.example.com/realms/mcp", None, "mcphub", &[], false, true)
            .await
            .unwrap();

        let rows = list_active_idps(&pool).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_platform_idp);
    }
}
