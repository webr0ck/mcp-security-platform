//! Fail-closed env/file config loading for `mcphubd` startup.

use mcphub_types::StartupError;
use std::net::SocketAddr;

pub struct AppConfig {
    /// Runtime connection — `mcphub_app`, least-privilege, non-owner,
    /// non-superuser. `assert_non_privileged_connection` runs against THIS
    /// pool. Everything except migrations uses it.
    pub database_url: String,
    /// Migration-time-only connection — owner/superuser role. Used ONLY by
    /// `migrate::check`. Deliberately separate from `database_url`: a role
    /// with migration privilege can `ALTER TABLE ... DISABLE TRIGGER` the
    /// audit-immutability guards, so it must never be the connection that
    /// serves live traffic.
    pub migration_database_url: String,
    pub redis_url: String,
    pub listen_addr: SocketAddr,
    /// Path to a JSON file containing `Vec<mcphub_identity::config::IdpConfig>`
    /// — the install-time / ansible-time IDP config. Required: file config is
    /// the fallback the moment the DB-backed runtime store is unreachable, so
    /// there must always be one on disk even in a DB-first deployment.
    pub idp_config_file: String,
    pub vault_addr: String,
    pub vault_token: String,
    pub vault_kek_path: String,
    /// >= 32 bytes, per `mcphub_store::PgRedisAuditSink::new`'s contract.
    /// Sourced from an env var (populated by a secrets manager / Vault
    /// agent injection in real deployments) — never persisted to Postgres,
    /// never logged.
    pub audit_hmac_key: Vec<u8>,
    // TODO: not yet consumed — dedicated ports are read directly off each
    // server's `dedicated_port` column (see `listeners.rs`); this range is
    // meant to validate/allocate new ones from the admin API, which is not
    // built yet.
    #[allow(dead_code)]
    pub dedicated_port_range: std::ops::Range<u16>,
}

fn required_env(name: &str) -> Result<String, StartupError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(StartupError::Config(format!("required env var {name} is not set"))),
    }
}

pub fn load() -> Result<AppConfig, StartupError> {
    let database_url = required_env("DATABASE_URL")?;
    let migration_database_url = required_env("MCPHUBD_MIGRATION_DATABASE_URL")?;
    let redis_url = required_env("REDIS_URL")?;
    let idp_config_file = required_env("MCPHUB_IDP_CONFIG_FILE")?;
    let vault_addr = required_env("MCPHUB_VAULT_ADDR")?;
    let vault_token = required_env("MCPHUB_VAULT_TOKEN")?;
    let vault_kek_path = std::env::var("MCPHUB_VAULT_KEK_PATH").unwrap_or_else(|_| "secret/data/mcphub/kek".to_string());
    let audit_hmac_key = required_env("MCPHUB_AUDIT_HMAC_KEY")?.into_bytes();
    if audit_hmac_key.len() < 32 {
        return Err(StartupError::Config("MCPHUB_AUDIT_HMAC_KEY must be at least 32 bytes".to_string()));
    }

    let listen_addr: SocketAddr = std::env::var("MCPHUB_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .map_err(|e| StartupError::Config(format!("invalid MCPHUB_LISTEN_ADDR: {e}")))?;

    let range_start: u16 = std::env::var("MCPHUB_DEDICATED_PORT_START")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9000);
    let range_end: u16 = std::env::var("MCPHUB_DEDICATED_PORT_END")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9100);

    Ok(AppConfig {
        database_url,
        migration_database_url,
        redis_url,
        listen_addr,
        idp_config_file,
        vault_addr,
        vault_token,
        vault_kek_path,
        audit_hmac_key,
        dedicated_port_range: range_start..range_end,
    })
}
