//! Seals a credential and writes it to `credentials`, so a tool can actually
//! be invoked.
//!
//! `CredentialBroker::inject` treats an ABSENT credential row as a hard deny,
//! not as "this tool needs no credential". So every invocable tool needs a row
//! here, even one holding a placeholder, or every call fails at step 10 of the
//! enforcement chain — surfacing as `policy_denied`, because
//! `GateError::InvalidRequest` maps to `DenyReason::PolicyDenied`. That is a
//! genuinely confusing chain to debug from the outside; this exists so nobody
//! else has to rediscover it.
//!
//!     cargo run -p mcphub-creds --example seal -- <principal> <server_uuid> <purpose> <secret>
//!
//! Reads MCPHUB_VAULT_ADDR / MCPHUB_VAULT_TOKEN / MCPHUB_VAULT_KEK_PATH and
//! DATABASE_URL from the environment (same names mcphubd uses), so sourcing the
//! same env file the daemon uses is enough.

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        return Err("usage: seal <principal> <server_uuid> <purpose> <secret>".into());
    }
    let (principal, server_id, purpose, secret) = (&args[0], &args[1], &args[2], &args[3]);
    let server_uuid: uuid::Uuid = server_id.parse()?;

    let vault_addr = std::env::var("MCPHUB_VAULT_ADDR")?;
    let vault_token = std::env::var("MCPHUB_VAULT_TOKEN")?;
    let kek_path =
        std::env::var("MCPHUB_VAULT_KEK_PATH").unwrap_or_else(|_| "secret/data/mcphub/kek".to_string());
    let database_url = std::env::var("DATABASE_URL")?;

    let kek = mcphub_creds::VaultKekSource::new(&vault_addr, &vault_token, &kek_path);
    let store = mcphub_creds::store::CredentialStore::new(kek);
    // AAD binds the ciphertext to (principal, server, purpose) — the same triple
    // the row is keyed on — so a blob cannot be replayed into another context.
    let blob = store.encrypt(secret, principal, &server_uuid.to_string(), purpose).await?;

    let pool = PgPoolOptions::new().max_connections(1).connect(&database_url).await?;
    mcphub_store::repo::credentials::upsert_credential(&pool, principal, server_uuid, purpose, 1, &[], &blob, &[])
        .await?;

    println!("sealed credential for principal={principal} server={server_uuid} purpose={purpose}");
    Ok(())
}
