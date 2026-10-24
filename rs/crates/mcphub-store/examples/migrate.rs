//! Applies the embedded migrations to a database.
//!
//! `mcphubd` deliberately only *checks* the schema at startup (`migrate::check`)
//! and refuses to boot if it is dirty or behind — it never migrates itself, so a
//! rollback to an older binary can never be silently "fixed" by that binary
//! migrating the schema forward underneath it.
//!
//! That leaves someone needing to actually apply them. This is that someone.
//! Run it with the OWNER/superuser DSN (the same one `mcphubd` takes as
//! `MCPHUBD_MIGRATION_DATABASE_URL`), never the least-privilege runtime role —
//! the runtime role cannot create tables, by design.
//!
//!     cargo run -p mcphub-store --example migrate -- postgres://user:pw@host:port/db
//!
//! Falls back to `MCPHUBD_MIGRATION_DATABASE_URL` if no argument is given.

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("MCPHUBD_MIGRATION_DATABASE_URL").ok())
        .ok_or("usage: migrate <DATABASE_URL>  (or set MCPHUBD_MIGRATION_DATABASE_URL)")?;

    let pool = PgPoolOptions::new().max_connections(1).connect(&url).await?;
    mcphub_store::migrate::run(&pool).await?;
    println!("migrations applied");

    // Prove the schema now satisfies the same gate mcphubd applies at startup,
    // so a successful run here means mcphubd will boot rather than "probably".
    mcphub_store::migrate::check(&pool).await?;
    println!("migrate::check passed — mcphubd will accept this schema");
    Ok(())
}
