//! The self-service MCP server binary.
//!
//! Binds loopback-only by default. This server must be reachable ONLY by the
//! gateway (ARCHITECTURE.md invariant 6 — backends are network-isolated), and
//! it trusts the gateway's identity headers completely, so exposing it directly
//! would hand anyone who can reach it the ability to assert any identity. In a
//! real deployment the podman internal network enforces that; the default bind
//! is the second lock.
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().json().init();

    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required (least-privilege runtime role, same as mcphubd)")?;
    let addr: SocketAddr = std::env::var("MCPHUB_SELFSERVICE_LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:9100".to_string())
        .parse()?;

    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(8).connect(&database_url).await?;
    let app = mcphub_selfservice::router(pool);

    tracing::info!(%addr, "mcphub-selfservice listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
