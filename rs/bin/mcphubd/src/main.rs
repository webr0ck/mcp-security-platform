//! `mcphubd` — the single binary. Thin wrapper: real startup/wiring logic
//! lives in `lib.rs`'s `build_app` so `tests/e2e.rs` can exercise the exact
//! same app in-process.

#![forbid(unsafe_code)]

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_current_span(true)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cfg = mcphubd::config::load()?;
    let built = mcphubd::build_app(&cfg).await?;

    let listener = tokio::net::TcpListener::bind(cfg.listen_addr).await.map_err(|source| mcphub_types::StartupError::Bind {
        addr: cfg.listen_addr.to_string(),
        source,
    })?;
    tracing::info!(addr = %cfg.listen_addr, "mcphubd listening");

    // --- Dedicated per-server listeners (auth_mode = dedicated_port). ---
    let idps_by_id = mcphubd::build_idps_by_id(&built.pool, &built.idps_by_issuer).await;
    let dedicated_servers = mcphub_store::repo::servers::list_active_servers(&built.pool).await.unwrap_or_default();
    mcphubd::listeners::spawn_dedicated_listeners(
        built.gw_state.clone(),
        &dedicated_servers,
        &idps_by_id,
        &built.discovery_docs,
        &std::env::var("MCPHUB_PUBLIC_HOST").unwrap_or_else(|_| "localhost".to_string()),
    )
    .await;

    axum::serve(listener, built.app.into_make_service_with_connect_info::<std::net::SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}
