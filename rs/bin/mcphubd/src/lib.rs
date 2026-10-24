//! Library half of `mcphubd`, split out from `main.rs` so integration
//! tests (`tests/e2e.rs`) can build the exact same app the real binary
//! serves — same gates, same wiring, same fail-closed startup checks —
//! without spawning a subprocess. `main.rs` is now a thin wrapper that
//! calls [`build_app`] and binds the real listener.

#![forbid(unsafe_code)]

pub mod config;
pub mod idp_store;
pub mod listeners;
pub mod ui;
pub mod wiring;

use mcphub_gateway::{AppState, Gates};
use mcphub_identity::config::{FileIdpConfigLoader, IdpConfig};
use mcphub_identity::jwks::JwksCache;
use mcphub_identity::registry::IssuerRegistry;
use mcphub_policy::RegorusPolicyEngine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Everything startup produced that a caller (real `main`, or a test) might
/// need afterward: the served `Router`, the gateway `AppState` (for mounting
/// dedicated listeners), the pool (for direct DB assertions in tests), and
/// the resolved IDP/discovery maps (for dedicated-listener wiring).
pub struct Built {
    pub app: axum::Router,
    pub gw_state: AppState,
    pub pool: sqlx::PgPool,
    pub idps_by_issuer: HashMap<String, IdpConfig>,
    pub discovery_docs: HashMap<String, mcphub_identity::discovery::DiscoveryDocument>,
    pub registry: Arc<IssuerRegistry>,
    pub jwks_cache: Arc<JwksCache>,
    pub jwks_uris: Arc<HashMap<String, String>>,
}

/// Runs the full fail-closed startup sequence and assembles the real gates.
/// No `Gates::deny_all()` anywhere in this path — every gate is backed by a
/// real adapter in `wiring::*`. Returns `Err` (never a degraded-but-serving
/// app) on any dependency failure.
pub async fn build_app(cfg: &config::AppConfig) -> anyhow::Result<Built> {
    // --- Postgres: connect, then refuse to start on a dirty/behind schema. ---
    // `PoolConfig::default()`'s 500ms `acquire_timeout` is deliberately tight
    // for production (see its doc comment: bounds fail-closed deny latency).
    // Under contended local/CI hosts that's sometimes too tight just to
    // *establish* the pool's initial connections against a cold database —
    // `MCPHUB_DB_ACQUIRE_TIMEOUT_MS` lets an operator (or `tests/e2e.rs`)
    // widen it without touching the crate's production default.
    fn pool_config() -> mcphub_store::PoolConfig {
        let mut cfg = mcphub_store::PoolConfig::default();
        if let Some(ms) = std::env::var("MCPHUB_DB_ACQUIRE_TIMEOUT_MS").ok().and_then(|v| v.parse::<u64>().ok()) {
            cfg.acquire_timeout = Duration::from_millis(ms);
        }
        cfg
    }
    // Migration check runs on a SEPARATE, owner/superuser connection
    // (`migration_database_url`) — the runtime `pool` below must be a
    // least-privilege role that CANNOT run migrations, so the two
    // requirements ("check the schema" and "connect as non-privileged")
    // are structurally incompatible on one connection.
    let migration_pool = mcphub_store::pool::connect(&cfg.migration_database_url, pool_config())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refusing to start: cannot connect to Postgres (migration role)");
            e
        })?;
    mcphub_store::migrate::check(&migration_pool).await.map_err(|e| {
        tracing::error!(error = %e, "refusing to start: schema check failed");
        e
    })?;
    // Defense-in-depth: a `dedicated_port` server whose IDP has no
    // dedicated port assigned is a state the 0009 migration's triggers are
    // supposed to make unreachable — but a privileged connection can
    // disable a trigger, so this check doesn't rely on one having fired.
    let misconfigured = mcphub_store::repo::servers::find_dedicated_port_misconfigurations(&migration_pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refusing to start: could not check for dedicated_port misconfigurations");
            e
        })?;
    if !misconfigured.is_empty() {
        anyhow::bail!("refusing to start: {} server(s) are auth_mode=dedicated_port with no dedicated port on their IDP: {misconfigured:?}", misconfigured.len());
    }
    migration_pool.close().await;

    let pool = mcphub_store::pool::connect(&cfg.database_url, pool_config())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refusing to start: cannot connect to Postgres (runtime role)");
            e
        })?;
    tracing::info!("postgres connected, schema check passed");

    // A superuser, or the owner of `audit_events`, can `TRUNCATE`/`DROP`/
    // `ALTER TABLE ... DISABLE TRIGGER` its own append-only guard — making
    // every trigger in the schema decorative. Refuse to start rather than
    // run as a connection that could quietly defeat the audit invariants.
    // Checked against the RUNTIME pool, not the migration one — the
    // migration role is expected/required to be privileged; the runtime
    // role must not be.
    mcphub_store::assert_non_privileged_connection(&pool).await.map_err(|e| {
        tracing::error!(error = %e, "refusing to start: connected role is privileged enough to bypass the audit-immutability triggers");
        e
    })?;

    // --- Redis: an explicit connect probe up front (fail-closed at boot,
    // not silently degraded); the audit sink opens its own connection below. ---
    let redis_probe = mcphub_store::RedisStore::connect(&cfg.redis_url).await.map_err(|e| {
        tracing::error!(error = %e, "refusing to start: cannot connect to redis");
        e
    })?;
    drop(redis_probe);
    tracing::info!("redis connected");

    // --- IDP config: file (required fallback) + runtime DB store, runtime wins. ---
    let file_raw = std::fs::read_to_string(&cfg.idp_config_file).map_err(|e| {
        tracing::error!(error = %e, path = %cfg.idp_config_file, "refusing to start: cannot read IDP config file");
        mcphub_types::StartupError::Config(format!("cannot read {}: {e}", cfg.idp_config_file))
    })?;
    let file_loader = FileIdpConfigLoader::from_json(&file_raw).map_err(|e| {
        tracing::error!(error = %e, "refusing to start: IDP config file is malformed");
        mcphub_types::StartupError::Config(format!("IDP config file malformed: {e}"))
    })?;
    let runtime_store = idp_store::PgIdpConfigStore::new(pool.clone());
    let idp_configs = mcphub_identity::config::load_effective_config(&file_loader, Some(&runtime_store))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "refusing to start: no usable IDP configuration (file empty and runtime store empty/unreachable)");
            mcphub_types::StartupError::NoIdentityConfig
        })?;
    tracing::info!(count = idp_configs.len(), "IDP configuration loaded");

    // --- Discovery: resolve jwks_uri + AS endpoints per configured IDP up front. ---
    // `mcphub_identity::discovery::fetch_discovery` hard-requires an
    // `https://` issuer (correct production behavior — RFC 8414 discovery
    // over plaintext is not something to support). `MCPHUB_JWKS_URI_OVERRIDES`
    // is a narrow, explicit escape hatch for issuers configured WITHOUT
    // discovery: a JSON map `{"issuer": "jwks_uri"}` that pins the JWKS
    // location directly, skipping only the discovery *fetch* — token
    // signature/claims validation downstream is completely unaffected. This
    // is also what `tests/e2e.rs`'s self-hosted plain-HTTP test IDP uses,
    // since standing up a trusted TLS fixture for a loopback test server is
    // out of scope here.
    let jwks_overrides: HashMap<String, String> = std::env::var("MCPHUB_JWKS_URI_OVERRIDES")
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();

    let mut jwks_uris: HashMap<String, String> = HashMap::new();
    let mut discovery_docs: HashMap<String, mcphub_identity::discovery::DiscoveryDocument> = HashMap::new();
    for idp in &idp_configs {
        if let Some(uri) = jwks_overrides.get(&idp.issuer) {
            jwks_uris.insert(idp.issuer.clone(), uri.clone());
            continue;
        }
        let Some(_discovery_url) = &idp.discovery_url else {
            tracing::warn!(issuer = %idp.issuer, "IDP has no discovery_url configured and no JWKS override; skipping (requests from this issuer will fail-closed on JWKS lookup)");
            continue;
        };
        match mcphub_identity::discovery::fetch_discovery(&idp.issuer, &[]).await {
            Ok(doc) => {
                jwks_uris.insert(idp.issuer.clone(), doc.jwks_uri.clone());
                discovery_docs.insert(idp.issuer.clone(), doc);
            }
            Err(e) => {
                tracing::error!(error = %e, issuer = %idp.issuer, "refusing to start: discovery failed for a configured IDP");
                anyhow::bail!("discovery failed for issuer {}: {e}", idp.issuer);
            }
        }
    }

    let registry = Arc::new(
        IssuerRegistry::from_configs(idp_configs.clone())
            .map_err(|e| mcphub_types::StartupError::Config(format!("IDP registry rejected the configured issuers: {e}")))?,
    );
    let jwks_cache =
        Arc::new(JwksCache::new().map_err(|e| mcphub_types::StartupError::Config(format!("failed to build JWKS client: {e}")))?);
    let jwks_uris = Arc::new(jwks_uris);
    let idps_by_issuer: HashMap<String, IdpConfig> = idp_configs.into_iter().map(|c| (c.issuer.clone(), c)).collect();

    // --- Vault-backed credential broker KEK. No plaintext KEK fallback. ---
    let kek_source = mcphub_creds::VaultKekSource::new(&cfg.vault_addr, &cfg.vault_token, &cfg.vault_kek_path);
    let cred_store = mcphub_creds::store::CredentialStore::new(kek_source);
    let cred_source = wiring::credential::StoreCredentialSource::new(pool.clone());
    let credential_broker = Arc::new(mcphub_creds::Broker::new(cred_store, cred_source));

    // --- Policy engine: load embedded authz.rego, sync initial data. ---
    let policy_engine = Arc::new(RegorusPolicyEngine::new(Duration::from_secs(120)));
    // NOTE: anomaly.rego is NOT loaded here yet, deliberately. Loading it
    // alongside authz.rego triggers a regorus prepared-entrypoint bug
    // ("previous value is not an object" inside `structural_deny_reasons`)
    // that fires on EVERY evaluation, not just anomaly-triggering ones —
    // see `mcphub_policy::engine`'s
    // `anomaly_bundle_structural_rule_fires_and_denies` test (intentionally
    // left red/ignored) for the pinned repro. Loading it here today would
    // fail-closed-deny every single request platform-wide, which is worse
    // than the anomaly rules staying inert. `input.recent_calls` IS
    // correctly populated by `wiring::policy::StorePolicyEngine::evaluate`
    // regardless (fail-closed on a Redis read error, per the brief) — only
    // the bundle load is held back, so flipping this back to
    // `unsigned_for_tests_with_anomaly(EMBEDDED_AUTHZ_REGO,
    // EMBEDDED_ANOMALY_REGO)` is the entire fix once the regorus issue is
    // resolved.
    policy_engine
        .load_bundle(&mcphub_policy::PolicyBundle::unsigned_for_tests(mcphub_policy::PolicyBundle::EMBEDDED_AUTHZ_REGO))
        .map_err(|e| mcphub_types::StartupError::Config(format!("failed to load authz.rego bundle: {e}")))?;
    wiring::policy::sync_policy_data(&policy_engine, &pool).await?;
    spawn_policy_refresh(policy_engine.clone(), pool.clone());

    // --- Anomaly window: its own redis connection (separate from the audit
    // sink's — `RedisStore` wraps a `ConnectionManager`, cheap to hold more
    // than one, and keeping them separate means a `record_invocation`/
    // `recent_calls_window` slowdown can't starve audit writes or vice versa). ---
    let redis_for_policy = mcphub_store::RedisStore::connect(&cfg.redis_url).await.map_err(|e| {
        tracing::error!(error = %e, "refusing to start: cannot connect to redis for the anomaly window");
        e
    })?;

    // --- Audit sink: Postgres + redis + stdout, via the reconciliation adapter. ---
    let redis_for_audit = mcphub_store::RedisStore::connect(&cfg.redis_url).await?;
    let store_audit_sink = mcphub_store::PgRedisAuditSink::new(pool.clone(), redis_for_audit, cfg.audit_hmac_key.clone())?;
    let audit_sink = Arc::new(wiring::audit::AuditSinkAdapter::new(store_audit_sink));

    // --- Assemble the real gates. No `Gates::deny_all()` left in the path. ---
    let gates = Gates {
        authenticator: Arc::new(wiring::authenticator::StoreAuthenticator {
            registry: registry.clone(),
            jwks_cache: jwks_cache.clone(),
            jwks_uris: jwks_uris.clone(),
            pool: pool.clone(),
        }),
        entitlement: Arc::new(wiring::entitlement::StoreEntitlement::new(pool.clone())),
        rate_limiter: Arc::new(mcphub_policy::GovernorRateLimiter::new(
            std::env::var("MCPHUB_RATE_LIMIT_PER_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(600),
        )),
        policy: Arc::new(wiring::policy::StorePolicyEngine {
            engine: policy_engine.clone(),
            pool: pool.clone(),
            redis: redis_for_policy,
        }),
        credentials: credential_broker,
        dispatcher: Arc::new(wiring::dispatcher::HttpBackendDispatcher::new(pool.clone())?),
        audit: audit_sink,
    };

    let gw_state = AppState::new(gates);
    let ui_state = ui::build_ui_state(
        pool.clone(),
        registry.clone(),
        jwks_cache.clone(),
        jwks_uris.clone(),
        &idps_by_issuer,
        &discovery_docs,
        cfg.listen_addr.port(),
    );
    // OAuth discovery on the SHARED port. MCP clients (Claude Code, Claude
    // Desktop, Codex, the ChatGPT app) fetch
    // `/.well-known/oauth-protected-resource` from the MCP URL they were given
    // to learn how to authenticate; without it they cannot connect at all.
    // Dedicated ports publish their own (pointing at their own IDP) — this is
    // the shared port's, pointing at the platform IDP.
    //
    // Best-effort by design: if no IDP is usable for a browser/client OAuth
    // flow, the routes are simply absent and clients get a clean 404 at
    // discovery, rather than the process refusing to boot and taking the
    // bearer-token API path down with it.
    let mut app = mcphub_gateway::build(gw_state.clone()).merge(mcphub_ui::router(ui_state));
    match ui::portal_idp_and_doc(&idps_by_issuer, &discovery_docs) {
        Some((idp, doc)) => {
            let base = ui::public_base_url(cfg.listen_addr.port());
            app = app.merge(listeners::shared_oauth_metadata_router(&idp, &doc, &base));
            tracing::info!(resource = %format!("{base}/mcp"), issuer = %idp.issuer, "shared-port OAuth discovery mounted");
        }
        None => tracing::warn!(
            "no IDP has both a client_id and a redirect_uri_allowlist — shared-port OAuth discovery NOT mounted; \
             MCP clients (Claude Code, Codex, ChatGPT app) will not be able to authenticate against /mcp"
        ),
    }

    Ok(Built { app, gw_state, pool, idps_by_issuer, discovery_docs, registry, jwks_cache, jwks_uris })
}

/// Maps `servers.idp_id` -> resolved `IdpConfig` for the dedicated-listener
/// metadata endpoints.
pub async fn build_idps_by_id(pool: &sqlx::PgPool, idps_by_issuer: &HashMap<String, IdpConfig>) -> HashMap<uuid::Uuid, IdpConfig> {
    let rows = mcphub_store::repo::idp::list_active_idps(pool).await.unwrap_or_default();
    rows.into_iter()
        .filter_map(|row| idps_by_issuer.get(&row.issuer).map(|idp| (row.idp_id, idp.clone())))
        .collect()
}

/// Best-effort background refresh of the policy engine's synced data.
fn spawn_policy_refresh(engine: Arc<RegorusPolicyEngine>, pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = wiring::policy::sync_policy_data(&engine, &pool).await {
                tracing::error!(error = %e, "policy data refresh failed; engine will fail closed once max_data_age elapses");
            }
        }
    });
}
