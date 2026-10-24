//! End-to-end tests against the REAL wired app: `mcphubd::build_app` (same
//! code path `main.rs` uses), a live podman Postgres, a live podman Redis,
//! and a self-hosted test JWKS/discovery server (RSA keypair minted
//! per-test, same pattern `mcphub-identity`'s own unit tests use).
//!
//! Requires (NOT --rm: the redis/postgres-kill tests stop() and start()
//! these containers, which would otherwise vanish):
//!   podman run -d --name mcphubd-e2e-pg -p 55499:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_USER=postgres postgres:16
//!   podman run -d --name mcphubd-e2e-redis -p 63799:6379 redis:7-alpine
//!   podman run -d --name mcphubd-e2e-vault --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root-e2e-token -p 18299:8200 hashicorp/vault:1.15
//!   (then seed the KEK: POST {"data":{"master_secret":"<32+ hex bytes>"}} to
//!   http://127.0.0.1:18299/v1/secret/data/mcphub/kek with header
//!   X-Vault-Token: root-e2e-token)
//!
//! Ports are deliberately non-standard (not the repo-wide 55432/63790
//! convention) to avoid colliding with other engineers'/agents' own test
//! runs against those shared default ports.
//!
//! Run with: cargo test -p mcphubd --test e2e -- --ignored --test-threads=1
//! (single-threaded: several tests stop/start the shared podman containers)

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use mcphub_identity::claims::{ProviderHint, RoleMapping};
use mcphub_identity::config::{AuthModeHint, IdpConfig};
use mcphub_store::repo::{grants, quarantine, roles, servers, tools};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde::Serialize;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ADMIN_DB_URL: &str = "postgres://postgres:test@127.0.0.1:55499/postgres";
const REDIS_URL: &str = "redis://127.0.0.1:63799";

// ---------------------------------------------------------------------
// Test IDP: mints its own RSA keypair, serves JWKS + discovery over a real
// local HTTP server (reuses the keypair-minting pattern from
// mcphub-identity's `lib.rs` unit tests; adds the HTTP serving layer that
// pattern didn't need since those tests construct `IssuerKeys` in-process).
// ---------------------------------------------------------------------

struct TestIdp {
    issuer: String,
    kid: String,
    priv_pem: String,
    client_id: String,
}

async fn spawn_test_idp() -> TestIdp {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let pub_key = priv_key.to_public_key();
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let priv_pem = priv_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
    let kid = "e2e-kid-1".to_string();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let issuer = format!("http://{addr}");

    let jwks = json!({"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": n_b64, "e": e_b64}]});
    let discovery = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
    });

    let app = axum::Router::new()
        .route("/.well-known/openid-configuration", axum::routing::get(move || async move { axum::Json(discovery) }))
        .route("/.well-known/jwks.json", axum::routing::get(move || async move { axum::Json(jwks) }));

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    TestIdp { issuer, kid, priv_pem, client_id: "mcphub-e2e".to_string() }
}

#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: String,
    exp: i64,
    nbf: i64,
    iat: i64,
}

fn mint_token(idp: &TestIdp, sub: &str, exp_offset_secs: i64) -> String {
    let now = jsonwebtoken::get_current_timestamp() as i64;
    let claims =
        Claims { sub: sub.to_string(), iss: idp.issuer.clone(), aud: idp.client_id.clone(), exp: now + exp_offset_secs, nbf: now - 10, iat: now };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(idp.kid.clone());
    encode(&header, &claims, &EncodingKey::from_rsa_pem(idp.priv_pem.as_bytes()).unwrap()).unwrap()
}

// ---------------------------------------------------------------------
// Fake backend MCP server — records how many times it was actually hit, so
// the "denied before any backend dispatch" test can assert zero calls.
// ---------------------------------------------------------------------

async fn spawn_fake_backend() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = hits.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new().route(
        "/invoke",
        axum::routing::post(move |axum::Json(_body): axum::Json<serde_json::Value>| {
            let hits = hits2.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"ok": true}))
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}/invoke"), hits)
}

// ---------------------------------------------------------------------
// Fresh throwaway database per test, migrated.
// ---------------------------------------------------------------------

/// Returns (migration_url, app_url, app_pool). `migrate::run` (and
/// `mcphubd`'s own `migrate::check`) run against the superuser
/// (`migration_url`); everything else — including the app's own runtime
/// pool built by `build_app` — connects as `mcphubd_e2e_app`, a real LOGIN
/// role that is a member of `mcphub_app` (created by migration 0004) and
/// therefore neither a superuser nor the owner of `audit_events`. This
/// mirrors the split `fix-deploy` provisioned for production
/// (`MCPHUBD_MIGRATION_DATABASE_URL` vs `DATABASE_URL`) and is required
/// for `assert_non_privileged_connection` to pass at startup.
async fn fresh_migrated_db() -> (String, String, PgPool) {
    let admin_pool = PgPoolOptions::new().max_connections(1).connect(ADMIN_DB_URL).await.expect("connect admin db");
    let db_name = format!("mcphubd_e2e_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\"")).execute(&admin_pool).await.expect("create test db");
    let migration_url = format!("postgres://postgres:test@127.0.0.1:55499/{db_name}");
    let migration_pool = PgPoolOptions::new().max_connections(5).connect(&migration_url).await.expect("connect test db");
    mcphub_store::migrate::run(&migration_pool).await.expect("run migrations");

    // Roles are cluster-wide, so this is idempotent across every test's
    // fresh database (`mcphub_app` itself is (re)created per-database by
    // the migration above; the LOGIN role wrapping it only needs to exist
    // once per cluster).
    sqlx::query(
        "DO $$ BEGIN \
            IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'mcphubd_e2e_app') THEN \
                CREATE ROLE mcphubd_e2e_app LOGIN PASSWORD 'test' IN ROLE mcphub_app; \
            END IF; \
        END $$;",
    )
    .execute(&migration_pool)
    .await
    .expect("create least-privilege login role");
    sqlx::query("GRANT USAGE ON SCHEMA public TO mcphubd_e2e_app").execute(&migration_pool).await.expect("grant schema usage");

    let app_url = format!("postgres://mcphubd_e2e_app:test@127.0.0.1:55499/{db_name}");
    let app_pool = PgPoolOptions::new().max_connections(5).connect(&app_url).await.expect("connect as least-privilege role");

    (migration_url, app_url, app_pool)
}

struct TestCtx {
    app: axum::Router,
    pool: PgPool,
    _idp: TestIdp,
    backend_hits: Arc<AtomicUsize>,
    server_id: Uuid,
    granted_tool_id: Uuid,
    quarantined_tool_id: Uuid,
    principal: &'static str,
}

async fn setup() -> TestCtx {
    let (migration_url, app_url, pool) = fresh_migrated_db().await;
    let idp = spawn_test_idp().await;
    let (backend_url, backend_hits) = spawn_fake_backend().await;

    // Register + approve a server pointing at the fake backend.
    let server_id = servers::register_server(&pool, &format!("srv-{}", Uuid::new_v4()), &backend_url, "owner-1")
        .await
        .expect("register server");
    servers::approve_server(&pool, server_id, "admin-1").await.expect("approve server");
    // The fake backend is a loopback listener; explicitly allowlist it the
    // same way a real lab/internal deployment would (see migration 0007) —
    // the SSRF gate denies unlisted private/loopback upstreams by default,
    // deliberately, and this test must not bypass that by other means.
    servers::set_allowed_cidr(&pool, server_id, Some("127.0.0.0/8")).await.expect("allowlist loopback for the fake backend");

    // A grantable, low-risk tool.
    let granted_tool_id = tools::upsert_tool(&pool, server_id, "ping", "1.0.0", "ping tool", &json!({}), "tester")
        .await
        .expect("upsert granted tool");
    sqlx::query("UPDATE tool_registry SET risk_score = 10, risk_level = 'low' WHERE tool_id = $1")
        .bind(granted_tool_id)
        .execute(&pool)
        .await
        .expect("set risk_score");

    // A second tool, quarantined.
    let quarantined_tool_id = tools::upsert_tool(&pool, server_id, "danger", "1.0.0", "quarantined tool", &json!({}), "tester")
        .await
        .expect("upsert quarantined tool");
    sqlx::query("UPDATE tool_registry SET risk_score = 10, risk_level = 'low' WHERE tool_id = $1")
        .bind(quarantined_tool_id)
        .execute(&pool)
        .await
        .expect("set risk_score");
    quarantine::quarantine(&pool, quarantine::QuarantineTarget::Tool, quarantined_tool_id, "flagged in test setup", "analyst-1")
        .await
        .expect("quarantine tool");

    let principal = "alice";
    let known_issuers = std::collections::HashSet::from([idp.issuer.clone()]);
    roles::grant_role(&pool, principal, &idp.issuer, mcphub_types::Role::Employee, "test-setup", &known_issuers)
        .await
        .expect("grant role");
    grants::upsert_grant(
        &pool,
        principal,
        Some(server_id),
        &["ping".to_string(), "danger".to_string()],
        &[],
        "medium",
        "test-setup",
    )
    .await
    .expect("upsert grant");

    // Real credential, sealed through the real `mcphub-creds` broker against
    // a live Vault dev server: `CredentialBroker::inject` treats an absent
    // credential row as a hard deny (`CredsError::NotFound`), not "no
    // injection needed" — see the handoff report's flagged gap on this. A
    // granted, non-quarantined, policy-allowed call still cannot reach
    // `dispatch` without a seeded credential, so the happy-path test needs
    // one exactly like a real deployment would.
    let kek = mcphub_creds::VaultKekSource::new("http://127.0.0.1:18299", "root-e2e-token", "secret/data/mcphub/kek");
    let cred_store = mcphub_creds::store::CredentialStore::new(kek);
    let blob = cred_store.encrypt("e2e-fake-upstream-token", principal, &server_id.to_string(), "ping").await.expect("seal test credential");
    mcphub_store::repo::credentials::upsert_credential(&pool, principal, server_id, "ping", 1, &[], &blob, &[])
        .await
        .expect("seed credential row");

    // IDP config file.
    let idp_config = IdpConfig {
        // The e2e test IDP stands in for the platform's own trusted admin
        // source, so it carries the top ceiling. The ceiling itself is
        // exercised in mcphub-identity's unit tests, not here.
        max_assertable_role: mcphub_types::Role::SuperAdmin,
        issuer: idp.issuer.clone(),
        discovery_url: Some(format!("{}/.well-known/openid-configuration", idp.issuer)),
        issuer_aliases: vec![],
        audiences: vec![idp.client_id.clone()],
        role_mapping: RoleMapping::default_for(ProviderHint::Generic),
        allowed_algs: vec!["RS256".to_string()],
        clock_skew_seconds: 60,
        auth_mode: AuthModeHint::SharedPassthrough,
        dedicated_port: None,
        supports_token_exchange: false,
        client_id: Some(idp.client_id.clone()),
        redirect_uri_allowlist: vec![],
    };
    let idp_file = std::env::temp_dir().join(format!("mcphubd-e2e-idp-{}.json", Uuid::new_v4()));
    std::fs::write(&idp_file, serde_json::to_string(&vec![idp_config]).unwrap()).unwrap();

    std::env::set_var("DATABASE_URL", &app_url);
    std::env::set_var("MCPHUBD_MIGRATION_DATABASE_URL", &migration_url);
    std::env::set_var("REDIS_URL", REDIS_URL);
    std::env::set_var("MCPHUB_IDP_CONFIG_FILE", idp_file.to_str().unwrap());
    std::env::set_var("MCPHUB_VAULT_ADDR", "http://127.0.0.1:18299");
    std::env::set_var("MCPHUB_VAULT_TOKEN", "root-e2e-token");
    std::env::set_var("MCPHUB_AUDIT_HMAC_KEY", "e2e-test-audit-hmac-key-32-bytes-minimum!!");
    // Local/CI hosts under load sometimes can't establish a pool's initial
    // connections inside the production 500ms `acquire_timeout` — widen it
    // for the test run only (see lib.rs's doc comment on this knob).
    std::env::set_var("MCPHUB_DB_ACQUIRE_TIMEOUT_MS", "5000");
    // The test IDP is a plain-HTTP loopback server (no trusted TLS fixture
    // available here) — pin its JWKS URI directly instead of going through
    // `fetch_discovery`, which correctly requires `https://` for real
    // discovery. See lib.rs's `MCPHUB_JWKS_URI_OVERRIDES` doc comment.
    std::env::set_var(
        "MCPHUB_JWKS_URI_OVERRIDES",
        serde_json::to_string(&json!({idp.issuer.clone(): format!("{}/.well-known/jwks.json", idp.issuer)})).unwrap(),
    );

    let cfg = mcphubd::config::load().expect("load config");
    let built = mcphubd::build_app(&cfg).await.expect("build_app should succeed against live deps");

    TestCtx { app: built.app, pool, _idp: idp, backend_hits, server_id, granted_tool_id, quarantined_tool_id, principal }
}

fn rest_invoke_req(tool: &str, server_id: Uuid, token: Option<&str>) -> Request<Body> {
    let body = json!({"server_id": server_id.to_string(), "params": {}});
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/tools/{tool}/invoke"))
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

fn mcp_call_req(tool: &str, token: Option<&str>) -> Request<Body> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}});
    let mut req = Request::builder().method("POST").uri("/mcp").header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.body(Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

fn mcp_list_req(token: Option<&str>) -> Request<Body> {
    let mut req = Request::builder().method("POST").uri("/mcp").header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    req.body(Body::from(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn valid_token_granted_tool_allows_and_writes_audit_row() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&token))).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "expected allow, got body: {body}");
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 1, "backend should have been dispatched to exactly once");

    let request_id = body["request_id"].as_str().unwrap();
    let row: (String, Option<String>) = sqlx::query_as("SELECT outcome, deny_reason FROM audit_events WHERE request_id = $1")
        .bind(request_id)
        .fetch_one(&ctx.pool)
        .await
        .expect("audit row must exist in Postgres");
    assert_eq!(row.0, "allow");
    assert_eq!(row.1, None);
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn valid_token_non_granted_tool_is_denied_with_reason_recorded() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    // A real, active, non-quarantined tool this principal has no grant for.
    let ungranted_tool_id = tools::upsert_tool(&ctx.pool, ctx.server_id, "other-tool", "1.0.0", "no grant for alice", &json!({}), "tester")
        .await
        .unwrap();
    sqlx::query("UPDATE tool_registry SET risk_score = 10, risk_level = 'low' WHERE tool_id = $1")
        .bind(ungranted_tool_id)
        .execute(&ctx.pool)
        .await
        .unwrap();

    let resp = ctx.app.clone().oneshot(rest_invoke_req("other-tool", ctx.server_id, Some(&token))).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(status.is_client_error(), "expected a deny, got {status}: {body}");
    assert_eq!(body["error"], "entitlement_missing");

    let row: (String, Option<String>) =
        sqlx::query_as("SELECT outcome, deny_reason FROM audit_events WHERE tool_name = 'other-tool' ORDER BY event_ts DESC LIMIT 1")
            .fetch_one(&ctx.pool)
            .await
            .expect("deny must also be audited");
    assert_eq!(row.0, "deny");
    assert_eq!(row.1.as_deref(), Some("entitlement_missing"));
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn tool_absent_from_tools_list_is_denied_on_tools_call_same_reason_over_http() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    // Confirm it is really absent from discovery first.
    let list_req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap()))
        .unwrap();
    let list_resp = ctx.app.clone().oneshot(list_req).await.unwrap();
    let list_body = body_json(list_resp).await;
    let names: Vec<&str> = list_body["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(!names.contains(&"nonexistent-tool"), "tool must not be in the discovery list for this test to prove anything");

    let resp = ctx.app.clone().oneshot(mcp_call_req("nonexistent-tool", Some(&token))).await.unwrap();
    let body = body_json(resp).await;
    assert_eq!(body["error"]["message"], "entitlement_missing", "discovery==invoke: same reason as an absent-from-list tool");
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 0, "backend must never be dispatched to for a call denied pre-dispatch");

    // Regression check: this specific denial happens in
    // `resolve_tool_by_name`, BEFORE `invoke()` is ever reached — before the
    // fix, no audit path existed there at all, so a `/mcp` `tools/call`
    // denial produced zero rows in Postgres, redis, AND stdout (the REST
    // path audited the identical denial correctly the whole time).
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT outcome, deny_reason FROM audit_events WHERE tool_name = 'nonexistent-tool' ORDER BY event_ts DESC LIMIT 1")
            .fetch_one(&ctx.pool)
            .await
            .expect("the /mcp tools/call pre-invoke denial must still produce an audit row");
    assert_eq!(row.0, "deny");
    assert_eq!(row.1.as_deref(), Some("entitlement_missing"));
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn expired_token_is_denied_before_any_backend_dispatch() {
    let ctx = setup().await;
    let expired = mint_token(&ctx._idp, ctx.principal, -300);

    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&expired))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 0, "an expired token must never reach dispatch");

    let missing_resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, None)).await.unwrap();
    assert_eq!(missing_resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 0, "a missing token must never reach dispatch either");
}

/// D1 regression test: an unauthenticated request carrying a BOGUS,
/// non-existent `server_id` must still leave an audit trace — before the
/// fix, `wiring/audit.rs` wrote that unvalidated wire-supplied UUID
/// straight into `audit_events.server_id` (an FK), the INSERT failed
/// (23503), `PgRedisAuditSink::emit` returned `Err` before ever reaching
/// its own stdout step, and `invocation.rs`'s `let _ = ...emit(...)`
/// discarded that error — leaving literally nothing in Postgres, Redis, or
/// stdout. The fix: `server_id` is only ever written on `Allow` (`Deny`
/// always writes NULL), and the adapter now logs an unconditional stdout
/// line before attempting the store write at all.
#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn unauthenticated_request_with_bogus_server_id_still_produces_an_audit_record() {
    let ctx = setup().await;
    let bogus_server = Uuid::new_v4(); // does not exist in the DB at all

    let resp = ctx
        .app
        .clone()
        .oneshot(rest_invoke_req("whatever-tool-name", bogus_server, Some("garbage-not-even-a-jwt")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "bad token must deny before ever touching the bogus server_id");
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 0);

    // The row must exist, must be a deny, and — the actual point of the
    // fix — `server_id` must be NULL (never the bogus wire-supplied UUID),
    // which is exactly what makes the INSERT succeed instead of hitting
    // the FK constraint and vanishing.
    let row: (String, Option<Uuid>) = sqlx::query_as(
        "SELECT outcome, server_id FROM audit_events WHERE tool_name = 'whatever-tool-name' ORDER BY event_ts DESC LIMIT 1",
    )
    .fetch_one(&ctx.pool)
    .await
    .expect("an audit row MUST exist for this attempt — this is the D1 regression check");
    assert_eq!(row.0, "deny");
    assert_eq!(row.1, None, "server_id must never be the attacker-supplied bogus UUID");
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn quarantined_tool_denied_via_rest_and_mcp() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    let rest_resp = ctx.app.clone().oneshot(rest_invoke_req("danger", ctx.server_id, Some(&token))).await.unwrap();
    assert!(rest_resp.status().is_client_error(), "REST path must deny a quarantined tool");
    let rest_body = body_json(rest_resp).await;
    assert_eq!(rest_body["error"], "quarantined");

    let mcp_resp = ctx.app.clone().oneshot(mcp_call_req("danger", Some(&token))).await.unwrap();
    let mcp_body = body_json(mcp_resp).await;
    // NOTE: the /mcp path resolves tool names only through
    // `EntitlementStore::list_visible` (never a second by-name lookup — see
    // `invocation::resolve_tool_by_name`'s doc comment on why). This repo's
    // `list_visible` wiring (bin/mcphubd/src/wiring/entitlement.rs) already
    // excludes quarantined tools from the visible set as defense in depth,
    // so on this path the denial surfaces as `entitlement_missing` rather
    // than `quarantined` — still a deny, just via the earlier gate. Both
    // paths reject the call; only the REST path (which builds an
    // `InvokeRequest` directly, reaching the dedicated quarantine gate)
    // reports the `quarantined` code specifically.
    assert!(mcp_body["error"]["message"] == "quarantined" || mcp_body["error"]["message"] == "entitlement_missing");
    assert_eq!(ctx.backend_hits.load(Ordering::SeqCst), 0, "quarantined tool must never be dispatched to");

    let _ = ctx.quarantined_tool_id; // referenced for readability of intent above
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn redis_killed_mid_flight_denies_the_request() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    // Sanity: works while redis is up.
    let ok_resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&token))).await.unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK, "must succeed while redis is healthy, to prove the later denial is caused by the kill");

    std::process::Command::new("podman").args(["stop", "-t", "0", "mcphubd-e2e-redis"]).status().expect("stop redis container");

    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&token))).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        status == StatusCode::SERVICE_UNAVAILABLE || status.is_client_error(),
        "redis outage must deny (fail-closed), got {status}: {body}"
    );
    assert_ne!(status, StatusCode::OK, "THE invariant: a redis outage must never allow a request through");

    // Restart for subsequent tests / cleanup.
    std::process::Command::new("podman").args(["start", "mcphubd-e2e-redis"]).status().expect("restart redis container");
    for _ in 0..30 {
        if std::process::Command::new("podman")
            .args(["exec", "mcphubd-e2e-redis", "redis-cli", "ping"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn postgres_killed_denies_the_request() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    let ok_resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&token))).await.unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK, "must succeed while postgres is healthy, to prove the later denial is caused by the kill");

    std::process::Command::new("podman").args(["stop", "-t", "0", "mcphubd-e2e-pg"]).status().expect("stop postgres container");

    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&token))).await.unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert_ne!(status, StatusCode::OK, "THE invariant: a postgres outage must never allow a request through, got {status}: {body}");

    // Restart postgres so any later test in this binary can still run
    // (tokio test harness may interleave `#[tokio::test]` functions across
    // threads even with --test-threads=1's process-level serialization of
    // *this* file, since each test spins its own runtime).
    std::process::Command::new("podman").args(["start", "mcphubd-e2e-pg"]).status().expect("restart postgres container");
    for _ in 0..30 {
        if std::process::Command::new("podman")
            .args(["exec", "mcphubd-e2e-pg", "pg_isready", "-U", "postgres"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn discovery_eq_invoke_and_denied_at_startup_gate_smoke() {
    // Smaller smoke test: SuperAdmin is never granted in setup(), so this
    // also exercises the "wrong roles" path organically via a second
    // principal minted here with no role_grants row at all.
    let ctx = setup().await;
    let unknown_principal_token = mint_token(&ctx._idp, "totally-unknown-user", 300);
    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", ctx.server_id, Some(&unknown_principal_token))).await.unwrap();
    assert!(resp.status().is_client_error(), "a principal with zero role grants must not be able to invoke a granted-to-someone-else tool");
}

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn wrong_server_id_for_a_real_tool_name_is_denied_not_misrouted() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);
    let bogus_server = Uuid::new_v4();
    let resp = ctx.app.clone().oneshot(rest_invoke_req("ping", bogus_server, Some(&token))).await.unwrap();
    assert!(resp.status().is_client_error());
    let _ = ctx.granted_tool_id;
}

// ---------------------------------------------------------------------
// Multi-IDP ceiling-bypass regression (the critic's finding): every other
// test in this file configures exactly ONE IDP, so the entire multi-IDP
// surface — where `IdpConfig.max_assertable_role` differs PER issuer — had
// no end-to-end coverage at all. This is that coverage: two configured
// IDPs at different ceilings, a `role_grants` row (not a token claim)
// asserting `SuperAdmin` for the low-trust one, and a proof that the real
// enforcement path (`StoreAuthenticator::authenticate`, exercised via a
// live HTTP request through `mcphubd::build_app`) never lets that grant
// through.
// ---------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn low_trust_idp_role_grants_row_above_ceiling_does_not_yield_admin_access() {
    let (migration_url, app_url, pool) = fresh_migrated_db().await;
    let trusted_idp = spawn_test_idp().await; // the platform's own admin source
    let lowtrust_idp = spawn_test_idp().await; // e.g. a partner/contractor tenant
    let (backend_url, _backend_hits) = spawn_fake_backend().await;

    // One approved server with one tool NOBODY has an explicit grant for.
    // If the low-trust principal below ends up `SuperAdmin`, `list_visible`
    // (bin/mcphubd/src/wiring/entitlement.rs) returns it via
    // `LIST_VISIBLE_ADMIN_SQL` with no grant check at all; if the ceiling
    // held, it's invisible (no `grants` row) and uninvokable
    // (`entitlement_missing`).
    let server_id = servers::register_server(&pool, &format!("srv-{}", Uuid::new_v4()), &backend_url, "owner-1")
        .await
        .expect("register server");
    servers::approve_server(&pool, server_id, "admin-1").await.expect("approve server");
    servers::set_allowed_cidr(&pool, server_id, Some("127.0.0.0/8")).await.expect("allowlist loopback for the fake backend");
    let tool_id = tools::upsert_tool(&pool, server_id, "secret-tool", "1.0.0", "admin-only-in-a-buggy-build", &json!({}), "tester")
        .await
        .expect("upsert tool");
    sqlx::query("UPDATE tool_registry SET risk_score = 10, risk_level = 'low' WHERE tool_id = $1")
        .bind(tool_id)
        .execute(&pool)
        .await
        .expect("set risk_score");

    // THE attack: no token claim ever asserts SuperAdmin. A `role_grants`
    // row does, directly, for the LOW-TRUST issuer — exactly the write-path
    // shape the critic described (a contractor tenant's principal getting a
    // `role_grants` row instead of needing a forged role claim).
    let mallory = "mallory";
    let known_issuers = std::collections::HashSet::from([trusted_idp.issuer.clone(), lowtrust_idp.issuer.clone()]);
    roles::grant_role(&pool, mallory, &lowtrust_idp.issuer, mcphub_types::Role::SuperAdmin, "attacker-or-bug", &known_issuers)
        .await
        .expect("grant role");

    // Two IDPs, two ceilings: the corporate/trusted IDP may assert
    // SuperAdmin; the low-trust IDP may assert nothing above Employee.
    let idp_configs = vec![
        IdpConfig {
            max_assertable_role: mcphub_types::Role::SuperAdmin,
            issuer: trusted_idp.issuer.clone(),
            discovery_url: Some(format!("{}/.well-known/openid-configuration", trusted_idp.issuer)),
            issuer_aliases: vec![],
            audiences: vec![trusted_idp.client_id.clone()],
            role_mapping: RoleMapping::default_for(ProviderHint::Generic),
            allowed_algs: vec!["RS256".to_string()],
            clock_skew_seconds: 60,
            auth_mode: AuthModeHint::SharedPassthrough,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: Some(trusted_idp.client_id.clone()),
            redirect_uri_allowlist: vec![],
        },
        IdpConfig {
            max_assertable_role: mcphub_types::Role::Employee,
            issuer: lowtrust_idp.issuer.clone(),
            discovery_url: Some(format!("{}/.well-known/openid-configuration", lowtrust_idp.issuer)),
            issuer_aliases: vec![],
            audiences: vec![lowtrust_idp.client_id.clone()],
            // Deliberately NOT `default_for(Generic)`: that table shares
            // privileged role-name strings (e.g. "mcphub-super-admin") with
            // the trusted IDP's mapping above, and
            // `check_no_cross_idp_privileged_role_string_collisions` refuses
            // to boot with the same privileged string owned by two IDPs at
            // different ceilings (correctly — see that function's doc
            // comment). This test's attack is the `role_grants` write path,
            // not a claim, so this IDP needs no claim→role mapping at all.
            role_mapping: RoleMapping::default(),
            allowed_algs: vec!["RS256".to_string()],
            clock_skew_seconds: 60,
            auth_mode: AuthModeHint::SharedPassthrough,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: Some(lowtrust_idp.client_id.clone()),
            redirect_uri_allowlist: vec![],
        },
    ];
    let idp_file = std::env::temp_dir().join(format!("mcphubd-e2e-idp-multi-{}.json", Uuid::new_v4()));
    std::fs::write(&idp_file, serde_json::to_string(&idp_configs).unwrap()).unwrap();

    std::env::set_var("DATABASE_URL", &app_url);
    std::env::set_var("MCPHUBD_MIGRATION_DATABASE_URL", &migration_url);
    std::env::set_var("REDIS_URL", REDIS_URL);
    std::env::set_var("MCPHUB_IDP_CONFIG_FILE", idp_file.to_str().unwrap());
    std::env::set_var("MCPHUB_VAULT_ADDR", "http://127.0.0.1:18299");
    std::env::set_var("MCPHUB_VAULT_TOKEN", "root-e2e-token");
    std::env::set_var("MCPHUB_AUDIT_HMAC_KEY", "e2e-test-audit-hmac-key-32-bytes-minimum!!");
    std::env::set_var("MCPHUB_DB_ACQUIRE_TIMEOUT_MS", "5000");
    std::env::set_var(
        "MCPHUB_JWKS_URI_OVERRIDES",
        serde_json::to_string(&json!({
            trusted_idp.issuer.clone(): format!("{}/.well-known/jwks.json", trusted_idp.issuer),
            lowtrust_idp.issuer.clone(): format!("{}/.well-known/jwks.json", lowtrust_idp.issuer),
        }))
        .unwrap(),
    );

    let cfg = mcphubd::config::load().expect("load config");
    let built = mcphubd::build_app(&cfg).await.expect("build_app should succeed against live deps");
    let app = built.app;

    let token = mint_token(&lowtrust_idp, mallory, 300);

    // 1) Discovery must NOT include the tool — if the SuperAdmin grant had
    //    survived the ceiling, `list_visible`'s admin branch would return
    //    every active tool on every approved server, no grant required.
    let list_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let list_body = body_json(list_resp).await;
    let names: Vec<&str> = list_body["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(
        !names.contains(&"secret-tool"),
        "a role_grants row above the low-trust issuer's ceiling must not grant admin-wide tool visibility: got {names:?}"
    );

    // 2) discovery == invoke: calling it directly must be denied the same way.
    let call_resp = app.clone().oneshot(mcp_call_req("secret-tool", Some(&token))).await.unwrap();
    let call_body = body_json(call_resp).await;
    assert_eq!(
        call_body["error"]["message"], "entitlement_missing",
        "the ceiling-dropped SuperAdmin grant must not be usable to invoke a tool this principal has no explicit grant for: {call_body}"
    );
}

/// grants ∧ profiles: a principal's own profile may NARROW what `grants`
/// allows, and that narrowing must apply to BOTH `tools/list` and
/// `tools/call` — not one or the other. A profile that could hide a tool from
/// discovery while still permitting invocation (or vice versa) would be a
/// discovery≠invoke split, which is exactly what invariant 3 forbids.
///
/// Both halves are asserted here against a tool the caller IS granted, so a
/// failure can only mean the profile filter didn't apply — not that the grant
/// was missing.
#[tokio::test]
#[ignore = "requires live podman postgres+redis+test IDP; run with `cargo test -p mcphubd --test e2e -- --ignored --test-threads=1`"]
async fn a_disabled_profile_narrows_both_discovery_and_invocation() {
    let ctx = setup().await;
    let token = mint_token(&ctx._idp, ctx.principal, 300);

    // Baseline: the tool is granted, so it is visible and invocable.
    let listed = body_json(ctx.app.clone().oneshot(mcp_list_req(Some(&token))).await.unwrap()).await;
    let names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("unexpected tools/list body: {listed}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"ping".to_string()), "precondition: ping must be granted, got {names:?}");

    // The principal disables this MCP for themselves.
    let server_name: (String,) = sqlx::query_as("SELECT name FROM servers WHERE server_id = $1")
        .bind(ctx.server_id)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    mcphub_store::repo::profiles::upsert_profile(
        &ctx.pool,
        ctx.principal,
        &server_name.0,
        false,
        None,
        ctx.principal,
    )
    .await
    .expect("disable the mcp for this principal");

    // Discovery narrows.
    let listed = body_json(ctx.app.clone().oneshot(mcp_list_req(Some(&token))).await.unwrap()).await;
    let names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("unexpected tools/list body: {listed}"))
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(!names.contains(&"ping".to_string()), "a disabled profile must hide the tool, got {names:?}");

    // Invocation narrows with it, with the same reason discovery would give.
    let body = body_json(ctx.app.clone().oneshot(mcp_call_req("ping", Some(&token))).await.unwrap()).await;
    assert_eq!(
        body["error"]["message"], "entitlement_missing",
        "a disabled profile must deny invocation too, got {body}"
    );
}
