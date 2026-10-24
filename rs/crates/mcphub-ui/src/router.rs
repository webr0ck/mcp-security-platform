use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::csp::csp_layer;
use crate::pages::{admin, common, employee, owner, security};
use crate::state::AppState;

/// Builds the full portal router, ready to be nested/merged into the
/// gateway's axum app (`bin/mcphubd`). Owns nothing about identity
/// resolution or persistence beyond the `AppState` seam — see
/// `crate::data` and `crate::auth` for what's temporary there.
pub fn router(state: AppState) -> Router {
    let static_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/static");

    let router = Router::new()
        .route("/", get(common::home))
        .route("/login", get(common::login))
        .route("/callback", get(common::callback))
        .route("/logout", post(common::logout));

    // Dev-only session picker: a raw session-id form with NO credential
    // check beyond "does this session id exist in the fixture store" —
    // mounted at `/dev/login`, never `/login`, and gated behind an
    // explicitly-named, off-by-default feature (`auth::InMemorySessionStore`
    // itself is also feature-gated — see its module doc) so a normal
    // release build can never reach it, no matter which path it's on.
    #[cfg(feature = "dev_login")]
    let router = router.route("/dev/login", get(common::dev::login_form).post(common::dev::login_submit));

    router
        // Employee
        .route("/help", get(common::help))
        .route("/catalog", get(employee::catalog))
        .route("/catalog/request-access", post(employee::request_access))
        .route("/me/grants", get(employee::my_grants))
        // Server owner
        .route("/owner/servers", get(owner::servers))
        .route("/owner/servers/:id", get(owner::server_detail))
        // Security team
        .route("/security/audit", get(security::audit_list))
        .route("/security/audit/:id", get(security::audit_detail))
        .route("/security/policy", get(security::policy_decisions))
        .route("/security/quarantine", get(security::quarantine))
        .route("/security/quarantine/release", post(security::release_quarantine))
        .route("/security/anomalies", get(security::anomalies))
        // Super admin
        .route("/admin/idps", get(admin::idps).post(admin::idp_create))
        .route("/admin/idps/new", get(admin::idp_new_form))
        .route("/admin/servers", get(admin::servers))
        .route("/admin/limits", get(admin::limits_form).post(admin::limits_save))
        .route("/admin/grants", get(admin::grants))
        .nest_service("/static", ServeDir::new(static_dir))
        .fallback(common::not_found)
        .layer(axum::middleware::from_fn(csp_layer))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
