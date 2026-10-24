use axum::extract::{Extension, Form, State};
use axum::response::{IntoResponse, Redirect, Response};
use mcphub_types::Role;
use serde::Deserialize;

use crate::auth::{require_role, verify_csrf, CurrentUser};
use crate::chrome;
use crate::csp::CspNonce;
use crate::domain::{GlobalLimits, IdpConfig};
use crate::state::AppState;
use crate::templates::{AdminGrantsTemplate, AdminIdpNewTemplate, AdminIdpsTemplate, AdminLimitsTemplate, AdminServersTemplate};

const ROLE: &[Role] = &[Role::SuperAdmin];

pub async fn idps(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view identity providers") {
        return resp;
    }
    let idps = state.data.idps().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/idps", nonce, None);
    AdminIdpsTemplate { chrome, idps }.into_response()
}

pub async fn idp_new_form(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "add an identity provider") {
        return resp;
    }
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/idps", nonce, None);
    AdminIdpNewTemplate { chrome, error: None }.into_response()
}

#[derive(Deserialize)]
pub struct IdpForm {
    pub csrf_token: String,
    pub kind: String,
    pub display_name: String,
    pub issuer_url: String,
    pub supports_token_exchange: String,
}

pub async fn idp_create(
    State(state): State<AppState>,
    user: CurrentUser,
    Extension(nonce): Extension<CspNonce>,
    Form(form): Form<IdpForm>,
) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "add an identity provider") {
        return resp;
    }
    if let Err(resp) = verify_csrf(&state, &user, &form.csrf_token) {
        return resp;
    }

    let kind = match form.kind.as_str() {
        "entra" => "entra",
        "keycloak" => "keycloak",
        "zitadel" => "zitadel",
        _ => "generic_oidc",
    };

    if form.display_name.trim().is_empty() || !form.issuer_url.starts_with("https://") {
        let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/idps", nonce, None);
        let body = AdminIdpNewTemplate {
            chrome,
            error: Some("Display name is required and the issuer URL must use https://.".to_string()),
        };
        return (axum::http::StatusCode::UNPROCESSABLE_ENTITY, body).into_response();
    }

    state
        .data
        .create_idp(IdpConfig {
            id: form.display_name.to_lowercase().replace(' ', "-"),
            kind,
            display_name: form.display_name,
            issuer_url: form.issuer_url,
            supports_token_exchange: form.supports_token_exchange == "true",
        })
        .await;

    Redirect::to("/admin/idps").into_response()
}

pub async fn servers(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view the server registry") {
        return resp;
    }
    let servers = state.data.all_servers().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/servers", nonce, None);
    AdminServersTemplate { chrome, servers }.into_response()
}

pub async fn limits_form(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view global limits") {
        return resp;
    }
    let limits = state.data.global_limits().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/limits", nonce, None);
    AdminLimitsTemplate { chrome, limits }.into_response()
}

#[derive(Deserialize)]
pub struct LimitsForm {
    pub csrf_token: String,
    pub default_rate_limit_per_min: u32,
    pub anomaly_cutoff_threshold: f64,
    pub dedicated_port_range_start: u16,
    pub dedicated_port_range_end: u16,
}

pub async fn limits_save(State(state): State<AppState>, user: CurrentUser, Form(form): Form<LimitsForm>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "change global limits") {
        return resp;
    }
    if let Err(resp) = verify_csrf(&state, &user, &form.csrf_token) {
        return resp;
    }
    state
        .data
        .set_global_limits(GlobalLimits {
            default_rate_limit_per_min: form.default_rate_limit_per_min,
            anomaly_cutoff_threshold: form.anomaly_cutoff_threshold,
            dedicated_port_range_start: form.dedicated_port_range_start,
            dedicated_port_range_end: form.dedicated_port_range_end,
        })
        .await;
    Redirect::to("/admin/limits").into_response()
}

pub async fn grants(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view roles and grants") {
        return resp;
    }
    let grants = state.data.all_grants().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/admin/grants", nonce, None);
    AdminGrantsTemplate { chrome, grants }.into_response()
}
