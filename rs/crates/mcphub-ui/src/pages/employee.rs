use axum::extract::{Extension, Form, State};
use axum::response::{IntoResponse, Redirect, Response};
use mcphub_types::{Role, ServerId};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::{require_role, verify_csrf, CurrentUser};
use crate::chrome;
use crate::csp::CspNonce;
use crate::state::AppState;
use crate::templates::{EmployeeCatalogTemplate, EmployeeGrantsTemplate};

const ROLE: &[Role] = &[Role::Employee];

pub async fn catalog(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view the tool catalog") {
        return resp;
    }
    let tools = state.data.catalog_for(&user.identity.sub).await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/catalog", nonce, None);
    EmployeeCatalogTemplate { chrome, tools }.into_response()
}

pub async fn my_grants(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view your access") {
        return resp;
    }
    let grants = state.data.grants_for(&user.identity.sub).await;
    let requests = state.data.access_requests_for(&user.identity.sub).await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/me/grants", nonce, None);
    EmployeeGrantsTemplate { chrome, grants, requests }.into_response()
}

#[derive(Deserialize)]
pub struct RequestAccessForm {
    pub csrf_token: String,
    pub server_id: Uuid,
    pub tool_name: String,
}

pub async fn request_access(State(state): State<AppState>, user: CurrentUser, Form(form): Form<RequestAccessForm>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "request tool access") {
        return resp;
    }
    if let Err(resp) = verify_csrf(&state, &user, &form.csrf_token) {
        return resp;
    }
    state
        .data
        .create_access_request(&user.identity.sub, ServerId(form.server_id), &form.tool_name, "Requested from catalog")
        .await;
    Redirect::to("/me/grants").into_response()
}
