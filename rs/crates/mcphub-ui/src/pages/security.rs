use axum::extract::{Extension, Form, Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use mcphub_types::{Role, ServerId};
use serde::Deserialize;

use crate::auth::{require_role, verify_csrf, CurrentUser};
use crate::chrome;
use crate::csp::CspNonce;
use crate::state::AppState;
use crate::templates::{
    NotFoundTemplate, SecurityAnomaliesTemplate, SecurityAuditDetailTemplate, SecurityAuditListTemplate,
    SecurityPolicyTemplate, SecurityQuarantineTemplate,
};

const ROLE: &[Role] = &[Role::SecurityAnalyst];

pub async fn audit_list(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view audit events") {
        return resp;
    }
    let events = state.data.recent_audit_events(200).await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/security/audit", nonce, None);
    SecurityAuditListTemplate { chrome, events }.into_response()
}

pub async fn audit_detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Extension(nonce): Extension<CspNonce>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view audit event detail") {
        return resp;
    }
    let Some(event) = state.data.audit_event(id).await else {
        return (axum::http::StatusCode::NOT_FOUND, NotFoundTemplate).into_response();
    };
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/security/audit", nonce, None);
    SecurityAuditDetailTemplate { chrome, event }.into_response()
}

pub async fn policy_decisions(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view policy decisions") {
        return resp;
    }
    let denied = state.data.recent_audit_events(500).await.into_iter().filter(|e| e.decision == "deny").collect();
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/security/policy", nonce, None);
    SecurityPolicyTemplate { chrome, denied }.into_response()
}

pub async fn quarantine(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view quarantine") {
        return resp;
    }
    let entries = state.data.quarantine_entries().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/security/quarantine", nonce, None);
    SecurityQuarantineTemplate { chrome, entries }.into_response()
}

#[derive(Deserialize)]
pub struct ReleaseQuarantineForm {
    pub csrf_token: String,
    pub server_id: uuid::Uuid,
    pub tool_name: String,
}

pub async fn release_quarantine(State(state): State<AppState>, user: CurrentUser, Form(form): Form<ReleaseQuarantineForm>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "release a tool from quarantine") {
        return resp;
    }
    if let Err(resp) = verify_csrf(&state, &user, &form.csrf_token) {
        return resp;
    }
    state.data.release_quarantine(ServerId(form.server_id), &form.tool_name).await;
    Redirect::to("/security/quarantine").into_response()
}

pub async fn anomalies(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view anomalies") {
        return resp;
    }
    let anomalies = state.data.anomalies().await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/security/anomalies", nonce, None);
    SecurityAnomaliesTemplate { chrome, anomalies }.into_response()
}
