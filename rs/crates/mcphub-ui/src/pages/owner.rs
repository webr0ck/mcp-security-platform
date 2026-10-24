use axum::extract::{Extension, Path, State};
use axum::response::{IntoResponse, Response};
use mcphub_types::{Role, ServerId};

use crate::auth::{require_role, CurrentUser};
use crate::chrome;
use crate::csp::CspNonce;
use crate::state::AppState;
use crate::templates::{ForbiddenTemplate, NotFoundTemplate, OwnerServerDetailTemplate, OwnerServersTemplate};

const ROLE: &[Role] = &[Role::ServerOwner];

pub async fn servers(State(state): State<AppState>, user: CurrentUser, Extension(nonce): Extension<CspNonce>) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view server registrations") {
        return resp;
    }
    let servers = state.data.servers_for_owner(&user.identity.sub).await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/owner/servers", nonce, None);
    OwnerServersTemplate { chrome, servers }.into_response()
}

pub async fn server_detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Extension(nonce): Extension<CspNonce>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    if let Err(resp) = require_role(&user.identity, ROLE, "view server details") {
        return resp;
    }
    let server_id = ServerId(id);
    let Some(server) = state.data.server_by_id(server_id).await else {
        return (axum::http::StatusCode::NOT_FOUND, NotFoundTemplate).into_response();
    };
    // Ownership check: even though this route is role-gated, a server
    // owner must only ever see their own servers, never another owner's —
    // this is authorization, not just authentication, and must be
    // re-checked per-resource, not inferred from the route being reachable.
    if server.owner_sub != user.identity.sub {
        let body = ForbiddenTemplate { action: "view this server (you are not its owner)".to_string() };
        return (axum::http::StatusCode::FORBIDDEN, body).into_response();
    }
    let tools = state.data.tools_for_server(server_id).await;
    let chrome = chrome::build(&state, &user.identity, &user.session_id, "/owner/servers", nonce, None);
    OwnerServerDetailTemplate { chrome, server, tools }.into_response()
}
