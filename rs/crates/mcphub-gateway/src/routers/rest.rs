//! `POST /api/v1/tools/{id}/invoke` — the REST invocation path. Funnels
//! into `invocation::invoke` exactly like `routers::mcp`; this handler owns
//! nothing but request parsing and response mapping.

use crate::invocation::{invoke, InvokeRequest};
use crate::routers::{raw_credential_from_headers, validate_tool_name};
use crate::state::AppState;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use mcphub_types::{RequestId, ServerId, ToolRef};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

/// TODO: confirm exact request body shape with architect — ARCHITECTURE.md
/// pins the route (`POST /api/v1/tools/{id}/invoke`) but not the body
/// schema. `{id}` is taken as the tool name; `server_id` scopes it to a
/// specific server's registration (a tool name is not guaranteed globally
/// unique across servers), mirroring how `ToolRef` is shaped in
/// `mcphub-types`.
#[derive(Debug, Deserialize)]
pub struct InvokeBody {
    pub server_id: Uuid,
    #[serde(default)]
    pub params: serde_json::Value,
}

pub async fn invoke_tool(
    State(state): State<AppState>,
    Path(id): Path<String>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<InvokeBody>,
) -> impl IntoResponse {
    if !validate_tool_name(&id) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid tool name" })));
    }
    let raw = raw_credential_from_headers(&headers);
    let tool = ToolRef { server: ServerId(body.server_id), tool: id };
    let req = InvokeRequest {
        request_id: RequestId::new(Uuid::new_v4()),
        raw_credential: raw,
        tool,
        params: body.params,
        source_ip: connect_info.map(|ConnectInfo(addr)| addr.ip().to_string()),
    };

    match invoke(&state.gates, req).await {
        Ok(outcome) => (StatusCode::OK, Json(json!({ "request_id": outcome.request_id.to_string(), "result": outcome.result }))),
        Err(reason) => {
            let status = deny_status(&reason);
            (status, Json(json!({ "error": reason.code() })))
        }
    }
}

fn deny_status(reason: &mcphub_types::DenyReason) -> StatusCode {
    use mcphub_types::DenyReason::*;
    match reason {
        Unauthenticated => StatusCode::UNAUTHORIZED,
        NoGrant | Quarantined | PolicyDenied | EntitlementMissing | TaintFloor => StatusCode::FORBIDDEN,
        RateLimited => StatusCode::TOO_MANY_REQUESTS,
        DependencyUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::DenyReason;

    /// Exhaustive match compiles only if every `DenyReason` variant maps to
    /// a status — guards against a `_ => 500` catch-all creeping in.
    #[test]
    fn every_deny_reason_maps_to_a_status() {
        let reasons = [
            DenyReason::Unauthenticated,
            DenyReason::NoGrant,
            DenyReason::Quarantined,
            DenyReason::PolicyDenied,
            DenyReason::EntitlementMissing,
            DenyReason::RateLimited,
            DenyReason::TaintFloor,
            DenyReason::DependencyUnavailable("redis"),
        ];
        for r in reasons {
            let status = deny_status(&r);
            assert!(status.is_client_error() || status.is_server_error());
        }
    }
}
