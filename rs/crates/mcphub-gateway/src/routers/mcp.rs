//! `POST /mcp` — the MCP JSON-RPC path (`initialize`, `tools/list`,
//! `tools/call`). `tools/call` funnels into `invocation::invoke` exactly
//! like the REST router — see `invocation::resolve_tool_by_name` for how a
//! bare tool name is resolved to a `ToolRef` without reintroducing the
//! historical `invoke_tool`-indirection quarantine bypass (no separate
//! by-name lookup exists here; resolution only ever goes through
//! `EntitlementStore::list_visible`, the same call `tools/list` uses).

use crate::invocation::{invoke, list_visible_audited, resolve_tool_by_name, InvokeRequest};
use crate::mcp_protocol::{JsonRpcRequest, JsonRpcResponse, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::routers::{raw_credential_from_headers, validate_tool_name};
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json};
use mcphub_types::RequestId;
use serde_json::{json, Value};
use std::net::SocketAddr;
use uuid::Uuid;

pub async fn handle(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let id = req.id.clone().unwrap_or(Value::Null);
    let raw = raw_credential_from_headers(&headers);
    let source_ip = connect_info.map(|ConnectInfo(addr)| addr.ip().to_string());

    let resp = match req.method.as_str() {
        "initialize" => handle_initialize(id),
        "tools/list" => handle_tools_list(&state, &raw, id, source_ip.as_deref()).await,
        "tools/call" => handle_tools_call(&state, &raw, id, req.params, source_ip).await,
        _ => JsonRpcResponse::err(id, METHOD_NOT_FOUND, format!("unknown method: {}", req.method)),
    };

    Json(resp)
}

fn handle_initialize(id: Value) -> JsonRpcResponse {
    JsonRpcResponse::ok(
        id,
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": { "name": "mcphub-gateway", "version": env!("CARGO_PKG_VERSION") },
            "capabilities": { "tools": {} },
        }),
    )
}

async fn handle_tools_list(state: &AppState, raw: &crate::traits::RawCredential, id: Value, source_ip: Option<&str>) -> JsonRpcResponse {
    let request_id = RequestId::new(Uuid::new_v4());
    match list_visible_audited(&state.gates, raw, request_id, source_ip).await {
        Ok(visible) => {
            let tools: Vec<Value> = visible
                .into_iter()
                .map(|t| json!({ "name": t.tool, "server_id": t.server.to_string() }))
                .collect();
            JsonRpcResponse::ok(id, json!({ "tools": tools }))
        }
        Err(reason) => JsonRpcResponse::denied(id, reason),
    }
}

async fn handle_tools_call(
    state: &AppState,
    raw: &crate::traits::RawCredential,
    id: Value,
    params: Value,
    source_ip: Option<String>,
) -> JsonRpcResponse {
    let Some(name) = params.get("name").and_then(|v| v.as_str()) else {
        return JsonRpcResponse::err(id, INVALID_PARAMS, "tools/call requires params.name");
    };
    if !validate_tool_name(name) {
        return JsonRpcResponse::err(id, INVALID_PARAMS, "invalid tool name");
    }
    let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
    let request_id = RequestId::new(Uuid::new_v4());

    // Resolution ONLY through the visible-set lookup — see module docs.
    // Audited on every deny branch internally (see `audit_deny`'s doc
    // comment on why this matters specifically for `/mcp`).
    let (_identity, tool) = match resolve_tool_by_name(&state.gates, raw, name, request_id, source_ip.as_deref()).await {
        Ok(pair) => pair,
        Err(reason) => return JsonRpcResponse::denied(id, reason),
    };

    let req = InvokeRequest { request_id, raw_credential: raw.clone(), tool, params: arguments, source_ip };

    match invoke(&state.gates, req).await {
        Ok(outcome) => JsonRpcResponse::ok(id, outcome.result),
        Err(reason) => JsonRpcResponse::denied(id, reason),
    }
}
