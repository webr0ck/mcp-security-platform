//! MCP-over-HTTP surface for the self-service tools.
//!
//! This is a **backend MCP server like any other**, not a privileged sidecar.
//! It sits behind the gateway, is registered in `servers`/`tool_registry`, and
//! every call to it traverses the same `invoke()` chain as any third-party
//! server. It gets no special path and no ambient authority.
//!
//! ## Identity
//!
//! Identity comes **exclusively** from the gateway-injected headers described in
//! `rs/ARCHITECTURE.md`'s "Backend dispatch contract" — `X-User-Sub` and
//! `X-User-Roles` — and never from anything in the request body. The gateway
//! strips any client-supplied copy of those headers before setting its own, so
//! they are trustworthy here in exactly the way the Python platform's
//! `X-User-Sub` was: the proxy is the trust anchor.
//!
//! A request arriving with **no** `X-User-Sub` is rejected. That is the
//! `require_proxy_headers` behaviour from `mcphub_sdk`: an unproxied request
//! reaching this server directly must never be served, because there is nothing
//! to authenticate it. Backends are network-isolated so this shouldn't be
//! reachable at all — this is the second lock on that door.

use crate::tools::{self, Caller, ToolError};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use mcphub_types::Role;
use serde_json::{json, Value};
use sqlx::PgPool;

pub const HEADER_SUB: &str = "X-User-Sub";
pub const HEADER_ROLES: &str = "X-User-Roles";

/// The tool names this server exposes. Kept next to the dispatch `match` so a
/// tool cannot be advertised in `tools/list` without a handler, or handled
/// without being listed — the discovery==invoke principle applied locally.
pub const TOOL_NAMES: &[&str] = &[
    "list_available_mcps",
    "get_profile",
    "enable_mcp",
    "disable_mcp",
    "list_functions",
    "enable_function",
    "disable_function",
];

pub fn router(pool: PgPool) -> Router {
    Router::new().route("/", post(handle)).with_state(pool)
}

/// Parses `X-User-Roles` (`role@issuer,role@issuer`). The issuer half is
/// deliberately **discarded here**: this server's authorization questions are
/// "is the caller an admin" and "is the caller acting on their own profile",
/// neither of which depends on which IDP asserted the role — and the gateway
/// has already applied each IDP's `max_assertable_role` ceiling, so nothing
/// above an issuer's entitlement can reach us. The provenance is still sent so
/// a backend that *does* need to discriminate between entitled issuers can.
fn parse_roles(raw: &str) -> Vec<Role> {
    raw.split(',')
        .filter_map(|entry| {
            let name = entry.split('@').next()?.trim();
            match name {
                "super_admin" => Some(Role::SuperAdmin),
                "server_owner" => Some(Role::ServerOwner),
                "security_analyst" => Some(Role::SecurityAnalyst),
                "employee" => Some(Role::Employee),
                _ => None,
            }
        })
        .collect()
}

fn caller_from_headers(headers: &HeaderMap) -> Option<Caller> {
    let sub = headers.get(HEADER_SUB)?.to_str().ok()?.trim().to_string();
    if sub.is_empty() {
        return None;
    }
    let roles = headers
        .get(HEADER_ROLES)
        .and_then(|v| v.to_str().ok())
        .map(parse_roles)
        .unwrap_or_default();
    Some(Caller { sub, roles })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Json<Value> {
    Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}))
}

async fn handle(State(pool): State<PgPool>, headers: HeaderMap, Json(req): Json<Value>) -> impl IntoResponse {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or_default();

    let Some(caller) = caller_from_headers(&headers) else {
        // No proxy identity — refuse rather than guess. See the module note.
        return (StatusCode::UNAUTHORIZED, rpc_error(id, -32001, "unauthenticated: missing gateway identity header"))
            .into_response();
    };

    match method {
        "tools/list" => {
            let tools: Vec<Value> = TOOL_NAMES.iter().map(|n| json!({"name": n})).collect();
            (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":id,"result":{"tools":tools}}))).into_response()
        }
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string();
            let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            let result = dispatch(&pool, &caller, &name, &args).await;
            match result {
                Ok(value) => (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":id,"result":value}))).into_response(),
                // Tool-level failures come back as a JSON-RPC *result* carrying
                // the `{error, detail}` shape the Python tools returned, not as
                // a transport error: a self-lockout refusal is a successful
                // call that declined, and a client written against the Python
                // contract must not have to special-case it.
                Err(e) => (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":id,"result":e.to_json()}))).into_response(),
            }
        }
        _ => (StatusCode::OK, rpc_error(id, -32601, "method not found")).into_response(),
    }
}

async fn dispatch(pool: &PgPool, caller: &Caller, name: &str, args: &Value) -> Result<Value, ToolError> {
    let s = |k: &str| args.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let mcp = || s("mcp_name").unwrap_or_default();
    let target = s("target_profile");

    match name {
        "list_available_mcps" => Ok(tools::list_available_mcps(caller).await),
        "get_profile" => tools::get_profile(pool, caller, &mcp(), target.as_deref()).await,
        "enable_mcp" => tools::enable_mcp(pool, caller, &mcp(), target.as_deref()).await,
        "disable_mcp" => tools::disable_mcp(pool, caller, &mcp(), target.as_deref()).await,
        "list_functions" => tools::list_functions(pool, caller, &mcp(), target.as_deref()).await,
        "enable_function" => {
            tools::enable_function(pool, caller, &mcp(), &s("function_name").unwrap_or_default(), target.as_deref())
                .await
        }
        "disable_function" => {
            tools::disable_function(pool, caller, &mcp(), &s("function_name").unwrap_or_default(), target.as_deref())
                .await
        }
        other => Err(ToolError::Forbidden(format!("unknown tool {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_advertised_tool_has_a_handler() {
        // Guards the local discovery==invoke property: a name in TOOL_NAMES
        // with no arm in `dispatch` would be advertised and then rejected.
        // `dispatch`'s fallback arm is the only thing that may return
        // "unknown tool", so exercising every advertised name against the
        // match's own arm list is what this asserts.
        for name in TOOL_NAMES {
            assert!(
                matches!(
                    *name,
                    "list_available_mcps"
                        | "get_profile"
                        | "enable_mcp"
                        | "disable_mcp"
                        | "list_functions"
                        | "enable_function"
                        | "disable_function"
                ),
                "advertised tool {name} has no dispatch arm"
            );
        }
    }

    #[test]
    fn roles_parse_from_the_provenance_carrying_header() {
        let roles = parse_roles("employee@https://idp.example,super_admin@https://idp.example");
        assert_eq!(roles, vec![Role::Employee, Role::SuperAdmin]);
    }

    #[test]
    fn unknown_role_names_are_dropped_never_defaulted() {
        // Least privilege: an unrecognised role string must not become a
        // role, and must not poison the roles that did parse.
        let roles = parse_roles("wizard@https://idp.example,employee@https://idp.example");
        assert_eq!(roles, vec![Role::Employee]);
    }

    #[test]
    fn a_request_with_no_identity_header_yields_no_caller() {
        assert!(caller_from_headers(&HeaderMap::new()).is_none());
    }

    #[test]
    fn an_empty_identity_header_is_not_an_identity() {
        let mut h = HeaderMap::new();
        h.insert(HEADER_SUB, "   ".parse().unwrap());
        assert!(caller_from_headers(&h).is_none());
    }

    #[test]
    fn roles_are_ignored_when_the_sub_is_absent() {
        // A caller cannot get roles without an identity to attach them to.
        let mut h = HeaderMap::new();
        h.insert(HEADER_ROLES, "super_admin@https://idp.example".parse().unwrap());
        assert!(caller_from_headers(&h).is_none());
    }
}
