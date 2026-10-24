//! MCP JSON-RPC 2.0 framing. Kept separate from the axum handler
//! (`routers::mcp`) so the envelope parsing/serialization is unit-testable
//! without spinning up an HTTP server.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Standard JSON-RPC error codes we actually emit.
pub const PARSE_ERROR: i64 = -32700;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
/// Not a standard JSON-RPC code; reserved in the -32000..-32099 "server
/// error" band for gateway denials, so a client can distinguish "your
/// request was malformed" from "the gateway refused this call".
pub const DENIED: i64 = -32001;

impl JsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }

    pub fn err(id: Value, code: i64, message: impl Into<String>) -> Self {
        Self { jsonrpc: "2.0", id, result: None, error: Some(JsonRpcError { code, message: message.into() }) }
    }

    /// Denials never carry more detail than the `DenyReason`'s stable public
    /// code — no internal error text, no stack trace, no dependency name
    /// beyond what `DenyReason` itself already deems safe to disclose.
    pub fn denied(id: Value, reason: mcphub_types::DenyReason) -> Self {
        Self::err(id, DENIED, reason.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::DenyReason;

    #[test]
    fn parses_minimal_tools_call_request() {
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#;
        let req: JsonRpcRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.params["name"], "echo");
    }

    #[test]
    fn denied_response_carries_only_the_stable_code() {
        let resp = JsonRpcResponse::denied(Value::from(1), DenyReason::Quarantined);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["error"]["message"], "quarantined");
        assert_eq!(json["error"]["code"], DENIED);
    }
}
