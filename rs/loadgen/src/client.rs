use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use std::time::Instant;

use crate::metrics::{Lane, Outcome, Sample};
use hyper::StatusCode;
use crate::tokens::MintedToken;

pub type HttpClient = LegacyClient<HttpConnector, Full<Bytes>>;

pub fn build_client(pool_connections: usize) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_reuse_address(true);
    LegacyClient::builder(TokioExecutor::new())
        .pool_max_idle_per_host(pool_connections)
        .build(connector)
}

/// Which tool an agent asks for -- the echo server (and, per the same
/// contract, mcphubd) dispatches on the name to synthesize the three lanes
/// this harness measures: policy-allowed, policy-denied, and
/// credential-injection-required.
pub fn tool_for_lane(lane: Lane) -> &'static str {
    match lane {
        Lane::Allow => "loadgen-allowed-tool",
        Lane::Deny => "loadgen-denied-tool",
        Lane::CredentialInjection => "loadgen-cred-tool",
    }
}

fn jsonrpc(method: &str, params: Value, id: u64) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

/// initialize -> tools/list warmup for one agent. Not timed into the
/// steady-state histograms; failures here are logged and the agent proceeds
/// anyway (mirrors a real client that doesn't die on a slow first RTT).
pub async fn warmup_agent(client: &HttpClient, base_url: &str, token: &MintedToken) {
    let _ = send(
        client,
        base_url,
        token,
        jsonrpc("initialize", json!({"protocolVersion": "2025-06-18"}), 0),
    )
    .await;
    let _ = send(client, base_url, token, jsonrpc("tools/list", json!({}), 1)).await;
}

/// Fires exactly one tools/call for `lane` at the caller-supplied scheduled
/// time (open-loop: this function is invoked by the rate scheduler at the
/// tick deadline regardless of how busy the pool is; latency is measured
/// from that deadline, capturing any queueing delay).
pub async fn call_tool(
    client: &HttpClient,
    base_url: &str,
    token: &MintedToken,
    lane: Lane,
    scheduled_at: Instant,
    req_id: u64,
) -> Sample {
    let tool = tool_for_lane(lane);
    let body = jsonrpc(
        "tools/call",
        json!({"name": tool, "arguments": {}}),
        req_id,
    );
    let result = send(client, base_url, token, body).await;
    let latency_ns = scheduled_at.elapsed().as_nanos() as u64;
    let outcome = match result {
        Ok(SendOutcome::Json(value)) => classify(&value),
        // D6: an HTTP-status failure (401/403/429/5xx, no JSON-RPC body) is
        // NOT a policy denial -- it happened before `invoke` ever ran. It
        // used to be synthesized into a fake `{"error": ...}` body and fed
        // through `classify`, which landed it in the SAME deny-lane
        // histogram as a genuine sub-millisecond policy denial. A gateway
        // rejecting 100% of traffic with 401s then reported p50~=0.1ms and
        // PASS on the deny lane, having measured nothing about the actual
        // system under test.
        Ok(SendOutcome::HttpStatus(code)) => Outcome::HttpError(code),
        Err(e) => Outcome::TransportError(e),
    };
    Sample {
        lane,
        latency_ns,
        outcome,
    }
}

fn classify(value: &Value) -> Outcome {
    if let Some(err) = value.get("error") {
        let reason = err
            .get("data")
            .and_then(|d| d.get("deny_reason"))
            .and_then(|v| v.as_str())
            .or_else(|| err.get("message").and_then(|v| v.as_str()))
            .unwrap_or("unknown")
            .to_string();
        Outcome::Denied(reason)
    } else if value.get("result").is_some() {
        Outcome::Success
    } else {
        Outcome::Denied("malformed_response".to_string())
    }
}

enum SendOutcome {
    Json(Value),
    /// Non-2xx with no JSON-RPC body -- an edge/transport-layer rejection
    /// (gateway auth/rate-limit/WAF), not a policy decision. See D6.
    HttpStatus(u16),
}

async fn send(
    client: &HttpClient,
    base_url: &str,
    token: &MintedToken,
    body: Value,
) -> Result<SendOutcome, String> {
    let uri: hyper::Uri = format!("{base_url}/mcp").parse().map_err(|e| format!("{e}"))?;
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    if !token.access_token.is_empty() {
        builder = builder.header("authorization", format!("Bearer {}", token.access_token));
    }
    let req = builder
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&body).map_err(|e| e.to_string())?,
        )))
        .map_err(|e| e.to_string())?;
    let resp = client.request(req).await.map_err(|e| e.to_string())?;
    let status = resp.status();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    if status != StatusCode::OK {
        // Any non-200 (including other 2xx we don't expect from this API)
        // is reported as a distinct HttpError outcome, never folded into a
        // fabricated JSON-RPC deny body (D6).
        return Ok(SendOutcome::HttpStatus(status.as_u16()));
    }
    serde_json::from_slice(&body_bytes)
        .map(SendOutcome::Json)
        .map_err(|e| format!("invalid json: {e}"))
}
