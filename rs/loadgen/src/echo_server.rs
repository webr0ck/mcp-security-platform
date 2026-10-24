use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tracing::info;

use crate::args::EchoServerArgs;

/// Trivial standalone server implementing just enough of the /mcp JSON-RPC
/// contract (initialize / tools/list / tools/call over three synthetic tool
/// names) to validate the load-harness measurement pipeline end to end
/// before mcphubd itself is buildable. Not a stand-in for real enforcement
/// -- it exists solely so `loadgen run` can be proven correct against a
/// known-latency target.
pub async fn run(args: EchoServerArgs) -> anyhow::Result<()> {
    let addr: SocketAddr = ([127, 0, 0, 1], args.port).into();
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, latency_us = args.latency_us, "echo server listening");
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let latency_us = args.latency_us;
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, latency_us));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(error = %e, "connection closed");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    latency_us: u64,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let method = parsed.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = parsed.get("id").cloned().unwrap_or(Value::Null);

    let resp = match method {
        "initialize" => json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18"}}),
        "tools/list" => json!({"jsonrpc":"2.0","id":id,"result":{"tools":[
            {"name":"loadgen-allowed-tool"},
            {"name":"loadgen-cred-tool"},
        ]}}),
        "tools/call" => {
            let name = parsed
                .pointer("/params/name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if latency_us > 0 {
                tokio::time::sleep(Duration::from_micros(latency_us)).await;
            }
            match name {
                "loadgen-denied-tool" => json!({
                    "jsonrpc":"2.0","id":id,
                    "error":{"code":-32001,"message":"policy denied","data":{"deny_reason":"PolicyDenied"}}
                }),
                "loadgen-cred-tool" => {
                    // simulate the extra token-exchange hop credential
                    // injection costs.
                    tokio::time::sleep(Duration::from_micros(latency_us)).await;
                    json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"ok"}]}})
                }
                _ => json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"ok"}]}}),
            }
        }
        _ => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}}),
    };
    Ok(Response::new(Full::new(Bytes::from(
        serde_json::to_vec(&resp).unwrap(),
    ))))
}
