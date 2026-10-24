//! Test-only support: a minimal one-shot HTTP/1.1 mock server so
//! `discovery.rs` and `jwks.rs` can be tested against real HTTP round-trips
//! (host pinning, redirect rejection, issuer mismatch, TTL headers) without
//! a mocking dependency. Each spawned server accepts exactly
//! `responses.len()` connections, replying to connection *i* with
//! `responses[i]` verbatim (a complete raw HTTP/1.1 response, status line
//! through body) and then closing the connection. Good enough for the
//! single-GET request/response patterns every function under test makes;
//! not a general-purpose HTTP server.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub fn json_response(status: u16, body: &str) -> String {
    json_response_with_headers(status, &[], body)
}

pub fn json_response_with_headers(status: u16, extra_headers: &[(&str, &str)], body: &str) -> String {
    let status_line = match status {
        200 => "200 OK",
        302 => "302 Found",
        404 => "404 Not Found",
        _ => "500 Internal Server Error",
    };
    let mut headers = format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in extra_headers {
        headers.push_str(&format!("{k}: {v}\r\n"));
    }
    headers.push_str("\r\n");
    headers.push_str(body);
    headers
}

/// A chunked-transfer response with NO `Content-Length` header at all —
/// this is what a streaming/lying upstream looks like: a client can only
/// discover the true body size by reading the stream, never by trusting a
/// header up front.
pub fn chunked_response(status: u16, body: &str) -> String {
    let status_line = match status {
        200 => "200 OK",
        _ => "500 Internal Server Error",
    };
    let mut out =
        format!("HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n");
    out.push_str(&format!("{:x}\r\n", body.len()));
    out.push_str(body);
    out.push_str("\r\n0\r\n\r\n");
    out
}

pub fn redirect_response(location: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

/// Spawn a server on `127.0.0.1:0` that serves `responses` in order, one per
/// accepted connection, then shuts down. Returns the `http://127.0.0.1:PORT`
/// base URL.
pub async fn spawn(responses: Vec<String>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
    let addr = listener.local_addr().expect("local_addr");
    tokio::spawn(async move {
        for resp in responses {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 8192];
                // Best-effort drain of the request; we don't route on path,
                // callers encode a fixed response sequence per test.
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), sock.read(&mut buf)).await;
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        }
    });
    format!("http://{addr}")
}
