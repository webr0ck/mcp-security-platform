//! `BackendDispatcher` — the real HTTP client that talks to a backend MCP
//! server once a call has cleared every gate. Not one of the six named
//! traits, but `mcphub-gateway::traits` claims the seam and nothing else
//! owns it (see that module's doc comment) — this is the "real HTTP client
//! lives in mcphubd wiring" it points at.
//!
//! TODO: confirm the exact backend wire contract with the architect —
//! nothing in ARCHITECTURE.md pins what a dispatched call looks like on
//! the wire. This POSTs the tool's `params`/`arguments` JSON body straight
//! to the server's registered `upstream_url`, expecting a JSON response
//! back, which is the smallest thing that lets the e2e test (and this
//! adapter) agree on a contract; the real backend protocol (native MCP
//! JSON-RPC framing to the backend vs. a bespoke REST shape) is an open
//! question for the architect, not decided here.

use async_trait::async_trait;
use mcphub_gateway::traits::BackendDispatcher;
use mcphub_types::{GateError, ToolRef};
use sqlx::PgPool;
use std::collections::HashMap;
use std::time::Duration;

pub struct HttpBackendDispatcher {
    client: reqwest::Client,
    pool: PgPool,
}

impl HttpBackendDispatcher {
    pub fn new(pool: PgPool) -> Result<Self, mcphub_types::StartupError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(3))
            // No redirect-following at all: the simplest way to guarantee a
            // dispatch never silently lands on a host the SSRF guard never
            // saw (a 3xx to an attacker-controlled host would otherwise
            // bypass `ssrf::validate`, which only inspects the registered
            // upstream host, not wherever a redirect chain ends up).
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| mcphub_types::StartupError::Config(format!("failed to build HTTP dispatcher client: {e}")))?;
        Ok(Self { client, pool })
    }
}

#[async_trait]
impl BackendDispatcher for HttpBackendDispatcher {
    async fn dispatch(
        &self,
        tool: &ToolRef,
        request_id: mcphub_types::RequestId,
        headers: &HashMap<String, String>,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, GateError> {
        let server = mcphub_store::repo::servers::get_active_server(&self.pool, tool.server.0)
            .await?
            .ok_or(GateError::EntitlementMissing)?;

        // Backends speak MCP. Send a real `tools/call` JSON-RPC request, not a
        // bare arguments object: every backend in this platform is a FastMCP
        // app (the SDK scaffolder generates them), and a bare arguments blob is
        // a protocol none of them implement.
        //
        // This is also what makes multi-tool backends work at all. `tool.tool`
        // is carried in `params.name` — where the MCP spec says it lives — so a
        // server with N tools registered under one `server_id` (the
        // self-service server has 7) can route. It deliberately is NOT a
        // side-channel header: a header naming the method alongside an
        // MCP-shaped body would be two sources of truth for one fact, free to
        // disagree.
        //
        // `request_id` doubles as the JSON-RPC id so a backend's own logs
        // correlate with our audit record for the same call.
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id.to_string(),
            "method": "tools/call",
            "params": { "name": tool.tool, "arguments": body },
        });

        let mut req = self.client.post(&server.upstream_url).json(&envelope);
        for (k, v) in headers {
            req = req.header(k, v);
        }

        let resp = req
            .send()
            .await
            .map_err(|_| GateError::DependencyUnavailable("backend"))?;

        if !resp.status().is_success() {
            return Err(GateError::DependencyUnavailable("backend"));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|_| GateError::DependencyUnavailable("backend"))
    }
}
