//! The gate traits. Components 2 (identity), 3 (policy/creds) and 4 (store)
//! plug real implementations in at `mcphubd` wiring time; this crate only
//! depends on the trait objects, never on their concrete implementations, so
//! `mcphub-gateway` compiles and its tests run with zero knowledge of
//! Postgres, Redis, OPA, or an OIDC provider.
//!
//! Every trait method returns `Result<_, GateError>`. `invocation::invoke`
//! maps every `Err` to `Decision::Deny` — see
//! `invocation::tests::gate_error_never_becomes_allow` for the test that
//! pins this.
//!
//! Each trait ships a `DenyAll` implementation below so the crate compiles
//! and is testable standalone, and so `mcphubd` fails closed by default if a
//! real implementation is not wired for some reason.

use async_trait::async_trait;
use mcphub_types::{Decision, GateError, Identity, ServerId, ToolRef};
use std::collections::HashMap;

/// Raw material presented by the caller before identity is resolved: an
/// `Authorization` header value, mTLS peer info, etc. Kept intentionally
/// thin and crate-local (not in `mcphub-types`) since its shape is a gateway
/// wiring detail, not a shared vocabulary concept.
#[derive(Debug, Clone, Default)]
pub struct RawCredential {
    pub bearer_token: Option<String>,
    pub mtls_spiffe_id: Option<String>,
    pub api_key: Option<String>,
}

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, raw: &RawCredential) -> Result<Identity, GateError>;
}

/// Metadata about a tool/server needed by the ingress, SSRF, RBAC, and
/// quarantine checks that run ahead of entitlement. These checks are pure,
/// local logic in `invocation.rs` given this struct — they do not need
/// their own I/O traits, only the data.
#[derive(Debug, Clone)]
pub struct ToolMeta {
    pub server: ServerId,
    pub server_enabled: bool,
    pub quarantined: bool,
    pub required_role: Option<mcphub_types::Role>,
    /// Trust tier feeding the taint floor gate (0 = untrusted .. higher = more trusted).
    pub trust_tier: u8,
    /// Upstream backend host, re-validated at invoke time by the SSRF guard
    /// (registration-time checks alone are insufficient — see `ssrf.rs`).
    pub upstream_host: String,
    /// Registered CIDR this server is allowed to resolve into, if scoped.
    /// `None` means "public upstream, no private-range exemption".
    pub allowed_cidr: Option<String>,
    /// Resolved tool row id, for the audit ledger's `tool_id` FK (D8) — the
    /// existing `ToolRef.tool` is a caller-supplied name, not the stable
    /// surrogate key. `None` only when the concrete `EntitlementStore`
    /// genuinely has no such id to give (e.g. a synthetic/platform-meta tool).
    pub tool_id: Option<uuid::Uuid>,
}

#[async_trait]
pub trait EntitlementStore: Send + Sync {
    /// Metadata backing ingress/SSRF/RBAC/quarantine checks.
    async fn tool_meta(&self, tool: &ToolRef) -> Result<ToolMeta, GateError>;

    /// The exact set of tools visible to this identity's `tools/list`. Both
    /// the `tools/list` handler and `invoke`'s entitlement gate call this
    /// same method — that is what makes discovery==invoke structural rather
    /// than a convention two call sites could drift apart on.
    async fn list_visible(&self, identity: &Identity) -> Result<Vec<ToolRef>, GateError>;
}

#[async_trait]
pub trait RateLimiter: Send + Sync {
    /// `Ok(())` = under the limit. `Err` (including a dependency outage) is
    /// mapped to `Decision::Deny` by the caller — a rate limiter that cannot
    /// be consulted fails closed, it does not fail open.
    async fn check(&self, identity: &Identity, tool: &ToolRef) -> Result<(), GateError>;
}

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn evaluate(
        &self,
        identity: &Identity,
        tool: &ToolRef,
        input: &serde_json::Value,
    ) -> Result<Decision, GateError>;
}

#[async_trait]
pub trait CredentialBroker: Send + Sync {
    /// Returns headers to inject on dispatch to the backend. Actual secret
    /// material must be wrapped in `mcphub_types::Secret` upstream of this
    /// boundary (in `mcphub-creds`); by the time headers reach here they are
    /// plain strings meant to be sent over the wire, not logged.
    async fn inject(&self, identity: &Identity, tool: &ToolRef) -> Result<HashMap<String, String>, GateError>;
}

/// One audit record. Deliberately does not implement `Serialize` with a
/// blanket derive that could accidentally include request `params` — the
/// concrete `AuditSink` impl in `mcphub-store` owns redaction of anything
/// derived from request content.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub request_id: mcphub_types::RequestId,
    pub identity_sub: Option<String>,
    /// D8: which configured IDP asserted this identity. Without this, "which
    /// of our IDPs minted this token" is unanswerable from the ledger.
    pub identity_issuer: Option<String>,
    /// D8: roles held AT DECISION TIME — not re-derivable later if the
    /// principal's grants change afterward.
    pub identity_roles: Vec<String>,
    pub tool: Option<ToolRef>,
    /// D8: the resolved tool row id (see `ToolMeta::tool_id`), so
    /// `idx_audit_events_tool_ts ON (tool_id, event_ts DESC)` is not
    /// indexing a permanently-NULL column.
    pub tool_id: Option<uuid::Uuid>,
    pub outcome: AuditOutcome,
    /// D8: request-to-decision latency.
    pub latency_ms: Option<u32>,
    /// D8: the caller's network address. MUST be sourced from the TCP
    /// connection (or a proxy layer the operator explicitly trusts) —
    /// NEVER from a client-supplied header. This travels into an
    /// append-only, HMAC-covered ledger; an attacker-forgeable value here
    /// would let an attacker frame another IP for their own activity.
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    Allow,
    Deny(mcphub_types::DenyReason),
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Must durably queue the record before returning `Ok`. Invariant 4:
    /// audit is synchronous and precedes the response — a failure here is
    /// itself mapped to `Decision::Deny` by `invoke`, never silently
    /// swallowed.
    async fn emit(&self, record: AuditRecord) -> Result<(), GateError>;

    /// Best-effort health signal for `/healthz/ready` — default `true` so
    /// existing/test implementations don't need to override it. The real
    /// `mcphubd` wiring (`wiring::audit::AuditSinkAdapter`) delegates this
    /// to the concrete sink's own health (e.g. `mcphub_store::
    /// PgRedisAuditSink::is_writer_alive`), which is the "surface the
    /// writer-supervisor signal" half of that fix.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// Dispatches an already-authorized call to the backend MCP server. Not
/// named in ARCHITECTURE.md's six named traits, but something has to own
/// this seam and no other component claims it — see the report note in the
/// handoff. Kept minimal and mockable; the real HTTP client lives in
/// `mcphubd` wiring (reqwest is a workspace dependency but not pulled into
/// this crate, keeping `mcphub-gateway` free to unit-test dispatch with a
/// fake).
#[async_trait]
pub trait BackendDispatcher: Send + Sync {
    /// `request_id` is threaded through so the concrete dispatcher can
    /// reuse it as the outbound MCP `tools/call` JSON-RPC `id` — see
    /// ARCHITECTURE.md's "Backend dispatch contract" section — letting a
    /// backend's own logs correlate with our audit record for the same
    /// call. `headers` already carries the gateway-set identity headers by
    /// the time this is called (`invocation::invoke` sets them, stripping
    /// any pre-existing entry first); this trait does not construct them.
    async fn dispatch(
        &self,
        tool: &ToolRef,
        request_id: mcphub_types::RequestId,
        headers: &HashMap<String, String>,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, GateError>;
}

// ---------------------------------------------------------------------
// DenyAll: the fail-closed default for every trait above. Used so this
// crate compiles and is testable standalone, and as the safety-net wiring
// in `mcphubd` if a real implementation is somehow not provided.
// ---------------------------------------------------------------------

/// Fails closed on every gate. Constructing a gateway with only `DenyAll`
/// implementations denies every request — that is the point.
pub struct DenyAll;

#[async_trait]
impl Authenticator for DenyAll {
    async fn authenticate(&self, _raw: &RawCredential) -> Result<Identity, GateError> {
        Err(GateError::DependencyUnavailable("authenticator"))
    }
}

#[async_trait]
impl EntitlementStore for DenyAll {
    async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
        Err(GateError::DependencyUnavailable("entitlement_store"))
    }

    async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
        Err(GateError::DependencyUnavailable("entitlement_store"))
    }
}

#[async_trait]
impl RateLimiter for DenyAll {
    async fn check(&self, _identity: &Identity, _tool: &ToolRef) -> Result<(), GateError> {
        Err(GateError::DependencyUnavailable("rate_limiter"))
    }
}

#[async_trait]
impl PolicyEngine for DenyAll {
    async fn evaluate(
        &self,
        _identity: &Identity,
        _tool: &ToolRef,
        _input: &serde_json::Value,
    ) -> Result<Decision, GateError> {
        Err(GateError::DependencyUnavailable("policy_engine"))
    }
}

#[async_trait]
impl CredentialBroker for DenyAll {
    async fn inject(&self, _identity: &Identity, _tool: &ToolRef) -> Result<HashMap<String, String>, GateError> {
        Err(GateError::DependencyUnavailable("credential_broker"))
    }
}

#[async_trait]
impl AuditSink for DenyAll {
    async fn emit(&self, _record: AuditRecord) -> Result<(), GateError> {
        Err(GateError::DependencyUnavailable("audit_sink"))
    }
}

#[async_trait]
impl BackendDispatcher for DenyAll {
    async fn dispatch(
        &self,
        _tool: &ToolRef,
        _request_id: mcphub_types::RequestId,
        _headers: &HashMap<String, String>,
        _body: &serde_json::Value,
    ) -> Result<serde_json::Value, GateError> {
        Err(GateError::DependencyUnavailable("backend_dispatcher"))
    }
}
