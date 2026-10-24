//! The `UiData` trait and its view-model shapes — the read/write seam
//! between the portal (`mcphub-ui`, component 5) and persistence
//! (`mcphub-store`, component 4).
//!
//! This lives in `mcphub-types`, not in either of those crates, on
//! purpose: it is plain data plus an async trait signature, no I/O, which
//! is exactly this crate's charter. Putting it here means `mcphub-ui`
//! (presentation) and `mcphub-store` (storage) each depend only on
//! `mcphub-types` and never on each other — dependency arrows all point
//! one direction, at the shared vocabulary crate, not sideways between
//! sibling crates. `mcphub-ui` consumes `UiData`; `mcphub-store`
//! implements it (`PgUiData`); neither one names the other in its
//! `Cargo.toml`.
//!
//! (Originally drafted inside `mcphub-ui` as a TEMP placeholder pending
//! component 4 wiring a real implementation — moved down here once that
//! wiring revealed the layering inversion of `mcphub-store` depending on
//! `mcphub-ui`.)

use crate::decision::AuthMode;
use crate::decision::DenyReason;
use crate::identity::Role;
use crate::ids::ServerId;
use async_trait::async_trait;
use serde::Serialize;

#[async_trait]
pub trait UiData: Send + Sync {
    async fn servers_for_owner(&self, owner_sub: &str) -> Vec<McpServer>;
    async fn all_servers(&self) -> Vec<McpServer>;
    async fn server_by_id(&self, id: ServerId) -> Option<McpServer>;

    async fn tools_for_server(&self, id: ServerId) -> Vec<ToolEntry>;
    /// Only tools this identity may both discover and invoke — the visual
    /// side of the discovery==invoke invariant.
    async fn catalog_for(&self, sub: &str) -> Vec<ToolEntry>;

    async fn grants_for(&self, sub: &str) -> Vec<Grant>;
    async fn all_grants(&self) -> Vec<Grant>;
    async fn save_grant(&self, grant: Grant);

    async fn access_requests_for(&self, sub: &str) -> Vec<AccessRequest>;
    async fn create_access_request(&self, sub: &str, server_id: ServerId, tool_name: &str, justification: &str);

    async fn recent_audit_events(&self, limit: usize) -> Vec<AuditEvent>;
    async fn audit_event(&self, id: uuid::Uuid) -> Option<AuditEvent>;

    async fn quarantine_entries(&self) -> Vec<QuarantineEntry>;
    async fn release_quarantine(&self, server_id: ServerId, tool_name: &str) -> bool;

    async fn anomalies(&self) -> Vec<Anomaly>;

    async fn idps(&self) -> Vec<IdpConfig>;
    async fn create_idp(&self, cfg: IdpConfig);

    async fn global_limits(&self) -> GlobalLimits;
    async fn set_global_limits(&self, limits: GlobalLimits);

    /// Display-only role listing for the admin portal: EVERY role grant
    /// this `sub` holds, aggregated across every configured issuer.
    ///
    /// This is NOT the enforcement lookup. `sub` alone is not a safe
    /// identity key — two different IDPs can independently mint the same
    /// `sub` value for two different real-world identities, and this
    /// method would hand one identity's roles to the other's UI listing
    /// if it were mistaken for an authz check. The enforcement path is
    /// `mcphub-store`'s `repo::roles::resolve_roles(pool, sub, issuer)`,
    /// which is scoped to a specific issuer and is what `invoke()` must
    /// call. The name here is deliberately NOT `roles_for` so it cannot be
    /// reached for by a future caller who wants the enforcement answer.
    async fn display_roles_all_issuers(&self, sub: &str) -> Vec<Role>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ServerHealth {
    Healthy,
    Degraded,
    Unreachable,
}

impl ServerHealth {
    pub fn label(&self) -> &'static str {
        match self {
            ServerHealth::Healthy => "Healthy",
            ServerHealth::Degraded => "Degraded",
            ServerHealth::Unreachable => "Unreachable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OnboardingStatus {
    Draft,
    PendingReview,
    Approved,
    Rejected,
}

impl OnboardingStatus {
    pub fn label(&self) -> &'static str {
        match self {
            OnboardingStatus::Draft => "Draft",
            OnboardingStatus::PendingReview => "Pending review",
            OnboardingStatus::Approved => "Approved",
            OnboardingStatus::Rejected => "Rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct McpServer {
    pub id: ServerId,
    pub name: String,
    pub owner_sub: String,
    pub auth_mode: AuthModeView,
    pub health: ServerHealth,
    pub onboarding: OnboardingStatus,
    // NOTE: no `network_isolated` field here (deliberately removed, not
    // renamed). Network isolation is a platform-wide invariant
    // (ARCHITECTURE.md invariant 6: only the gateway may reach a backend),
    // not per-server state this schema tracks — there was no real signal
    // backing the field, and an unconditional "Isolated ✓" shown to the
    // security team is a false assurance, worse than showing nothing. Add
    // it back only once component 6's isolation check can feed a real
    // per-server value.
    pub enabled: bool,
}

/// A display-friendly projection of `AuthMode` (askama can't match on the
/// upstream enum's non-exhaustive-looking struct variant cleanly in all
/// template expressions, so we flatten it once here).
#[derive(Debug, Clone, Serialize)]
pub struct AuthModeView {
    pub kind: String,
    pub port: Option<u16>,
}

impl From<AuthMode> for AuthModeView {
    fn from(m: AuthMode) -> Self {
        match m {
            AuthMode::SharedPassthrough => AuthModeView { kind: "shared_passthrough".to_string(), port: None },
            AuthMode::SharedExchange => AuthModeView { kind: "shared_exchange".to_string(), port: None },
            AuthMode::DedicatedPort { port } => AuthModeView { kind: "dedicated_port".to_string(), port: Some(port) },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolEntry {
    pub server_id: ServerId,
    pub server_name: String,
    pub tool_name: String,
    pub description: String,
    /// True only when this identity's discovery would also include the
    /// tool — i.e. discovery==invoke is reflected in what employees see.
    pub invokable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Grant {
    pub principal_sub: String,
    pub server_id: ServerId,
    pub server_name: String,
    pub tool_name: Option<String>,
    pub granted_by: String,
    pub granted_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessRequest {
    pub id: uuid::Uuid,
    pub requester_sub: String,
    pub server_name: String,
    pub tool_name: String,
    pub justification: String,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub at: String,
    pub principal_sub: String,
    pub server_name: String,
    pub tool_name: String,
    pub decision: &'static str,
    pub deny_reason: Option<DenyReasonView>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DenyReasonView {
    pub code: &'static str,
    pub detail: &'static str,
}

impl From<DenyReason> for DenyReasonView {
    fn from(r: DenyReason) -> Self {
        DenyReasonView { code: r.code(), detail: deny_reason_detail(&r) }
    }
}

fn deny_reason_detail(r: &DenyReason) -> &'static str {
    match r {
        DenyReason::Unauthenticated => "No valid identity was resolved for this request.",
        DenyReason::NoGrant => "The caller has no grant for this server/tool.",
        DenyReason::Quarantined => "The tool is currently quarantined.",
        DenyReason::PolicyDenied => "An OPA policy rule denied this call.",
        DenyReason::EntitlementMissing => "The tool is not in this identity's discovery list.",
        DenyReason::RateLimited => "The caller exceeded the configured rate limit.",
        DenyReason::TaintFloor => "The response was blocked by the taint floor.",
        DenyReason::DependencyUnavailable(_) => "A required dependency was unreachable (fail-closed deny).",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineEntry {
    pub server_id: ServerId,
    pub server_name: String,
    pub tool_name: String,
    pub reason: String,
    pub quarantined_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    pub id: uuid::Uuid,
    pub at: String,
    pub principal_sub: String,
    pub kind: String,
    pub severity: &'static str,
    pub summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum IdpAuthModeDefault {
    SharedPassthrough,
    SharedExchange,
    DedicatedPort,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdpConfig {
    pub id: String,
    pub kind: &'static str, // "entra" | "keycloak" | "zitadel" | "generic_oidc"
    pub display_name: String,
    pub issuer_url: String,
    pub supports_token_exchange: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlobalLimits {
    pub default_rate_limit_per_min: u32,
    pub anomaly_cutoff_threshold: f64,
    pub dedicated_port_range_start: u16,
    pub dedicated_port_range_end: u16,
}
