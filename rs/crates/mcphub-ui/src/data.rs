//! `InMemoryUiData`: a fixture-backed `UiData` implementation for
//! rendering/tests only — never wire it into a production binary.
//!
//! The `UiData` trait itself lives in `mcphub_types::ui_data` (moved there
//! so this crate and `mcphub-store` don't depend on each other — see that
//! module's doc comment). Re-exported here so `mcphub_ui::data::UiData`
//! keeps resolving for existing callers.

use async_trait::async_trait;
use mcphub_types::{AuthMode, Role, ServerId};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

use crate::domain::*;

pub use mcphub_types::UiData;

pub struct InMemoryUiData {
    servers: RwLock<Vec<McpServer>>,
    tools: RwLock<Vec<ToolEntry>>,
    grants: RwLock<Vec<Grant>>,
    access_requests: RwLock<Vec<AccessRequest>>,
    audit: RwLock<Vec<AuditEvent>>,
    quarantine: RwLock<Vec<QuarantineEntry>>,
    anomalies: RwLock<Vec<Anomaly>>,
    idps: RwLock<Vec<IdpConfig>>,
    limits: RwLock<GlobalLimits>,
    roles: RwLock<HashMap<String, Vec<Role>>>,
}

impl Default for InMemoryUiData {
    fn default() -> Self {
        let server_a = ServerId(Uuid::from_u128(1));
        let server_b = ServerId(Uuid::from_u128(2));

        let servers = vec![
            McpServer {
                id: server_a,
                name: "github-mcp".into(),
                owner_sub: "owner-1".into(),
                auth_mode: AuthMode::SharedPassthrough.into(),
                health: ServerHealth::Healthy,
                onboarding: OnboardingStatus::Approved,
                enabled: true,
            },
            McpServer {
                id: server_b,
                name: "legacy-crm-mcp".into(),
                owner_sub: "owner-1".into(),
                auth_mode: AuthMode::DedicatedPort { port: 9001 }.into(),
                health: ServerHealth::Degraded,
                onboarding: OnboardingStatus::PendingReview,
                enabled: false,
            },
        ];

        let tools = vec![
            ToolEntry {
                server_id: server_a,
                server_name: "github-mcp".into(),
                tool_name: "list_issues".into(),
                description: "List issues in a repository.".into(),
                invokable: true,
            },
            ToolEntry {
                server_id: server_a,
                server_name: "github-mcp".into(),
                tool_name: "merge_pr".into(),
                description: "Merge an approved pull request.".into(),
                invokable: false,
            },
            ToolEntry {
                server_id: server_b,
                server_name: "legacy-crm-mcp".into(),
                tool_name: "export_contacts".into(),
                description: "Export CRM contacts as CSV.".into(),
                invokable: false,
            },
        ];

        let grants = vec![Grant {
            principal_sub: "employee-1".into(),
            server_id: server_a,
            server_name: "github-mcp".into(),
            tool_name: Some("list_issues".into()),
            granted_by: "admin-1".into(),
            granted_at: "2026-08-01T09:00:00Z".into(),
        }];

        let audit = vec![
            AuditEvent {
                id: Uuid::from_u128(101),
                at: "2026-08-14T10:15:00Z".into(),
                principal_sub: "employee-1".into(),
                server_name: "github-mcp".into(),
                tool_name: "list_issues".into(),
                decision: "allow",
                deny_reason: None,
                request_id: "req-101".into(),
            },
            AuditEvent {
                id: Uuid::from_u128(102),
                at: "2026-08-14T10:16:00Z".into(),
                principal_sub: "employee-2".into(),
                server_name: "legacy-crm-mcp".into(),
                tool_name: "export_contacts".into(),
                decision: "deny",
                deny_reason: Some(mcphub_types::DenyReason::NoGrant.into()),
                request_id: "req-102".into(),
            },
        ];

        let quarantine = vec![QuarantineEntry {
            server_id: server_b,
            server_name: "legacy-crm-mcp".into(),
            tool_name: "export_contacts".into(),
            reason: "New server pending first security review.".into(),
            quarantined_at: "2026-08-10T00:00:00Z".into(),
        }];

        let anomalies = vec![Anomaly {
            id: Uuid::from_u128(201),
            at: "2026-08-14T02:00:00Z".into(),
            principal_sub: "employee-2".into(),
            kind: "burst_rate".into(),
            severity: "medium",
            summary: "40 calls/min against legacy-crm-mcp, 8x baseline.".into(),
        }];

        let idps = vec![IdpConfig {
            id: "platform-keycloak".into(),
            kind: "keycloak",
            display_name: "Platform Keycloak".into(),
            issuer_url: "https://idp.internal/realms/platform".into(),
            supports_token_exchange: true,
        }];

        let limits = GlobalLimits {
            default_rate_limit_per_min: 120,
            anomaly_cutoff_threshold: 2.0,
            dedicated_port_range_start: 9000,
            dedicated_port_range_end: 9100,
        };

        let mut roles = HashMap::new();
        roles.insert("admin-1".to_string(), vec![Role::SuperAdmin]);
        roles.insert("owner-1".to_string(), vec![Role::ServerOwner]);
        roles.insert("secteam-1".to_string(), vec![Role::SecurityAnalyst]);
        roles.insert("employee-1".to_string(), vec![Role::Employee]);
        roles.insert("employee-2".to_string(), vec![Role::Employee]);

        Self {
            servers: RwLock::new(servers),
            tools: RwLock::new(tools),
            grants: RwLock::new(grants),
            access_requests: RwLock::new(Vec::new()),
            audit: RwLock::new(audit),
            quarantine: RwLock::new(quarantine),
            anomalies: RwLock::new(anomalies),
            idps: RwLock::new(idps),
            limits: RwLock::new(limits),
            roles: RwLock::new(roles),
        }
    }
}

#[async_trait]
impl UiData for InMemoryUiData {
    async fn servers_for_owner(&self, owner_sub: &str) -> Vec<McpServer> {
        self.servers.read().unwrap().iter().filter(|s| s.owner_sub == owner_sub).cloned().collect()
    }

    async fn all_servers(&self) -> Vec<McpServer> {
        self.servers.read().unwrap().clone()
    }

    async fn server_by_id(&self, id: ServerId) -> Option<McpServer> {
        self.servers.read().unwrap().iter().find(|s| s.id == id).cloned()
    }

    async fn tools_for_server(&self, id: ServerId) -> Vec<ToolEntry> {
        self.tools.read().unwrap().iter().filter(|t| t.server_id == id).cloned().collect()
    }

    async fn catalog_for(&self, _sub: &str) -> Vec<ToolEntry> {
        // Discovery==invoke: only tools flagged invokable are ever listed.
        self.tools.read().unwrap().iter().filter(|t| t.invokable).cloned().collect()
    }

    async fn grants_for(&self, sub: &str) -> Vec<Grant> {
        self.grants.read().unwrap().iter().filter(|g| g.principal_sub == sub).cloned().collect()
    }

    async fn all_grants(&self) -> Vec<Grant> {
        self.grants.read().unwrap().clone()
    }

    async fn save_grant(&self, grant: Grant) {
        self.grants.write().unwrap().push(grant);
    }

    async fn access_requests_for(&self, sub: &str) -> Vec<AccessRequest> {
        self.access_requests.read().unwrap().iter().filter(|r| r.requester_sub == sub).cloned().collect()
    }

    async fn create_access_request(&self, sub: &str, server_id: ServerId, tool_name: &str, justification: &str) {
        let server_name = self.server_by_id(server_id).await.map(|s| s.name).unwrap_or_default();
        self.access_requests.write().unwrap().push(AccessRequest {
            id: Uuid::from_u128(rand::random::<u64>() as u128),
            requester_sub: sub.to_string(),
            server_name,
            tool_name: tool_name.to_string(),
            justification: justification.to_string(),
            status: "pending",
        });
    }

    async fn recent_audit_events(&self, limit: usize) -> Vec<AuditEvent> {
        let events = self.audit.read().unwrap();
        events.iter().rev().take(limit).cloned().collect()
    }

    async fn audit_event(&self, id: Uuid) -> Option<AuditEvent> {
        self.audit.read().unwrap().iter().find(|e| e.id == id).cloned()
    }

    async fn quarantine_entries(&self) -> Vec<QuarantineEntry> {
        self.quarantine.read().unwrap().clone()
    }

    async fn release_quarantine(&self, server_id: ServerId, tool_name: &str) -> bool {
        let mut q = self.quarantine.write().unwrap();
        let before = q.len();
        q.retain(|e| !(e.server_id == server_id && e.tool_name == tool_name));
        q.len() != before
    }

    async fn anomalies(&self) -> Vec<Anomaly> {
        self.anomalies.read().unwrap().clone()
    }

    async fn idps(&self) -> Vec<IdpConfig> {
        self.idps.read().unwrap().clone()
    }

    async fn create_idp(&self, cfg: IdpConfig) {
        self.idps.write().unwrap().push(cfg);
    }

    async fn global_limits(&self) -> GlobalLimits {
        self.limits.read().unwrap().clone()
    }

    async fn set_global_limits(&self, limits: GlobalLimits) {
        *self.limits.write().unwrap() = limits;
    }

    async fn display_roles_all_issuers(&self, sub: &str) -> Vec<Role> {
        self.roles.read().unwrap().get(sub).cloned().unwrap_or_default()
    }
}
