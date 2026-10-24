//! View-model types for the portal, plus the role-scoped nav model.
//!
//! The `UiData` trait and its request/response shapes (`McpServer`,
//! `ToolEntry`, `Grant`, ...) now live in `mcphub-types::ui_data` — moved
//! there so `mcphub-ui` (presentation) and `mcphub-store` (storage) each
//! depend only on `mcphub-types` and never on each other. Re-exported here
//! so every existing `use crate::domain::*;` in this crate keeps working
//! unchanged.
//!
//! `NavItem` / `NAV_ITEMS` / `role_label` stay in this crate: they're
//! portal-navigation presentation, not part of the `UiData` read/write
//! contract, so they have no reason to live in `mcphub-types`.

pub use mcphub_types::{
    AccessRequest, Anomaly, AuditEvent, AuthModeView, DenyReasonView, GlobalLimits, Grant,
    IdpAuthModeDefault, IdpConfig, McpServer, OnboardingStatus, QuarantineEntry, ServerHealth,
    ToolEntry,
};

use mcphub_types::Role;

/// A role-scoped nav item. `active` is computed per-request in the handler,
/// not stored here.
#[derive(Debug, Clone)]
pub struct NavItem {
    pub href: &'static str,
    pub label: &'static str,
    pub roles: &'static [Role],
}

pub const NAV_ITEMS: &[NavItem] = &[
    // Help is the one item every role sees: the questions it answers
    // (why was I denied, how do I turn an MCP off, how do I add a server)
    // are asked by employees and admins alike.
    NavItem {
        href: "/help",
        label: "Help",
        roles: &[Role::Employee, Role::ServerOwner, Role::SecurityAnalyst, Role::SuperAdmin],
    },
    NavItem { href: "/catalog", label: "Catalog", roles: &[Role::Employee] },
    NavItem { href: "/me/grants", label: "My access", roles: &[Role::Employee] },
    NavItem { href: "/owner/servers", label: "My servers", roles: &[Role::ServerOwner] },
    NavItem { href: "/security/audit", label: "Audit", roles: &[Role::SecurityAnalyst] },
    NavItem { href: "/security/policy", label: "Policy decisions", roles: &[Role::SecurityAnalyst] },
    NavItem { href: "/security/quarantine", label: "Quarantine", roles: &[Role::SecurityAnalyst] },
    NavItem { href: "/security/anomalies", label: "Anomalies", roles: &[Role::SecurityAnalyst] },
    NavItem { href: "/admin/idps", label: "Identity providers", roles: &[Role::SuperAdmin] },
    NavItem { href: "/admin/servers", label: "Server registry", roles: &[Role::SuperAdmin] },
    NavItem { href: "/admin/limits", label: "Global limits", roles: &[Role::SuperAdmin] },
    NavItem { href: "/admin/grants", label: "Roles & grants", roles: &[Role::SuperAdmin] },
];

pub fn role_label(r: Role) -> &'static str {
    match r {
        Role::SuperAdmin => "Super admin",
        Role::ServerOwner => "Server owner",
        Role::SecurityAnalyst => "Security team",
        Role::Employee => "Employee",
    }
}
