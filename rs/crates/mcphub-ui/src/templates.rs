//! Template structs. Askama auto-escapes every `{{ }}` expression by
//! default for the `.html` extension — nothing in this crate uses the
//! `|safe` filter on user-controlled data (grep-verified in tests).

use askama::Template;

use crate::domain::*;

#[derive(Clone)]
pub struct NavItemView {
    pub href: &'static str,
    pub label: &'static str,
    pub active: bool,
}

/// Fields common to every rendered page: identity chrome, nav, CSP nonce,
/// CSRF token for any forms on the page, and an optional flash message.
#[derive(Clone)]
pub struct Chrome {
    pub user_email: String,
    pub user_role: String,
    pub nav: Vec<NavItemView>,
    pub csp_nonce: String,
    pub csrf_token: String,
    pub flash: Option<String>,
    pub mcp_url: String,
}

#[derive(Template)]
#[template(path = "forbidden.html")]
pub struct ForbiddenTemplate {
    pub action: String,
}

#[derive(Template)]
#[template(path = "not_found.html")]
pub struct NotFoundTemplate;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub csp_nonce: String,
    pub error: Option<String>,
}

// ---- Employee ----

#[derive(Template)]
#[template(path = "employee_catalog.html")]
pub struct EmployeeCatalogTemplate {
    pub chrome: Chrome,
    pub tools: Vec<ToolEntry>,
}

#[derive(Template)]
#[template(path = "employee_grants.html")]
pub struct EmployeeGrantsTemplate {
    pub chrome: Chrome,
    pub grants: Vec<Grant>,
    pub requests: Vec<AccessRequest>,
}

#[derive(Template)]
#[template(path = "help.html")]
pub struct HelpTemplate {
    pub chrome: Chrome,
}

// ---- Server owner ----

#[derive(Template)]
#[template(path = "owner_servers.html")]
pub struct OwnerServersTemplate {
    pub chrome: Chrome,
    pub servers: Vec<McpServer>,
}

#[derive(Template)]
#[template(path = "owner_server_detail.html")]
pub struct OwnerServerDetailTemplate {
    pub chrome: Chrome,
    pub server: McpServer,
    pub tools: Vec<ToolEntry>,
}

// ---- Security team ----

#[derive(Template)]
#[template(path = "security_audit_list.html")]
pub struct SecurityAuditListTemplate {
    pub chrome: Chrome,
    pub events: Vec<AuditEvent>,
}

#[derive(Template)]
#[template(path = "security_audit_detail.html")]
pub struct SecurityAuditDetailTemplate {
    pub chrome: Chrome,
    pub event: AuditEvent,
}

#[derive(Template)]
#[template(path = "security_policy.html")]
pub struct SecurityPolicyTemplate {
    pub chrome: Chrome,
    pub denied: Vec<AuditEvent>,
}

#[derive(Template)]
#[template(path = "security_quarantine.html")]
pub struct SecurityQuarantineTemplate {
    pub chrome: Chrome,
    pub entries: Vec<QuarantineEntry>,
}

#[derive(Template)]
#[template(path = "security_anomalies.html")]
pub struct SecurityAnomaliesTemplate {
    pub chrome: Chrome,
    pub anomalies: Vec<Anomaly>,
}

// ---- Super admin ----

#[derive(Template)]
#[template(path = "admin_idps.html")]
pub struct AdminIdpsTemplate {
    pub chrome: Chrome,
    pub idps: Vec<IdpConfig>,
}

#[derive(Template)]
#[template(path = "admin_idp_new.html")]
pub struct AdminIdpNewTemplate {
    pub chrome: Chrome,
    pub error: Option<String>,
}

#[derive(Template)]
#[template(path = "admin_servers.html")]
pub struct AdminServersTemplate {
    pub chrome: Chrome,
    pub servers: Vec<McpServer>,
}

#[derive(Template)]
#[template(path = "admin_limits.html")]
pub struct AdminLimitsTemplate {
    pub chrome: Chrome,
    pub limits: GlobalLimits,
}

#[derive(Template)]
#[template(path = "admin_grants.html")]
pub struct AdminGrantsTemplate {
    pub chrome: Chrome,
    pub grants: Vec<Grant>,
}

/// Renders a `Template` into an axum `Response`, deliberately implemented
/// by hand rather than pulled in from a framework-integration crate: it
/// keeps the render→response path in one visible place, and a render
/// failure becomes a 500 instead of an unhandled panic.
macro_rules! impl_into_response {
    ($($ty:ty),* $(,)?) => {
        $(
            impl axum::response::IntoResponse for $ty {
                fn into_response(self) -> axum::response::Response {
                    match askama::Template::render(&self) {
                        Ok(html) => axum::response::Html(html).into_response(),
                        Err(err) => (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("template render error: {err}"),
                        )
                            .into_response(),
                    }
                }
            }
        )*
    };
}

impl_into_response!(
    ForbiddenTemplate,
    HelpTemplate,
    NotFoundTemplate,
    LoginTemplate,
    EmployeeCatalogTemplate,
    EmployeeGrantsTemplate,
    OwnerServersTemplate,
    OwnerServerDetailTemplate,
    SecurityAuditListTemplate,
    SecurityAuditDetailTemplate,
    SecurityPolicyTemplate,
    SecurityQuarantineTemplate,
    SecurityAnomaliesTemplate,
    AdminIdpsTemplate,
    AdminIdpNewTemplate,
    AdminServersTemplate,
    AdminLimitsTemplate,
    AdminGrantsTemplate,
);
