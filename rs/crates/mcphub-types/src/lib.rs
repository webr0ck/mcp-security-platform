//! `mcphub-types` — shared types for the MCP security gateway. Zero I/O
//! dependencies by design: this crate defines the vocabulary every other
//! crate speaks (`Identity`, `Decision`, `DenyReason`, `Secret<T>`, ...), and
//! nothing in it should ever need a runtime, a socket, or a database driver.

#![forbid(unsafe_code)]

pub mod decision;
pub mod error;
pub mod identity;
pub mod ids;
pub mod secret;
pub mod ui_data;

pub use decision::{AuthMode, Decision, DenyReason, Obligations, ToolRef};
pub use error::{GateError, StartupError};
pub use identity::{GrantedRole, Identity, Role, TokenRef};
pub use ids::{IssuerId, RequestId, ServerId, ToolId};
pub use secret::Secret;
pub use ui_data::{
    AccessRequest, Anomaly, AuditEvent, AuthModeView, DenyReasonView, GlobalLimits, Grant,
    IdpAuthModeDefault, IdpConfig, McpServer, OnboardingStatus, QuarantineEntry, ServerHealth,
    ToolEntry, UiData,
};
