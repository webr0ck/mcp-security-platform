//! `mcphub-gateway` — the axum + tower application. Owns the single choke
//! point (`invocation::invoke`) that both the REST and MCP routers call,
//! the gate trait definitions components 2/3/4 implement, and the tower
//! layer stack.

#![forbid(unsafe_code)]

pub mod app;
pub mod invocation;
pub mod layers;
pub mod mcp_protocol;
pub mod response_filter;
pub mod routers;
pub mod ssrf;
pub mod state;
pub mod traits;

pub use app::build;
pub use invocation::{invoke, Gates, InvokeOutcome, InvokeRequest};
pub use state::AppState;
