//! `mcphub-selfservice` — the Rust port of the self-service MCP
//! (`mcp-servers/self-service/server.py`): per-identity MCP profile
//! management (7 tools). This is a BACKEND MCP server like any other — it
//! must be registered in `servers`/`tool_registry` and every call to it
//! traverses the same `invoke()` gate chain, it gets no special path. It
//! has no privileged database access beyond what `mcphub-store`'s repo
//! functions already expose, and writes no SQL of its own.
//!
//! Scope note: the Python server has 13 tools total. The other 9
//! (onboarding/review — `plan_mcp_server`, `submit_mcp_server`,
//! `approve_submission`, etc.) are NOT ported here — they depend on a
//! submission→clone→scan→review→approve pipeline that does not exist
//! anywhere in the Rust tree, and porting them would mean inventing that
//! architecture unreviewed. See the handoff note.

pub mod http;
pub mod tools;

pub use http::router;
pub use tools::{Caller, ToolError};
