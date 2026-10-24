pub mod health;
pub mod mcp;
pub mod rest;

use crate::traits::RawCredential;
use axum::http::HeaderMap;

/// Extracts raw caller credential material from inbound headers. This is
/// the only place headers are mapped to `RawCredential` — both routers call
/// it, so there is exactly one interpretation of "what did the caller
/// present" for the `Authenticator` gate to work from.
pub(crate) fn raw_credential_from_headers(headers: &HeaderMap) -> RawCredential {
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let api_key = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    RawCredential { bearer_token, mtls_spiffe_id: None, api_key }
}

/// D8-adjacent: bounds `tool_name` at ingress — REJECT (never sanitize-and-
/// store) a name that's empty, too long, or outside `[A-Za-z0-9._:-]`. This
/// string lands in `audit_events`, an APPEND-ONLY table with no UPDATE/
/// DELETE path, so anything that slips past here has no remediation short
/// of dropping the ledger. `wiring::audit`'s sanitizer in `mcphubd` is a
/// backstop for anything that reaches it some other way, not the control —
/// this is.
pub(crate) const MAX_TOOL_NAME_LEN: usize = 256;

pub(crate) fn validate_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_TOOL_NAME_LEN
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}
