//! Explains a policy decision: prints the actual `deny` reason set for a given
//! input instead of the single `policy_denied` code the gateway surfaces.
//!
//! The gateway deliberately collapses every policy denial to one opaque code on
//! the wire (a caller must not learn which rule caught them). That is correct,
//! and it also makes a legitimate misconfiguration nearly impossible to debug
//! from outside. This is the inside view.
//!
//!     cargo run -p mcphub-policy --example explain -- '<input-json>'
//!
//! With no argument it uses a minimal allow-shaped input, which is useful for
//! answering "is the bundle itself sane?" before blaming the data.

use mcphub_policy::{PolicyBundle, RegorusPolicyEngine};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let input: serde_json::Value = match std::env::args().nth(1) {
        Some(raw) => serde_json::from_str(&raw)?,
        None => json!({
            "client_id": "demo-principal",
            "client_roles": ["user"],
            "client_granted_roles": [{"role": "user", "asserted_by": "https://idp.example"}],
            "tool_id": "00000000-0000-0000-0000-000000000001",
            "tool_name": "ping",
            "tool_status": "active",
            "tool_risk_level": "low",
            "tool_server_id": "11111111-1111-1111-1111-111111111111",
            "owned_server_ids": [],
            "owner_max_risk_level": "medium",
            "params": {},
            "is_testing": false,
            "recent_calls": [],
            "window_seconds": 300
        }),
    };

    let engine = RegorusPolicyEngine::new(std::time::Duration::from_secs(3600));
    engine.load_bundle(&PolicyBundle::unsigned_for_tests(PolicyBundle::EMBEDDED_AUTHZ_REGO))?;

    // The data snapshot the gateway pushes. Keyed by principal, exactly as
    // `wiring::policy::sync_policy_data` builds it.
    let client_id = input.get("client_id").and_then(|v| v.as_str()).unwrap_or("demo-principal");
    let tool_name = input.get("tool_name").and_then(|v| v.as_str()).unwrap_or("ping");
    engine.sync_data(
        json!({ client_id: { "allowed_tools": [tool_name], "allowed_tags": [], "max_risk_level": "high" } }),
        json!({}),
        json!([]),
    )?;

    let result = engine.evaluate_raw(input.clone())?;
    println!("allow   : {}", result.allow);
    println!("reasons : {:?}", result.reasons);

    // Re-run with NO grant data, so the difference isolates "the rule is
    // unsatisfiable" from "the data never arrived" — the two failure modes that
    // both surface as a bare `policy_denied`.
    engine.sync_data(json!({}), json!({}), json!([]))?;
    let empty = engine.evaluate_raw(input)?;
    println!("\nwith empty grants data:");
    println!("allow   : {}", empty.allow);
    println!("reasons : {:?}", empty.reasons);
    Ok(())
}
