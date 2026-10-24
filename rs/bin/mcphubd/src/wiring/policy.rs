//! `PolicyEngine` ← `mcphub-policy::RegorusPolicyEngine`.
//!
//! FLAGGED GAP (not silently worked around): `RegorusPolicyEngine`'s own
//! `mcphub_gateway::traits::PolicyEngine` impl ignores `identity`/`tool`
//! entirely (`_identity`, `_tool`) and forwards the caller-supplied
//! `params` verbatim as the Rego `input`. But `authz.rego`'s documented
//! input schema (`crates/mcphub-policy/policies/authz.rego`'s header
//! comment) expects a much richer object — `client_id`, `client_roles`,
//! `tool_status`, `tool_risk_level`, etc. — none of which a caller's
//! request body carries (and none of which a caller should be trusted to
//! assert about themselves). Using that shim as-is would mean
//! `default allow := false` denies every real request, permanently.
//!
//! Rather than patch `mcphub-policy` (out of scope — its owner is mid-fix
//! on a separate throughput issue behind this same trait), this adapter
//! builds the input `authz.rego` actually expects from the resolved
//! `Identity`/`ToolRef` plus one extra Postgres lookup, and calls
//! `RegorusPolicyEngine::evaluate_raw` (public, synchronous) directly
//! instead of going through the ignoring shim.
//!
//! Also flagged: `authz.rego`'s `data.mcp_grants[client_id]` is NOT
//! server-scoped, while `mcphub-store`'s `grants` table is. `sync_data`
//! below aggregates (unions) each principal's grants across every server
//! they have one on into a single flat record — coarser than the real
//! per-server grant, but never *more* permissive than the entitlement gate
//! that already ran earlier in `invoke`'s chain, so this cannot itself
//! open an access path entitlement would have closed.

use mcphub_gateway::traits::PolicyEngine as PolicyEngineTrait;
use mcphub_policy::RegorusPolicyEngine;
use mcphub_types::{Decision, DenyReason, GateError, Identity, Role, ToolRef};
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

pub struct StorePolicyEngine {
    pub engine: Arc<RegorusPolicyEngine>,
    pub pool: PgPool,
    /// Backs `input.recent_calls` (anomaly structural deny rules — see
    /// `mcphub_store::redis_store::RecentCall`'s doc comment for the wire
    /// contract with `anomaly.rego`). A read failure here MUST deny the
    /// whole evaluation — see `evaluate`'s doc note on why an empty vec is
    /// never substituted for a failed read.
    pub redis: mcphub_store::RedisStore,
}

/// `authz.rego`'s role vocabulary (`"agent"`/`"user"`, `"admin"`/
/// `"platform_admin"`, `"analyst"`, `"server_owner"`/`"manager"`) is NOT
/// `mcphub_types::Role`'s variant names — it's a separate string contract
/// the policy bundle owns. Mapped explicitly here rather than via
/// `Role`'s `Debug`/a shared `Display`, so a rename on either side breaks
/// this function's compile (`Role`) or this crate's own tests
/// (`authz.rego`'s fixtures), not silently mismatches at runtime.
fn role_str(role: Role) -> &'static str {
    match role {
        Role::SuperAdmin => "admin",
        Role::ServerOwner => "server_owner",
        Role::SecurityAnalyst => "analyst",
        Role::Employee => "user",
    }
}

#[async_trait::async_trait]
impl PolicyEngineTrait for StorePolicyEngine {
    async fn evaluate(&self, identity: &Identity, tool: &ToolRef, input: &serde_json::Value) -> Result<Decision, GateError> {
        let tool_rows = mcphub_store::repo::tools::list_active_tools_for_server(&self.pool, tool.server.0).await?;
        let tool_row = tool_rows.into_iter().find(|t| t.name == tool.tool);

        // Anomaly window: READ failure must DENY, never degrade to an empty
        // window. `authz.rego`'s own comment on this is explicit — an empty
        // `recent_calls` is indistinguishable from "no history", so
        // swallowing a Redis error into `vec![]` here would silently
        // disable every anomaly structural rule while `evaluate_raw` keeps
        // returning ordinary `Allow`/`Deny` verdicts, looking perfectly
        // healthy. `?` on `StoreError` (via its `From` impl into
        // `GateError`) is what makes this actually deny, not an
        // `unwrap_or_default()` anywhere near this call.
        let recent_calls = self.redis.recent_calls_window(&identity.sub).await?;
        // Best-effort write: this call's own attempt joins the window for
        // FUTURE evaluations. A write failure degrades future anomaly
        // detection accuracy for this principal but does not itself make
        // THIS call's authorization decision untrustworthy — unlike the
        // read above, it does not gate `evaluate`'s return value. Logged,
        // not swallowed silently.
        if let Err(e) = self.redis.record_invocation(&identity.sub, &tool.tool).await {
            tracing::warn!(error = %e, principal = %identity.sub, tool = %tool.tool, "failed to record invocation into the anomaly window");
        }
        let recent_calls_json: Vec<serde_json::Value> =
            recent_calls.iter().map(|c| json!({"tool_name": c.tool_name, "timestamp": c.timestamp})).collect();

        let rego_input = json!({
            "client_id": identity.sub,
            "client_roles": identity.roles.iter().map(|g| role_str(g.role)).collect::<Vec<_>>(),
            // Role provenance, per ARCHITECTURE.md: a policy that cannot tell a
            // contractor tenant's `admin` from the corporate IDP's is not
            // enforcing anything. `client_roles` above stays a flat string array
            // so the existing `authz.rego` contract is unchanged; this is the
            // additive shape new rules should read.
            //
            // Note the ceiling in `IdpConfig.max_assertable_role` already dropped
            // anything an issuer was not entitled to assert — for BOTH
            // token-claim-derived roles (`mcphub_identity::claims::
            // RoleMapping::resolve`) and DB-sourced `role_grants` roles
            // (`mcphub_identity::claims::apply_ceiling`, applied in
            // `StoreAuthenticator::authenticate`) — so this is for rules
            // that need to discriminate *between* entitled issuers — not a
            // substitute for that ceiling.
            "client_granted_roles": identity.roles.iter().map(|g| json!({
                "role": role_str(g.role),
                "asserted_by": g.asserted_by.0,
            })).collect::<Vec<_>>(),
            "tool_id": tool_row.as_ref().map(|t| t.tool_id.to_string()).unwrap_or_default(),
            "tool_name": tool.tool,
            "tool_status": tool_row.as_ref().map(|t| t.status.clone()).unwrap_or_else(|| "active".to_string()),
            // Fail closed: an unscanned tool (NULL risk_level) must present
            // as the STRICTEST tier to the risk-ceiling check, matching
            // `entitlement.rs`'s equivalent gate and `upsert_tool`'s
            // fail-closed default — "low" here would have been fail-open.
            "tool_risk_level": tool_row.as_ref().and_then(|t| t.risk_level.clone()).unwrap_or_else(|| "critical".to_string()),
            "tool_server_id": tool.server.0.to_string(),
            // TODO: confirm with architect — server-owner grant scoping
            // (`owned_server_ids`) has no wiring source yet; always empty.
            "owned_server_ids": Vec::<String>::new(),
            "owner_max_risk_level": "medium",
            "params": input,
            // No "anomaly_score" field here (deliberately — was hardcoded
            // 0.0, permanently defeating the score-threshold check; see
            // sync_policy_data's anomaly-cutoff wiring and mcphub-policy's
            // `anomaly_score.rs`). The score is now computed inside
            // `evaluate_raw` itself from `recent_calls` below, matching how
            // the Python original computed it in application code rather
            // than trusting a caller-supplied number.
            "is_testing": false,
            "recent_calls": recent_calls_json,
            "window_seconds": mcphub_store::redis_store::ANOMALY_WINDOW_SECONDS,
        });

        let result = self.engine.evaluate_raw(rego_input).map_err(|e| e.to_gate_error())?;
        if result.allow {
            Ok(Decision::Allow { obligations: Default::default() })
        } else {
            // The wire response collapses every policy denial to one opaque
            // `policy_denied` code on purpose — a caller must not learn which
            // rule caught them. That also makes a genuine misconfiguration
            // undebuggable from outside, so the specific rule set is logged
            // here, operator-side only. Without this, "policy_denied" is
            // indistinguishable from a missing grant, a stale data snapshot,
            // and a real attack.
            tracing::info!(
                principal = %identity.sub,
                tool = %tool.tool,
                reasons = ?result.reasons,
                "policy denied"
            );
            Ok(Decision::Deny(DenyReason::PolicyDenied))
        }
    }
}

/// Loads the embedded `authz.rego` bundle and pushes an initial data
/// snapshot. Called once at startup; `spawn_policy_refresh` keeps it warm
/// afterward.
pub async fn sync_policy_data(engine: &RegorusPolicyEngine, pool: &PgPool) -> Result<(), mcphub_types::StartupError> {
    let all_grants = mcphub_store::repo::grants::list_all_grants(pool)
        .await
        .map_err(|e| mcphub_types::StartupError::Config(format!("policy data sync: {e}")))?;

    let mut grants_by_principal: HashMap<String, (Vec<String>, Vec<String>, String)> = HashMap::new();
    for (principal, row) in all_grants {
        let entry = grants_by_principal.entry(principal).or_insert_with(|| (vec![], vec![], "low".to_string()));
        entry.0.extend(row.allowed_tools);
        entry.1.extend(row.allowed_tags);
        if risk_rank(&row.max_risk_level) > risk_rank(&entry.2) {
            entry.2 = row.max_risk_level;
        }
    }
    tracing::info!(principals = grants_by_principal.len(), "policy data sync: grants loaded");
    let grants_json = json!(grants_by_principal
        .into_iter()
        .map(|(principal, (tools, tags, max_risk))| {
            (principal, json!({ "allowed_tools": tools, "allowed_tags": tags, "max_risk_level": max_risk }))
        })
        .collect::<HashMap<_, _>>());

    // `tools` map keyed by name -> {tags}. `tool_registry` has no tags
    // column (see entitlement.rs's matching TODO), so this is always empty
    // — present so `data.mcp.tools[name].tags` resolves to `[]`, not undefined.
    let tools_json = json!({});
    let injection_phrases_json = json!([]);

    engine
        .sync_data(grants_json, tools_json, injection_phrases_json)
        .map_err(|e| mcphub_types::StartupError::Config(format!("policy data sync: {e}")))?;

    // Anomaly cutoff (the admin "anomaly sensitivity" slider,
    // `crates/mcphub-ui/src/pages/admin.rs`, persisted via
    // `mcphub-store`'s `global_limits`/`set_global_limits`). Read here, on
    // this SAME periodic refresh (`spawn_policy_refresh`, every 30s) — NOT
    // per request, per the constraint on this control. `set_anomaly_cutoff`
    // is lock-free and doesn't touch the policy generation/cache (see its
    // doc comment in `engine.rs`), so a failed read here degrades to "keep
    // whatever cutoff was already set" rather than blocking the grants
    // sync above, which already returned `Ok` for this call.
    match sqlx::query_scalar::<_, f64>("SELECT anomaly_cutoff_threshold FROM global_limits WHERE id = 1")
        .fetch_optional(pool)
        .await
    {
        Ok(Some(cutoff)) => engine.set_anomaly_cutoff(cutoff),
        Ok(None) => tracing::warn!("global_limits row missing; keeping the current anomaly cutoff"),
        Err(e) => tracing::warn!(error = %e, "anomaly cutoff refresh failed; keeping the current anomaly cutoff"),
    }

    Ok(())
}

fn risk_rank(level: &str) -> u8 {
    match level {
        "low" => 0,
        "medium" => 1,
        "high" => 2,
        _ => 3,
    }
}
