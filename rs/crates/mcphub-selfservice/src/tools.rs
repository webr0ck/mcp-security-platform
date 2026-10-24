//! Profile-management tool logic — the Rust port of
//! `mcp-servers/self-service/server.py`'s 7 profile-management tools
//! (`list_available_mcps`, `get_profile`, `enable_mcp`, `disable_mcp`,
//! `list_functions`, `enable_function`, `disable_function`). The other 9
//! tools in the Python server (onboarding/review) are explicitly out of
//! scope here — they depend on a submission→clone→scan→review→approve
//! pipeline that does not exist anywhere in the Rust tree yet; see the
//! handoff note rather than this crate for that gap.
//!
//! Wire/transport-agnostic by design: every function here takes an
//! already-resolved [`Caller`] (never raw headers) and returns a plain
//! `Result<serde_json::Value, ToolError>`, so this logic is directly
//! testable without an HTTP server, and can be wired to whichever
//! backend-dispatch wire contract the gateway ends up using (see the
//! handoff note: `dispatch` does not currently forward the tool name or
//! caller identity to any backend at all — that is a prerequisite this
//! crate is blocked on, not something invented here).

use mcphub_store::repo::profiles::{self, ProfileRow, RECOVERY_FUNCTIONS, SELF_SERVICE_MCP_NAME};
use mcphub_store::StoreError;
use mcphub_types::Role;
use serde_json::{json, Value};
use sqlx::PgPool;

/// The resolved identity of whoever is calling a self-service tool. Never
/// constructed from caller-supplied headers by this crate itself — the
/// gateway is the trust anchor for identity; whatever wiring layer sits in
/// front of this crate turns an already-verified `mcphub_types::Identity`
/// into one of these.
pub struct Caller {
    pub sub: String,
    pub roles: Vec<Role>,
}

impl Caller {
    /// Mirrors the Python platform's "admin"/"platform_admin" role-string
    /// checks: `Role::SuperAdmin` is the only Rust role that plays that
    /// part — the closed `Role` enum has no separate admin/platform_admin
    /// split, so there is exactly one privileged role to check, not two.
    fn is_admin(&self) -> bool {
        self.roles.contains(&Role::SuperAdmin)
    }

    /// Mirrors the Python platform's read-side allowlist (admin,
    /// platform_admin, auditor): `SecurityAnalyst` is the closest Rust
    /// equivalent to "auditor" — a role that may inspect but has no
    /// platform-admin write authority elsewhere in this codebase either.
    fn may_read_others(&self) -> bool {
        self.is_admin() || self.roles.contains(&Role::SecurityAnalyst)
    }
}

#[derive(Debug)]
pub enum ToolError {
    Forbidden(String),
    SelfLockout(String),
    Store(StoreError),
}

impl From<StoreError> for ToolError {
    fn from(e: StoreError) -> Self {
        ToolError::Store(e)
    }
}

impl ToolError {
    /// `{error, detail}` — the same shape the Python tools return, so a
    /// client written against that contract needs no changes.
    pub fn to_json(&self) -> Value {
        match self {
            ToolError::Forbidden(detail) => json!({"error": "forbidden", "detail": detail}),
            ToolError::SelfLockout(detail) => json!({"error": "self_lockout_blocked", "detail": detail}),
            ToolError::Store(StoreError::InvariantViolation(detail)) => {
                json!({"error": "self_lockout_blocked", "detail": detail})
            }
            ToolError::Store(e) => json!({"error": "store_error", "detail": e.to_string()}),
        }
    }
}

fn resolve_read_target(caller: &Caller, target_profile: Option<&str>) -> Result<String, ToolError> {
    let profile_id = target_profile.unwrap_or(&caller.sub).to_string();
    if profile_id != caller.sub && !caller.may_read_others() {
        return Err(ToolError::Forbidden("only admin/auditor can view other profiles".into()));
    }
    Ok(profile_id)
}

fn resolve_write_target(caller: &Caller, target_profile: Option<&str>) -> Result<String, ToolError> {
    let profile_id = target_profile.unwrap_or(&caller.sub).to_string();
    if profile_id != caller.sub && !caller.is_admin() {
        return Err(ToolError::Forbidden("only admin can modify other profiles".into()));
    }
    Ok(profile_id)
}

/// `(enabled, allowed_functions)` with the platform default applied when no
/// explicit row exists — absence of a row is NOT a restriction, it means
/// "never touched, fully open" (enabled=true, allowed_functions=None).
fn effective(row: Option<ProfileRow>) -> (bool, Option<Vec<String>>) {
    match row {
        Some(r) => (r.enabled, r.allowed_functions),
        None => (true, None),
    }
}

pub async fn list_available_mcps(caller: &Caller) -> Value {
    json!({
        "profile_id": caller.sub,
        "mcps": [],
        "hint": "Use get_profile to see your full profile including all MCPs. Use enable_mcp/disable_mcp to change per-MCP settings.",
    })
}

pub async fn get_profile(pool: &PgPool, caller: &Caller, mcp_name: &str, target_profile: Option<&str>) -> Result<Value, ToolError> {
    let profile_id = resolve_read_target(caller, target_profile)?;
    let row = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let explicit_row = row.is_some();
    let (enabled, allowed_functions) = effective(row);
    Ok(json!({
        "principal": profile_id,
        "mcp_name": mcp_name,
        "enabled": enabled,
        "allowed_functions": allowed_functions,
        "explicit_row": explicit_row,
    }))
}

pub async fn enable_mcp(pool: &PgPool, caller: &Caller, mcp_name: &str, target_profile: Option<&str>) -> Result<Value, ToolError> {
    let profile_id = resolve_write_target(caller, target_profile)?;
    let existing = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let (_, allowed_functions) = effective(existing); // preserve any existing function restriction
    profiles::upsert_profile(pool, &profile_id, mcp_name, true, allowed_functions.as_deref(), &caller.sub).await?;
    Ok(json!({"ok": true, "principal": profile_id, "mcp_name": mcp_name, "enabled": true}))
}

pub async fn disable_mcp(pool: &PgPool, caller: &Caller, mcp_name: &str, target_profile: Option<&str>) -> Result<Value, ToolError> {
    let profile_id = resolve_write_target(caller, target_profile)?;
    let existing = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let (_, allowed_functions) = effective(existing);
    // Self-lockout (coarse: disabling the self-service MCP for yourself) is
    // enforced by `upsert_profile` itself — not duplicated here — so this
    // path and any future write path both get it for free.
    profiles::upsert_profile(pool, &profile_id, mcp_name, false, allowed_functions.as_deref(), &caller.sub).await?;
    Ok(json!({"ok": true, "principal": profile_id, "mcp_name": mcp_name, "enabled": false}))
}

pub async fn list_functions(pool: &PgPool, caller: &Caller, mcp_name: &str, target_profile: Option<&str>) -> Result<Value, ToolError> {
    let profile_id = resolve_read_target(caller, target_profile)?;
    let row = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let (enabled, allowed_functions) = effective(row);
    Ok(json!({
        "mcp_name": mcp_name,
        "profile_id": profile_id,
        "enabled": enabled,
        "allowed_functions": allowed_functions,
        "note": "null allowed_functions means all functions permitted",
    }))
}

pub async fn enable_function(
    pool: &PgPool,
    caller: &Caller,
    mcp_name: &str,
    function_name: &str,
    target_profile: Option<&str>,
) -> Result<Value, ToolError> {
    let profile_id = resolve_write_target(caller, target_profile)?;
    let existing = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let (enabled, allowed_functions) = effective(existing);

    let Some(current_af) = allowed_functions else {
        // Already unrestricted — all functions already allowed, no write needed.
        return Ok(json!({
            "ok": true, "principal": profile_id, "mcp_name": mcp_name, "function_name": function_name,
            "enabled": true, "note": "Profile is unrestricted — all functions already allowed",
        }));
    };
    if current_af.iter().any(|f| f == function_name) {
        return Ok(json!({
            "ok": true, "principal": profile_id, "mcp_name": mcp_name, "function_name": function_name,
            "enabled": true, "note": "Function already enabled",
        }));
    }

    let mut new_af = current_af;
    new_af.push(function_name.to_string());
    new_af.sort();
    profiles::upsert_profile(pool, &profile_id, mcp_name, enabled, Some(&new_af), &caller.sub).await?;
    Ok(json!({
        "ok": true, "principal": profile_id, "mcp_name": mcp_name, "function_name": function_name,
        "enabled": true, "allowed_functions": new_af,
    }))
}

/// If the profile is currently unrestricted (`allowed_functions=None`), the
/// list is narrowed to an EMPTY allowlist (deny-all) rather than "every
/// function except this one" — the full function set of an MCP is not known
/// at this layer, so there is no way to materialize its complement. This is
/// a deliberate, ported behavior (matches the Python platform's
/// `disable_function` exactly, including this same tradeoff), not an
/// oversight — see 0013_profiles.up.sql's doc comment.
pub async fn disable_function(
    pool: &PgPool,
    caller: &Caller,
    mcp_name: &str,
    function_name: &str,
    target_profile: Option<&str>,
) -> Result<Value, ToolError> {
    let profile_id = resolve_write_target(caller, target_profile)?;

    // Function-level self-lockout: `upsert_profile`'s guard only sees the
    // coarse enabled=false axis, not individual function names — this
    // narrower case (excluding a recovery function from your own
    // self-service allowlist, no admin bypass) has to be caught here,
    // before the current allowlist is even fetched.
    if !caller.is_admin() && profile_id == caller.sub && mcp_name == SELF_SERVICE_MCP_NAME && RECOVERY_FUNCTIONS.contains(&function_name) {
        return Err(ToolError::SelfLockout(format!(
            "cannot disable your own recovery function '{function_name}' on the self-service MCP — ask an admin if you need this disabled"
        )));
    }

    let existing = profiles::get_profile(pool, &profile_id, mcp_name).await?;
    let (enabled, allowed_functions) = effective(existing);

    if let Some(current_af) = &allowed_functions {
        if !current_af.iter().any(|f| f == function_name) {
            return Ok(json!({
                "ok": true, "principal": profile_id, "mcp_name": mcp_name, "function_name": function_name,
                "enabled": false, "note": "Function was not in allowed_functions — already effectively disabled",
                "allowed_functions": current_af,
            }));
        }
    }

    let new_af: Vec<String> = match allowed_functions {
        None => vec![],
        Some(af) => {
            let mut v: Vec<String> = af.into_iter().filter(|f| f != function_name).collect();
            v.sort();
            v
        }
    };
    profiles::upsert_profile(pool, &profile_id, mcp_name, enabled, Some(&new_af), &caller.sub).await?;
    Ok(json!({
        "ok": true, "principal": profile_id, "mcp_name": mcp_name, "function_name": function_name,
        "enabled": false, "allowed_functions": new_af,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_store::testing::test_pool_migrated;

    fn caller(sub: &str, roles: &[Role]) -> Caller {
        Caller { sub: sub.to_string(), roles: roles.to_vec() }
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disable_mcp_rejects_self_lockout_on_the_self_service_mcp() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let err = disable_mcp(&pool, &bob, SELF_SERVICE_MCP_NAME, None).await.unwrap_err();
        assert_eq!(err.to_json()["error"], "self_lockout_blocked");
        // Nothing was written — the row must not exist.
        assert!(profiles::get_profile(&pool, "bob", SELF_SERVICE_MCP_NAME).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disable_function_rejects_disabling_own_recovery_function() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let err = disable_function(&pool, &bob, SELF_SERVICE_MCP_NAME, "get_profile", None).await.unwrap_err();
        assert_eq!(err.to_json()["error"], "self_lockout_blocked");
        assert!(profiles::get_profile(&pool, "bob", SELF_SERVICE_MCP_NAME).await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disable_function_allows_non_recovery_function_on_self_service_mcp() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let result = disable_function(&pool, &bob, SELF_SERVICE_MCP_NAME, "list_functions", None).await.unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn admin_can_disable_recovery_function_for_another_principal() {
        let pool = test_pool_migrated().await;
        let admin = caller("admin-1", &[Role::SuperAdmin]);
        let result = disable_function(&pool, &admin, SELF_SERVICE_MCP_NAME, "get_profile", Some("bob")).await.unwrap();
        assert_eq!(result["ok"], true);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn non_admin_cannot_write_another_principals_profile() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let err = enable_mcp(&pool, &bob, "some-mcp", Some("alice")).await.unwrap_err();
        assert_eq!(err.to_json()["error"], "forbidden");
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn disabling_a_function_while_unrestricted_collapses_to_empty_allowlist_not_all_minus_one() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let result = disable_function(&pool, &bob, "some-mcp", "risky_fn", None).await.unwrap();
        // Ported Python semantics: NULL -> [] (deny-all), not "every function except risky_fn".
        assert_eq!(result["allowed_functions"], json!([]));
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn enable_function_is_a_noop_when_already_unrestricted() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        let result = enable_function(&pool, &bob, "some-mcp", "any_fn", None).await.unwrap();
        assert_eq!(result["note"], "Profile is unrestricted — all functions already allowed");
        // No row should have been written.
        assert!(profiles::get_profile(&pool, "bob", "some-mcp").await.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn enable_mcp_preserves_existing_function_restriction() {
        let pool = test_pool_migrated().await;
        let bob = caller("bob", &[Role::Employee]);
        profiles::upsert_profile(&pool, "bob", "some-mcp", false, Some(&["read".to_string()]), "bob").await.unwrap();
        let result = enable_mcp(&pool, &bob, "some-mcp", None).await.unwrap();
        assert_eq!(result["enabled"], true);
        let row = profiles::get_profile(&pool, "bob", "some-mcp").await.unwrap().unwrap();
        assert!(row.enabled);
        assert_eq!(row.allowed_functions, Some(vec!["read".to_string()]));
    }
}
