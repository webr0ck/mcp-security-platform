//! The single choke point. Both the REST router (`routers::rest`) and the
//! MCP JSON-RPC router (`routers::mcp`) call [`invoke`] and nothing else —
//! there is no second enforcement path. See `tests` below for the tests
//! that pin this file's two hardest invariants:
//!
//! - `err_from_every_gate_maps_to_deny`: construct a gate that returns
//!   `Err`, assert the outcome is `Decision::Deny`, for *every* gate in the
//!   chain.
//! - `discovery_eq_invoke_denies_tool_not_in_list`: a tool absent from
//!   `EntitlementStore::list_visible` is denied on `invoke` with
//!   `DenyReason::EntitlementMissing`, using the exact same store call the
//!   `tools/list` handler uses — so the two cannot structurally diverge.
//!
//! Enforcement order (do not reorder — this mirrors ARCHITECTURE.md
//! verbatim):
//!
//! ```text
//! authenticate → resolve identity → ingress (server enabled) → SSRF guard
//! → rbac (role has server) → quarantine gate → entitlement (discovery==invoke)
//! → rate limit / anomaly cutoff → policy (regorus) → taint floor
//! → credential injection → dispatch to backend → response filter → audit emit
//! ```

use crate::ssrf;
use crate::traits::{
    AuditRecord, AuditOutcome, AuditSink, Authenticator, BackendDispatcher, CredentialBroker,
    EntitlementStore, PolicyEngine, RateLimiter, RawCredential, ToolMeta,
};
use mcphub_types::{Decision, DenyReason, Identity, RequestId, ToolRef};
use std::sync::Arc;
use std::time::Instant;

/// The full set of gate implementations `invoke` is wired against. Built
/// once at `mcphubd` startup, cloned (cheap: `Arc` fields) per request.
#[derive(Clone)]
pub struct Gates {
    pub authenticator: Arc<dyn Authenticator>,
    pub entitlement: Arc<dyn EntitlementStore>,
    pub rate_limiter: Arc<dyn RateLimiter>,
    pub policy: Arc<dyn PolicyEngine>,
    pub credentials: Arc<dyn CredentialBroker>,
    pub dispatcher: Arc<dyn BackendDispatcher>,
    pub audit: Arc<dyn AuditSink>,
}

impl Gates {
    /// All gates set to the fail-closed `DenyAll` implementation. Used as
    /// the base for standalone crate tests and as the safety-net default in
    /// `mcphubd` before real wiring is attached.
    pub fn deny_all() -> Self {
        use crate::traits::DenyAll;
        let deny_all = Arc::new(DenyAll);
        Gates {
            authenticator: deny_all.clone(),
            entitlement: deny_all.clone(),
            rate_limiter: deny_all.clone(),
            policy: deny_all.clone(),
            credentials: deny_all.clone(),
            dispatcher: deny_all.clone(),
            audit: deny_all,
        }
    }
}

/// The one and only entry point either router may call to invoke a tool.
#[derive(Debug, Clone)]
pub struct InvokeRequest {
    pub request_id: RequestId,
    pub raw_credential: RawCredential,
    pub tool: ToolRef,
    pub params: serde_json::Value,
    /// D8: the caller's network address, from the TCP connection (or an
    /// operator-trusted proxy layer) — see `AuditRecord::source_ip`'s doc
    /// comment for why this must never be client-header-derived.
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct InvokeOutcome {
    pub request_id: RequestId,
    pub result: serde_json::Value,
}

/// The single choke point. Maps every gate's `Err` to `Decision::Deny` —
/// there is no code path in this function that turns a `GateError` into an
/// allow.
#[tracing::instrument(skip(gates, req), fields(request_id = %req.request_id, tool = %req.tool.tool))]
pub async fn invoke(gates: &Gates, req: InvokeRequest) -> Result<InvokeOutcome, DenyReason> {
    let started = Instant::now();
    // 1. authenticate → resolve identity
    let identity = match gates.authenticator.authenticate(&req.raw_credential).await {
        Ok(identity) => identity,
        Err(_e) => {
            deny_and_audit(gates, &req, None, None, started, DenyReason::Unauthenticated).await;
            return Err(DenyReason::Unauthenticated);
        }
    };

    // Fetch tool metadata once; backs ingress/SSRF/RBAC/quarantine below.
    let meta = match gates.entitlement.tool_meta(&req.tool).await {
        Ok(meta) => meta,
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            deny_and_audit(gates, &req, Some(&identity), None, started, reason).await;
            return Err(reason);
        }
    };
    let tool_id = meta.tool_id;

    // 2. ingress (server enabled)
    if let Err(reason) = check_ingress(&meta) {
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
        return Err(reason);
    }

    // 3. SSRF guard
    if let Err(reason) = ssrf::validate(&meta) {
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
        return Err(reason);
    }

    // 4. rbac (role has server)
    if let Err(reason) = check_rbac(&identity, &meta) {
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
        return Err(reason);
    }

    // 5. quarantine gate
    if meta.quarantined {
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, DenyReason::Quarantined).await;
        return Err(DenyReason::Quarantined);
    }

    // 6. entitlement (discovery == invoke). This calls the exact same
    // `list_visible` the `tools/list` handler calls — see module docs.
    match gates.entitlement.list_visible(&identity).await {
        Ok(visible) => {
            if !visible.contains(&req.tool) {
                deny_and_audit(gates, &req, Some(&identity), tool_id, started, DenyReason::EntitlementMissing).await;
                return Err(DenyReason::EntitlementMissing);
            }
        }
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
            return Err(reason);
        }
    }

    // 7. rate limit / anomaly cutoff
    if let Err(e) = gates.rate_limiter.check(&identity, &req.tool).await {
        let reason = e.to_deny_reason();
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
        return Err(reason);
    }

    // 8. policy (regorus)
    let decision = match gates.policy.evaluate(&identity, &req.tool, &req.params).await {
        Ok(decision) => decision,
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
            return Err(reason);
        }
    };
    let obligations = match decision {
        Decision::Allow { obligations } => obligations,
        Decision::Deny(reason) => {
            deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
            return Err(reason);
        }
    };

    // 9. taint floor. Enforce mode denies on a tier below the configured
    // floor; notify mode (obligations.taint_notice already set by the
    // policy engine) just carries a disclaimer through to the response.
    if let Err(reason) = check_taint_floor(&meta) {
        deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
        return Err(reason);
    }

    // 10. credential injection
    let mut headers = match gates.credentials.inject(&identity, &req.tool).await {
        Ok(headers) => headers,
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
            return Err(reason);
        }
    };
    set_identity_headers(&mut headers, &identity);

    // 11. dispatch to backend
    let backend_result = match gates.dispatcher.dispatch(&req.tool, req.request_id, &headers, &req.params).await {
        Ok(result) => result,
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            deny_and_audit(gates, &req, Some(&identity), tool_id, started, reason).await;
            return Err(reason);
        }
    };

    // 12. response filter — obligations.requires_response_filter is honored
    // by the concrete response-filter implementation; this crate only
    // enforces that the flag is threaded through, not the filtering logic
    // itself (that belongs to mcphub-store / mcphub-policy per redaction
    // rules owned there).
    let filtered = if obligations.requires_response_filter {
        crate::response_filter::filter(backend_result)
    } else {
        backend_result
    };

    // 13. audit emit — synchronous, precedes the response (invariant 4). A
    // failure here denies the call: the caller must not receive a result
    // that was never durably audited.
    if let Err(audit_err) = gates
        .audit
        .emit(AuditRecord {
            request_id: req.request_id,
            identity_sub: Some(identity.sub.clone()),
            identity_issuer: Some(identity.issuer.0.clone()),
            identity_roles: identity_role_strings(&identity),
            tool: Some(req.tool.clone()),
            tool_id,
            outcome: AuditOutcome::Allow,
            latency_ms: Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32),
            source_ip: req.source_ip.clone(),
        })
        .await
    {
        // The side effect already happened — `dispatch` (step 11) ran
        // before this point — so the caller MUST be denied (invariant 4:
        // audit failure denies), but the ledger's own `Allow` write never
        // landed. Silently returning `Err` here previously left this
        // outcome completely unaudited: the response says deny, the
        // durable store has nothing, and the sink's own stdout fallback
        // (which fired moments ago tagged `outcome: allow`, before this
        // failure was known) is now actively misleading. Two things fix
        // that: log loudly, and make a second, best-effort attempt to
        // write the TRUE outcome (`Deny`) — `audit_deny` has its own
        // failure handling (another loud log) if even that fails, but it
        // never makes this function's return value worse than it already
        // is; `Err(DependencyUnavailable)` is returned regardless of
        // whether the follow-up write succeeds.
        let reason = DenyReason::DependencyUnavailable("audit_sink");
        tracing::error!(
            request_id = %req.request_id,
            error = %audit_err,
            "allow-path audit write failed AFTER dispatch already ran — denying the caller and attempting a corrective deny record"
        );
        audit_deny(gates, req.request_id, Some(&identity), Some(&req.tool), tool_id, started, req.source_ip.as_deref(), reason).await;
        return Err(reason);
    }

    Ok(InvokeOutcome { request_id: req.request_id, result: filtered })
}

/// Resolves a bare tool name (as given in an MCP `tools/call` request) to a
/// concrete `ToolRef`, and returns the resolved `Identity` alongside it.
///
/// This is the structural fix for the historical `invoke_tool` indirection
/// bug: the old Python platform had a meta-tool that accepted an arbitrary
/// sub-tool name in its arguments and resolved it via a database lookup
/// that was NOT scoped to the caller's entitled set, checking entitlement
/// only after resolving — which let a quarantined/unentitled tool's row get
/// silently substituted for a different, entitled tool's row when names
/// collided. Here there is no separate lookup path at all: a name is only
/// ever resolved by finding it in `EntitlementStore::list_visible`, the
/// exact same call that answers `tools/list`. A name absent from that list
/// cannot be invoked — full stop, not "invoked and then checked".
pub async fn resolve_tool_by_name(
    gates: &Gates,
    raw: &RawCredential,
    name: &str,
    request_id: RequestId,
    source_ip: Option<&str>,
) -> Result<(Identity, ToolRef), DenyReason> {
    let started = Instant::now();
    let identity = match gates.authenticator.authenticate(raw).await {
        Ok(identity) => identity,
        Err(_) => {
            audit_deny(gates, request_id, None, None, None, started, source_ip, DenyReason::Unauthenticated).await;
            return Err(DenyReason::Unauthenticated);
        }
    };
    let visible = match gates.entitlement.list_visible(&identity).await {
        Ok(visible) => visible,
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            audit_deny(gates, request_id, Some(&identity), None, None, started, source_ip, reason).await;
            return Err(reason);
        }
    };
    match visible.into_iter().find(|t| t.tool == name) {
        Some(tool) => Ok((identity, tool)),
        None => {
            // No resolved `ToolRef` exists for a name outside the visible
            // set (that's the whole point of this function — see the doc
            // comment above) — a synthetic, server-less `ToolRef` carries
            // just the attempted name into the audit record. Safe: the D1
            // fix means `Deny` never writes `server_id` from `tool` at all
            // (see `wiring::audit`'s adapter), so a nil `ServerId` here
            // can never reach the FK column.
            let synthetic_tool = ToolRef { server: mcphub_types::ServerId(uuid::Uuid::nil()), tool: name.to_string() };
            audit_deny(gates, request_id, Some(&identity), Some(&synthetic_tool), None, started, source_ip, DenyReason::EntitlementMissing).await;
            Err(DenyReason::EntitlementMissing)
        }
    }
}

/// `/mcp` `tools/list`'s audited counterpart to `list_visible` — used by
/// `routers::mcp::handle_tools_list` so an unauthenticated (or otherwise
/// failing) discovery request is audited exactly like every other denial,
/// instead of returning straight to the caller with no record anywhere
/// (the gap this function exists to close — see `audit_deny`'s doc
/// comment).
pub async fn list_visible_audited(
    gates: &Gates,
    raw: &RawCredential,
    request_id: RequestId,
    source_ip: Option<&str>,
) -> Result<Vec<ToolRef>, DenyReason> {
    let started = Instant::now();
    let identity = match gates.authenticator.authenticate(raw).await {
        Ok(identity) => identity,
        Err(_) => {
            audit_deny(gates, request_id, None, None, None, started, source_ip, DenyReason::Unauthenticated).await;
            return Err(DenyReason::Unauthenticated);
        }
    };
    match gates.entitlement.list_visible(&identity).await {
        Ok(visible) => Ok(visible),
        Err(e) => {
            tracing::info!(gate_error = ?e, "gate returned an error; collapsing to a deny reason");
            let reason = e.to_deny_reason();
            audit_deny(gates, request_id, Some(&identity), None, None, started, source_ip, reason).await;
            Err(reason)
        }
    }
}

/// D8: roles held AT DECISION TIME, for the audit ledger. `Debug`-derived
/// (not the `authz.rego` role vocabulary — that mapping is a policy-bundle
/// concern the gateway crate doesn't own) since this is a forensic label,
/// not something re-parsed by any consumer.
fn identity_role_strings(identity: &Identity) -> Vec<String> {
    identity.roles.iter().map(|g| format!("{:?}", g.role)).collect()
}

/// D-critic finding: this gate used to also check `meta.network_isolated`,
/// a field `bin/mcphubd`'s `EntitlementStore` adapter hardcoded to `true`
/// for every tool — a check that could never fire, which reads as
/// enforcement in both the code and ARCHITECTURE.md's enforcement-order
/// docs while doing nothing. Removed rather than wired to a fake signal:
/// there is no per-tool/per-server DB column recording whether a given
/// backend is actually network-isolated (see the historical note that used
/// to live on `mcphub_types::ui_data::McpServer` — deliberately no such
/// column, because network isolation here is a PLATFORM-WIDE property, not
/// a per-row fact this service observes). Isolation (ARCHITECTURE.md
/// invariant 6: "only the gateway may reach a backend") is enforced at the
/// network/deployment layer instead — container/podman network policy that
/// makes a backend genuinely unreachable except via the gateway, verified
/// out-of-band by `scripts/check_network_isolation.py` /
/// `verify_isolation.py` (deploy-time, not a per-request Rust check). See
/// ARCHITECTURE.md's invariant 6 for the updated wording pointing there.
fn check_ingress(meta: &ToolMeta) -> Result<(), DenyReason> {
    if !meta.server_enabled {
        return Err(DenyReason::NoGrant);
    }
    Ok(())
}

/// Per-tool RBAC floor (ARCHITECTURE.md chain step 4; backed by migration
/// 0012's `tool_registry.required_role`). `meta.required_role == None`
/// means "no per-tool role requirement" — allow, subject to every other
/// gate — NOT "unknown, deny". This is deliberately the OPPOSITE reading
/// from the taint floor's `trust_tier == 0` (below), where an unknown/
/// unscanned value fails closed: `required_role` NULL is the true, common,
/// unremarkable state for a tool (most tools have no extra role floor
/// above whatever grants/RBAC already demand), and every row is NULL
/// before an operator explicitly opts a specific tool in — reading NULL as
/// "deny" would lock out the entire platform the moment this column
/// existed. See migration 0012's own comment for the identical note from
/// the schema side; if a future column is added with `risk_level`-style
/// "NULL means unknown, fail closed" semantics, do not assume this one
/// matches that pattern.
fn check_rbac(identity: &Identity, meta: &ToolMeta) -> Result<(), DenyReason> {
    match meta.required_role {
        Some(role) if !identity.has_role(role) => Err(DenyReason::NoGrant),
        _ => Ok(()),
    }
}

/// TODO: confirm exact taint-floor threshold/config source with architect;
/// mirroring the Python platform's B-coarse floor, `trust_tier == 0` (fully
/// untrusted, unscanned) denies outright in enforce mode. Higher tiers pass
/// through to the (policy-engine-attached) notify disclaimer instead.
fn check_taint_floor(meta: &ToolMeta) -> Result<(), DenyReason> {
    if meta.trust_tier == 0 {
        return Err(DenyReason::TaintFloor);
    }
    Ok(())
}

/// Backend dispatch contract, identity half (see ARCHITECTURE.md's "Backend
/// dispatch contract" section for the full spec this implements). Header
/// names match the Python platform's SDK (`sdk/mcphub-sdk/mcphub_sdk/
/// context.py`) exactly — `X-User-Sub` / `X-User-Role` — so existing and
/// SDK-scaffolded backends work unmodified. `X-User-Roles` (plural) is new:
/// the Python single-string `role` header cannot express multiple roles
/// with provenance, so it is a compat shim only (best rank wins), while
/// `X-User-Roles` carries the full `role@issuer` list any backend that
/// cares about provenance should read instead — see `GrantedRole`'s own doc
/// comment for why a role without its asserting issuer is not safe to trust.
///
/// SECURITY: strips any pre-existing entry for these header names from
/// `headers` BEFORE inserting the gateway-computed value — never merges,
/// never trusts anything already present. `headers` today only ever
/// originates from `CredentialBroker::inject` (never from raw client HTTP
/// headers — there is no such pass-through path in this router), but this
/// strip-then-set order is the one thing standing between a future
/// change that DOES merge client-controlled data into `headers` and a
/// repeat of the exact bug a critic found one layer up the stack (nginx
/// forwarding `X-Client-Cert-CN` unscrubbed on a shared port): complete
/// identity spoofing against every backend at once. See
/// `identity_headers_overwrite_any_preexisting_entry_never_merge` below.
const IDENTITY_HEADER_SUB: &str = "X-User-Sub";
const IDENTITY_HEADER_ROLE: &str = "X-User-Role";
const IDENTITY_HEADER_ROLES: &str = "X-User-Roles";

fn set_identity_headers(headers: &mut std::collections::HashMap<String, String>, identity: &Identity) {
    for key in [IDENTITY_HEADER_SUB, IDENTITY_HEADER_ROLE, IDENTITY_HEADER_ROLES] {
        headers.remove(key);
    }
    headers.insert(IDENTITY_HEADER_SUB.to_string(), identity.sub.clone());
    // Compat shim for the single-string Python `role` header: highest-rank
    // role wins (matches the platform's existing single-role mental model
    // — see `mcphub_types::Role::rank`), never a list, never provenance.
    let best_role = identity.roles.iter().max_by_key(|g| g.role.rank());
    headers.insert(IDENTITY_HEADER_ROLE.to_string(), best_role.map(|g| g.role.as_str()).unwrap_or("agent").to_string());
    let roles_with_provenance = identity
        .roles
        .iter()
        .map(|g| format!("{}@{}", g.role.as_str(), g.asserted_by))
        .collect::<Vec<_>>()
        .join(",");
    headers.insert(IDENTITY_HEADER_ROLES.to_string(), roles_with_provenance);
}

async fn deny_and_audit(
    gates: &Gates,
    req: &InvokeRequest,
    identity: Option<&Identity>,
    tool_id: Option<uuid::Uuid>,
    started: Instant,
    reason: DenyReason,
) {
    audit_deny(gates, req.request_id, identity, Some(&req.tool), tool_id, started, req.source_ip.as_deref(), reason).await;
}

/// The general form of `deny_and_audit`, callable from outside `invoke`
/// itself. Exists because denials happen at TWO call sites that are not
/// `invoke`: `resolve_tool_by_name` (bare-name resolution, `/mcp`
/// `tools/call`) and `list_visible_audited` (`/mcp` `tools/list`) — before
/// this fix, both denied by returning `Err`/an empty list straight to their
/// caller with no audit emit anywhere, so an unauthenticated `tools/call`
/// or `tools/list` over the primary MCP protocol produced ZERO records in
/// Postgres, redis, AND stdout (the REST path audited the identical
/// denials correctly the whole time — this was an `/mcp`-specific gap).
pub(crate) async fn audit_deny(
    gates: &Gates,
    request_id: RequestId,
    identity: Option<&Identity>,
    tool: Option<&ToolRef>,
    tool_id: Option<uuid::Uuid>,
    started: Instant,
    source_ip: Option<&str>,
    reason: DenyReason,
) {
    // Best-effort: a failure to audit a deny is logged by the AuditSink
    // implementation itself; unlike the allow path, invoke() has already
    // decided to deny regardless of whether the audit write succeeds, so we
    // do not further fail the outcome here. This mirrors the Python
    // platform's INV-001 synchronous-deny-audit behavior without changing
    // the already-decided Deny outcome.
    if let Err(audit_err) = gates
        .audit
        .emit(AuditRecord {
            request_id,
            identity_sub: identity.map(|i| i.sub.clone()),
            identity_issuer: identity.map(|i| i.issuer.0.clone()),
            identity_roles: identity.map(identity_role_strings).unwrap_or_default(),
            tool: tool.cloned(),
            tool_id,
            outcome: AuditOutcome::Deny(reason),
            latency_ms: Some(started.elapsed().as_millis().min(u32::MAX as u128) as u32),
            source_ip: source_ip.map(str::to_string),
        })
        .await
    {
        // Invariant 4 already denies the caller regardless (the outcome
        // was decided before this function was ever called) — this branch
        // exists so a failed deny-audit is LOUD, never silent. A bare
        // `let _ =` here previously made a rejected/failed write
        // indistinguishable from a written one; see the AuditSink adapter
        // for the stdout-fallback half of this fix.
        tracing::error!(
            %request_id,
            deny_reason = %reason,
            error = %audit_err,
            "deny-path audit write failed — the request is still denied, but this deny record may be incomplete in the durable store"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{DenyAll, ToolMeta};
    use async_trait::async_trait;
    use mcphub_types::{GateError, GrantedRole, IssuerId, Role, ServerId, TokenRef};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn test_tool() -> ToolRef {
        ToolRef { server: ServerId(Uuid::nil()), tool: "echo".into() }
    }

    fn test_identity() -> Identity {
        Identity {
            sub: "user-1".into(),
            issuer: IssuerId::new("platform"),
            email: None,
            roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
            groups: vec![],
            token_ref: TokenRef::none(),
        }
    }

    fn test_req() -> InvokeRequest {
        InvokeRequest {
            request_id: RequestId::new(Uuid::nil()),
            raw_credential: RawCredential { bearer_token: Some("t".into()), ..Default::default() },
            tool: test_tool(),
            params: serde_json::json!({}),
            source_ip: Some("127.0.0.1".to_string()),
        }
    }

    struct OkAuth;
    #[async_trait]
    impl Authenticator for OkAuth {
        async fn authenticate(&self, _raw: &RawCredential) -> Result<Identity, GateError> {
            Ok(test_identity())
        }
    }

    struct OkEntitlement { visible: bool, meta_err: bool }
    #[async_trait]
    impl EntitlementStore for OkEntitlement {
        async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
            if self.meta_err {
                return Err(GateError::DependencyUnavailable("store"));
            }
            Ok(ToolMeta {
                server: test_tool().server,
                server_enabled: true,
                quarantined: false,
                // Deliberately `Some`, not `None` — this is the baseline
                // fixture nearly every test in this file shares via
                // `happy_gates()`. `test_identity()` holds `Role::Employee`,
                // so this stays a no-op pass-through for every OTHER test's
                // assertions, but it exercises `check_rbac`'s "identity HAS
                // the role" branch instead of every fixture in this file
                // uniformly taking the `None` short-circuit — see the
                // critic finding this responds to: every fixture setting
                // the same passing value is how a dead gate hides.
                required_role: Some(mcphub_types::Role::Employee),
                trust_tier: 5,
                upstream_host: "backend.internal".into(),
                allowed_cidr: None,
                tool_id: None,
            })
        }
        async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
            Ok(if self.visible { vec![test_tool()] } else { vec![] })
        }
    }

    struct OkRateLimiter;
    #[async_trait]
    impl RateLimiter for OkRateLimiter {
        async fn check(&self, _identity: &Identity, _tool: &ToolRef) -> Result<(), GateError> {
            Ok(())
        }
    }

    struct OkPolicy;
    #[async_trait]
    impl PolicyEngine for OkPolicy {
        async fn evaluate(
            &self,
            _identity: &Identity,
            _tool: &ToolRef,
            _input: &serde_json::Value,
        ) -> Result<Decision, GateError> {
            Ok(Decision::Allow { obligations: Default::default() })
        }
    }

    struct OkCreds;
    #[async_trait]
    impl CredentialBroker for OkCreds {
        async fn inject(&self, _identity: &Identity, _tool: &ToolRef) -> Result<HashMap<String, String>, GateError> {
            Ok(HashMap::new())
        }
    }

    struct OkDispatch;
    #[async_trait]
    impl BackendDispatcher for OkDispatch {
        async fn dispatch(
            &self,
            _tool: &ToolRef,
            _request_id: RequestId,
            _headers: &HashMap<String, String>,
            _body: &serde_json::Value,
        ) -> Result<serde_json::Value, GateError> {
            Ok(serde_json::json!({"ok": true}))
        }
    }

    /// Records whatever headers actually reached `dispatch`, so tests can
    /// assert on the gateway's identity-header contract from the outside
    /// (the only place that matters — what a backend actually observes).
    struct SpyDispatch {
        seen_headers: std::sync::Mutex<Option<HashMap<String, String>>>,
    }
    impl SpyDispatch {
        fn new() -> Self {
            Self { seen_headers: std::sync::Mutex::new(None) }
        }
    }
    #[async_trait]
    impl BackendDispatcher for SpyDispatch {
        async fn dispatch(
            &self,
            _tool: &ToolRef,
            _request_id: RequestId,
            headers: &HashMap<String, String>,
            _body: &serde_json::Value,
        ) -> Result<serde_json::Value, GateError> {
            *self.seen_headers.lock().unwrap() = Some(headers.clone());
            Ok(serde_json::json!({"ok": true}))
        }
    }

    /// A credential broker standing in for either a misconfigured
    /// credential (an admin accidentally naming a stored credential
    /// `X-User-Sub`) or a future refactor that merges other header sources
    /// in — either way, `headers` arrives at `dispatch` already containing
    /// an attacker-shaped identity header BEFORE the gateway's own
    /// strip-then-set runs.
    struct CredsWithSpoofedIdentityHeader;
    #[async_trait]
    impl CredentialBroker for CredsWithSpoofedIdentityHeader {
        async fn inject(&self, _identity: &Identity, _tool: &ToolRef) -> Result<HashMap<String, String>, GateError> {
            let mut h = HashMap::new();
            h.insert("X-User-Sub".to_string(), "someone-else".to_string());
            h.insert("X-User-Role".to_string(), "super_admin".to_string());
            h.insert("X-User-Roles".to_string(), "super_admin@https://attacker.example.com".to_string());
            Ok(h)
        }
    }

    struct OkAudit;
    #[async_trait]
    impl AuditSink for OkAudit {
        async fn emit(&self, _record: AuditRecord) -> Result<(), GateError> {
            Ok(())
        }
    }

    fn happy_gates() -> Gates {
        Gates {
            authenticator: Arc::new(OkAuth),
            entitlement: Arc::new(OkEntitlement { visible: true, meta_err: false }),
            rate_limiter: Arc::new(OkRateLimiter),
            policy: Arc::new(OkPolicy),
            credentials: Arc::new(OkCreds),
            dispatcher: Arc::new(OkDispatch),
            audit: Arc::new(OkAudit),
        }
    }

    #[tokio::test]
    async fn happy_path_allows() {
        let gates = happy_gates();
        let outcome = invoke(&gates, test_req()).await.expect("should allow");
        assert_eq!(outcome.result, serde_json::json!({"ok": true}));
    }

    /// Invariant 1: `Err` from any gate maps to Deny, never Allow. Sweeps
    /// every gate in the chain, substituting a `DenyAll` (or Err-returning)
    /// implementation for that one gate while keeping the rest happy, and
    /// asserts the outcome is always `Err(DenyReason)`.
    #[tokio::test]
    async fn err_from_every_gate_maps_to_deny() {
        // authenticator
        let mut gates = happy_gates();
        gates.authenticator = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // entitlement (tool_meta lookup failure)
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(OkEntitlement { visible: true, meta_err: true });
        assert!(invoke(&gates, test_req()).await.is_err());

        // entitlement (list_visible failure)
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // rate limiter
        let mut gates = happy_gates();
        gates.rate_limiter = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // policy
        let mut gates = happy_gates();
        gates.policy = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // credentials
        let mut gates = happy_gates();
        gates.credentials = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // dispatcher
        let mut gates = happy_gates();
        gates.dispatcher = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());

        // audit (allow-path emit failure must still deny the outcome)
        let mut gates = happy_gates();
        gates.audit = Arc::new(DenyAll);
        assert!(invoke(&gates, test_req()).await.is_err());
    }

    /// Discovery == invoke, enforced inside `invoke`, not the lister: a tool
    /// absent from `list_visible` is denied with `EntitlementMissing`, and
    /// the same store call backs both `tools/list` and this gate.
    #[tokio::test]
    async fn discovery_eq_invoke_denies_tool_not_in_list() {
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(OkEntitlement { visible: false, meta_err: false });
        let err = invoke(&gates, test_req()).await.unwrap_err();
        assert_eq!(err, DenyReason::EntitlementMissing);
    }

    #[tokio::test]
    async fn quarantined_tool_denied_before_entitlement() {
        struct QuarantinedEntitlement;
        #[async_trait]
        impl EntitlementStore for QuarantinedEntitlement {
            async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
                Ok(ToolMeta {
                    server: test_tool().server,
                    server_enabled: true,
                    quarantined: true,
                    required_role: None,
                    trust_tier: 5,
                    upstream_host: "backend.internal".into(),
                    allowed_cidr: None,
                    tool_id: None,
                })
            }
            async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
                // Even if it WOULD be visible, quarantine must win — it is
                // ordered before entitlement.
                Ok(vec![test_tool()])
            }
        }
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(QuarantinedEntitlement);
        let err = invoke(&gates, test_req()).await.unwrap_err();
        assert_eq!(err, DenyReason::Quarantined);
    }

    #[tokio::test]
    async fn rbac_denies_role_without_required_role() {
        struct RoleGatedEntitlement;
        #[async_trait]
        impl EntitlementStore for RoleGatedEntitlement {
            async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
                Ok(ToolMeta {
                    server: test_tool().server,
                    server_enabled: true,
                    quarantined: false,
                    required_role: Some(Role::SuperAdmin),
                    trust_tier: 5,
                    upstream_host: "backend.internal".into(),
                    allowed_cidr: None,
                    tool_id: None,
                })
            }
            async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
                Ok(vec![test_tool()])
            }
        }
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(RoleGatedEntitlement);
        let err = invoke(&gates, test_req()).await.unwrap_err();
        assert_eq!(err, DenyReason::NoGrant);
    }

    /// Companion to `rbac_denies_role_without_required_role`: proves the
    /// gate isn't just an unconditional deny — an identity that HAS the
    /// required role is allowed through (subject to every other gate, all
    /// happy here). Without this, a mutation that made `check_rbac` always
    /// return `Err` would pass the deny test above and go unnoticed.
    #[tokio::test]
    async fn rbac_allows_identity_with_the_required_role() {
        struct RoleGatedEntitlement;
        #[async_trait]
        impl EntitlementStore for RoleGatedEntitlement {
            async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
                Ok(ToolMeta {
                    server: test_tool().server,
                    server_enabled: true,
                    quarantined: false,
                    // test_identity() holds Role::Employee — see below.
                    required_role: Some(Role::Employee),
                    trust_tier: 5,
                    upstream_host: "backend.internal".into(),
                    allowed_cidr: None,
                    tool_id: None,
                })
            }
            async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
                Ok(vec![test_tool()])
            }
        }
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(RoleGatedEntitlement);
        let outcome = invoke(&gates, test_req()).await;
        assert!(outcome.is_ok(), "identity holding the required role must be allowed through, got {outcome:?}");
    }

    /// Pins the quarantine-bypass fix: a name not present in
    /// `list_visible` cannot be resolved to a `ToolRef` at all — there is
    /// no fallback lookup that could substitute a different tool's row.
    #[tokio::test]
    async fn resolve_tool_by_name_denies_names_outside_visible_set() {
        let gates = happy_gates(); // OkEntitlement { visible: true } exposes only "echo"
        let err = resolve_tool_by_name(&gates, &RawCredential { bearer_token: Some("t".into()), ..Default::default() }, "some-other-tool", RequestId::new(Uuid::nil()), None)
            .await
            .unwrap_err();
        assert_eq!(err, DenyReason::EntitlementMissing);
    }

    #[tokio::test]
    async fn resolve_tool_by_name_finds_visible_tool() {
        let gates = happy_gates();
        let (_identity, tool) = resolve_tool_by_name(
            &gates,
            &RawCredential { bearer_token: Some("t".into()), ..Default::default() },
            "echo",
            RequestId::new(Uuid::nil()),
            None,
        )
        .await
        .expect("echo is visible");
        assert_eq!(tool.tool, "echo");
    }

    #[tokio::test]
    async fn taint_floor_denies_untrusted_tool() {
        struct UntrustedEntitlement;
        #[async_trait]
        impl EntitlementStore for UntrustedEntitlement {
            async fn tool_meta(&self, _tool: &ToolRef) -> Result<ToolMeta, GateError> {
                Ok(ToolMeta {
                    server: test_tool().server,
                    server_enabled: true,
                    quarantined: false,
                    required_role: None,
                    trust_tier: 0,
                    upstream_host: "backend.internal".into(),
                    allowed_cidr: None,
                    tool_id: None,
                })
            }
            async fn list_visible(&self, _identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
                Ok(vec![test_tool()])
            }
        }
        let mut gates = happy_gates();
        gates.entitlement = Arc::new(UntrustedEntitlement);
        let err = invoke(&gates, test_req()).await.unwrap_err();
        assert_eq!(err, DenyReason::TaintFloor);
    }
}
