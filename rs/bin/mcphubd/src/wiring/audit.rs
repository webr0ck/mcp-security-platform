//! Reconciles the two `AuditSink` traits: `mcphub-gateway`'s (the one
//! `invocation::invoke` actually calls — it owns the enforcement choke
//! point) and `mcphub-store`'s (defined before `mcphub-gateway::src` had
//! any content). We keep the gateway trait as canonical and adapt
//! `mcphub_store::PgRedisAuditSink` to it here, rather than maintaining two
//! parallel traits anywhere else in the tree.

use async_trait::async_trait;
use mcphub_gateway::traits::{AuditOutcome, AuditRecord as GwAuditRecord, AuditSink as GwAuditSink};
use mcphub_store::audit::{AuditRecord as StoreAuditRecord, AuditSink as StoreAuditSink, Outcome as StoreOutcome};
use mcphub_types::GateError;
use uuid::Uuid;

pub struct AuditSinkAdapter<S: StoreAuditSink> {
    inner: S,
}

impl<S: StoreAuditSink> AuditSinkAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

/// Bound at the audit-write boundary too (belt-and-braces alongside store's
/// own backstop and the gateway routers' ingress validation): `tool_name`
/// lands in an APPEND-ONLY table with no UPDATE/DELETE path, so anything
/// that slips in has no remediation short of dropping the table.
const MAX_TOOL_NAME_LEN: usize = 256;

fn sanitize_tool_name(name: &str) -> String {
    let truncated: String = name.chars().take(MAX_TOOL_NAME_LEN).collect();
    if truncated.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-')) && !truncated.is_empty() {
        truncated
    } else {
        // Must itself satisfy the same charset this function enforces —
        // `[invalid]`'s brackets are outside `[A-Za-z0-9._:-]`, so a
        // fallback value that can't pass ingress validation is a trap for
        // whatever consumes this later. Unreachable today (both routers
        // reject an invalid name with 400 before `invoke` is ever called —
        // see `routers::validate_tool_name`), kept only as defense in depth
        // for any future caller of this adapter that doesn't route through
        // ingress validation first.
        "invalid".to_string()
    }
}

#[async_trait]
impl<S: StoreAuditSink + Send + Sync> GwAuditSink for AuditSinkAdapter<S> {
    async fn emit(&self, record: GwAuditRecord) -> Result<(), GateError> {
        let (outcome, deny_reason) = match record.outcome {
            AuditOutcome::Allow => (StoreOutcome::Allow, None),
            AuditOutcome::Deny(reason) => (StoreOutcome::Deny, Some(reason.code().to_string())),
        };

        // D1 fix: `record.tool.server` is populated straight off the wire
        // (`ToolRef { server: ServerId(body.server_id), .. }` in
        // `routers::rest::invoke_tool`) and every deny path that reaches
        // this sink — `invoke()`'s own `deny_and_audit`, plus
        // `resolve_tool_by_name`/`list_visible_audited`'s `audit_deny`
        // calls for the `/mcp` path's pre-`invoke` denials — passes that
        // same unvalidated `ToolRef` through. Writing an attacker-controlled UUID
        // straight into an FK column means a bogus `server_id` makes the
        // INSERT itself fail (23503), and `PgRedisAuditSink`'s ordering
        // means that failure short-circuits before it ever reaches its own
        // stdout fallback — so a probe with a bogus token AND a bogus
        // server_id leaves zero trace anywhere. On `Allow`, `dispatch` has
        // already happened, which only occurs after `tool_meta` confirmed
        // the server row exists — so the FK is provably valid there. On
        // `Deny`, never trust it; the raw claimed value still travels (not
        // an FK, no injection-into-a-constraint risk) via `tool_name`.
        let server_id = match record.outcome {
            AuditOutcome::Allow => record.tool.as_ref().map(|t| t.server.0),
            AuditOutcome::Deny(_) => None,
        };
        let tool_name = record.tool.as_ref().map(|t| sanitize_tool_name(&t.tool)).unwrap_or_default();

        // D8: forensic fields. `principal_id` still falls back to a fixed
        // sentinel for pre-authentication denials (there is no real
        // principal yet at that point in the chain) — but `source_ip` is
        // now populated regardless, so distinct unauthenticated attempts
        // from distinct sources no longer collapse into one indistinguishable
        // bucket the way they did before this fix.
        let store_record = StoreAuditRecord {
            event_id: Uuid::new_v4(),
            request_id: record.request_id.to_string(),
            principal_id: record.identity_sub.clone().unwrap_or_else(|| "unauthenticated".to_string()),
            issuer: record.identity_issuer.clone(),
            server_id,
            tool_id: record.tool_id,
            tool_name,
            outcome,
            deny_reason,
            latency_ms: record.latency_ms.map(|ms| ms as i32),
            source_ip: record.source_ip.clone(),
            enrichment: mcphub_store::audit::AuditEnrichment { roles: record.identity_roles.clone(), ..Default::default() },
        };

        // Unconditional stdout line BEFORE attempting the store's own
        // Postgres/redis/stdout sequence: `PgRedisAuditSink::emit` fails
        // its whole call (no partial success) the instant the Postgres
        // INSERT errors, which — before this — meant a rejected write
        // (bad FK, transient outage, anything) left NO trace anywhere,
        // silencing exactly the events (probes with bogus IDs, DB hiccups
        // mid-attack) an auditor most needs. This can't itself fail in a
        // way that suppresses the line — `tracing` writing to stdout is
        // not something an attacker-controlled value can turn into an
        // error the way a DB constraint can.
        tracing::info!(
            target: "mcp_audit_fallback",
            request_id = %store_record.request_id,
            principal_id = %store_record.principal_id,
            tool_name = %store_record.tool_name,
            outcome = ?store_record.outcome,
            deny_reason = ?store_record.deny_reason,
            "audit event (stdout fallback, precedes store write)"
        );

        self.inner.emit(store_record).await
    }

    fn is_healthy(&self) -> bool {
        self.inner.is_healthy()
    }
}
