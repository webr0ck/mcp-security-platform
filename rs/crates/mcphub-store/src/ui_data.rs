//! `PgUiData` — the Postgres implementation of `mcphub_types::UiData`
//! (moved there from `mcphub-ui` — see that module's doc comment — so this
//! crate depends only on `mcphub-types`, never on the presentation crate).
//! Requested by component 5 (`crates/mcphub-ui/src/data.rs`): "Component
//! 4: please implement `UiData` against Postgres and swap `InMemoryUiData`
//! out at the wiring site in `bin/mcphubd`."
//!
//! This is a read/write seam for the ADMIN PORTAL, not the tool-invocation
//! hot path — none of these queries need the pool-sizing/latency care that
//! `repo::grants` or `audit.rs` do. Several of the trait's view shapes
//! don't have a direct table in the 0001-0004 hot-path schema (access
//! requests, anomaly alerts, a single global rate-limit default row), so
//! `0005_ui_support.up.sql` adds three UI-only tables to back them.
//!
//! Known simplifications (flagged, not hidden):
//! - `ServerHealth` (Healthy/Degraded/Unreachable) has no backing table —
//!   there is no liveness/health-check subsystem in this schema. Derived
//!   from `servers.status` as a placeholder; a real health check belongs
//!   to whichever component owns backend connectivity probing.
//! - `McpServer` has no `network_isolated` field anymore (removed, not
//!   just unused here) — network isolation is enforced platform-wide by
//!   the gateway (ARCHITECTURE.md invariant 6), not a per-server toggle,
//!   so there was never a real per-row signal to back it; an unconditional
//!   "Isolated ✓" would have been a false assurance to the security team.
//! - `IdpConfig::kind` (the display-only "entra"/"keycloak"/"generic_oidc"
//!   label) isn't stored — `idp_configs` doesn't have an adapter-kind
//!   column. Derived heuristically from the issuer URL; genuinely wrong
//!   for issuers that don't match the heuristic. `UiData::create_idp`'s
//!   input type also has no `client_id`/`scopes`/`discovery_url` fields,
//!   so rows created through this path get empty placeholders for those —
//!   the real admin-onboarding flow needs a fuller form than this trait
//!   currently exposes (component 5, please extend `IdpConfig`/
//!   `create_idp` if/when that flow is built).
//! - `display_roles_all_issuers(sub)` (named that, not `roles_for`,
//!   precisely so it cannot be mistaken for the enforcement lookup)
//!   aggregates role grants across every issuer for that `sub`. Fine for a
//!   display list; the enforcement path is `repo::roles::resolve_roles`,
//!   which is issuer-scoped and IS what `invoke()` must call — see
//!   `repo::roles`'s test proving two identities sharing a `sub` under
//!   different issuers do not see each other's roles there.

use crate::repo::roles::{role_from_db, role_to_db};
use async_trait::async_trait;
use mcphub_types::ui_data::*;
use mcphub_types::{AuthMode, DenyReason, Role, ServerId};
use sqlx::PgPool;
use uuid::Uuid;

pub struct PgUiData {
    pool: PgPool,
}

impl PgUiData {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn auth_mode_view(mode: &str, port: Option<i32>) -> AuthModeView {
    let mode = match mode {
        "shared_passthrough" => AuthMode::SharedPassthrough,
        "shared_exchange" => AuthMode::SharedExchange,
        "dedicated_port" => AuthMode::DedicatedPort { port: port.unwrap_or(0) as u16 },
        _ => AuthMode::SharedPassthrough, // unreachable given the DB CHECK constraint; safe default
    };
    mode.into()
}

fn server_health(status: &str) -> ServerHealth {
    // ponytail: no health-check subsystem backs this yet — see module docs.
    match status {
        "approved" => ServerHealth::Healthy,
        "suspended" => ServerHealth::Degraded,
        _ => ServerHealth::Unreachable,
    }
}

fn onboarding_status(status: &str) -> OnboardingStatus {
    match status {
        "pending" => OnboardingStatus::PendingReview,
        "approved" => OnboardingStatus::Approved,
        _ => OnboardingStatus::Rejected, // suspended, quarantined, rejected all read as "not usable"
    }
}

#[derive(sqlx::FromRow)]
struct ServerDbRow {
    server_id: Uuid,
    name: String,
    owner_principal_id: String,
    auth_mode: String,
    dedicated_port: Option<i32>,
    status: String,
    deleted_at: Option<time::OffsetDateTime>,
}

impl From<ServerDbRow> for McpServer {
    fn from(r: ServerDbRow) -> Self {
        McpServer {
            id: ServerId(r.server_id),
            name: r.name,
            owner_sub: r.owner_principal_id,
            auth_mode: auth_mode_view(&r.auth_mode, r.dedicated_port),
            health: server_health(&r.status),
            onboarding: onboarding_status(&r.status),
            enabled: r.status == "approved" && r.deleted_at.is_none(),
        }
    }
}

fn deny_reason_view_from_code(code: &str) -> Option<DenyReasonView> {
    // The DB only stores the stable machine code, not the original
    // structured DenyReason (e.g. DependencyUnavailable's inner &str is
    // lost). Reconstruct the closest DenyReason for display purposes only.
    let reason = match code {
        "unauthenticated" => DenyReason::Unauthenticated,
        "no_grant" => DenyReason::NoGrant,
        "quarantined" => DenyReason::Quarantined,
        "policy_denied" => DenyReason::PolicyDenied,
        "entitlement_missing" => DenyReason::EntitlementMissing,
        "rate_limited" => DenyReason::RateLimited,
        "taint_floor" => DenyReason::TaintFloor,
        "dependency_unavailable" => DenyReason::DependencyUnavailable("unknown"),
        _ => return None,
    };
    Some(reason.into())
}

#[async_trait]
impl UiData for PgUiData {
    async fn servers_for_owner(&self, owner_sub: &str) -> Vec<McpServer> {
        sqlx::query_as::<_, ServerDbRow>(
            "SELECT s.server_id, s.name, s.owner_principal_id, s.auth_mode::text, i.dedicated_port, s.status::text, s.deleted_at
             FROM servers s LEFT JOIN idp_configs i ON i.idp_id = s.idp_id AND i.deleted_at IS NULL
             WHERE s.owner_principal_id = $1 AND s.deleted_at IS NULL",
        )
        .bind(owner_sub)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, owner = %owner_sub, "servers_for_owner: query failed; returning empty list");
            Vec::new()
        })
        .into_iter()
        .map(McpServer::from)
        .collect()
    }

    async fn all_servers(&self) -> Vec<McpServer> {
        sqlx::query_as::<_, ServerDbRow>(
            "SELECT s.server_id, s.name, s.owner_principal_id, s.auth_mode::text, i.dedicated_port, s.status::text, s.deleted_at
             FROM servers s LEFT JOIN idp_configs i ON i.idp_id = s.idp_id AND i.deleted_at IS NULL
             WHERE s.deleted_at IS NULL",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "all_servers: query failed; returning empty list (NOT \"no servers exist\")");
            Vec::new()
        })
        .into_iter()
        .map(McpServer::from)
        .collect()
    }

    async fn server_by_id(&self, id: ServerId) -> Option<McpServer> {
        sqlx::query_as::<_, ServerDbRow>(
            "SELECT s.server_id, s.name, s.owner_principal_id, s.auth_mode::text, i.dedicated_port, s.status::text, s.deleted_at
             FROM servers s LEFT JOIN idp_configs i ON i.idp_id = s.idp_id AND i.deleted_at IS NULL
             WHERE s.server_id = $1 AND s.deleted_at IS NULL",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, server_id = %id.0, "server_by_id: query failed; treating as not found");
            None
        })
        .map(McpServer::from)
    }

    async fn tools_for_server(&self, id: ServerId) -> Vec<ToolEntry> {
        // NOTE: a query failure here and a "server not found" both
        // currently render as an empty owner name — server_by_id already
        // logs its own failure above, so this isn't a silent swallow, but
        // the two cases remain indistinguishable to the UI layer without a
        // richer return type than `Option<McpServer>` (out of this crate's
        // scope — see this crate's handoff report).
        let server_name = self.server_by_id(id).await.map(|s| s.name).unwrap_or_default();
        sqlx::query_as::<_, (String, String)>(
            "SELECT name, description FROM tool_registry
             WHERE server_id = $1 AND deleted_at IS NULL AND status = 'active'",
        )
        .bind(id.0)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, server_id = %id.0, "tools_for_server: query failed; returning empty list");
            Vec::new()
        })
        .into_iter()
        .map(|(tool_name, description)| ToolEntry {
            server_id: id,
            server_name: server_name.clone(),
            tool_name,
            description,
            // Owner-management view, not identity-scoped: every active
            // tool the owner registered is "invokable" in the sense that
            // it's live, not that any particular caller has a grant for
            // it. `catalog_for` below is the identity-scoped, grant-gated
            // view the discovery==invoke invariant actually applies to.
            invokable: true,
        })
        .collect()
    }

    async fn catalog_for(&self, sub: &str) -> Vec<ToolEntry> {
        // discovery==invoke (ARCHITECTURE.md invariant 3): only tools this
        // principal actually has a grant for are ever returned here.
        //
        // REVIEW NOTE (D10 fix — deviation from the original filter,
        // documented per this crate's conventions): the original filter
        // was `allowed_tools.contains(tool_name) || !allowed_tags.is_empty()`.
        // `tool_registry` has no tags column at all in this schema, so
        // `allowed_tags` can never be matched against anything the tool
        // actually has — the second disjunct degraded to "this principal
        // has ANY tag-based grant at all, on ANY server", which combined
        // with the platform-wide join above (`g.server_id IS NULL`) meant
        // one non-empty `allowed_tags` on a platform-wide grant exposed
        // every active tool on every approved server. That also disagreed
        // with `entitlement::list_visible` (the actual `tools/call`
        // enforcement path in bin/mcphubd), which correctly requires exact
        // name membership — i.e. discovery and invoke could show different
        // catalogs for the same principal, violating invariant 3 by
        // construction.
        //
        // Fix: require exact tool-name membership only, matching
        // `entitlement::list_visible` exactly. Tag-based grants are not
        // representable against this schema (no per-tool tags table) and
        // must not be treated as "matches everything" — see this crate's
        // handoff report for the schema addition (a `tool_tags` table, or
        // a `tags TEXT[]` column on `tool_registry`) needed to support
        // them for real.
        let rows = sqlx::query_as::<_, (Uuid, String, String, String, Vec<String>)>(
            "SELECT s.server_id, s.name, t.name, t.description, g.allowed_tools
             FROM tool_registry t
             JOIN servers s ON s.server_id = t.server_id AND s.deleted_at IS NULL AND s.status = 'approved'
             JOIN grants g ON g.principal_id = $1 AND (g.server_id = s.server_id OR g.server_id IS NULL)
             WHERE t.deleted_at IS NULL AND t.status = 'active'",
        )
        .bind(sub)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, principal = %sub, "catalog_for: query failed; returning empty catalog");
            Vec::new()
        });

        rows.into_iter()
            .filter(|(_, _, tool_name, _, allowed_tools)| allowed_tools.contains(tool_name))
            .map(|(server_id, server_name, tool_name, description, _)| ToolEntry {
                server_id: ServerId(server_id),
                server_name,
                tool_name,
                description,
                invokable: true,
            })
            .collect()
    }

    async fn grants_for(&self, sub: &str) -> Vec<Grant> {
        self.grants_matching("g.principal_id = $1", sub).await
    }

    async fn all_grants(&self) -> Vec<Grant> {
        self.grants_matching("TRUE", "").await
    }

    async fn save_grant(&self, grant: Grant) {
        // Flattens the UI's one-tool-per-row `Grant` onto this schema's
        // one-row-per-(principal, server) `grants.allowed_tools` array —
        // read-modify-write is fine here, this is an admin action, not a
        // hot path.
        //
        // REVIEW NOTE (D11 fix): the original code treated a READ FAILURE
        // the same as "no existing row" (`unwrap_or(None)`), then wrote
        // whatever it had (just the one new tool_name) back with
        // `allowed_tools = EXCLUDED.allowed_tools` — an UPSERT that
        // OVERWRITES the array, not appends. On a transient read error
        // against an EXISTING grant, that silently discarded every other
        // tool the principal had been granted. Fixed to abort the write
        // entirely (and log) when the read fails, rather than guessing
        // "empty" and clobbering. `save_grant`'s signature returns `()`
        // (defined in mcphub-types, outside this crate) so a genuine
        // error still can't be surfaced to the caller today — see this
        // crate's handoff report for the `Result`-returning trait change
        // this ultimately needs.
        let existing: Result<Option<(Vec<String>,)>, sqlx::Error> = sqlx::query_as(
            "SELECT allowed_tools FROM grants WHERE principal_id = $1 AND server_id = $2",
        )
        .bind(&grant.principal_sub)
        .bind(grant.server_id.0)
        .fetch_optional(&self.pool)
        .await;

        let existing = match existing {
            Ok(existing) => existing,
            Err(e) => {
                tracing::error!(
                    error = %e, principal = %grant.principal_sub, server_id = %grant.server_id.0,
                    "save_grant: failed to read existing grant; ABORTING write rather than risk \
                     clobbering allowed_tools with an incomplete array"
                );
                return;
            }
        };

        let mut allowed_tools = existing.map(|(t,)| t).unwrap_or_default();
        if let Some(tool_name) = &grant.tool_name {
            if !allowed_tools.contains(tool_name) {
                allowed_tools.push(tool_name.clone());
            }
        }

        if let Err(e) = sqlx::query(
            "INSERT INTO grants (principal_id, server_id, allowed_tools, granted_by)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (principal_id, server_id) DO UPDATE SET
                 allowed_tools = EXCLUDED.allowed_tools, granted_by = EXCLUDED.granted_by",
        )
        .bind(&grant.principal_sub)
        .bind(grant.server_id.0)
        .bind(&allowed_tools)
        .bind(&grant.granted_by)
        .execute(&self.pool)
        .await
        {
            tracing::error!(
                error = %e, principal = %grant.principal_sub, server_id = %grant.server_id.0,
                "save_grant: write failed"
            );
        }
    }

    async fn access_requests_for(&self, sub: &str) -> Vec<AccessRequest> {
        sqlx::query_as::<_, (Uuid, String, String, String, String)>(
            "SELECT r.request_id, s.name, r.tool_name, r.justification, r.status
             FROM access_requests r JOIN servers s ON s.server_id = r.server_id
             WHERE r.requester_sub = $1 ORDER BY r.created_at DESC",
        )
        .bind(sub)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, principal = %sub, "access_requests_for: query failed; returning empty list");
            Vec::new()
        })
        .into_iter()
        .map(|(id, server_name, tool_name, justification, status)| AccessRequest {
            id,
            requester_sub: sub.to_string(),
            server_name,
            tool_name,
            justification,
            status: access_request_status_static(&status),
        })
        .collect()
    }

    async fn create_access_request(&self, sub: &str, server_id: ServerId, tool_name: &str, justification: &str) {
        let _ = sqlx::query(
            "INSERT INTO access_requests (requester_sub, server_id, tool_name, justification)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(sub)
        .bind(server_id.0)
        .bind(tool_name)
        .bind(justification)
        .execute(&self.pool)
        .await;
    }

    async fn recent_audit_events(&self, limit: usize) -> Vec<AuditEvent> {
        self.audit_events_matching("TRUE", None, Some(limit as i64)).await
    }

    async fn audit_event(&self, id: Uuid) -> Option<AuditEvent> {
        self.audit_events_matching("e.event_id = $2", Some(id), Some(1)).await.into_iter().next()
    }

    async fn quarantine_entries(&self) -> Vec<QuarantineEntry> {
        // Server-level quarantines show as tool_name "*"; tool-level ones
        // resolve their owning server via tool_registry.
        let rows = sqlx::query_as::<_, (String, Uuid, String, String, String, time::OffsetDateTime)>(
            r#"
            SELECT q.target_type::text, s.server_id, s.name, '*', q.reason, q.quarantined_at
            FROM quarantine_events q JOIN servers s ON s.server_id = q.target_id
            WHERE q.target_type = 'server' AND q.released_at IS NULL
            UNION ALL
            SELECT q.target_type::text, s.server_id, s.name, t.name, q.reason, q.quarantined_at
            FROM quarantine_events q
            JOIN tool_registry t ON t.tool_id = q.target_id
            JOIN servers s ON s.server_id = t.server_id
            WHERE q.target_type = 'tool' AND q.released_at IS NULL
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "quarantine_entries: query failed; returning empty list \
                (NOT \"nothing is quarantined\" — this view must never be read as an all-clear on error)");
            Vec::new()
        });

        rows.into_iter()
            .map(|(_, server_id, server_name, tool_name, reason, quarantined_at)| QuarantineEntry {
                server_id: ServerId(server_id),
                server_name,
                tool_name,
                reason,
                quarantined_at: quarantined_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            })
            .collect()
    }

    async fn release_quarantine(&self, server_id: ServerId, tool_name: &str) -> bool {
        let result = if tool_name == "*" {
            sqlx::query(
                "UPDATE quarantine_events SET released_at = now(), released_by = 'portal'
                 WHERE target_type = 'server' AND target_id = $1 AND released_at IS NULL",
            )
            .bind(server_id.0)
            .execute(&self.pool)
            .await
        } else {
            let tool_id: Option<(Uuid,)> = sqlx::query_as(
                "SELECT tool_id FROM tool_registry WHERE server_id = $1 AND name = $2 AND deleted_at IS NULL",
            )
            .bind(server_id.0)
            .bind(tool_name)
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, server_id = %server_id.0, tool_name, "release_quarantine: tool lookup failed");
                None
            });

            match tool_id {
                Some((tid,)) => {
                    sqlx::query(
                        "UPDATE quarantine_events SET released_at = now(), released_by = 'portal'
                         WHERE target_type = 'tool' AND target_id = $1 AND released_at IS NULL",
                    )
                    .bind(tid)
                    .execute(&self.pool)
                    .await
                }
                None => return false,
            }
        };

        result
            .map(|r| r.rows_affected() > 0)
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, server_id = %server_id.0, tool_name, "release_quarantine: update failed");
                false
            })
    }

    async fn anomalies(&self) -> Vec<Anomaly> {
        sqlx::query_as::<_, (Uuid, time::OffsetDateTime, String, String, String, String)>(
            "SELECT alert_id, detected_at, principal_id, kind, severity, summary
             FROM anomaly_alerts ORDER BY detected_at DESC LIMIT 200",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "anomalies: query failed; returning empty list \
                (NOT \"no anomalies\" — this feeds the security team's alert view)");
            Vec::new()
        })
        .into_iter()
        .map(|(id, at, principal_sub, kind, severity, summary)| Anomaly {
            id,
            at: at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
            principal_sub,
            kind,
            severity: severity_static(&severity),
            summary,
        })
        .collect()
    }

    async fn idps(&self) -> Vec<IdpConfig> {
        sqlx::query_as::<_, (String, String, String, bool)>(
            "SELECT idp_id::text, name, issuer, supports_token_exchange FROM idp_configs WHERE deleted_at IS NULL",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "idps: query failed; returning empty list");
            Vec::new()
        })
        .into_iter()
        .map(|(id, name, issuer, supports_token_exchange)| IdpConfig {
            id,
            kind: idp_kind_from_issuer(&issuer),
            display_name: name,
            issuer_url: issuer,
            supports_token_exchange,
        })
        .collect()
    }

    async fn create_idp(&self, cfg: IdpConfig) {
        // See module docs: this trait's IdpConfig carries no client_id —
        // real onboarding needs a fuller form than this seam exposes.
        if let Err(e) = sqlx::query(
            "INSERT INTO idp_configs (name, issuer, client_id, supports_token_exchange)
             VALUES ($1, $2, '', $3)
             ON CONFLICT (name) WHERE deleted_at IS NULL DO UPDATE SET
                 issuer = EXCLUDED.issuer, supports_token_exchange = EXCLUDED.supports_token_exchange",
        )
        .bind(&cfg.display_name)
        .bind(&cfg.issuer_url)
        .bind(cfg.supports_token_exchange)
        .execute(&self.pool)
        .await
        {
            tracing::error!(error = %e, idp = %cfg.display_name, "create_idp: write failed");
        }
    }

    async fn global_limits(&self) -> GlobalLimits {
        let row: Option<(i32, f64, i32, i32)> = sqlx::query_as(
            "SELECT default_rate_limit_per_min, anomaly_cutoff_threshold, dedicated_port_range_start, dedicated_port_range_end
             FROM global_limits WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "global_limits: query failed; falling back to hardcoded defaults \
                (these defaults do NOT necessarily match what's actually configured)");
            None
        });

        match row {
            Some((rpm, cutoff, start, end)) => GlobalLimits {
                default_rate_limit_per_min: rpm as u32,
                anomaly_cutoff_threshold: cutoff,
                dedicated_port_range_start: start as u16,
                dedicated_port_range_end: end as u16,
            },
            None => GlobalLimits {
                default_rate_limit_per_min: 120,
                anomaly_cutoff_threshold: 0.85,
                dedicated_port_range_start: 9000,
                dedicated_port_range_end: 9100,
            },
        }
    }

    async fn set_global_limits(&self, limits: GlobalLimits) {
        if let Err(e) = sqlx::query(
            "UPDATE global_limits SET default_rate_limit_per_min = $1, anomaly_cutoff_threshold = $2,
                 dedicated_port_range_start = $3, dedicated_port_range_end = $4
             WHERE id = 1",
        )
        .bind(limits.default_rate_limit_per_min as i32)
        .bind(limits.anomaly_cutoff_threshold)
        .bind(limits.dedicated_port_range_start as i32)
        .bind(limits.dedicated_port_range_end as i32)
        .execute(&self.pool)
        .await
        {
            tracing::error!(error = %e, "set_global_limits: write failed — limits were NOT updated");
        }
    }

    async fn display_roles_all_issuers(&self, sub: &str) -> Vec<Role> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT DISTINCT role::text FROM role_grants WHERE principal_id = $1")
                .bind(sub)
                .fetch_all(&self.pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, principal = %sub, "display_roles_all_issuers: query failed; returning empty role set");
                    Vec::new()
                });
        rows.into_iter().filter_map(|(r,)| role_from_db(&r)).collect()
    }
}

impl PgUiData {
    /// REVIEW NOTE (D10 — known, NOT fully fixable in this crate): `grants`
    /// allows `server_id IS NULL` for platform-wide grants (e.g. a
    /// super-admin's tooling access), but the INNER JOIN below silently
    /// EXCLUDES every such row, because there is no `servers` row for a
    /// NULL `server_id` to join against. That means `all_grants()` (the
    /// super-admin "audit every grant" view) is missing exactly the most
    /// powerful grants in the system, and `grants_for(sub)` similarly
    /// hides a principal's own platform-wide grants from themselves.
    ///
    /// This cannot be fixed correctly inside this crate alone:
    /// `mcphub_types::ui_data::Grant` (owned by component 1, outside this
    /// crate's directories) has `server_id: ServerId` and
    /// `server_name: String` as non-optional fields — there is no way to
    /// represent "no server" without either fabricating a fake UUID
    /// (actively misleading) or leaving the row out (today's bug). The
    /// real fix is `Grant.server_id: Option<ServerId>` (and
    /// `server_name: Option<String>`) in mcphub-types, with this query
    /// changed to a LEFT JOIN — see this crate's handoff report. Until
    /// that lands, at minimum make the gap observable rather than silent.
    async fn grants_matching(&self, where_clause: &str, principal: &str) -> Vec<Grant> {
        let sql = format!(
            "SELECT g.principal_id, s.server_id, s.name, g.allowed_tools, g.granted_by
             FROM grants g JOIN servers s ON s.server_id = g.server_id
             WHERE {where_clause}"
        );
        let query = if where_clause.contains('$') {
            sqlx::query_as::<_, (String, Uuid, String, Vec<String>, String)>(&sql).bind(principal)
        } else {
            sqlx::query_as::<_, (String, Uuid, String, Vec<String>, String)>(&sql)
        };

        let platform_wide_where = if where_clause.contains('$') {
            format!("SELECT count(*) FROM grants g WHERE g.server_id IS NULL AND ({where_clause})")
        } else {
            format!("SELECT count(*) FROM grants g WHERE g.server_id IS NULL AND ({where_clause})")
        };
        let excluded: i64 = if where_clause.contains('$') {
            sqlx::query_scalar(&platform_wide_where).bind(principal).fetch_one(&self.pool).await
        } else {
            sqlx::query_scalar(&platform_wide_where).fetch_one(&self.pool).await
        }
        .unwrap_or(0);
        if excluded > 0 {
            tracing::warn!(
                excluded_count = excluded, principal = %principal,
                "grants_matching: {excluded} platform-wide grant(s) (server_id IS NULL) exist but are \
                 excluded from this result by an INNER JOIN — known gap, see this crate's D10 handoff note"
            );
        }

        query
            .fetch_all(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "grants_matching: query failed; returning empty list");
                Vec::new()
            })
            .into_iter()
            .flat_map(|(principal_sub, server_id, server_name, allowed_tools, granted_by)| {
                let tools: Vec<Option<String>> =
                    if allowed_tools.is_empty() { vec![None] } else { allowed_tools.into_iter().map(Some).collect() };
                tools.into_iter().map(move |tool_name| Grant {
                    principal_sub: principal_sub.clone(),
                    server_id: ServerId(server_id),
                    server_name: server_name.clone(),
                    tool_name,
                    granted_by: granted_by.clone(),
                    granted_at: String::new(), // grants has no per-row grant timestamp for array entries
                })
            })
            .collect()
    }

    async fn audit_events_matching(&self, where_clause: &str, id: Option<Uuid>, limit: Option<i64>) -> Vec<AuditEvent> {
        let sql = format!(
            "SELECT e.event_id, e.event_ts, e.principal_id, COALESCE(s.name, ''), e.tool_name, e.outcome, e.deny_reason, e.request_id
             FROM audit_events e LEFT JOIN servers s ON s.server_id = e.server_id
             WHERE {where_clause} ORDER BY e.event_ts DESC {}",
            limit.map(|l| format!("LIMIT {l}")).unwrap_or_default()
        );
        let rows: Vec<(Uuid, time::OffsetDateTime, String, String, String, String, Option<String>, String)> =
            match id {
                Some(id) => sqlx::query_as(&sql).bind(id).fetch_all(&self.pool).await,
                None => sqlx::query_as(&sql).fetch_all(&self.pool).await,
            }
            .unwrap_or_else(|e| {
                // D11: this is the audit-trail READ path (recent_audit_events /
                // audit_event / the portal's audit view). Silently returning
                // an empty list on a DB error means an analyst investigating
                // an incident sees "no events" and concludes nothing
                // happened — the exact wrong-signal scenario flagged in the
                // review. Logging is the most this fn's `Vec<AuditEvent>`
                // return type (defined in mcphub-types, outside this crate)
                // can surface today — see this crate's handoff report for
                // the `Result`-returning trait change this ultimately needs.
                tracing::error!(
                    error = %e,
                    "audit_events_matching: query failed; returning EMPTY list — this is NOT \
                     evidence that no matching audit events exist"
                );
                Vec::new()
            });

        rows.into_iter()
            .map(|(event_id, at, principal_sub, server_name, tool_name, outcome, deny_reason, request_id)| AuditEvent {
                id: event_id,
                at: at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),
                principal_sub,
                server_name,
                tool_name,
                decision: if outcome == "allow" { "allow" } else { "deny" },
                deny_reason: deny_reason.as_deref().and_then(deny_reason_view_from_code),
                request_id,
            })
            .collect()
    }
}

fn access_request_status_static(s: &str) -> &'static str {
    match s {
        "pending" => "pending",
        "approved" => "approved",
        "rejected" => "rejected",
        _ => "pending",
    }
}

fn severity_static(s: &str) -> &'static str {
    match s {
        "low" => "low",
        "medium" => "medium",
        "high" => "high",
        "critical" => "critical",
        _ => "medium",
    }
}

fn idp_kind_from_issuer(issuer: &str) -> &'static str {
    // Display-only heuristic — see module docs. `kind` isn't a stored column.
    if issuer.contains("microsoftonline") || issuer.contains("entra") {
        "entra"
    } else if issuer.contains("zitadel") {
        "zitadel"
    } else if issuer.contains("realms") {
        "keycloak"
    } else {
        "generic_oidc"
    }
}

// role_to_db is currently unused here (display_roles_all_issuers reads text
// directly via SELECT ... role::text) but kept imported for symmetry with repo::roles
// and to make a future write-path (e.g. an admin "grant role" UI action)
// a one-line addition rather than a new lookup table.
#[allow(unused_imports)]
use role_to_db as _unused_role_to_db_reexport;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_pool_migrated;

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn servers_for_owner_maps_status_to_view_fields() {
        let pool = test_pool_migrated().await;
        let ui = PgUiData::new(pool.clone());

        let (server_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO servers (name, upstream_url, owner_principal_id, status)
             VALUES ($1, $2, $3, 'approved') RETURNING server_id",
        )
        .bind("gh-mcp")
        .bind("https://upstream.example.com")
        .bind("owner-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        let servers = ui.servers_for_owner("owner-1").await;
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].id, ServerId(server_id));
        assert!(servers[0].enabled);
        assert_eq!(servers[0].health, ServerHealth::Healthy);
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn save_grant_then_grants_for_roundtrips() {
        let pool = test_pool_migrated().await;
        let ui = PgUiData::new(pool.clone());

        let (server_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO servers (name, upstream_url, owner_principal_id) VALUES ($1, $2, $3) RETURNING server_id",
        )
        .bind("srv-1")
        .bind("https://upstream.example.com")
        .bind("owner-1")
        .fetch_one(&pool)
        .await
        .unwrap();

        ui.save_grant(Grant {
            principal_sub: "alice".into(),
            server_id: ServerId(server_id),
            server_name: "srv-1".into(),
            tool_name: Some("echo".into()),
            granted_by: "admin-1".into(),
            granted_at: String::new(),
        })
        .await;

        let grants = ui.grants_for("alice").await;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].tool_name.as_deref(), Some("echo"));
    }

    #[tokio::test]
    #[ignore = "requires a live Postgres; run with `cargo test -- --ignored`"]
    async fn global_limits_roundtrip() {
        let pool = test_pool_migrated().await;
        let ui = PgUiData::new(pool.clone());

        let before = ui.global_limits().await;
        assert_eq!(before.default_rate_limit_per_min, 120);

        ui.set_global_limits(GlobalLimits {
            default_rate_limit_per_min: 500,
            anomaly_cutoff_threshold: 0.5,
            dedicated_port_range_start: 9000,
            dedicated_port_range_end: 9050,
        })
        .await;

        let after = ui.global_limits().await;
        assert_eq!(after.default_rate_limit_per_min, 500);
        assert_eq!(after.dedicated_port_range_end, 9050);
        // `anomaly_cutoff_threshold` specifically — this test previously
        // set it but never asserted it round-tripped, so a broken column
        // mapping for this one field (the admin "anomaly sensitivity"
        // slider, `mcphub-policy::RegorusPolicyEngine::set_anomaly_cutoff`
        // reads it every 30s via `bin/mcphubd`'s policy refresh) would have
        // passed this test silently.
        assert_eq!(after.anomaly_cutoff_threshold, 0.5);
    }
}
