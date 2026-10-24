//! `EntitlementStore` ← `mcphub-store`'s tools/servers/grants/quarantine
//! repos, queried directly against Postgres on every call.
//!
//! `mcphub-policy::entitlement::GrantResolver` was deliberately NOT used
//! here even though ARCHITECTURE.md's brief names it: its `GrantsSource`/
//! `ToolCatalog` traits are synchronous (no `async fn`), which means the
//! data has to be pre-loaded into memory by something before `evaluate`
//! can run. That's a fine design for the policy engine's own data (synced
//! on a bundle-reload cadence), but it is the wrong shape for
//! `EntitlementStore`: the whole point of the "Postgres killed -> DENY"
//! invariant is that a dependency outage is visible to the *next* request,
//! immediately — a synchronous in-memory cache would keep answering from
//! stale data for as long as the last successful refresh, silently
//! breaking that invariant. Querying Postgres directly, per call, is both
// ponytail: the simplest thing that is actually correct here, and it
// makes the fail-closed behavior fall out of `?` on `StoreError` for free
// instead of needing a cache-staleness policy. Upgrade path if this needs
// to get faster: a moka cache with a short TTL that is invalidated (not
// just expired) on DB error, so a stale answer is never served past an
// observed outage.
//! its own doc note above.

use async_trait::async_trait;
use mcphub_gateway::traits::{EntitlementStore, ToolMeta};
use mcphub_types::{GateError, Identity, Role, ServerId, ToolRef};
use sqlx::PgPool;

pub struct StoreEntitlement {
    pool: PgPool,
}

impl StoreEntitlement {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// D4 fix: `tool_meta` was 4 sequential round trips per call (server row,
/// tool list, 2x quarantine lookup) on the single hottest path in the
/// gateway. One query, joined, replaces all four — quarantine state is
/// pulled in via `EXISTS` subqueries instead of a follow-up round trip
/// each.
#[derive(sqlx::FromRow)]
struct ToolMetaRow {
    server_status: String,
    upstream_url: String,
    allowed_cidr: Option<String>,
    risk_score: Option<i16>,
    tool_id: uuid::Uuid,
    /// `role_enum::text`, or NULL — mapped via `repo::roles::role_from_db`
    /// (NOT reimplemented here — see that function's own doc note on why
    /// this is the one conversion point). NULL means "no per-tool role
    /// requirement" (migration 0012's deliberate, documented NULL
    /// semantics — the opposite of `risk_score`'s "NULL = untrusted").
    required_role: Option<String>,
    server_quarantined: bool,
    tool_quarantined: bool,
}

const TOOL_META_SQL: &str = r#"
    SELECT
        s.status::text AS server_status,
        s.upstream_url,
        s.allowed_cidr,
        t.risk_score,
        t.tool_id,
        t.required_role::text,
        EXISTS (
            SELECT 1 FROM quarantine_events q
            WHERE q.target_type = 'server'::quarantine_target_enum
              AND q.target_id = s.server_id AND q.released_at IS NULL
        ) AS server_quarantined,
        EXISTS (
            SELECT 1 FROM quarantine_events q
            WHERE q.target_type = 'tool'::quarantine_target_enum
              AND q.target_id = t.tool_id AND q.released_at IS NULL
        ) AS tool_quarantined
    FROM servers s
    JOIN tool_registry t ON t.server_id = s.server_id AND t.deleted_at IS NULL AND t.status = 'active'
    WHERE s.server_id = $1 AND s.deleted_at IS NULL AND t.name = $2
"#;

/// D4 fix: `list_visible` was O(servers × tools) sequential round trips
/// (a quarantine check per server, a tool list per server, a grants
/// resolve per server, then ANOTHER quarantine check per tool) — at 100
/// servers × 20 tools that is ~2,300 round trips for a single call. One
/// query per role tier replaces the whole nested loop. `DISTINCT` matters
/// here: a principal can match both a server-scoped and a platform-wide
/// grant for the same tool, which would otherwise duplicate the row.
const LIST_VISIBLE_ADMIN_SQL: &str = r#"
    SELECT DISTINCT s.server_id, s.name AS server_name, t.name
    FROM servers s
    JOIN tool_registry t ON t.server_id = s.server_id AND t.deleted_at IS NULL AND t.status = 'active'
    WHERE s.deleted_at IS NULL AND s.status = 'approved'
      AND NOT EXISTS (
          SELECT 1 FROM quarantine_events q
          WHERE q.target_type = 'server'::quarantine_target_enum
            AND q.target_id = s.server_id AND q.released_at IS NULL
      )
      AND NOT EXISTS (
          SELECT 1 FROM quarantine_events q
          WHERE q.target_type = 'tool'::quarantine_target_enum
            AND q.target_id = t.tool_id AND q.released_at IS NULL
      )
"#;

// TODO: `allowed_tags` matching is not implemented — `tool_registry` has no
// tags column to match against yet, so only exact `allowed_tools` name
// membership is enforced here (same gap as before this query was
// consolidated). Risk ceiling is fail-closed: a NULL `risk_level` never
// satisfies `t.risk_level IS NOT NULL`, so an unscanned tool is excluded
// from every principal's visible set, matching D12's fix.
const LIST_VISIBLE_GRANTED_SQL: &str = r#"
    SELECT DISTINCT s.server_id, s.name AS server_name, t.name
    FROM servers s
    JOIN tool_registry t ON t.server_id = s.server_id AND t.deleted_at IS NULL AND t.status = 'active'
    JOIN grants g ON (g.server_id = s.server_id OR g.server_id IS NULL) AND g.principal_id = $1
    WHERE s.deleted_at IS NULL AND s.status = 'approved'
      AND t.name = ANY(g.allowed_tools)
      AND t.risk_level IS NOT NULL
      AND (CASE t.risk_level WHEN 'low' THEN 0 WHEN 'medium' THEN 1 WHEN 'high' THEN 2 ELSE 3 END)
          <= (CASE g.max_risk_level WHEN 'low' THEN 0 WHEN 'medium' THEN 1 WHEN 'high' THEN 2 ELSE 3 END)
      AND NOT EXISTS (
          SELECT 1 FROM quarantine_events q
          WHERE q.target_type = 'server'::quarantine_target_enum
            AND q.target_id = s.server_id AND q.released_at IS NULL
      )
      AND NOT EXISTS (
          SELECT 1 FROM quarantine_events q
          WHERE q.target_type = 'tool'::quarantine_target_enum
            AND q.target_id = t.tool_id AND q.released_at IS NULL
      )
"#;

#[async_trait]
impl EntitlementStore for StoreEntitlement {
    async fn tool_meta(&self, tool: &ToolRef) -> Result<ToolMeta, GateError> {
        let row: ToolMetaRow = sqlx::query_as(TOOL_META_SQL)
            .bind(tool.server.0)
            .bind(&tool.tool)
            .fetch_optional(&self.pool)
            .await
            .map_err(mcphub_store::StoreError::from)?
            .ok_or(GateError::EntitlementMissing)?;

        let upstream_host = reqwest::Url::parse(&row.upstream_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();

        // Migration 0012 added `tool_registry.required_role`. NULL means
        // "no per-tool role requirement" — deliberately the OPPOSITE
        // reading from `risk_score`'s NULL (below), not an inconsistency:
        // NULL is the true, common, unremarkable state (most tools have no
        // extra role floor), and every pre-migration row is NULL, so a
        // fail-closed "NULL = deny" reading here would have locked out the
        // entire platform on deploy. A tool that genuinely needs a role
        // floor gets one by setting this column explicitly — opt-in, not
        // opt-out. An unparseable non-NULL value (shouldn't happen — the
        // column is a Postgres enum — but `role_from_db` can't express
        // "corrupt", so this defensively fails closed by denying every
        // role rather than silently treating garbage as "no requirement").
        let required_role = match row.required_role.as_deref() {
            None => None,
            Some(s) => Some(
                mcphub_store::repo::roles::role_from_db(s)
                    .ok_or_else(|| GateError::InvalidRequest(format!("tool_registry.required_role has an unmapped value: {s}")))?,
            ),
        };

        // `network_isolated` is NOT a schema gap — it was REMOVED (see
        // `invocation::check_ingress`'s doc comment): there is no
        // per-tool/per-server signal for it because network isolation is a
        // platform-wide deployment-layer property (container/podman
        // network policy + `scripts/check_network_isolation.py`), not a
        // per-request fact this service can observe. A hardcoded `true`
        // fed a gate that could never fire, which is worse than no gate at
        // all — removed rather than left decorative.
        let trust_tier = match row.risk_score {
            Some(score) => (((100 - score as i32).max(0)) / 10) as u8,
            None => 0,
        };

        Ok(ToolMeta {
            server: tool.server,
            server_enabled: row.server_status == "approved",
            quarantined: row.server_quarantined || row.tool_quarantined,
            required_role,
            trust_tier,
            upstream_host,
            allowed_cidr: row.allowed_cidr,
            tool_id: Some(row.tool_id),
        })
    }

    async fn list_visible(&self, identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
        let is_super_admin = identity.has_role(Role::SuperAdmin);

        let rows: Vec<(uuid::Uuid, String, String)> = if is_super_admin {
            sqlx::query_as(LIST_VISIBLE_ADMIN_SQL).fetch_all(&self.pool).await
        } else {
            sqlx::query_as(LIST_VISIBLE_GRANTED_SQL).bind(&identity.sub).fetch_all(&self.pool).await
        }
        .map_err(mcphub_store::StoreError::from)?;

        // grants ∧ profiles.
        //
        // `grants` (and the admin branch) decide what a principal is entitled
        // to at all. `profiles` is the principal's own per-MCP narrowing on top
        // of that — disable an MCP they don't want exposed, or restrict which
        // of its functions are reachable. Profiles may only ever NARROW: a
        // profile row cannot grant access `grants` did not already allow,
        // because it is applied as a filter over the granted set rather than
        // as an alternative source of entitlement. There is no branch below
        // that can add a `ToolRef`.
        //
        // Applying it HERE, inside `list_visible`, is deliberate: this is the
        // single method both `tools/list` and `invoke`'s entitlement gate call,
        // so a profile exclusion narrows discovery and invocation together and
        // cannot drift. A separate gate would have been a second enforcement
        // path — exactly what invariant 2 forbids.
        //
        // Fail-closed: a profiles lookup failure propagates as `Err` (denying
        // the call), never as "no profile, allow everything".
        let mut visible = Vec::with_capacity(rows.len());
        let mut profile_cache: std::collections::HashMap<String, Option<mcphub_store::repo::profiles::ProfileRow>> =
            std::collections::HashMap::new();
        for (server_id, server_name, tool_name) in rows {
            let profile = match profile_cache.get(&server_name) {
                Some(p) => p.clone(),
                None => {
                    let p = mcphub_store::repo::profiles::get_profile(&self.pool, &identity.sub, &server_name).await?;
                    profile_cache.insert(server_name.clone(), p.clone());
                    p
                }
            };
            if let Some(profile) = profile {
                if !profile.enabled {
                    continue;
                }
                // `None` == unrestricted (every function of an enabled MCP).
                // `Some(list)` == an explicit allowlist; anything absent is out.
                if let Some(allowed) = &profile.allowed_functions {
                    if !allowed.iter().any(|f| f == &tool_name) {
                        continue;
                    }
                }
            }
            visible.push(ToolRef { server: ServerId(server_id), tool: tool_name });
        }
        Ok(visible)
    }
}
