//! Discovery == invoke (ARCHITECTURE.md invariant 3 / `entitlement.py` in
//! the Python platform).
//!
//! There is exactly ONE function that decides "is this tool visible/callable
//! by this identity" — [`GrantResolver::entitled_tools`]. `EntitlementStore::
//! list_visible` (the `tools/list` discovery path) and the invoke-path
//! entitlement check both call it; the invoke path does so through
//! [`GrantResolver::is_entitled`], which is defined purely in terms of the
//! same set — it is structurally impossible for the two to return different
//! answers for the same identity+tool, because there is no second code path
//! that recomputes the set a different way.
//!
//! Backing data (`GrantsSource`, `ToolCatalog`) is injected so this crate
//! stays testable without a database. The real Postgres-backed
//! implementations are `mcphub-store`'s (component 4) to wire; this module
//! defines the trait boundary and the shared predicate they must sit behind.

use mcphub_gateway::traits::{EntitlementStore, ToolMeta};
use mcphub_types::{GateError, Identity, ToolRef};
use std::collections::{HashMap, HashSet};

/// Resolves the raw per-identity grant set — analogous to
/// `data.mcp_grants[client_id].allowed_tools` / `allowed_tags` in
/// `authz.rego`, and to `check_entitlement`'s entitlement/server_role_grant
/// lookups in the Python platform. Pure data lookup: no active/quarantine
/// filtering here — that belongs to [`GrantResolver::entitled_tools`], which
/// combines this with catalog state.
pub trait GrantsSource: Send + Sync {
    fn granted_tools(&self, identity: &Identity) -> HashSet<ToolRef>;
}

/// Resolves tool metadata needed to decide visibility (server enabled,
/// quarantine status) and to answer `EntitlementStore::tool_meta`.
pub trait ToolCatalog: Send + Sync {
    fn meta(&self, tool: &ToolRef) -> Option<ToolMeta>;
}

/// The single discovery==invoke predicate, plus the two trait
/// implementations (`EntitlementStore::list_visible` / the invoke gate) that
/// must never diverge because they both terminate here.
pub struct GrantResolver<G: GrantsSource, C: ToolCatalog> {
    grants: G,
    catalog: C,
}

impl<G: GrantsSource, C: ToolCatalog> GrantResolver<G, C> {
    pub fn new(grants: G, catalog: C) -> Self {
        Self { grants, catalog }
    }

    /// THE function. A tool is entitled only if it is both granted to the
    /// identity AND currently active in the catalog (not quarantined, its
    /// server enabled) — mirrors `tool_is_active` + grant checks in
    /// `authz.rego`, collapsed into the visibility set rather than
    /// re-evaluated per call site.
    pub fn entitled_tools(&self, identity: &Identity) -> HashSet<ToolRef> {
        self.grants
            .granted_tools(identity)
            .into_iter()
            .filter(|tool| {
                self.catalog
                    .meta(tool)
                    .map(|m| m.server_enabled && !m.quarantined)
                    .unwrap_or(false) // unknown tool -> fail closed, not visible
            })
            .collect()
    }

    /// Invoke-path check. Defined strictly as membership in
    /// `entitled_tools` — there is no separate "can invoke" computation to
    /// drift from the discovery set.
    pub fn is_entitled(&self, identity: &Identity, tool: &ToolRef) -> bool {
        self.entitled_tools(identity).contains(tool)
    }
}

#[async_trait::async_trait]
impl<G: GrantsSource, C: ToolCatalog> EntitlementStore for GrantResolver<G, C> {
    async fn tool_meta(&self, tool: &ToolRef) -> Result<ToolMeta, GateError> {
        self.catalog
            .meta(tool)
            .ok_or_else(|| GateError::InvalidRequest(format!("unknown tool {}", tool.tool)))
    }

    async fn list_visible(&self, identity: &Identity) -> Result<Vec<ToolRef>, GateError> {
        Ok(self.entitled_tools(identity).into_iter().collect())
    }
}

/// In-memory test/dev double for [`GrantsSource`] — a straight
/// `sub -> Vec<ToolRef>` map, analogous to `data.mcp_grants[client_id].
/// allowed_tools` with tags already expanded.
#[derive(Default, Clone)]
pub struct InMemoryGrants(pub HashMap<String, HashSet<ToolRef>>);

impl GrantsSource for InMemoryGrants {
    fn granted_tools(&self, identity: &Identity) -> HashSet<ToolRef> {
        self.0.get(&identity.sub).cloned().unwrap_or_default()
    }
}

/// In-memory test/dev double for [`ToolCatalog`].
#[derive(Default, Clone)]
pub struct InMemoryCatalog(pub HashMap<ToolRef, ToolMeta>);

impl ToolCatalog for InMemoryCatalog {
    fn meta(&self, tool: &ToolRef) -> Option<ToolMeta> {
        self.0.get(tool).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::{GrantedRole, IssuerId, Role, ServerId, TokenRef};
    use uuid::Uuid;

    fn identity(sub: &str) -> Identity {
        Identity {
            sub: sub.into(),
            issuer: IssuerId::new("platform"),
            email: None,
            roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
            groups: vec![],
            token_ref: TokenRef::none(),
        }
    }

    fn tool(name: &str) -> ToolRef {
        ToolRef {
            server: ServerId::new(Uuid::nil()),
            tool: name.into(),
        }
    }

    fn active_meta() -> ToolMeta {
        ToolMeta {
            server: ServerId::new(Uuid::nil()),
            server_enabled: true,
            quarantined: false,
            required_role: None,
            trust_tier: 2,
            upstream_host: "backend.internal".into(),
            allowed_cidr: None,
            tool_id: None,
        }
    }

    #[tokio::test]
    async fn discovery_equals_invoke_same_function_same_answer() {
        let mut grants = HashMap::new();
        grants.insert(
            "alice".to_string(),
            HashSet::from([tool("visible_tool")]),
        );
        let mut catalog = HashMap::new();
        catalog.insert(tool("visible_tool"), active_meta());

        let resolver = GrantResolver::new(InMemoryGrants(grants), InMemoryCatalog(catalog));
        let id = identity("alice");

        // Discovery path.
        let visible = resolver.list_visible(&id).await.unwrap();
        assert!(visible.contains(&tool("visible_tool")));
        assert!(!visible.contains(&tool("absent_tool")));

        // Invoke path — literally the same predicate, so a tool absent from
        // `list_visible`'s output must also be denied here.
        assert!(resolver.is_entitled(&id, &tool("visible_tool")));
        assert!(!resolver.is_entitled(&id, &tool("absent_tool")));
    }

    #[tokio::test]
    async fn quarantined_tool_is_granted_but_not_entitled() {
        let mut grants = HashMap::new();
        grants.insert("bob".to_string(), HashSet::from([tool("q_tool")]));
        let mut catalog = HashMap::new();
        let mut meta = active_meta();
        meta.quarantined = true;
        catalog.insert(tool("q_tool"), meta);

        let resolver = GrantResolver::new(InMemoryGrants(grants), InMemoryCatalog(catalog));
        let id = identity("bob");
        assert!(!resolver.is_entitled(&id, &tool("q_tool")));
        assert!(resolver.list_visible(&id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn unknown_identity_gets_empty_set_fail_closed() {
        let resolver = GrantResolver::new(InMemoryGrants::default(), InMemoryCatalog::default());
        let id = identity("nobody");
        assert!(resolver.list_visible(&id).await.unwrap().is_empty());
        assert!(!resolver.is_entitled(&id, &tool("anything")));
    }
}
