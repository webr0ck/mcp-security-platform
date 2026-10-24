//! `dedicated_port` support: per-IDP listener metadata. A dedicated port
//! serves ONE IDP's RFC 9728 protected-resource metadata and RFC 8414 AS
//! metadata — that's the whole point of the isolation valve: one weird IDP
//! never degrades auth for every other MCP server on the shared port
//! (ARCHITECTURE.md). Several servers can legitimately sit behind the same
//! awkward IDP and share that IDP's dedicated listener, so allocation is
//! keyed on the IDP, never on the server: keying on `ServerId` would stand
//! up N identical listeners advertising identical metadata on N different
//! ports for what is really one IDP relationship, and would make the
//! isolation valve's uniqueness guarantee (`mcphub-store`'s
//! `idp_configs.dedicated_port` unique constraint) unenforceable at this
//! layer.

use crate::config::{AuthModeHint, IdpConfig};
use crate::error::{IdentityError, Result};
use mcphub_types::IssuerId;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ops::Range;

/// RFC 9728 `oauth-protected-resource` document for one dedicated-port IDP.
pub fn protected_resource_metadata(resource: &str, authorization_server: &str) -> Value {
    json!({
        "resource": resource,
        "authorization_servers": [authorization_server],
    })
}

/// RFC 8414 AS metadata for that IDP, scoped to this port's `resource` —
/// distinct from the shared port's single-IDP metadata, which is untouched
/// by any dedicated-port allocation.
pub fn as_metadata(idp: &IdpConfig, issuer_endpoints: &IssuerEndpoints) -> Value {
    json!({
        "issuer": idp.issuer,
        "authorization_endpoint": issuer_endpoints.authorization_endpoint,
        "token_endpoint": issuer_endpoints.token_endpoint,
        "registration_endpoint": issuer_endpoints.registration_endpoint,
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code"],
    })
}

#[derive(Debug, Clone)]
pub struct IssuerEndpoints {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub registration_endpoint: Option<String>,
}

/// Allocates dedicated ports from `listeners.dedicated_range` (e.g.
/// `9000..9100`), one per [`IssuerId`], and records the mapping so the
/// gateway can mount `protected_resource_metadata`/`as_metadata` per port
/// and so an IDP keeps the same port across restarts (looked up before
/// allocating a fresh one — mirrors `mcphub-store`'s
/// `idp_configs.dedicated_port` column, which this allocator's `restore`
/// path is meant to be seeded from at startup).
pub struct DedicatedPortAllocator {
    range: Range<u16>,
    allocated: HashMap<IssuerId, u16>,
    in_use_ports: std::collections::HashSet<u16>,
}

impl DedicatedPortAllocator {
    pub fn new(range: Range<u16>) -> Self {
        Self { range, allocated: HashMap::new(), in_use_ports: std::collections::HashSet::new() }
    }

    /// Restore a previously-allocated port for `issuer` (from
    /// `idp_configs.dedicated_port`) instead of allocating a new one.
    pub fn restore(&mut self, issuer: IssuerId, port: u16) -> Result<()> {
        if !self.range.contains(&port) {
            return Err(IdentityError::Internal(format!("port {port} outside configured dedicated_range")));
        }
        if let Some(existing) = self.in_use_ports.get(&port) {
            if *existing != port || self.allocated.get(&issuer) != Some(&port) {
                return Err(IdentityError::PortRangeExhausted);
            }
        }
        self.allocated.insert(issuer, port);
        self.in_use_ports.insert(port);
        Ok(())
    }

    pub fn allocate(&mut self, issuer: IssuerId) -> Result<u16> {
        if let Some(existing) = self.allocated.get(&issuer) {
            return Ok(*existing);
        }
        for port in self.range.clone() {
            if !self.in_use_ports.contains(&port) {
                self.allocated.insert(issuer, port);
                self.in_use_ports.insert(port);
                return Ok(port);
            }
        }
        Err(IdentityError::PortRangeExhausted)
    }

    pub fn port_for(&self, issuer: &IssuerId) -> Option<u16> {
        self.allocated.get(issuer).copied()
    }

    pub fn release(&mut self, issuer: &IssuerId) {
        if let Some(port) = self.allocated.remove(issuer) {
            self.in_use_ports.remove(&port);
        }
    }
}

/// A server whose `auth_mode` is `DedicatedPort` must route through ITS
/// IDP's dedicated listener — never the shared one. If that IDP has no
/// port allocated (an admission-time bug: an `IdpConfig` was saved with
/// `auth_mode: DedicatedPort` but never went through allocation/restore,
/// or the allocator was rebuilt and lost state), this is a hard,
/// detectable misconfiguration. It must be surfaced as an error the caller
/// fails closed on, never treated as "no dedicated port, so just use the
/// shared listener" — that fallback would silently defeat the entire
/// isolation valve (a weird/compromised IDP degrading every OTHER server on
/// the shared port) while every symptom looks like things are working.
pub fn require_dedicated_port(idp: &IdpConfig, allocator: &DedicatedPortAllocator) -> Result<u16> {
    if idp.auth_mode != AuthModeHint::DedicatedPort {
        return Err(IdentityError::Internal(format!(
            "require_dedicated_port called for issuer {} whose auth_mode is {:?}, not DedicatedPort",
            idp.issuer, idp.auth_mode
        )));
    }
    allocator
        .port_for(&IssuerId::new(idp.issuer.clone()))
        .ok_or_else(|| IdentityError::DedicatedPortNotAllocated(idp.issuer.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::RoleMapping;
    use mcphub_types::Role;

    fn iss(s: &str) -> IssuerId {
        IssuerId::new(s)
    }

    fn idp_with_mode(issuer: &str, auth_mode: AuthModeHint) -> IdpConfig {
        IdpConfig {
            issuer: issuer.to_string(),
            discovery_url: None,
            issuer_aliases: vec![],
            audiences: vec!["mcphub".into()],
            role_mapping: RoleMapping::default(),
            allowed_algs: vec!["RS256".into()],
            clock_skew_seconds: 60,
            auth_mode,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: None,
            redirect_uri_allowlist: vec![],
            max_assertable_role: Role::Employee,
        }
    }

    #[test]
    fn allocates_distinct_ports_per_issuer() {
        let mut alloc = DedicatedPortAllocator::new(9000..9003);
        let p1 = alloc.allocate(iss("https://idp-a.example.com")).unwrap();
        let p2 = alloc.allocate(iss("https://idp-b.example.com")).unwrap();
        assert_ne!(p1, p2);
        assert!((9000..9003).contains(&p1));
    }

    #[test]
    fn allocation_is_idempotent_per_issuer() {
        let mut alloc = DedicatedPortAllocator::new(9000..9010);
        let p1 = alloc.allocate(iss("https://idp-a.example.com")).unwrap();
        let p1_again = alloc.allocate(iss("https://idp-a.example.com")).unwrap();
        assert_eq!(p1, p1_again);
    }

    /// The actual fix: several servers behind the SAME IDP must share ONE
    /// dedicated port, not get one each. Modeled here as two `allocate`
    /// calls for the same issuer standing in for two different servers'
    /// `dedicated_port` resolution both landing on the same IDP.
    #[test]
    fn multiple_servers_behind_the_same_idp_share_one_port() {
        let mut alloc = DedicatedPortAllocator::new(9000..9010);
        let issuer = iss("https://awkward-vendor-idp.example.com");
        // Server A's resolution path...
        let port_for_server_a = alloc.allocate(issuer.clone()).unwrap();
        // ...and Server B's, behind the same IDP.
        let port_for_server_b = alloc.allocate(issuer.clone()).unwrap();
        assert_eq!(port_for_server_a, port_for_server_b, "servers sharing an IDP must share its dedicated port, not each get their own");
    }

    #[test]
    fn range_exhaustion_is_reported_not_panicked() {
        let mut alloc = DedicatedPortAllocator::new(9000..9001);
        alloc.allocate(iss("https://idp-a.example.com")).unwrap();
        assert_eq!(alloc.allocate(iss("https://idp-b.example.com")).unwrap_err(), IdentityError::PortRangeExhausted);
    }

    #[test]
    fn shared_port_metadata_is_independent_of_dedicated_allocation() {
        // Shared-port metadata is just protected_resource_metadata/as_metadata
        // called with the platform IDP's own issuer — no port allocator
        // involvement at all, which is the point: allocating/exhausting
        // dedicated ports never touches it.
        let meta = protected_resource_metadata("https://gateway.example.com/mcp", "https://platform-idp.example.com");
        assert_eq!(meta["resource"], "https://gateway.example.com/mcp");
    }

    // --- require_dedicated_port: fail-closed on missing allocation -------

    #[test]
    fn require_dedicated_port_returns_the_allocated_port() {
        let mut alloc = DedicatedPortAllocator::new(9000..9010);
        let idp = idp_with_mode("https://vendor-idp.example.com", AuthModeHint::DedicatedPort);
        let port = alloc.allocate(iss(&idp.issuer)).unwrap();
        assert_eq!(require_dedicated_port(&idp, &alloc).unwrap(), port);
    }

    /// The invariant the architect asked for: an IDP configured for
    /// `dedicated_port` with NO port allocated must be a detectable,
    /// fail-closed error — never a silent success that some caller could
    /// mistake for "use the shared listener".
    #[test]
    fn require_dedicated_port_fails_closed_when_idps_port_is_not_allocated() {
        let alloc = DedicatedPortAllocator::new(9000..9010); // nothing allocated
        let idp = idp_with_mode("https://vendor-idp.example.com", AuthModeHint::DedicatedPort);
        let err = require_dedicated_port(&idp, &alloc).unwrap_err();
        assert_eq!(err, IdentityError::DedicatedPortNotAllocated("https://vendor-idp.example.com".to_string()));
    }

    #[test]
    fn require_dedicated_port_rejects_non_dedicated_auth_mode() {
        let alloc = DedicatedPortAllocator::new(9000..9010);
        let idp = idp_with_mode("https://shared-idp.example.com", AuthModeHint::SharedPassthrough);
        assert!(require_dedicated_port(&idp, &alloc).is_err());
    }
}
