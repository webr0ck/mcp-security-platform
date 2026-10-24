use crate::ids::IssuerId;
use crate::secret::Secret;
use serde::{Deserialize, Serialize};

/// Resolved roles. Deliberately a closed enum, not raw claim strings — role
/// resolution (claims → `Role`) happens once in `mcphub-identity` so every
/// downstream gate matches on a fixed, exhaustively-checkable set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    SuperAdmin,
    ServerOwner,
    SecurityAnalyst,
    Employee,
}

impl Role {
    /// Privilege rank used ONLY to enforce `IdpConfig::max_assertable_role`
    /// (a per-IDP ceiling — see `GrantedRole` and ARCHITECTURE.md's "Core
    /// types" section). `ServerOwner` and `SecurityAnalyst` are peers, not
    /// ordered against each other — they share a rank. This is not a
    /// general-purpose privilege total order for authorization decisions;
    /// RBAC/Rego still match on the concrete `Role`, never on rank.
    pub fn rank(self) -> u8 {
        match self {
            Role::Employee => 0,
            Role::ServerOwner | Role::SecurityAnalyst => 1,
            Role::SuperAdmin => 2,
        }
    }

    /// Canonical wire/DB string form — the one conversion point for this
    /// direction (`mcphub-store::repo::roles::role_to_db` mirrors these
    /// exact strings and should be read as delegating to this, not as an
    /// independent source of truth). Lives on the type itself so crates
    /// that must not depend on `mcphub-store` (e.g. `mcphub-gateway`,
    /// serializing roles for the backend-dispatch header contract) can
    /// still produce it.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::SuperAdmin => "super_admin",
            Role::ServerOwner => "server_owner",
            Role::SecurityAnalyst => "security_analyst",
            Role::Employee => "employee",
        }
    }
}

/// A role is NEVER a bare [`Role`]. It is always paired with the issuer that
/// asserted it, and that provenance survives all the way to the
/// authorization decision (RBAC, Rego input) — see ARCHITECTURE.md's "Core
/// types" section for why: a bare `Role` with no issuer binding lets the
/// weakest configured IDP mint `SuperAdmin` by asserting a role claim string
/// no more privileged than any other IDP's, with no way for downstream
/// policy to tell a partner tenant's self-granted admin claim from the
/// corporate IDP's.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GrantedRole {
    pub role: Role,
    pub asserted_by: IssuerId,
}

/// Opaque handle for downstream token exchange (RFC 8693) or passthrough.
/// Carries the caller's raw bearer token when one exists, wrapped so it can
/// never be logged or displayed accidentally. `None` for callers without a
/// forwardable token (e.g. mTLS-only, API-key-only principals).
#[derive(Debug, Clone)]
pub struct TokenRef(Option<Secret<String>>);

impl TokenRef {
    pub fn none() -> Self {
        Self(None)
    }

    pub fn from_bearer(token: impl Into<String>) -> Self {
        Self(Some(Secret::new(token.into())))
    }

    pub fn is_present(&self) -> bool {
        self.0.is_some()
    }

    /// Explicit opt-in read, mirroring `Secret::expose_secret`. Only the
    /// identity-exchange and credential-injection code paths should call
    /// this.
    pub fn expose(&self) -> Option<&str> {
        self.0.as_ref().map(|s| s.expose_secret().as_str())
    }
}

/// A resolved caller identity — the output of the `authenticate` +
/// `resolve identity` steps in the enforcement order. Everything downstream
/// of identity resolution operates on this, never on raw claims.
#[derive(Debug, Clone)]
pub struct Identity {
    pub sub: String,
    pub issuer: IssuerId,
    pub email: Option<String>,
    pub roles: Vec<GrantedRole>,
    pub groups: Vec<String>,
    pub token_ref: TokenRef,
}

impl Identity {
    /// True if ANY granted role matches, regardless of which issuer
    /// asserted it — safe because ceiling enforcement
    /// (`IdpConfig::max_assertable_role`) already happened at role
    /// *resolution* time, for BOTH sources `Identity.roles` can be built
    /// from: token-claim-derived roles (`mcphub_identity::claims::
    /// RoleMapping::resolve`) and DB-sourced `role_grants` roles
    /// (`mcphub_identity::claims::apply_ceiling`, called from
    /// `StoreAuthenticator::authenticate` in `bin/mcphubd`). Nothing reaches
    /// `Identity.roles` that its issuer wasn't allowed to assert, from
    /// either source. Callers that need to distinguish *which* issuer
    /// vouched for a role (e.g. a policy specifically trusting only the
    /// corporate IDP) should inspect `roles` directly for
    /// `GrantedRole.asserted_by`.
    pub fn has_role(&self, role: Role) -> bool {
        self.roles.iter().any(|g| g.role == role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_ref_debug_never_contains_raw_token() {
        let tr = TokenRef::from_bearer("eyJraWQiOiJzZWNyZXQtand0LXRva2VuIn0");
        let rendered = format!("{:?}", tr);
        assert!(!rendered.contains("eyJraWQi"));
    }

    #[test]
    fn identity_has_role_checks_membership() {
        let id = Identity {
            sub: "user-1".into(),
            issuer: IssuerId::new("platform"),
            email: None,
            roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
            groups: vec![],
            token_ref: TokenRef::none(),
        };
        assert!(id.has_role(Role::Employee));
        assert!(!id.has_role(Role::SuperAdmin));
    }

    #[test]
    fn role_rank_orders_super_admin_above_peer_roles_above_employee() {
        assert!(Role::SuperAdmin.rank() > Role::ServerOwner.rank());
        assert!(Role::SuperAdmin.rank() > Role::SecurityAnalyst.rank());
        assert_eq!(Role::ServerOwner.rank(), Role::SecurityAnalyst.rank());
        assert!(Role::ServerOwner.rank() > Role::Employee.rank());
    }
}
