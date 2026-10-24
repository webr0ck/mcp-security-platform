//! Declarative claim → [`GrantedRole`] mapping.
//!
//! Ported intent from `proxy/app/middleware/auth.py`'s `_validate_oidc_jwt`
//! (top-level `roles` claim, falling back to Keycloak's
//! `realm_access.roles`) generalized to also cover Entra ID's `roles`/
//! `groups` app-role claims and Zitadel's
//! `urn:zitadel:iam:org:project:roles:<id>:<key>` structured claim — without
//! hardcoding a vendor branch per provider. A [`RoleMapping`] is just a list
//! of (claim path, extraction strategy, raw value → `Role`) rules, loaded
//! from `IdpConfig`; the vendor divergence lives in *configuration*, not in
//! `match` arms here.
//!
//! **Provenance and ceiling enforcement are load-bearing, not optional.**
//! [`RoleMapping::resolve`] takes the asserting `IssuerId` and that IDP's
//! `max_assertable_role` ceiling, and returns [`GrantedRole`]s stamped with
//! the issuer — never a bare `Role`. A role string above an IDP's ceiling is
//! DROPPED and logged (`tracing::warn!`), never silently clamped to the
//! ceiling and never allowed through. This exists because the platform
//! serves multiple IDPs of unequal trust simultaneously (a partner/
//! contractor tenant alongside the corporate IDP); without an issuer-scoped
//! ceiling, an admin in the weakest configured tenant can self-grant a role
//! claim string identical to the corporate IDP's `SuperAdmin` marker and the
//! resulting token is cryptographically flawless — see ARCHITECTURE.md's
//! "Core types" section for the full incident writeup this crate is fixing.

use mcphub_types::{GrantedRole, IssuerId, Role};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

/// How to pull a set of raw role/group strings out of a claim value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimExtract {
    /// `claims["roles"]` is a JSON array of strings (Entra `roles`, a
    /// top-level Keycloak custom mapper, ...). A SCALAR string value at
    /// this claim is NOT accepted here — see [`ClaimExtract::TopLevelScalar`]
    /// for that, an explicit opt-in rather than an implicit coercion. Whether
    /// a claim is emitted as a scalar or a single-element array is
    /// provider/mapper-specific and not something this extractor should
    /// guess at.
    TopLevelArray { claim: String },
    /// `claims["realm_access"]["roles"]` — Keycloak's default location.
    /// Array-only, same rationale as `TopLevelArray`.
    NestedArray { path: Vec<String> },
    /// A claim whose value is a bare JSON string, not an array — e.g. some
    /// custom Entra app-role mappers emit a single space-delimited or
    /// single-value string claim rather than a JSON array. Explicit opt-in:
    /// an operator who configures this rule is declaring "yes, this claim
    /// really is scalar-shaped", rather than this extractor silently
    /// treating any stray scalar as a one-element role list.
    TopLevelScalar { claim: String },
    /// `claims["resource_access"][client_id]["roles"]` — Keycloak
    /// client-scoped roles.
    ResourceAccess { client_id: String },
    /// Zitadel emits one claim per project:
    /// `urn:zitadel:iam:org:project:roles` -> `{ "<role-key>": { "<org-id>": "<org-name>" } }`.
    /// The object's *keys* are the granted role names.
    ZitadelProjectRoles { claim: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleMappingRule {
    pub extract: ClaimExtract,
    /// Maps a raw claim string (case-sensitive) to a platform [`Role`].
    /// Unmapped raw values are ignored (least privilege — never inferred).
    pub role_values: BTreeMap<String, RoleName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoleName {
    SuperAdmin,
    ServerOwner,
    SecurityAnalyst,
    Employee,
}

impl From<RoleName> for Role {
    fn from(r: RoleName) -> Self {
        match r {
            RoleName::SuperAdmin => Role::SuperAdmin,
            RoleName::ServerOwner => Role::ServerOwner,
            RoleName::SecurityAnalyst => Role::SecurityAnalyst,
            RoleName::Employee => Role::Employee,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleMapping {
    pub rules: Vec<RoleMappingRule>,
}

impl RoleMapping {
    /// Convenience constructor matching the three named IDPs in
    /// ARCHITECTURE.md, useful as a STARTING POINT an operator copies into
    /// a specific `IdpConfig` and then reviews/adjusts — never a value two
    /// different `IdpConfig`s should share unexamined. This is why there is
    /// no "shared default role table" constant anymore: this function
    /// builds a fresh table per call, and pairing it with an appropriate
    /// `IdpConfig::max_assertable_role` is what actually makes reusing the
    /// same role-name strings across IDPs safe (see `config::IdpConfig`
    /// doc comment and `registry::check_no_cross_idp_privileged_role_string_collisions`,
    /// which refuses to boot if two IDPs at DIFFERENT ceilings share a
    /// privileged role string — the unintended-collision case this
    /// convenience constructor could otherwise produce).
    pub fn default_for(profile: ProviderHint) -> Self {
        match profile {
            ProviderHint::Keycloak => RoleMapping {
                rules: vec![
                    RoleMappingRule {
                        extract: ClaimExtract::TopLevelArray { claim: "roles".into() },
                        role_values: default_role_values(),
                    },
                    RoleMappingRule {
                        extract: ClaimExtract::NestedArray {
                            path: vec!["realm_access".into(), "roles".into()],
                        },
                        role_values: default_role_values(),
                    },
                ],
            },
            ProviderHint::Entra => RoleMapping {
                rules: vec![RoleMappingRule {
                    extract: ClaimExtract::TopLevelArray { claim: "roles".into() },
                    role_values: default_role_values(),
                }],
            },
            ProviderHint::Zitadel => RoleMapping {
                rules: vec![RoleMappingRule {
                    extract: ClaimExtract::ZitadelProjectRoles {
                        claim: "urn:zitadel:iam:org:project:roles".into(),
                    },
                    role_values: default_role_values(),
                }],
            },
            ProviderHint::Generic => RoleMapping {
                rules: vec![RoleMappingRule {
                    extract: ClaimExtract::TopLevelArray { claim: "roles".into() },
                    role_values: default_role_values(),
                }],
            },
        }
    }

    /// Resolve `claims` against every rule, stamping each surviving role
    /// with `issuer` (provenance — see module docs) and dropping anything
    /// above `max_assertable_role`'s rank (logged at `warn`, never
    /// silently clamped). Deduplicates by `Role` using a `HashSet` — O(1)
    /// per candidate instead of the previous `Vec::contains` linear scan,
    /// which mattered: Entra `groups`/`roles` claims with several thousand
    /// entries are routine, and every entry's cost was previously O(n) just
    /// for the dedup check on top of an unconditional per-entry `String`
    /// allocation (see `extract_raw`/`array_of_strings`, which now borrow
    /// `&str` out of the claims `Value` instead of allocating one per raw
    /// entry — only the few that actually match a `role_values` key get
    /// cloned).
    pub fn resolve(&self, claims: &Value, issuer: &IssuerId, max_assertable_role: Role) -> Vec<GrantedRole> {
        let mut seen: HashSet<Role> = HashSet::new();
        let mut out: Vec<GrantedRole> = Vec::new();
        for rule in &self.rules {
            for raw in extract_raw(claims, &rule.extract) {
                let Some(role_name) = rule.role_values.get(raw) else { continue };
                let role: Role = (*role_name).into();

                if role_exceeds_ceiling(role, max_assertable_role) {
                    tracing::warn!(
                        issuer = %issuer.0,
                        claim_value = raw,
                        role = ?role,
                        max_assertable_role = ?max_assertable_role,
                        "dropping role claim above this issuer's max_assertable_role ceiling"
                    );
                    continue;
                }

                if seen.insert(role) {
                    out.push(GrantedRole { role, asserted_by: issuer.clone() });
                }
            }
        }
        out
    }
}

/// Single implementation of the `Role::rank` ceiling comparison — shared by
/// claim-derived role resolution (`RoleMapping::resolve`, above) and
/// DB-sourced role resolution (`apply_ceiling`, below). One implementation,
/// not two that can drift out of sync.
fn role_exceeds_ceiling(role: Role, max_assertable_role: Role) -> bool {
    role.rank() > max_assertable_role.rank()
}

/// Applies the same issuer ceiling to a role set that did NOT come from
/// token claims — namely, roles resolved from the `role_grants` table in
/// Postgres (`mcphub_store::repo::roles::resolve_roles`). `resolve_identity`
/// (this crate's claim path, via `RoleMapping::resolve` above) already
/// enforces `IdpConfig::max_assertable_role`; this is the DB-sourced
/// equivalent, meant to be called from `StoreAuthenticator::authenticate`
/// (`bin/mcphubd/src/wiring/authenticator.rs`) immediately after loading
/// `role_grants` rows for `(identity.sub, identity.issuer)`.
///
/// Without this, a `role_grants` row is a second, uncapped path to any
/// role string — an operator (or an attacker who can write that table,
/// e.g. via a future unguarded admin endpoint) could hand a low-trust
/// issuer's principal `SuperAdmin` even though that issuer's IdpConfig caps
/// it at `Employee`. Stamps every surviving role with `issuer` (provenance)
/// and drops + logs (`warn`) anything above `max_assertable_role`, exactly
/// like the claim path.
pub fn apply_ceiling(roles: impl IntoIterator<Item = Role>, issuer: &IssuerId, max_assertable_role: Role) -> Vec<GrantedRole> {
    let mut seen: HashSet<Role> = HashSet::new();
    let mut out: Vec<GrantedRole> = Vec::new();
    for role in roles {
        if role_exceeds_ceiling(role, max_assertable_role) {
            tracing::warn!(
                issuer = %issuer.0,
                role = ?role,
                max_assertable_role = ?max_assertable_role,
                "dropping DB-sourced role_grants row above this issuer's max_assertable_role ceiling"
            );
            continue;
        }
        if seen.insert(role) {
            out.push(GrantedRole { role, asserted_by: issuer.clone() });
        }
    }
    out
}

fn default_role_values() -> BTreeMap<String, RoleName> {
    let mut m = BTreeMap::new();
    m.insert("mcphub-super-admin".to_string(), RoleName::SuperAdmin);
    m.insert("mcphub-server-owner".to_string(), RoleName::ServerOwner);
    m.insert("mcphub-security-analyst".to_string(), RoleName::SecurityAnalyst);
    m.insert("mcphub-employee".to_string(), RoleName::Employee);
    m
}

#[derive(Debug, Clone, Copy)]
pub enum ProviderHint {
    Keycloak,
    Entra,
    Zitadel,
    Generic,
}

/// Borrows raw role-candidate strings directly out of `claims` — no
/// allocation for entries that don't end up mapping to a role, which is the
/// overwhelming majority of entries in a large `groups`/`roles` claim.
fn extract_raw<'a>(claims: &'a Value, extract: &ClaimExtract) -> Vec<&'a str> {
    match extract {
        ClaimExtract::TopLevelArray { claim } => array_of_str(claims.get(claim)),
        ClaimExtract::NestedArray { path } => {
            let mut cur = claims;
            for seg in path {
                match cur.get(seg) {
                    Some(v) => cur = v,
                    None => return vec![],
                }
            }
            array_of_str(Some(cur))
        }
        ClaimExtract::TopLevelScalar { claim } => match claims.get(claim) {
            Some(Value::String(s)) => vec![s.as_str()],
            _ => vec![],
        },
        ClaimExtract::ResourceAccess { client_id } => {
            array_of_str(claims.get("resource_access").and_then(|ra| ra.get(client_id)).and_then(|c| c.get("roles")))
        }
        ClaimExtract::ZitadelProjectRoles { claim } => match claims.get(claim) {
            Some(Value::Object(map)) => map.keys().map(String::as_str).collect(),
            _ => vec![],
        },
    }
}

/// Array-only — a bare scalar string is NOT coerced into a one-element
/// list here (see [`ClaimExtract::TopLevelScalar`] for the explicit-opt-in
/// path). Whether a given claim is emitted as an array or a scalar is
/// provider/mapper-specific; silently accepting either shape for a rule an
/// operator configured as "array" risks granting a role via a claim the
/// operator believed was a non-role field that merely happens to hold a
/// string equal to a configured role name.
fn array_of_str(v: Option<&Value>) -> Vec<&str> {
    match v {
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_str()).collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn iss(s: &str) -> IssuerId {
        IssuerId::new(s)
    }

    #[test]
    fn keycloak_realm_access_roles_resolve() {
        let mapping = RoleMapping::default_for(ProviderHint::Keycloak);
        let claims = json!({ "realm_access": { "roles": ["mcphub-security-analyst"] } });
        let roles = mapping.resolve(&claims, &iss("kc"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::SecurityAnalyst, asserted_by: iss("kc") }]);
    }

    #[test]
    fn entra_top_level_roles_resolve() {
        let mapping = RoleMapping::default_for(ProviderHint::Entra);
        let claims = json!({ "roles": ["mcphub-employee"], "appid": "abc" });
        let roles = mapping.resolve(&claims, &iss("entra"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::Employee, asserted_by: iss("entra") }]);
    }

    #[test]
    fn zitadel_project_roles_resolve() {
        let mapping = RoleMapping::default_for(ProviderHint::Zitadel);
        let claims = json!({
            "urn:zitadel:iam:org:project:roles": {
                "mcphub-server-owner": { "org-id": "org-name" }
            }
        });
        let roles = mapping.resolve(&claims, &iss("zitadel"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::ServerOwner, asserted_by: iss("zitadel") }]);
    }

    #[test]
    fn unmapped_raw_role_is_dropped_not_defaulted() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic);
        let claims = json!({ "roles": ["some-unrelated-app-role"] });
        assert!(mapping.resolve(&claims, &iss("g"), Role::SuperAdmin).is_empty());
    }

    // --- NEW-1: provenance + ceiling enforcement -----------------------

    #[test]
    fn granted_role_is_stamped_with_the_configured_issuer() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic);
        let claims = json!({ "roles": ["mcphub-employee"] });
        let roles = mapping.resolve(&claims, &iss("https://trusted.example.com"), Role::SuperAdmin);
        assert_eq!(roles[0].asserted_by, iss("https://trusted.example.com"));
    }

    /// The headline defect: a low-trust IDP (ceiling = Employee) must NOT
    /// be able to mint SuperAdmin just because its role table happens to
    /// map the same string an admin-source IDP uses.
    #[test]
    fn role_above_issuers_ceiling_is_dropped_not_granted() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic); // maps "mcphub-super-admin" -> SuperAdmin, same as any other IDP's default table
        let claims = json!({ "roles": ["mcphub-super-admin"] });
        let roles = mapping.resolve(&claims, &iss("https://partner-tenant.example.com"), Role::Employee);
        assert!(roles.is_empty(), "a non-admin-source IDP must never be able to assert SuperAdmin: got {roles:?}");
    }

    #[test]
    fn role_at_or_below_ceiling_is_granted() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic);
        let claims = json!({ "roles": ["mcphub-server-owner"] });
        let roles = mapping.resolve(&claims, &iss("https://tenant.example.com"), Role::ServerOwner);
        assert_eq!(roles, vec![GrantedRole { role: Role::ServerOwner, asserted_by: iss("https://tenant.example.com") }]);
    }

    #[test]
    fn admin_source_idp_can_still_assert_super_admin() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic);
        let claims = json!({ "roles": ["mcphub-super-admin"] });
        let roles = mapping.resolve(&claims, &iss("https://corporate-idp.example.com"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::SuperAdmin, asserted_by: iss("https://corporate-idp.example.com") }]);
    }

    // --- NEW-2: scalar-vs-array coercion, decided explicitly ------------

    #[test]
    fn scalar_string_on_an_array_only_rule_is_not_coerced_into_a_role() {
        let mapping = RoleMapping::default_for(ProviderHint::Generic); // TopLevelArray { claim: "roles" }
        let claims = json!({ "roles": "mcphub-super-admin" }); // scalar, not an array
        let roles = mapping.resolve(&claims, &iss("g"), Role::SuperAdmin);
        assert!(roles.is_empty(), "a scalar value on an array-typed rule must not be silently accepted as a role");
    }

    #[test]
    fn explicit_scalar_extractor_accepts_a_scalar_claim() {
        let mapping = RoleMapping {
            rules: vec![RoleMappingRule {
                extract: ClaimExtract::TopLevelScalar { claim: "role".into() },
                role_values: default_role_values(),
            }],
        };
        let claims = json!({ "role": "mcphub-employee" });
        let roles = mapping.resolve(&claims, &iss("g"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::Employee, asserted_by: iss("g") }]);
    }

    #[test]
    fn explicit_scalar_extractor_does_not_split_a_multi_word_string() {
        // Symmetric with the array case: a scalar claim is taken whole, not
        // parsed/split — "a b mcphub-super-admin" is one raw candidate
        // string, which won't match any configured role_values entry.
        let mapping = RoleMapping {
            rules: vec![RoleMappingRule {
                extract: ClaimExtract::TopLevelScalar { claim: "role".into() },
                role_values: default_role_values(),
            }],
        };
        let claims = json!({ "role": "a b mcphub-super-admin" });
        let roles = mapping.resolve(&claims, &iss("g"), Role::SuperAdmin);
        assert!(roles.is_empty());
    }

    // --- NEW-3(a): ResourceAccess actually exercised ---------------------

    #[test]
    fn keycloak_resource_access_client_scoped_roles_resolve() {
        let mapping = RoleMapping {
            rules: vec![RoleMappingRule {
                extract: ClaimExtract::ResourceAccess { client_id: "mcphub-portal".into() },
                role_values: default_role_values(),
            }],
        };
        let claims = json!({
            "resource_access": {
                "mcphub-portal": { "roles": ["mcphub-security-analyst"] },
                "some-other-client": { "roles": ["mcphub-super-admin"] }
            }
        });
        let roles = mapping.resolve(&claims, &iss("kc"), Role::SuperAdmin);
        assert_eq!(roles, vec![GrantedRole { role: Role::SecurityAnalyst, asserted_by: iss("kc") }]);
    }

    #[test]
    fn resource_access_ignores_roles_under_a_different_client_id() {
        let mapping = RoleMapping {
            rules: vec![RoleMappingRule {
                extract: ClaimExtract::ResourceAccess { client_id: "mcphub-portal".into() },
                role_values: default_role_values(),
            }],
        };
        let claims = json!({ "resource_access": { "unrelated-client": { "roles": ["mcphub-super-admin"] } } });
        assert!(mapping.resolve(&claims, &iss("kc"), Role::SuperAdmin).is_empty());
    }

    // --- NEW-3(b): dedup correctness after switching to a HashSet --------

    #[test]
    fn duplicate_role_claims_across_rules_still_dedup_to_one() {
        let mapping = RoleMapping {
            rules: vec![
                RoleMappingRule {
                    extract: ClaimExtract::TopLevelArray { claim: "roles".into() },
                    role_values: default_role_values(),
                },
                RoleMappingRule {
                    extract: ClaimExtract::NestedArray { path: vec!["realm_access".into(), "roles".into()] },
                    role_values: default_role_values(),
                },
            ],
        };
        let claims = json!({
            "roles": ["mcphub-employee"],
            "realm_access": { "roles": ["mcphub-employee"] }
        });
        let roles = mapping.resolve(&claims, &iss("g"), Role::SuperAdmin);
        assert_eq!(roles.len(), 1, "the same role from two rules must still dedup to a single GrantedRole");
    }
}
