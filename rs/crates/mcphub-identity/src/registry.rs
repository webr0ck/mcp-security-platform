//! Multi-issuer registry: resolves a configured [`IdpConfig`] from a token's
//! `iss` claim — and *only* from a token's `iss` claim. An issuer string
//! that is not in this registry is a hard deny (`IdentityError::UnknownIssuer`),
//! never a fallback to some default IDP. This is the mitigation for the
//! classic multi-tenant OIDC bug: an attacker sets `iss` to a URL they
//! control, pointing at their own JWKS, hoping the relying party will fetch
//! and trust it. Because `resolve` only ever looks up a pre-registered,
//! operator-configured map, that attack has no purchase here — the attacker's
//! JWKS is simply never consulted.

use crate::config::IdpConfig;
use crate::error::{IdentityError, Result};
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Default, Debug)]
pub struct IssuerRegistry {
    by_issuer: HashMap<String, IdpConfig>,
}

impl IssuerRegistry {
    /// Builds the registry, hard-erroring if any issuer string OR issuer
    /// alias is claimed by more than one distinct `IdpConfig`. The
    /// previous implementation `insert()`ed every issuer and alias with
    /// last-write-wins and no error: since IDP config is settable at
    /// runtime (`POST /api/v1/admin/idps`) and runtime wins over file
    /// config, a Zitadel config whose `issuer_aliases` happened to contain
    /// Keycloak's issuer string would silently make every Keycloak token
    /// resolve to Zitadel's `role_mapping` — an attacker-influenced
    /// claim→role mapping applied to another IDP's tokens. A collision here
    /// is always a misconfiguration (or an attack), never something to
    /// resolve by picking a winner.
    pub fn from_configs(configs: Vec<IdpConfig>) -> Result<Self> {
        check_no_issuer_alias_collisions(&configs)?;
        check_no_cross_idp_privileged_role_string_collisions(&configs)?;
        let mut by_issuer = HashMap::new();
        for cfg in configs {
            by_issuer.insert(cfg.issuer.clone(), cfg.clone());
            for alias in &cfg.issuer_aliases {
                by_issuer.insert(alias.clone(), cfg.clone());
            }
        }
        Ok(Self { by_issuer })
    }

    /// Hard deny on any issuer not explicitly configured.
    pub fn resolve(&self, iss: &str) -> Result<&IdpConfig> {
        self.by_issuer.get(iss).ok_or(IdentityError::UnknownIssuer)
    }
}

/// Shared by `IssuerRegistry::from_configs` and
/// `config::load_effective_config` so the collision check happens both at
/// the point configs are assembled (load/admission time) and, defensively,
/// wherever a registry is actually built from a config list — a duplicate
/// issuer-or-alias across distinct configs is a hard error in both places,
/// never a silent last-write-wins.
pub fn check_no_issuer_alias_collisions(configs: &[IdpConfig]) -> Result<()> {
    let mut owner_by_claim: HashMap<&str, &str> = HashMap::new();
    for cfg in configs {
        for claim in std::iter::once(cfg.issuer.as_str()).chain(cfg.issuer_aliases.iter().map(String::as_str)) {
            match owner_by_claim.get(claim) {
                Some(owner) if *owner != cfg.issuer.as_str() => {
                    return Err(IdentityError::DuplicateIssuerConfig(claim.to_string()));
                }
                Some(_) => {}
                None => {
                    owner_by_claim.insert(claim, cfg.issuer.as_str());
                }
            }
        }
    }
    Ok(())
}

/// Shared by `IssuerRegistry::from_configs` and
/// `config::load_effective_config`. ARCHITECTURE.md rule 3 ("No shared
/// default role table"): two configured IDPs mapping the SAME raw role
/// string to a PRIVILEGED role (anything above `Employee` — see
/// `Role::rank`) must be an explicit, reviewed operator decision, not an
/// accident of both configs starting from `RoleMapping::default_for(...)`'s
/// convenience table. "Explicit decision" here is operationalized as: the
/// two configs must share the same `max_assertable_role` ceiling — sharing
/// a privileged role string across IDPs trusted to the SAME degree is a
/// deliberate, safe operator convention (e.g. both are corporate-owned
/// realms configured identically); sharing it across DIFFERENT trust
/// ceilings is exactly the shape of the unintended-collision hazard this
/// rule exists to catch, even though `claims::RoleMapping::resolve`'s
/// per-request ceiling check is the actual last line of defense regardless.
pub fn check_no_cross_idp_privileged_role_string_collisions(configs: &[IdpConfig]) -> Result<()> {
    use mcphub_types::Role;
    let mut owner_by_role_string: HashMap<&str, (&str, Role)> = HashMap::new();
    for cfg in configs {
        for rule in &cfg.role_mapping.rules {
            for (raw, role_name) in &rule.role_values {
                let role: Role = (*role_name).into();
                if role.rank() == 0 {
                    continue; // Employee (or any future rank-0 role) is not privileged
                }
                match owner_by_role_string.get(raw.as_str()) {
                    Some((owner_issuer, owner_ceiling))
                        if *owner_issuer != cfg.issuer.as_str() && *owner_ceiling != cfg.max_assertable_role =>
                    {
                        return Err(IdentityError::PrivilegedRoleStringCollision(raw.clone()));
                    }
                    _ => {
                        owner_by_role_string.insert(raw.as_str(), (cfg.issuer.as_str(), cfg.max_assertable_role));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Decode a JWT's payload **without verifying the signature**. Shared by
/// every "peek a claim before/around full verification" caller in this
/// crate; nothing that reads through this function may be trusted for
/// anything beyond routing/UX decisions — every claim is re-checked
/// cryptographically in `validate::validate_claims` once the correct key is
/// in hand.
fn decode_unverified_payload(token: &str) -> Result<Value> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(IdentityError::Malformed)?;
    let payload_b64 = parts.next().ok_or(IdentityError::Malformed)?;
    if parts.next().is_none() {
        return Err(IdentityError::Malformed);
    }
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| IdentityError::Malformed)?;
    serde_json::from_slice(&payload_bytes).map_err(|_| IdentityError::Malformed)
}

/// Extract the `iss` claim from a JWT **without verifying the signature**,
/// used only to pick which configured issuer's key material to verify
/// against next. This value must never be trusted for anything beyond that
/// routing decision — every field (including `iss` itself) is re-checked
/// cryptographically in `validate::validate_claims` once the correct key is
/// in hand.
pub fn peek_unverified_issuer(token: &str) -> Result<String> {
    decode_unverified_payload(token)?
        .get("iss")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or(IdentityError::Malformed)
}

/// Extract the `nonce` claim from an ID token **without verifying the
/// signature**. Used only in the PKCE callback (`pkce::validate_callback`)
/// to compare against the `PendingFlow`'s recorded nonce; that comparison
/// is a replay/injection check, not an authenticity check, and the
/// authenticity of this same token is separately, cryptographically proven
/// moments later by `mcphub_identity::resolve_identity` (which calls
/// `validate::validate_claims`) before any `Identity` is trusted or a
/// session is minted. Returns `Ok(None)` (not an error) when the claim is
/// absent — callers that require a nonce enforce that themselves.
pub fn peek_unverified_nonce(token: &str) -> Result<Option<String>> {
    Ok(decode_unverified_payload(token)?.get("nonce").and_then(|v| v.as_str()).map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::RoleMapping;
    use crate::config::AuthModeHint;

    fn cfg(issuer: &str) -> IdpConfig {
        IdpConfig {
            issuer: issuer.to_string(),
            discovery_url: None,
            issuer_aliases: vec![],
            audiences: vec!["mcphub".into()],
            role_mapping: RoleMapping::default(),
            allowed_algs: vec!["RS256".into()],
            clock_skew_seconds: 60,
            auth_mode: AuthModeHint::SharedPassthrough,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: None,
            redirect_uri_allowlist: vec![],
            max_assertable_role: mcphub_types::Role::SuperAdmin,
        }
    }

    #[test]
    fn unconfigured_issuer_is_hard_denied() {
        let reg = IssuerRegistry::from_configs(vec![cfg("https://good-idp.example.com")]).unwrap();
        let err = reg.resolve("https://attacker.example.com").unwrap_err();
        assert_eq!(err, IdentityError::UnknownIssuer);
    }

    #[test]
    fn configured_issuer_resolves() {
        let reg = IssuerRegistry::from_configs(vec![cfg("https://good-idp.example.com")]).unwrap();
        assert!(reg.resolve("https://good-idp.example.com").is_ok());
    }

    #[test]
    fn alias_issuer_resolves_to_same_config() {
        let mut c = cfg("https://login.microsoftonline.com/tenant/v2.0");
        c.issuer_aliases = vec!["https://sts.windows.net/tenant/".into()];
        let reg = IssuerRegistry::from_configs(vec![c]).unwrap();
        assert!(reg.resolve("https://sts.windows.net/tenant/").is_ok());
    }

    /// Defect 6: a Zitadel config whose `issuer_aliases` happens to contain
    /// Keycloak's issuer string must be rejected at construction — not
    /// silently let last-write-wins decide, which is how a runtime-set IDP
    /// config could previously hijack another IDP's tokens into its own
    /// `role_mapping`.
    #[test]
    fn alias_colliding_with_another_configs_primary_issuer_is_a_hard_error() {
        let keycloak = cfg("https://keycloak.example.com/realms/mcphub");
        let mut zitadel = cfg("https://zitadel.example.com");
        zitadel.issuer_aliases = vec!["https://keycloak.example.com/realms/mcphub".to_string()];
        let err = IssuerRegistry::from_configs(vec![keycloak, zitadel]).unwrap_err();
        assert_eq!(err, IdentityError::DuplicateIssuerConfig("https://keycloak.example.com/realms/mcphub".to_string()));
    }

    #[test]
    fn alias_colliding_with_another_configs_alias_is_a_hard_error() {
        let mut a = cfg("https://a.example.com");
        a.issuer_aliases = vec!["https://shared-alias.example.com".to_string()];
        let mut b = cfg("https://b.example.com");
        b.issuer_aliases = vec!["https://shared-alias.example.com".to_string()];
        assert!(IssuerRegistry::from_configs(vec![a, b]).is_err());
    }

    #[test]
    fn distinct_issuers_with_distinct_aliases_load_fine() {
        let mut a = cfg("https://a.example.com");
        a.issuer_aliases = vec!["https://a-alias.example.com".to_string()];
        let mut b = cfg("https://b.example.com");
        b.issuer_aliases = vec!["https://b-alias.example.com".to_string()];
        assert!(IssuerRegistry::from_configs(vec![a, b]).is_ok());
    }

    // --- NEW-1 addendum: cross-IDP privileged role-string collisions -----

    use crate::claims::{ClaimExtract, RoleMappingRule, RoleName};
    use mcphub_types::Role;
    use std::collections::BTreeMap;

    fn role_mapping_with(claim_value: &str, role: RoleName) -> RoleMapping {
        let mut role_values = BTreeMap::new();
        role_values.insert(claim_value.to_string(), role);
        RoleMapping {
            rules: vec![RoleMappingRule { extract: ClaimExtract::TopLevelArray { claim: "roles".into() }, role_values }],
        }
    }

    #[test]
    fn two_idps_at_different_ceilings_sharing_a_privileged_role_string_is_a_hard_error() {
        let mut trusted = cfg("https://corporate-idp.example.com");
        trusted.role_mapping = role_mapping_with("mcphub-super-admin", RoleName::SuperAdmin);
        trusted.max_assertable_role = Role::SuperAdmin;

        let mut partner = cfg("https://partner-tenant.example.com");
        partner.role_mapping = role_mapping_with("mcphub-super-admin", RoleName::SuperAdmin);
        partner.max_assertable_role = Role::Employee; // different ceiling — unintended collision

        let err = IssuerRegistry::from_configs(vec![trusted, partner]).unwrap_err();
        assert_eq!(err, IdentityError::PrivilegedRoleStringCollision("mcphub-super-admin".to_string()));
    }

    #[test]
    fn two_idps_at_the_same_ceiling_sharing_a_privileged_role_string_is_allowed() {
        let mut a = cfg("https://a.example.com");
        a.role_mapping = role_mapping_with("mcphub-server-owner", RoleName::ServerOwner);
        a.max_assertable_role = Role::ServerOwner;

        let mut b = cfg("https://b.example.com");
        b.role_mapping = role_mapping_with("mcphub-server-owner", RoleName::ServerOwner);
        b.max_assertable_role = Role::ServerOwner;

        assert!(IssuerRegistry::from_configs(vec![a, b]).is_ok(), "same-ceiling IDPs sharing a role string is an explicit, safe operator convention");
    }

    #[test]
    fn sharing_an_employee_level_role_string_across_different_ceilings_is_fine() {
        // Employee (rank 0) is not privileged — sharing that string is not
        // the hazard this check exists for.
        let mut a = cfg("https://a.example.com");
        a.role_mapping = role_mapping_with("mcphub-employee", RoleName::Employee);
        a.max_assertable_role = Role::SuperAdmin;

        let mut b = cfg("https://b.example.com");
        b.role_mapping = role_mapping_with("mcphub-employee", RoleName::Employee);
        b.max_assertable_role = Role::Employee;

        assert!(IssuerRegistry::from_configs(vec![a, b]).is_ok());
    }
}
