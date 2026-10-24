//! `IdpConfig` — loadable from a file (install/ansible time) and from a
//! runtime store (admin API), with runtime winning. Per ARCHITECTURE.md:
//! "Runtime config wins; if the DB is unreachable at startup, boot from the
//! file config; if neither is present, refuse to start (fail-closed)."

use crate::claims::RoleMapping;
use crate::error::{IdentityError, Result};
use async_trait::async_trait;
use mcphub_types::Role;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One configured identity provider. Keyed by `issuer` (must exactly match
/// the token's `iss` claim — no normalization, no trailing-slash leniency,
/// to keep issuer resolution unambiguous).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpConfig {
    /// Exact `iss` value this config answers for.
    pub issuer: String,
    /// `.well-known/openid-configuration` base, if it differs from `issuer`
    /// (some Entra tenants publish discovery at a v2.0 path distinct from
    /// the v1 issuer they still emit in tokens — see `entra_issuer_aliases`).
    pub discovery_url: Option<String>,
    /// Additional issuer strings this IDP is also allowed to assert in `iss`
    /// (Entra v1/v2 dual-issuer quirk). Every alias must resolve to the same
    /// JWKS / role mapping as the primary `issuer`.
    pub issuer_aliases: Vec<String>,
    /// Expected `aud` value(s); a token is accepted if its `aud` intersects
    /// this set (RFC 7519 `aud` may be an array).
    pub audiences: Vec<String>,
    pub role_mapping: RoleMapping,
    /// Privilege ceiling: the highest-rank [`Role`] this IDP's tokens may
    /// ever assert (see `Role::rank`). A role claim resolving above this
    /// ceiling is dropped and logged in `claims::RoleMapping::resolve`,
    /// never silently clamped down to the ceiling and never let through.
    /// Only an IDP explicitly configured as `Role::SuperAdmin` here is the
    /// platform's trusted admin source — this is the actual fix for "the
    /// weakest configured IDP can mint SuperAdmin" (see ARCHITECTURE.md).
    /// There is deliberately no `Default` for `IdpConfig` — every operator
    /// must set this explicitly, not inherit a permissive default.
    pub max_assertable_role: Role,
    /// Signature algorithms this issuer's tokens may legitimately use.
    /// Never includes `none`. Enforced against the JWT header, not inferred
    /// from the key type, so alg-confusion (RSA key material reused to
    /// "verify" an HS256 token) is structurally rejected.
    pub allowed_algs: Vec<String>,
    pub clock_skew_seconds: u64,
    pub auth_mode: AuthModeHint,
    pub dedicated_port: Option<u16>,
    /// Detected at startup by probing discovery metadata for
    /// `token_endpoint_auth_methods_supported` / grant type advertisement;
    /// see `discovery::supports_token_exchange`.
    pub supports_token_exchange: bool,
    /// OAuth client used for the PKCE browser flow / dynamic registration.
    pub client_id: Option<String>,
    pub redirect_uri_allowlist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthModeHint {
    SharedPassthrough,
    SharedExchange,
    DedicatedPort,
}

impl IdpConfig {
    pub fn matches_issuer(&self, iss: &str) -> bool {
        self.issuer == iss || self.issuer_aliases.iter().any(|a| a == iss)
    }
}

/// Runtime store for admin-managed IDP config (`POST /api/v1/admin/idps`).
/// Implemented against Postgres in `mcphub-store`; kept as a trait here so
/// this crate has no direct DB dependency.
#[async_trait]
pub trait IdpConfigStore: Send + Sync {
    async fn list(&self) -> Result<Vec<IdpConfig>>;
}

/// File-backed loader for install/ansible-time config.
#[derive(Debug, Clone, Default)]
pub struct FileIdpConfigLoader {
    pub configs: Vec<IdpConfig>,
}

impl FileIdpConfigLoader {
    pub fn from_json(raw: &str) -> Result<Self> {
        let configs: Vec<IdpConfig> =
            serde_json::from_str(raw).map_err(|e| IdentityError::Internal(format!("idp config file: {e}")))?;
        Ok(Self { configs })
    }
}

/// Merge file config with runtime store config: runtime wins per-issuer.
/// If the runtime store is unreachable, callers should pass `None` for
/// `runtime` and boot from file config alone (still fail-closed: an issuer
/// absent from *both* sources is simply not in the resulting registry, and
/// `resolve()` hard-denies unknown issuers).
pub async fn load_effective_config(
    file: &FileIdpConfigLoader,
    runtime: Option<&dyn IdpConfigStore>,
) -> Result<Vec<IdpConfig>> {
    let mut by_issuer: HashMap<String, IdpConfig> =
        file.configs.iter().cloned().map(|c| (c.issuer.clone(), c)).collect();

    if let Some(store) = runtime {
        let runtime_configs = store.list().await?;
        for cfg in runtime_configs {
            by_issuer.insert(cfg.issuer.clone(), cfg);
        }
    }

    if by_issuer.is_empty() {
        // Fail-closed at startup: refuse to boot with zero configured IDPs.
        return Err(IdentityError::Internal("no IDPs configured (file empty and runtime store empty/unreachable)".into()));
    }

    let effective: Vec<IdpConfig> = by_issuer.into_values().collect();
    // Same-primary-issuer collisions are already resolved above (runtime
    // wins). What's NOT yet checked is an issuer_aliases entry on one
    // config colliding with another config's primary issuer or alias —
    // see `registry::check_no_issuer_alias_collisions` for why that's a
    // hard error, not a last-write-wins.
    crate::registry::check_no_issuer_alias_collisions(&effective)?;
    // See `registry::check_no_cross_idp_privileged_role_string_collisions`:
    // two IDPs at different trust ceilings sharing a privileged role-name
    // string is an unintended-collision hazard, refused at load time.
    crate::registry::check_no_cross_idp_privileged_role_string_collisions(&effective)?;

    Ok(effective)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(issuer: &str) -> IdpConfig {
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
            max_assertable_role: Role::SuperAdmin,
        }
    }

    struct StubStore(Vec<IdpConfig>);
    #[async_trait]
    impl IdpConfigStore for StubStore {
        async fn list(&self) -> Result<Vec<IdpConfig>> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test]
    async fn runtime_config_wins_over_file_for_same_issuer() {
        let file = FileIdpConfigLoader { configs: vec![sample("https://a")] };
        let mut runtime_cfg = sample("https://a");
        runtime_cfg.audiences = vec!["overridden".into()];
        let store = StubStore(vec![runtime_cfg]);

        let effective = load_effective_config(&file, Some(&store)).await.unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].audiences, vec!["overridden".to_string()]);
    }

    #[tokio::test]
    async fn empty_file_and_no_runtime_refuses_to_produce_config() {
        let file = FileIdpConfigLoader::default();
        let result = load_effective_config(&file, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_config_used_when_runtime_store_absent() {
        let file = FileIdpConfigLoader { configs: vec![sample("https://a")] };
        let effective = load_effective_config(&file, None).await.unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].issuer, "https://a");
    }

    /// Defect 6, checked at the load/admission boundary this function IS:
    /// a runtime-supplied config whose `issuer_aliases` collides with
    /// another config's primary issuer must refuse to load at all, not
    /// silently produce a registry where one of them wins.
    #[tokio::test]
    async fn runtime_config_with_alias_colliding_another_issuer_is_rejected() {
        let file = FileIdpConfigLoader { configs: vec![sample("https://keycloak.example.com")] };
        let mut zitadel = sample("https://zitadel.example.com");
        zitadel.issuer_aliases = vec!["https://keycloak.example.com".to_string()];
        let store = StubStore(vec![zitadel]);

        let result = load_effective_config(&file, Some(&store)).await;
        assert!(result.is_err(), "a colliding alias across distinct configs must be a hard load-time error");
    }
}
