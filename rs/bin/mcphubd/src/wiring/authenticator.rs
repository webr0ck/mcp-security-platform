//! `Authenticator` ← `mcphub-identity` for JWT/JWKS validation, with roles
//! then re-resolved from Postgres via the ISSUER-SCOPED
//! `mcphub_store::repo::roles::resolve_roles(pool, sub, issuer)` — never
//! `display_roles_all_issuers`, which aggregates across issuers and exists
//! purely for the admin UI's display list (see its doc comment).
//!
//! `mcphub_identity::resolve_identity` already produces an `Identity` with
//! roles derived from token claims (`IdpConfig::role_mapping`); we discard
//! that claim-derived role set and replace it with the DB lookup, per the
//! integration brief. The claim-derived roles remain useful as an IdP
//! onboarding signal but are not the enforcement source of truth here.
//!
//! **The DB lookup is a second, uncapped source of roles unless it is
//! ceiling-checked too.** `resolve_identity`'s claim path applies
//! `IdpConfig::max_assertable_role` (see `mcphub_identity::claims::
//! RoleMapping::resolve`), but a `role_grants` row bypasses claims
//! entirely — a low-trust issuer's principal with a `role_grants` row
//! naming `super_admin` would otherwise sail straight past the ceiling
//! that exists precisely to stop that. So after loading `db_roles` we
//! re-resolve the SAME `IdpConfig` this token authenticated against (via
//! `registry.resolve(&identity.issuer.0)` — guaranteed present, since
//! `identity.issuer` is exactly the configured issuer string
//! `resolve_identity` just looked up in this same registry) and run the DB
//! roles through `mcphub_identity::claims::apply_ceiling`, the identical
//! rank-comparison the claim path uses. One ceiling implementation, applied
//! on both role sources.

use async_trait::async_trait;
use mcphub_gateway::traits::{Authenticator, RawCredential};
use mcphub_identity::jwks::JwksCache;
use mcphub_identity::registry::IssuerRegistry;
use mcphub_types::GateError;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;

pub struct StoreAuthenticator {
    pub registry: Arc<IssuerRegistry>,
    pub jwks_cache: Arc<JwksCache>,
    /// issuer -> jwks_uri, resolved once at startup via RFC 8414 discovery
    /// (see `main.rs`'s startup sequence). `resolve_identity` takes this as
    /// a synchronous closure, so it cannot itself perform discovery.
    pub jwks_uris: Arc<HashMap<String, String>>,
    pub pool: PgPool,
}

#[async_trait]
impl Authenticator for StoreAuthenticator {
    async fn authenticate(&self, raw: &RawCredential) -> Result<mcphub_types::Identity, GateError> {
        let token = raw
            .bearer_token
            .as_deref()
            .ok_or_else(|| GateError::InvalidRequest("missing bearer token".to_string()))?;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let jwks_uris = self.jwks_uris.clone();
        let mut identity = mcphub_identity::resolve_identity(token, &self.registry, &self.jwks_cache, move |idp| {
            jwks_uris.get(&idp.issuer).cloned().unwrap_or_default()
        }, now)
        .await
        .map_err(|_| GateError::DependencyUnavailable("identity"))?;

        // Enforcement roles come from Postgres, issuer-scoped — never the
        // claim-derived set, and never the display-only cross-issuer
        // aggregate (`display_roles_all_issuers`).
        let db_roles = mcphub_store::repo::roles::resolve_roles(&self.pool, &identity.sub, &identity.issuer.0).await?;

        // The `IdpConfig` this token authenticated against — same registry
        // lookup `resolve_identity` already did internally via the token's
        // (verified) `iss`. `identity.issuer` IS the configured issuer
        // string (never a raw/alias claim — see `resolve_identity`'s doc
        // comment), so this resolve cannot fail under correct operation;
        // fail closed regardless rather than assume.
        let idp = self.registry.resolve(&identity.issuer.0).map_err(|e| {
            tracing::error!(error = ?e, issuer = %identity.issuer.0, "authenticated identity's issuer vanished from the registry between resolve_identity and the DB role ceiling check");
            GateError::DependencyUnavailable("identity")
        })?;

        // Stamping every surviving DB role with `identity.issuer` is sound
        // *because* `resolve_roles` filters by that same issuer in SQL. If
        // that query ever stops being issuer-scoped, this becomes a
        // provenance forgery — the roles would claim an issuer that did not
        // assert them. `apply_ceiling` additionally drops (and logs) any
        // role above `idp.max_assertable_role` — see the module doc
        // comment: this is what closes the `role_grants`-row bypass of the
        // per-issuer ceiling.
        identity.roles = mcphub_identity::claims::apply_ceiling(db_roles, &identity.issuer, idp.max_assertable_role);

        Ok(identity)
    }
}
