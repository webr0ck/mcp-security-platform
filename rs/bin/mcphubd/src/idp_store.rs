//! Bridges `mcphub-store`'s `idp_configs` table to
//! `mcphub-identity::config::IdpConfigStore` — the runtime half of
//! ARCHITECTURE.md's "runtime config wins; if the DB is unreachable at
//! startup, boot from the file config" rule.
//!
//! TODO: confirm with architect — `idp_configs` does not persist
//! `role_mapping` / `allowed_algs` / `clock_skew_seconds` /
//! `redirect_uri_allowlist`. Rows loaded from the DB get fixed defaults for
//! those fields (generic role mapping, RS256-only, 60s skew, no redirect
//! URIs registered) — a DB-configured IDP cannot yet express a non-generic
//! role mapping at runtime, only the file config can, until those columns
//! exist. `dedicated_port`/`auth_mode` ARE read from the DB now (moved to
//! `idp_configs` in migration 0009 — see that migration's comment).

use async_trait::async_trait;
use mcphub_identity::claims::{ProviderHint, RoleMapping};
use mcphub_identity::config::{AuthModeHint, IdpConfig, IdpConfigStore};
use mcphub_identity::error::{IdentityError, Result as IdResult};
use mcphub_types::Role;
use sqlx::PgPool;

pub struct PgIdpConfigStore {
    pool: PgPool,
}

impl PgIdpConfigStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl IdpConfigStore for PgIdpConfigStore {
    async fn list(&self) -> IdResult<Vec<IdpConfig>> {
        let rows = mcphub_store::repo::idp::list_active_idps(&self.pool).await.map_err(|e| {
            // Fixed component name only — never leak a dynamically formatted
            // string into a `&'static str`. The real error detail belongs in
            // the log line, not in a type whose whole point is to be a
            // bounded, operator-controlled label (see `DenyReason::
            // DependencyUnavailable`'s doc comment in mcphub-types).
            tracing::error!(error = %e, "idp_configs list failed");
            IdentityError::DependencyUnavailable("postgres")
        })?;

        Ok(rows
            .into_iter()
            .map(|row| IdpConfig {
                issuer: row.issuer,
                discovery_url: row.discovery_url,
                issuer_aliases: vec![],
                audiences: vec![row.client_id.clone()],
                role_mapping: RoleMapping::default_for(ProviderHint::Generic),
                // FAIL CLOSED. This row came from the runtime admin API, and it
                // is built with the *shared* default role table above — which is
                // precisely the hole that let any configured IDP mint
                // `SuperAdmin` by naming a role `mcphub-super-admin` in its own
                // tenant. The ceiling is what contains that for token-claim-
                // derived roles: an IDP registered at runtime may assert
                // nothing above `Employee` via a token claim until an operator
                // deliberately raises it. It ALSO now bounds `role_grants`
                // rows for this issuer — `StoreAuthenticator::authenticate`
                // (`bin/mcphubd/src/wiring/authenticator.rs`) re-resolves this
                // same `IdpConfig` and runs DB-sourced roles through
                // `mcphub_identity::claims::apply_ceiling` before they reach
                // `Identity.roles`, so a `role_grants` row above this ceiling
                // is dropped exactly like an over-privileged token claim
                // would be, not just the claim path.
                //
                // TODO(schema): `idp_configs` needs a `max_assertable_role`
                // column so this is operator-controlled rather than pinned here.
                // Until it exists, do NOT "fix" this by widening the default —
                // raising it re-opens the privilege-escalation path for every
                // runtime-registered IDP at once.
                max_assertable_role: Role::Employee,
                allowed_algs: vec!["RS256".to_string()],
                clock_skew_seconds: 60,
                auth_mode: if row.dedicated_port.is_some() { AuthModeHint::DedicatedPort } else { AuthModeHint::SharedPassthrough },
                dedicated_port: row.dedicated_port.map(|p| p as u16),
                supports_token_exchange: row.supports_token_exchange,
                client_id: Some(row.client_id),
                redirect_uri_allowlist: vec![],
            })
            .collect())
    }
}
