//! Mounts the portal (`mcphub-ui`) into the same axum app, backed by the
//! real `PgUiData` and a real OIDC PKCE browser login.
//!
//! `mcphub-ui` stays free of `mcphub-identity` and Postgres (see
//! `rs/ARCHITECTURE.md` — that crate owns templates + static only), so the
//! actual login flow is implemented here, against this binary's own
//! `IssuerRegistry` / `JwksCache` / discovery / pool — the exact same
//! pieces `wiring::authenticator::StoreAuthenticator` uses for bearer-token
//! requests. `PortalOidcClient::complete` deliberately calls the SAME
//! `mcphub_identity::resolve_identity` + `mcphub_store::repo::roles::
//! resolve_roles` + `mcphub_identity::claims::apply_ceiling` sequence
//! `StoreAuthenticator` does — one validation path and one role-ceiling
//! implementation, reused for the browser flow rather than re-invented.
//!
//! The dev session-picker `/login` route is compiled out of this binary
//! entirely (`mcphub-ui`'s `dev_login` feature, default-off, and this
//! crate's `Cargo.toml` sets `default-features = false`) — see
//! `mcphub_ui::auth`'s module doc for why a reachable session picker in
//! production is a total auth bypass.

use async_trait::async_trait;
use mcphub_identity::config::IdpConfig;
use mcphub_identity::discovery::DiscoveryDocument;
use mcphub_identity::jwks::JwksCache;
use mcphub_identity::pkce::PendingFlowStore;
use mcphub_identity::registry::IssuerRegistry;
use mcphub_store::PgUiData;
use mcphub_types::Identity;
use mcphub_ui::auth::BoundedSessionStore;
use mcphub_ui::oidc::{OidcLogin, OidcLoginError};
use mcphub_ui::AppState as UiAppState;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const PORTAL_LOGIN_SCOPE: &str = "openid profile email";

/// No portal-capable IDP is configured (none of the loaded `IdpConfig`s has
/// both a `client_id` and a non-empty `redirect_uri_allowlist`). `/login`
/// fails closed with `UpstreamUnavailable` rather than the binary refusing
/// to start — the gateway's bearer-token path (dedicated ports, MCP
/// clients) does not depend on the browser login working.
struct PortalLoginUnconfigured;

#[async_trait]
impl OidcLogin for PortalLoginUnconfigured {
    async fn start(&self) -> Result<String, OidcLoginError> {
        tracing::error!("portal login requested but no IDP is configured for it (need client_id + redirect_uri_allowlist)");
        Err(OidcLoginError::UpstreamUnavailable)
    }

    async fn complete(&self, _code: &str, _state: &str) -> Result<Identity, OidcLoginError> {
        Err(OidcLoginError::UpstreamUnavailable)
    }
}

/// Real OIDC PKCE browser login for one designated "portal" IDP.
///
/// Multi-IDP note: only ONE configured IDP drives the portal's own
/// `/login` — the one selected by [`choose_portal_idp`]. This is
/// independent of how many IDPs are configured for MCP-server-facing
/// `auth_mode`s (`shared_passthrough`/`shared_exchange`/`dedicated_port`);
/// letting a human pick which IDP to sign into the portal with (rather than
/// always using the first eligible one) is a real gap, not papered over —
/// see the report for this pass.
struct PortalOidcClient {
    idp: IdpConfig,
    client_id: String,
    authorization_endpoint: url::Url,
    token_endpoint: url::Url,
    redirect_uri: String,
    registry: Arc<IssuerRegistry>,
    jwks_cache: Arc<JwksCache>,
    jwks_uri: String,
    pool: PgPool,
    pending: Mutex<PendingFlowStore>,
}

#[async_trait]
impl OidcLogin for PortalOidcClient {
    async fn start(&self) -> Result<String, OidcLoginError> {
        let (req, pending) = mcphub_identity::pkce::start_login(
            self.authorization_endpoint.as_str(),
            &self.client_id,
            &self.redirect_uri,
            &self.idp.redirect_uri_allowlist,
            PORTAL_LOGIN_SCOPE,
        )
        .map_err(|e| {
            tracing::error!(error = ?e, "portal login: failed to start PKCE flow");
            OidcLoginError::UpstreamUnavailable
        })?;

        self.pending.lock().unwrap().insert(pending).map_err(|e| {
            tracing::warn!(error = ?e, "portal login: pending-flow store rejected insert (likely at capacity)");
            OidcLoginError::UpstreamUnavailable
        })?;

        Ok(req.to_url())
    }

    async fn complete(&self, code: &str, state: &str) -> Result<Identity, OidcLoginError> {
        // Single-use: removed from the store the moment we look it up, so a
        // replayed `state` (even a correct one, twice) fails the second time
        // regardless of what happens below.
        let pending = self.pending.lock().unwrap().consume(state).map_err(|_| OidcLoginError::InvalidCallback)?;

        let token = mcphub_identity::pkce::exchange_authorization_code(
            &self.token_endpoint,
            &self.client_id,
            code,
            &pending.redirect_uri,
            &pending.pkce.verifier,
        )
        .await
        .map_err(|e| {
            tracing::warn!(error = ?e, "portal login: authorization code redemption failed");
            OidcLoginError::InvalidCallback
        })?;

        let nonce = mcphub_identity::registry::peek_unverified_nonce(&token.id_token)
            .map_err(|_| OidcLoginError::InvalidCallback)?
            .ok_or(OidcLoginError::InvalidCallback)?;

        mcphub_identity::pkce::validate_callback(&pending, state, &nonce, &self.redirect_uri)
            .map_err(|_| OidcLoginError::InvalidCallback)?;

        // The ONE validation path — signature, issuer, audience, exp/nbf/iat
        // skew, alg allowlist — is `resolve_identity`, the same function
        // `StoreAuthenticator::authenticate` calls for bearer tokens. Not
        // re-implemented here.
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let jwks_uri = self.jwks_uri.clone();
        let mut identity =
            mcphub_identity::resolve_identity(&token.id_token, &self.registry, &self.jwks_cache, move |_idp| jwks_uri.clone(), now)
                .await
                .map_err(|e| {
                    tracing::warn!(error = ?e, "portal login: id_token failed validation");
                    OidcLoginError::InvalidCallback
                })?;

        // Enforcement roles come from Postgres, issuer-scoped, ceiling-
        // applied — never the claim-derived set `resolve_identity` produced
        // above. Identical to `StoreAuthenticator::authenticate`'s DB-role
        // step; see that file's module doc for why the ceiling re-check is
        // required even though `resolve_identity` already applied one to
        // the claim path.
        let db_roles = mcphub_store::repo::roles::resolve_roles(&self.pool, &identity.sub, &identity.issuer.0).await.map_err(|e| {
            tracing::error!(error = ?e, "portal login: DB role lookup failed");
            OidcLoginError::UpstreamUnavailable
        })?;
        let idp = self.registry.resolve(&identity.issuer.0).map_err(|e| {
            tracing::error!(error = ?e, issuer = %identity.issuer.0, "portal login: authenticated issuer vanished from the registry");
            OidcLoginError::UpstreamUnavailable
        })?;
        identity.roles = mcphub_identity::claims::apply_ceiling(db_roles, &identity.issuer, idp.max_assertable_role);

        Ok(identity)
    }
}

/// Only an IDP with both a `client_id` and a non-empty
/// `redirect_uri_allowlist` can drive a browser login — those are exactly
/// the fields the PKCE flow needs and that MCP-server-facing-only IDPs
/// (bearer-token consumers with no portal client registered) won't have
/// set. First match wins; see `PortalOidcClient`'s doc comment for the
/// multi-IDP gap this leaves.
fn choose_portal_idp(idps_by_issuer: &HashMap<String, IdpConfig>) -> Option<IdpConfig> {
    idps_by_issuer.values().find(|idp| idp.client_id.is_some() && !idp.redirect_uri_allowlist.is_empty()).cloned()
}

/// `http://{MCPHUB_PUBLIC_HOST}:{port}/callback` unless
/// `MCPHUB_PORTAL_REDIRECT_URI` is set explicitly (needed whenever the
/// public-facing scheme/host/port the IDP was registered against differs
/// from what this process binds — e.g. behind the nginx gateway's mTLS
/// termination). Whatever this resolves to MUST already be present in the
/// chosen IDP's `redirect_uri_allowlist` — `pkce::start_login` enforces
/// that and fails closed if it isn't.
fn portal_redirect_uri(port: u16) -> String {
    if let Ok(explicit) = std::env::var("MCPHUB_PORTAL_REDIRECT_URI") {
        if !explicit.trim().is_empty() {
            return explicit;
        }
    }
    let host = std::env::var("MCPHUB_PUBLIC_HOST").unwrap_or_else(|_| "localhost".to_string());
    format!("http://{host}:{port}/callback")
}

fn build_oidc_client(
    registry: Arc<IssuerRegistry>,
    jwks_cache: Arc<JwksCache>,
    jwks_uris: Arc<HashMap<String, String>>,
    idps_by_issuer: &HashMap<String, IdpConfig>,
    discovery_docs: &HashMap<String, DiscoveryDocument>,
    pool: PgPool,
    listen_port: u16,
) -> Arc<dyn OidcLogin> {
    let Some(idp) = choose_portal_idp(idps_by_issuer) else {
        tracing::warn!("no IDP is configured with both client_id and redirect_uri_allowlist; portal /login will fail closed");
        return Arc::new(PortalLoginUnconfigured);
    };
    let Some(client_id) = idp.client_id.clone() else {
        return Arc::new(PortalLoginUnconfigured);
    };
    let Some(doc) = discovery_docs.get(&idp.issuer) else {
        tracing::warn!(issuer = %idp.issuer, "portal IDP has no discovery document (fetch failed or discovery_url unset); /login will fail closed");
        return Arc::new(PortalLoginUnconfigured);
    };
    let (Ok(authorization_endpoint), Ok(token_endpoint)) =
        (doc.validate_authorization_endpoint(&idp.issuer, &[]), doc.validate_token_endpoint(&idp.issuer, &[]))
    else {
        tracing::error!(issuer = %idp.issuer, "portal IDP's discovery document has no valid/host-pinned authorization_endpoint or token_endpoint; /login will fail closed");
        return Arc::new(PortalLoginUnconfigured);
    };
    let Some(jwks_uri) = jwks_uris.get(&idp.issuer).cloned() else {
        return Arc::new(PortalLoginUnconfigured);
    };

    let redirect_uri = portal_redirect_uri(listen_port);
    if !idp.redirect_uri_allowlist.iter().any(|u| u == &redirect_uri) {
        tracing::error!(
            redirect_uri = %redirect_uri,
            allowlist = ?idp.redirect_uri_allowlist,
            "computed portal redirect_uri is not on the chosen IDP's redirect_uri_allowlist; /login will fail closed (fix MCPHUB_PORTAL_REDIRECT_URI/MCPHUB_PUBLIC_HOST or the IDP config)"
        );
        return Arc::new(PortalLoginUnconfigured);
    }

    Arc::new(PortalOidcClient {
        idp,
        client_id,
        authorization_endpoint,
        token_endpoint,
        redirect_uri,
        registry,
        jwks_cache,
        jwks_uri,
        pool,
        pending: Mutex::new(PendingFlowStore::default()),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_ui_state(
    pool: PgPool,
    registry: Arc<IssuerRegistry>,
    jwks_cache: Arc<JwksCache>,
    jwks_uris: Arc<HashMap<String, String>>,
    idps_by_issuer: &HashMap<String, IdpConfig>,
    discovery_docs: &HashMap<String, DiscoveryDocument>,
    listen_port: u16,
) -> UiAppState {
    let oidc = build_oidc_client(registry, jwks_cache, jwks_uris, idps_by_issuer, discovery_docs, pool.clone(), listen_port);
    let sessions = Arc::new(BoundedSessionStore::new());
    let mut state = UiAppState::new(Arc::new(PgUiData::new(pool)), sessions, oidc)
        .with_mcp_url(format!("{}/mcp", public_base_url(listen_port)));

    // Lab/dev escape hatch ONLY: the session cookie's `Secure` attribute is
    // dropped when this is explicitly set, mirroring
    // `mcphub_identity::http`'s `MCPHUB_IDP_CA_BUNDLE` pattern (explicit,
    // auditable, additive; the default stays secure). Needed when mcphubd
    // is reached directly over plain HTTP (e.g. this lab's
    // `http://<host>:8088`, no TLS termination in front of it) — a real
    // deployment behind the nginx gateway's mTLS termination should never
    // set this.
    if std::env::var("MCPHUB_COOKIE_INSECURE_HTTP").as_deref() == Ok("1") {
        tracing::warn!("MCPHUB_COOKIE_INSECURE_HTTP=1: session cookie is NOT marked Secure. Do not set this outside a plain-HTTP lab/dev deployment.");
        state = state.allow_insecure_cookies();
    }

    state
}

/// The public base URL this gateway is reached at, for OAuth `resource`
/// identifiers and redirect URIs. Same precedence as `portal_redirect_uri`:
/// an explicit override wins, because the public scheme/host/port often
/// differs from what this process binds (e.g. behind the nginx mTLS edge).
pub fn public_base_url(port: u16) -> String {
    if let Ok(explicit) = std::env::var("MCPHUB_PUBLIC_BASE_URL") {
        if !explicit.trim().is_empty() {
            return explicit.trim_end_matches('/').to_string();
        }
    }
    let host = std::env::var("MCPHUB_PUBLIC_HOST").unwrap_or_else(|_| "localhost".to_string());
    format!("http://{host}:{port}")
}

/// The IDP the shared port advertises for OAuth, plus its cached discovery
/// document. Same selection as the portal loginuses — one IDP drives both,
/// so a client and a browser session resolve to the same issuer.
pub fn portal_idp_and_doc(
    idps_by_issuer: &HashMap<String, IdpConfig>,
    discovery_docs: &HashMap<String, mcphub_identity::discovery::DiscoveryDocument>,
) -> Option<(IdpConfig, mcphub_identity::discovery::DiscoveryDocument)> {
    let idp = choose_portal_idp(idps_by_issuer)?;
    let doc = discovery_docs.get(&idp.issuer)?.clone();
    Some((idp, doc))
}
