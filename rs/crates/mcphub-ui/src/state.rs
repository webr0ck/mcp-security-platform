use std::sync::Arc;

use crate::auth::SessionStore;
use crate::csrf::CsrfSecret;
use crate::data::UiData;
use crate::oidc::OidcLogin;

#[derive(Clone)]
pub struct AppState {
    pub data: Arc<dyn UiData>,
    pub sessions: Arc<dyn SessionStore>,
    pub oidc: Arc<dyn OidcLogin>,
    pub csrf: CsrfSecret,
    /// Whether the session cookie carries the `Secure` attribute. Defaults
    /// to `true`; only ever flipped by [`Self::allow_insecure_cookies`].
    pub cookie_secure: bool,
    /// The public `/mcp` URL shown on the Help page so a user can copy it
    /// into their MCP client. Display-only — nothing authorizes off it.
    /// Defaults to a relative hint when the deployment hasn't told us its
    /// public origin, rather than printing a localhost URL that would be
    /// wrong for everyone reading it over the network.
    pub mcp_url: String,
}

impl AppState {
    /// Sets the public `/mcp` URL displayed on the Help page.
    pub fn with_mcp_url(mut self, url: impl Into<String>) -> Self {
        self.mcp_url = url.into();
        self
    }

    pub fn new(data: Arc<dyn UiData>, sessions: Arc<dyn SessionStore>, oidc: Arc<dyn OidcLogin>) -> Self {
        Self {
            data,
            sessions,
            oidc,
            csrf: CsrfSecret::generate(),
            cookie_secure: true,
            mcp_url: "<this gateway's base URL>/mcp".to_string(),
        }
    }

    /// Lab/dev escape hatch: drop the session cookie's `Secure` attribute
    /// so it survives over plain HTTP. Mirrors `mcphub_identity::http`'s
    /// `MCPHUB_IDP_CA_BUNDLE` pattern — explicit, auditable, additive; the
    /// default stays secure. `bin/mcphubd`'s production wiring must only
    /// call this behind its own explicit env-var gate, never
    /// unconditionally.
    pub fn allow_insecure_cookies(mut self) -> Self {
        self.cookie_secure = false;
        self
    }
}
