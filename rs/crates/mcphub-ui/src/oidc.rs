//! The seam between the portal's `/login` + `/callback` routes and a real
//! OAuth 2.1 PKCE browser flow. Deliberately narrow: this crate has zero
//! dependency on `mcphub-identity` or a database (see `rs/ARCHITECTURE.md`
//! — `mcphub-ui` owns templates + static only), so the actual PKCE
//! state/nonce handling, authorization-code redemption, JWT validation, and
//! DB-sourced role-ceiling resolution all live in the implementation wired
//! at `bin/mcphubd/src/ui.rs` (mirrors `wiring::authenticator::
//! StoreAuthenticator`'s `resolve_identity` → `apply_ceiling` pattern —
//! this is the SAME validation path the gateway itself uses for bearer
//! tokens, not a second one invented for the browser).

use async_trait::async_trait;
use mcphub_types::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcLoginError {
    /// `state`/`nonce`/`redirect_uri` mismatch, an expired or already-used
    /// pending flow, or a code the token endpoint rejected. Deliberately
    /// one variant, not several — none of these should ever be
    /// distinguished in the user-facing error (that would leak flow
    /// internals to whoever is poking at `/callback`).
    InvalidCallback,
    /// Discovery, the token endpoint, or the DB role lookup was
    /// unreachable. Fail-closed: never treated as "log the user in anyway".
    UpstreamUnavailable,
}

/// What the portal needs from an OIDC integration to run the login flow.
#[async_trait]
pub trait OidcLogin: Send + Sync {
    /// Start a new login attempt: allocate PKCE/state/nonce server-side and
    /// return the URL the browser should be redirected to.
    async fn start(&self) -> Result<String, OidcLoginError>;

    /// Redeem the callback's `code` against the pending flow named by
    /// `state`, fully validate the resulting token, and resolve real
    /// enforcement roles for it (DB `role_grants`, issuer-scoped, ceiling-
    /// applied) — never the token's own role claims. `state` is looked up
    /// against a single-use, TTL-bounded store; an unknown, expired, or
    /// already-consumed `state` is `InvalidCallback`.
    async fn complete(&self, code: &str, state: &str) -> Result<Identity, OidcLoginError>;
}
