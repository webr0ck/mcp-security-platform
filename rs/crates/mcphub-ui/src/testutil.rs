//! Test doubles shared between this crate's own tests and its `tests/`
//! integration suite (a separate compilation unit, so it can't see
//! `#[cfg(test)]` items — hence this being a small, always-compiled, `pub`
//! module rather than `#[cfg(test)]`). None of this is security-sensitive
//! on its own: it's inert unless a caller explicitly constructs and wires
//! it, exactly like `data::InMemoryUiData`.

use async_trait::async_trait;
use mcphub_types::Identity;
use std::sync::RwLock;

use crate::oidc::{OidcLogin, OidcLoginError};

/// A minimal, honest `OidcLogin` double: it does NOT exercise
/// `mcphub-identity`'s PKCE/JWT machinery (that crate has its own test
/// suite for that — see `pkce.rs` and `lib.rs`'s `resolve_identity`
/// end-to-end test). What it DOES prove, at the HTTP-router level this
/// crate owns: `/login` redirects, `/callback` accepts a matching `state`
/// exactly once and rejects everything else (unknown state, replayed
/// state), and a successful `complete()` hands back the configured
/// `Identity` for the session store to mint a real session from.
pub struct StubOidcLogin {
    pending_state: RwLock<Option<String>>,
    identity: Identity,
}

impl StubOidcLogin {
    pub fn new(identity: Identity) -> Self {
        Self { pending_state: RwLock::new(None), identity }
    }
}

#[async_trait]
impl OidcLogin for StubOidcLogin {
    async fn start(&self) -> Result<String, OidcLoginError> {
        let state = "stub-flow-state".to_string();
        *self.pending_state.write().unwrap() = Some(state.clone());
        Ok(format!("https://idp.example.com/authorize?state={state}"))
    }

    async fn complete(&self, _code: &str, state: &str) -> Result<Identity, OidcLoginError> {
        // Single-use: `.take()` clears it regardless of match outcome, so a
        // replayed `state` (even the correct one, twice) fails the second
        // time — mirrors `PendingFlowStore::consume`.
        let pending = self.pending_state.write().unwrap().take();
        match pending {
            Some(expected) if expected == state => Ok(self.identity.clone()),
            _ => Err(OidcLoginError::InvalidCallback),
        }
    }
}

/// Always denies `start()` — for exercising the "identity provider
/// unreachable" path.
pub struct UnavailableOidcLogin;

#[async_trait]
impl OidcLogin for UnavailableOidcLogin {
    async fn start(&self) -> Result<String, OidcLoginError> {
        Err(OidcLoginError::UpstreamUnavailable)
    }

    async fn complete(&self, _code: &str, _state: &str) -> Result<Identity, OidcLoginError> {
        Err(OidcLoginError::UpstreamUnavailable)
    }
}
