//! Session resolution and server-side role gating.
//!
//! `SessionStore` is the seam between the portal and wherever sessions
//! actually live. [`BoundedSessionStore`] is the real, production
//! implementation — in-process, bounded, TTL-evicted, opaque random IDs,
//! same discipline as `mcphub_identity::pkce::PendingFlowStore`. It is
//! deliberately NOT backed by a raw guessable key: the previous dev-only
//! `InMemorySessionStore` seeded fixed IDs like `"sess-admin"` that a
//! browser could set directly as an unsigned cookie value with no login at
//! all — a total auth bypass. That type is now compiled only under the
//! `dev_login` feature (off by default in `bin/mcphubd`, see
//! `router.rs`), gated at the type level as well as the route level, so it
//! cannot end up wired into a release binary by mistake.
//!
//! Every page handler must call [`require_role`] (or equivalent) itself —
//! the nav in [`crate::domain::NAV_ITEMS`] is a UX convenience only. This
//! file exists so that guarantee is enforced in one place and tested once,
//! not re-implemented per handler.

use async_trait::async_trait;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use mcphub_types::{Identity, Role};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::state::AppState;
use crate::templates::ForbiddenTemplate;

#[async_trait]
pub trait SessionStore: Send + Sync {
    /// `None` for an unknown, expired, or never-issued session id. Callers
    /// must never distinguish these cases in a response — "not a valid
    /// session" is the only signal a caller gets.
    async fn resolve(&self, session_id: &str) -> Option<Identity>;

    /// Mint a new, opaque, unguessable session bound to `identity` and
    /// return its id. `None` means the store is at capacity — callers MUST
    /// treat that as a hard failure (show an error), never fall back to
    /// proceeding unauthenticated or reusing another session's id.
    async fn create(&self, identity: Identity) -> Option<String>;

    /// Invalidate a session server-side (logout). Idempotent: destroying an
    /// already-gone session is not an error.
    async fn destroy(&self, session_id: &str);
}

const SESSION_ID_BYTES: usize = 32; // 256 bits
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(8 * 3600);
const MAX_SESSIONS: usize = 10_000;

fn random_opaque_id(len: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

struct SessionRecord {
    identity: Identity,
    expires_at: Instant,
}

/// The real, production `SessionStore`: in-process, bounded, TTL-evicted.
/// No DB dependency — sessions don't need to survive a restart, and a
/// gateway-local store keeps `/callback` and every subsequent gated page
/// off the database's critical path.
///
/// Bounded the same way `PendingFlowStore` is: `create` first sweeps
/// expired entries (lazy eviction, no background task) and then refuses to
/// grow past `max_sessions` — otherwise an attacker (or a buggy client)
/// completing the OAuth flow in a loop could grow this map without bound.
pub struct BoundedSessionStore {
    sessions: RwLock<HashMap<String, SessionRecord>>,
    ttl: Duration,
    max_sessions: usize,
}

impl Default for BoundedSessionStore {
    fn default() -> Self {
        Self::with_limits(DEFAULT_SESSION_TTL, MAX_SESSIONS)
    }
}

impl BoundedSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// For tests that need to observe expiry/capacity behavior without
    /// waiting 8 hours or minting 10,000 sessions.
    pub fn with_limits(ttl: Duration, max_sessions: usize) -> Self {
        Self { sessions: RwLock::new(HashMap::new()), ttl, max_sessions }
    }

    fn evict_expired(sessions: &mut HashMap<String, SessionRecord>) {
        let now = Instant::now();
        sessions.retain(|_, r| r.expires_at > now);
    }
}

#[async_trait]
impl SessionStore for BoundedSessionStore {
    async fn resolve(&self, session_id: &str) -> Option<Identity> {
        let sessions = self.sessions.read().unwrap();
        let now = Instant::now();
        sessions.get(session_id).filter(|r| r.expires_at > now).map(|r| r.identity.clone())
    }

    async fn create(&self, identity: Identity) -> Option<String> {
        let mut sessions = self.sessions.write().unwrap();
        Self::evict_expired(&mut sessions);
        if sessions.len() >= self.max_sessions {
            tracing::error!(max_sessions = self.max_sessions, "session store at capacity; refusing to mint a new session");
            return None;
        }
        let id = random_opaque_id(SESSION_ID_BYTES);
        sessions.insert(id.clone(), SessionRecord { identity, expires_at: Instant::now() + self.ttl });
        Some(id)
    }

    async fn destroy(&self, session_id: &str) {
        self.sessions.write().unwrap().remove(session_id);
    }
}

/// TEMP dev-only fixture, compiled ONLY under the `dev_login` feature
/// (default-on for this crate's own tests, explicitly disabled by
/// `bin/mcphubd`'s `default-features = false`). Seeds fixed, guessable
/// session ids (`"sess-admin"` -> SuperAdmin, etc.) with no login step at
/// all — reachable in production this is a total auth bypass, which is
/// exactly why it is feature-gated at the type level, not just the route
/// level (see `router.rs`).
#[cfg(feature = "dev_login")]
use mcphub_types::{GrantedRole, IssuerId, TokenRef};

#[cfg(feature = "dev_login")]
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<String, Identity>>,
}

#[cfg(feature = "dev_login")]
impl Default for InMemorySessionStore {
    fn default() -> Self {
        let mut sessions = HashMap::new();
        sessions.insert(
            "sess-admin".to_string(),
            Identity {
                sub: "admin-1".into(),
                issuer: IssuerId::new("platform"),
                email: Some("admin@example.com".into()),
                roles: vec![GrantedRole { role: Role::SuperAdmin, asserted_by: IssuerId::new("platform") }],
                groups: vec![],
                token_ref: TokenRef::none(),
            },
        );
        sessions.insert(
            "sess-owner".to_string(),
            Identity {
                sub: "owner-1".into(),
                issuer: IssuerId::new("platform"),
                email: Some("owner@example.com".into()),
                roles: vec![GrantedRole { role: Role::ServerOwner, asserted_by: IssuerId::new("platform") }],
                groups: vec![],
                token_ref: TokenRef::none(),
            },
        );
        sessions.insert(
            "sess-security".to_string(),
            Identity {
                sub: "secteam-1".into(),
                issuer: IssuerId::new("platform"),
                email: Some("secteam@example.com".into()),
                roles: vec![GrantedRole { role: Role::SecurityAnalyst, asserted_by: IssuerId::new("platform") }],
                groups: vec![],
                token_ref: TokenRef::none(),
            },
        );
        sessions.insert(
            "sess-employee".to_string(),
            Identity {
                sub: "employee-1".into(),
                issuer: IssuerId::new("platform"),
                email: Some("employee@example.com".into()),
                roles: vec![GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("platform") }],
                groups: vec![],
                token_ref: TokenRef::none(),
            },
        );
        Self { sessions: RwLock::new(sessions) }
    }
}

#[cfg(feature = "dev_login")]
#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn resolve(&self, session_id: &str) -> Option<Identity> {
        self.sessions.read().unwrap().get(session_id).cloned()
    }

    /// Dev fixture only: "creating" a session just adds another random
    /// entry pointing at a synthetic Employee identity. Nothing in this
    /// crate's dev routes actually calls this — the dev picker POSTs a
    /// fixed session id straight from the seeded map — but the trait
    /// requires an implementation.
    async fn create(&self, identity: Identity) -> Option<String> {
        let id = random_opaque_id(SESSION_ID_BYTES);
        self.sessions.write().unwrap().insert(id.clone(), identity);
        Some(id)
    }

    async fn destroy(&self, session_id: &str) {
        self.sessions.write().unwrap().remove(session_id);
    }
}

/// The resolved caller for the current request. Extracting this and nothing
/// else buys you *authentication*; every handler that gates on role must
/// still call [`require_role`] explicitly — extraction success alone must
/// never be read as authorization.
#[derive(Clone)]
pub struct CurrentUser {
    pub identity: Identity,
    pub session_id: String,
}

pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::to("/login").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for CurrentUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);
        let session_id = extract_session_cookie(parts).ok_or(AuthRedirect)?;
        let identity = app_state.sessions.resolve(&session_id).await.ok_or(AuthRedirect)?;
        Ok(CurrentUser { identity, session_id })
    }
}

fn extract_session_cookie(parts: &Parts) -> Option<String> {
    let header = parts.headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some(v) = pair.strip_prefix("mcphub_session=") {
            return Some(v.to_string());
        }
    }
    None
}

/// Server-side authorization check. This — not nav visibility — is the
/// enforcement point. A direct GET/POST to a gated route by a caller
/// lacking every listed role gets a real 403 page, never a redirect or a
/// silently empty screen.
pub fn require_role(user: &Identity, allowed: &[Role], action: &str) -> Result<(), Response> {
    if allowed.iter().any(|r| user.has_role(*r)) {
        Ok(())
    } else {
        let body = ForbiddenTemplate { action: action.to_string() };
        Err((StatusCode::FORBIDDEN, body).into_response())
    }
}

/// Every mutating (POST) handler must call this before touching any state.
/// Rejection is a 403, not a silent no-op — a caller with a stale or absent
/// token must see that the submission was refused.
pub fn verify_csrf(state: &AppState, user: &CurrentUser, submitted_token: &str) -> Result<(), Response> {
    if state.csrf.verify(&user.session_id, submitted_token) {
        Ok(())
    } else {
        let body = ForbiddenTemplate { action: "submit this form (invalid or missing CSRF token)".to_string() };
        Err((StatusCode::FORBIDDEN, body).into_response())
    }
}
