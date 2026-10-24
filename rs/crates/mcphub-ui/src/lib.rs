//! `mcphub-ui` — the server-rendered portal. Askama templates + a small
//! static bundle, mounted as an axum router (see [`router::router`]).
//!
//! Design direction (binding, see `rs/ARCHITECTURE.md`): no neon, no glow,
//! no gradients. One neutral gray scale, one accent hue, system font stack,
//! 4px spacing grid, borders over shadows. Four personas share one nav,
//! filtered by role; every route is gated server-side regardless of what
//! the nav shows (see [`auth::require_role`]).
//!
//! One seam is TEMP-owned by this crate until its real owner lands:
//! - [`data::UiData`] / [`data::InMemoryUiData`] — belongs in
//!   `mcphub-store` (component 4).
//!
//! Login is real, not a stub: [`oidc::OidcLogin`] is the trait `/login` and
//! `/callback` (see `pages::common`) drive, implemented against
//! `mcphub-identity` + Postgres at the `bin/mcphubd` wiring site (this
//! crate stays free of both, per `rs/ARCHITECTURE.md`).
//! [`auth::BoundedSessionStore`] is the real, production `SessionStore` —
//! bounded, TTL-evicted, unguessable session ids. `auth::InMemorySessionStore`
//! still exists but only under this crate's own `dev_login` feature
//! (default-on here, explicitly off in `bin/mcphubd`) — see `auth`'s module
//! doc for why that one's session ids must never be reachable in production.

#![forbid(unsafe_code)]

pub mod auth;
pub mod chrome;
pub mod csp;
pub mod csrf;
pub mod data;
pub mod domain;
pub mod oidc;
pub mod pages;
pub mod router;
pub mod state;
pub mod templates;
pub mod testutil;

pub use router::router;
pub use state::AppState;
