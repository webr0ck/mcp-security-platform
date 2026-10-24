//! `mcphub-creds` — AES-256-GCM credential broker with a Vault-backed KEK.
//! Component 3's second crate (see `mcphub-policy` for the Rego/entitlement
//! side).

#![forbid(unsafe_code)]

pub mod adapters;
pub mod broker;
pub mod error;
pub mod store;
pub mod vault;

pub use adapters::{inject, CredentialMaterial, InjectionKind, InjectionOutput};
pub use broker::{Broker, CredentialRecord, CredentialSource, InMemoryCredentialSource};
pub use error::CredsError;
pub use store::CredentialStore;
pub use vault::{KekSource, VaultKekSource};
