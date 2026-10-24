use mcphub_types::GateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredsError {
    #[error("vault unreachable")]
    VaultUnavailable,

    #[error("vault returned a malformed master secret")]
    MasterSecretMalformed,

    #[error("master secret is shorter than the 256-bit entropy floor")]
    MasterSecretTooShort,

    #[error("credential blob is too short to be valid")]
    BlobTooShort,

    #[error("decryption failed (wrong key, wrong AAD context, or tampering)")]
    DecryptionFailed,

    #[error("no credential material found for this identity/server/credential")]
    NotFound,

    #[error("injection adapter does not match the stored credential material shape")]
    AdapterMismatch,

    #[error("internal cryptographic operation failed")]
    Internal,

    #[error("configuration error: {0}")]
    Config(String),
}

impl CredsError {
    /// Every path here is "the broker could not produce usable credential
    /// material" — never "here is a credential anyway." A Vault outage, a
    /// bad blob, and a decryption/tamper failure all map to
    /// `DependencyUnavailable`, which the `mcphub-gateway` trait boundary
    /// turns into `Decision::Deny`. There is no `Err` variant here that a
    /// caller could plausibly unwrap into a token string.
    pub fn to_gate_error(&self) -> GateError {
        match self {
            CredsError::VaultUnavailable => GateError::DependencyUnavailable("vault"),
            CredsError::MasterSecretMalformed | CredsError::MasterSecretTooShort => {
                GateError::DependencyUnavailable("vault_master_secret")
            }
            CredsError::BlobTooShort
            | CredsError::DecryptionFailed
            | CredsError::AdapterMismatch => GateError::DependencyUnavailable("credential_store"),
            CredsError::NotFound => GateError::InvalidRequest("no credential enrolled".into()),
            CredsError::Internal => GateError::Internal,
            CredsError::Config(msg) => GateError::InvalidRequest(msg.clone()),
        }
    }
}
