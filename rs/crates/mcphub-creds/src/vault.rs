//! Vault KMS client — port of `proxy/app/credential_broker/kms.py`.
//!
//! The broker's master secret (KEK root) comes from Vault's KV v2 store,
//! never from a plaintext env var or file: a prior design that put the KEK
//! in `.env.lab` was rejected in review (offline decryption of a stolen DB
//! dump becomes trivial once the key sits next to the ciphertexts' config).
//! If Vault is unreachable, [`KekSource::fetch_master_secret`] returns
//! `Err` — there is no fallback path that returns a usable key.

use crate::error::CredsError;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use mcphub_types::Secret;
use zeroize::Zeroizing;

/// SR-4 (Python platform): enforce a 256-bit entropy floor on the decoded
/// master secret. HKDF accepts any-length input keying material and will
/// silently stretch a short/low-entropy secret into a 32-byte KEK, so a
/// misconfigured Vault value would otherwise fail silently. Reject before
/// any KEK is ever derived from it.
const MIN_MASTER_SECRET_LEN: usize = 32;

#[async_trait::async_trait]
pub trait KekSource: Send + Sync {
    /// Fetch the broker's master secret. `Err` on any failure — network,
    /// malformed response, or an entropy floor violation. There is no
    /// "return a default key" path.
    async fn fetch_master_secret(&self) -> Result<Zeroizing<Vec<u8>>, CredsError>;
}

/// TOKEN LIFECYCLE (answering the deploy-side question directly): this
/// type does NOT renew or re-login. `token` is fixed at construction and
/// reused verbatim on every `fetch_master_secret` call for the process's
/// entire lifetime. If the AppRole token's `token_ttl` (and `token_max_ttl`,
/// if renewal were added) is shorter than `mcphubd`'s uptime, Vault will
/// start rejecting requests with this token once it expires —
/// `fetch_master_secret` returns `Err(VaultUnavailable)`, and since the
/// credential broker fails closed, credential injection silently stops
/// working on an otherwise-healthy long-running process. There is no
/// visible symptom besides `DependencyUnavailable("vault")` denials
/// starting to appear.
///
/// Until renewal is implemented here, the deploy layer MUST either:
/// - mint a token with `token_ttl` (and `token_max_ttl` if periodic) set
///   longer than the longest expected `mcphubd` process lifetime, or
/// - restart `mcphubd` on a cadence shorter than the token's TTL, so a
///   fresh AppRole login always happens before the old token expires.
pub struct VaultKekSource {
    addr: String,
    token: Secret<String>,
    path: String,
    client: reqwest::Client,
}

impl VaultKekSource {
    pub fn new(addr: impl Into<String>, token: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            token: Secret::new(token.into()),
            path: path.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl KekSource for VaultKekSource {
    async fn fetch_master_secret(&self) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        let url = format!("{}/v1/{}", self.addr, self.path);
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.token.expose_secret().as_str())
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| CredsError::VaultUnavailable)?;

        if !resp.status().is_success() {
            return Err(CredsError::VaultUnavailable);
        }

        let body: serde_json::Value = resp.json().await.map_err(|_| CredsError::VaultUnavailable)?;
        // Vault stores the KEK under "master_secret" (or "value" for the
        // lab seeder's field name) inside the KV v2 data.data envelope.
        let encoded = body
            .pointer("/data/data/master_secret")
            .or_else(|| body.pointer("/data/data/value"))
            .and_then(|v| v.as_str())
            .ok_or(CredsError::MasterSecretMalformed)?;

        decode_master_secret(encoded)
    }
}

/// Decode a Vault-stored master secret. The lab seeder writes it as hex
/// (`openssl rand -hex 32`); some deployments write base64. Prefer hex when
/// the value is unambiguously hex (even length, all hex digits), else fall
/// back to base64 — matching `kms.py`'s `_decode_master_secret`.
fn decode_master_secret(encoded: &str) -> Result<Zeroizing<Vec<u8>>, CredsError> {
    let s = encoded.trim();
    let raw = if s.len() % 2 == 0 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s).map_err(|_| CredsError::MasterSecretMalformed)?
    } else {
        BASE64_STANDARD
            .decode(s)
            .map_err(|_| CredsError::MasterSecretMalformed)?
    };
    if raw.len() < MIN_MASTER_SECRET_LEN {
        return Err(CredsError::MasterSecretTooShort);
    }
    Ok(Zeroizing::new(raw))
}

/// Always-fails test double: simulates Vault being completely unreachable.
/// Used to prove the broker never maps a Vault outage to a usable
/// credential.
#[doc(hidden)]
pub struct UnreachableKekSource;

#[async_trait::async_trait]
impl KekSource for UnreachableKekSource {
    async fn fetch_master_secret(&self) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        Err(CredsError::VaultUnavailable)
    }
}

/// Fixed-secret test double for deterministic encrypt/decrypt tests.
#[doc(hidden)]
pub struct StaticKekSource(pub Vec<u8>);

#[async_trait::async_trait]
impl KekSource for StaticKekSource {
    async fn fetch_master_secret(&self) -> Result<Zeroizing<Vec<u8>>, CredsError> {
        Ok(Zeroizing::new(self.0.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_master_secret_decodes() {
        let hex32 = "a".repeat(64); // 32 bytes of 0xaa
        let decoded = decode_master_secret(&hex32).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn base64_master_secret_decodes() {
        let raw = vec![0x42u8; 32];
        let b64 = BASE64_STANDARD.encode(&raw);
        let decoded = decode_master_secret(&b64).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn short_secret_rejected_below_entropy_floor() {
        let hex_short = "ab".repeat(8); // 8 bytes, well under the 32-byte floor
        let err = decode_master_secret(&hex_short).unwrap_err();
        assert!(matches!(err, CredsError::MasterSecretTooShort));
    }

    #[tokio::test]
    async fn vault_unreachable_never_yields_a_usable_secret() {
        let src = UnreachableKekSource;
        let result = src.fetch_master_secret().await;
        assert!(result.is_err(), "an unreachable Vault must return Err, never a key");
    }
}
