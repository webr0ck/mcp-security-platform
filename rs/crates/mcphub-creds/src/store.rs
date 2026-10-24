//! AES-256-GCM credential store with a per-identity KEK derived via HKDF —
//! port of `proxy/app/credential_broker/approaches/approach_a.py`.
//!
//! Blob format (identical layout to the Python original): `salt(32B) ||
//! nonce(12B) || ciphertext+tag`. A fresh random salt is generated on every
//! `encrypt` call and prepended, so every encryption derives an
//! independent KEK from the same master secret via HKDF-SHA256 — this also
//! means the (key, nonce) pair is unique per encryption even before
//! accounting for nonce randomness, since the key itself changes each time.
//!
//! Nonce: 96 bits, drawn fresh from `aws-lc-rs`'s CSPRNG for every
//! encryption, never reused. Birthday-bound note: for random 96-bit nonces
//! under a *fixed* key, collision risk becomes non-negligible around 2^32
//! encryptions under that one key (NIST SP 800-38D). We never reach that
//! regime because the key itself is re-derived (fresh HKDF salt) on every
//! call — each nonce is drawn under a practically-unique key, not
//! accumulated against one long-lived key.
//!
//! AAD binds the ciphertext to (identity, server, credential_name) so a
//! ciphertext cannot be replayed into a different context (row-swap /
//! credential-confusion attack) — port of `_make_aad` / FIND-010 in the
//! Python original, adapted to the (identity, server, credential-name)
//! shape ARCHITECTURE.md specifies (the Python original also threads an
//! `owner_type` field; flagged as a possible 4th AAD component to add once
//! `mcphub-store`'s schema is finalized).

use crate::error::CredsError;
use crate::vault::KekSource;
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use mcphub_types::Secret;
use zeroize::Zeroizing;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HKDF_INFO_PREFIX: &str = "mcphub-credential-broker-kek-v1:";
const AAD_PREFIX: &str = "mcphub-cred-v1";

pub struct CredentialStore<K: KekSource> {
    kek_source: K,
    rng: SystemRandom,
}

impl<K: KekSource> CredentialStore<K> {
    pub fn new(kek_source: K) -> Self {
        Self {
            kek_source,
            rng: SystemRandom::new(),
        }
    }

    pub async fn encrypt(
        &self,
        plaintext: &str,
        identity: &str,
        server: &str,
        credential_name: &str,
    ) -> Result<Vec<u8>, CredsError> {
        let master = self.kek_source.fetch_master_secret().await?;

        let mut salt = [0u8; SALT_LEN];
        self.rng.fill(&mut salt).map_err(|_| CredsError::Internal)?;
        let kek = derive_kek(identity, &master, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce_bytes).map_err(|_| CredsError::Internal)?;

        let unbound = UnboundKey::new(&aead::AES_256_GCM, kek.as_ref()).map_err(|_| CredsError::Internal)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = make_aad(identity, server, credential_name);

        let mut in_out = plaintext.as_bytes().to_vec();
        key.seal_in_place_append_tag(nonce, Aad::from(aad.as_slice()), &mut in_out)
            .map_err(|_| CredsError::Internal)?;

        let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + in_out.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    pub async fn decrypt(
        &self,
        blob: &[u8],
        identity: &str,
        server: &str,
        credential_name: &str,
    ) -> Result<Secret<String>, CredsError> {
        let min_size = SALT_LEN + NONCE_LEN + 1;
        if blob.len() < min_size {
            return Err(CredsError::BlobTooShort);
        }
        let master = self.kek_source.fetch_master_secret().await?;

        let salt = &blob[..SALT_LEN];
        let nonce_bytes: [u8; NONCE_LEN] = blob[SALT_LEN..SALT_LEN + NONCE_LEN]
            .try_into()
            .expect("slice is exactly NONCE_LEN");
        let ciphertext = &blob[SALT_LEN + NONCE_LEN..];

        let kek = derive_kek(identity, &master, salt)?;
        let unbound = UnboundKey::new(&aead::AES_256_GCM, kek.as_ref()).map_err(|_| CredsError::DecryptionFailed)?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let aad = make_aad(identity, server, credential_name);

        let mut buf = ciphertext.to_vec();
        let plain = key
            .open_in_place(nonce, Aad::from(aad.as_slice()), &mut buf)
            .map_err(|_| CredsError::DecryptionFailed)?;
        let s = String::from_utf8(plain.to_vec()).map_err(|_| CredsError::DecryptionFailed)?;
        Ok(Secret::new(s))
    }
}

/// HKDF-SHA256(salt, master_secret) -> PRK, expanded with an
/// identity-bound `info` string into a 32-byte AES-256 key. Returned
/// wrapped in `Zeroizing` so the derived key material is wiped on drop —
/// there is no code path that lets a derived KEK outlive the call that
/// used it.
fn derive_kek(identity: &str, master: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CredsError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(master);
    let info = format!("{HKDF_INFO_PREFIX}{identity}");
    let info_parts = [info.as_bytes()];
    let okm = prk
        .expand(&info_parts, hkdf::HKDF_SHA256)
        .map_err(|_| CredsError::Internal)?;
    let mut out = Zeroizing::new([0u8; 32]);
    okm.fill(out.as_mut_slice()).map_err(|_| CredsError::Internal)?;
    Ok(out)
}

/// Canonical AAD binding ciphertext to its (identity, server,
/// credential_name) context — decryption only succeeds when all three
/// match the values used at encryption time.
fn make_aad(identity: &str, server: &str, credential_name: &str) -> Vec<u8> {
    format!("{AAD_PREFIX}|{identity}|{server}|{credential_name}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::StaticKekSource;

    fn store() -> CredentialStore<StaticKekSource> {
        CredentialStore::new(StaticKekSource(vec![0x11u8; 32]))
    }

    #[tokio::test]
    async fn round_trip_encrypt_decrypt() {
        let s = store();
        let blob = s.encrypt("s3cr3t-token", "alice", "jira", "api_token").await.unwrap();
        let plain = s.decrypt(&blob, "alice", "jira", "api_token").await.unwrap();
        assert_eq!(plain.expose_secret(), "s3cr3t-token");
    }

    #[tokio::test]
    async fn aad_mismatch_fails_decryption() {
        let s = store();
        let blob = s.encrypt("secret", "alice", "jira", "api_token").await.unwrap();

        // Wrong identity.
        assert!(s.decrypt(&blob, "bob", "jira", "api_token").await.is_err());
        // Wrong server.
        assert!(s.decrypt(&blob, "alice", "github", "api_token").await.is_err());
        // Wrong credential name.
        assert!(s.decrypt(&blob, "alice", "jira", "other_cred").await.is_err());
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_gcm_tag() {
        let s = store();
        let mut blob = s.encrypt("secret", "alice", "jira", "api_token").await.unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF; // flip a bit in the tag/ciphertext
        assert!(s.decrypt(&blob, "alice", "jira", "api_token").await.is_err());
    }

    #[tokio::test]
    async fn truncated_blob_rejected() {
        let s = store();
        let err = s.decrypt(&[0u8; 4], "alice", "jira", "api_token").await.unwrap_err();
        assert!(matches!(err, CredsError::BlobTooShort));
    }

    #[tokio::test]
    async fn nonce_is_never_reused_across_encryptions() {
        let s = store();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let blob = s.encrypt("x", "alice", "jira", "api_token").await.unwrap();
            let nonce = blob[SALT_LEN..SALT_LEN + NONCE_LEN].to_vec();
            assert!(seen.insert(nonce), "nonce reused across encryptions");
        }
    }

    #[tokio::test]
    async fn vault_unreachable_never_maps_to_a_usable_credential() {
        use crate::vault::UnreachableKekSource;
        let s = CredentialStore::new(UnreachableKekSource);
        let err = s.encrypt("x", "alice", "jira", "api_token").await.unwrap_err();
        assert!(matches!(err, CredsError::VaultUnavailable));
        let err2 = s.decrypt(&[0u8; 64], "alice", "jira", "api_token").await.unwrap_err();
        assert!(matches!(err2, CredsError::VaultUnavailable | CredsError::BlobTooShort));
    }

    #[test]
    fn derived_kek_material_is_wrapped_for_zeroize_on_drop() {
        // `derive_kek` returns `Zeroizing<[u8; 32]>` specifically so the KEK
        // is wiped when it goes out of scope — there is no code path that
        // returns a bare `[u8; 32]` a caller could forget to scrub. We
        // cannot safely inspect memory *after* Drop (that would be
        // use-after-free even for a stack array, and this crate forbids
        // `unsafe_code`), so this test instead pins the type-level
        // guarantee: `Zeroizing`'s `Drop` impl calls the same `zeroize()`
        // this asserts against, so it is the identical code path.
        use zeroize::Zeroize;
        let master = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let mut kek = derive_kek("alice", &master, &salt).unwrap();
        assert_ne!(kek.as_slice(), [0u8; 32], "sanity: key material is non-zero before zeroize");
        kek.zeroize();
        assert_eq!(kek.as_slice(), [0u8; 32], "zeroize() must scrub the derived key material");
    }
}
