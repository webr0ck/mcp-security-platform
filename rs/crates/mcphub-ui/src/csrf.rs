//! Synchronizer-token CSRF protection for every mutating form.
//!
//! Token = base64(session_id) + "." + hex(HMAC-SHA256(secret, session_id)).
//! It is derived deterministically from the session id and a server secret
//! rather than stored server-side, so it needs no extra table and is
//! naturally invalidated when the session is. Every `<form method="post">`
//! must render it via `csrf_field()` and every mutating handler must call
//! [`verify`] before touching any state.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct CsrfSecret(pub [u8; 32]);

impl CsrfSecret {
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn token_for(&self, session_id: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac accepts any key length");
        mac.update(session_id.as_bytes());
        let sig = mac.finalize().into_bytes();
        hex(&sig)
    }

    pub fn verify(&self, session_id: &str, submitted: &str) -> bool {
        let expected = self.token_for(session_id);
        // Constant-time comparison: token equality must not leak via timing.
        expected.as_bytes().ct_eq(submitted.as_bytes()).into()
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips_for_same_session() {
        let secret = CsrfSecret::generate();
        let token = secret.token_for("sess-1");
        assert!(secret.verify("sess-1", &token));
    }

    #[test]
    fn token_rejects_mismatched_session() {
        let secret = CsrfSecret::generate();
        let token = secret.token_for("sess-1");
        assert!(!secret.verify("sess-2", &token));
    }

    #[test]
    fn token_rejects_tampered_value() {
        let secret = CsrfSecret::generate();
        let mut token = secret.token_for("sess-1");
        token.push('0');
        assert!(!secret.verify("sess-1", &token));
    }
}
