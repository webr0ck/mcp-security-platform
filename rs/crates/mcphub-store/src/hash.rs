//! SHA-256 helpers shared by the audit hash-chain (`audit.rs`) and the
//! tool-registry content digest (`repo::tools`). Uses `aws-lc-rs`, already
//! pinned workspace-wide for AEAD/HKDF, instead of pulling in a second
//! SHA-256 implementation.

use aws_lc_rs::{digest, hmac};

pub fn sha256_hex(data: &[u8]) -> String {
    let d = digest::digest(&digest::SHA256, data);
    hex_encode(d.as_ref())
}

/// Keyed digest for the audit hash chain (D3): an attacker with DB write
/// access (the stated threat model for `audit_events`) can recompute an
/// unkeyed SHA-256 chain in seconds by rewriting every row's hash to match
/// their tampered content. HMAC-SHA256 over a key that never touches the
/// database (sourced from Vault/env at process startup, see
/// `PgRedisAuditSink::new`) means a DB-only attacker cannot forge a
/// consistent chain even with full read/write access to every row —
/// they'd also need the process's HMAC key, which lives outside Postgres.
pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    hex_encode(tag.as_ref())
}

/// Constant-time-ish verification helper (recompute + compare) used by the
/// offline chain verifier. Not exposed as a distinct "verify" primitive
/// from aws-lc-rs's HMAC verify because we need the recomputed hex string
/// for reporting *which* row failed and (heuristically) why.
pub fn hmac_sha256_hex_matches(key: &[u8], data: &[u8], expected_hex: &str) -> bool {
    hmac_sha256_hex(key, data) == expected_hex
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_is_deterministic_and_64_chars() {
        let a = sha256_hex(b"hello world");
        let b = sha256_hex(b"hello world");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_hex_differs_for_different_input() {
        assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
    }

    #[test]
    fn hmac_differs_from_unkeyed_sha256_for_same_input() {
        // Mutation proof (D3): an attacker who only knows how to compute
        // plain SHA-256 (as they could for the old unkeyed digest) must NOT
        // be able to reproduce the HMAC without the key.
        let data = b"core-json-bytes";
        assert_ne!(hmac_sha256_hex(b"some-32-byte-or-longer-secret-key!!", data), sha256_hex(data));
    }

    #[test]
    fn hmac_requires_the_correct_key() {
        let data = b"core-json-bytes";
        let correct = hmac_sha256_hex(b"key-a-at-least-32-bytes-long!!!!", data);
        let wrong = hmac_sha256_hex(b"key-b-at-least-32-bytes-long!!!!", data);
        assert_ne!(correct, wrong);
        assert!(hmac_sha256_hex_matches(b"key-a-at-least-32-bytes-long!!!!", data, &correct));
        assert!(!hmac_sha256_hex_matches(b"key-b-at-least-32-bytes-long!!!!", data, &correct));
    }

    #[test]
    fn hmac_is_deterministic_and_64_hex_chars() {
        let a = hmac_sha256_hex(b"deterministic-key-32-bytes-long!", b"payload");
        let b = hmac_sha256_hex(b"deterministic-key-32-bytes-long!", b"payload");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
