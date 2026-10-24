//! Signed policy bundle loading (F-002 / INV-012 in the Python platform).
//!
//! An OPA-style bundle (`opa build -b policies/rego --signing-alg HS256
//! --signing-key <keyfile> -o bundle.tar.gz`, see
//! `scripts/sign_policy_bundle.sh`) is a `.tar.gz` containing the `.rego`
//! sources, a `.manifest`, and a `.signatures.json` holding one or more
//! compact JWS strings (`HS256`). The JWS payload lists every signed file by
//! name with a SHA-256 hash; verification means: the JWS signature checks
//! out against the configured key, AND every file we are about to load is
//! present in that signed list with a matching hash.
//!
//! An unsigned or badly-signed bundle must refuse to load — the caller
//! (`RegorusPolicyEngine`) treats "no bundle loaded" as "deny every
//! request", never as "skip policy".
//!
//! Divergence from the Python/OPA original, flagged for the architect: we
//! read the real `.tar.gz` produced by `sign_policy_bundle.sh` (via
//! `flate2`/`tar`), but we only require the file(s) we actually load
//! (currently just `authz.rego`) to be present and hash-verified in the
//! signed file list — we do not replicate OPA's full bundle activation
//! semantics (wasm modules, nested roots, `data.json` merging by path,
//! etc). That is out of scope for "verify the core deny-by-default policy
//! loads only when signed correctly."

use crate::error::PolicyError;
use aws_lc_ring_compat::{hmac_verify, sha256_hex};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

/// A loaded, signature-verified policy bundle: raw file contents keyed by
/// in-bundle path (e.g. `"authz.rego"`).
#[derive(Debug, Clone)]
pub struct PolicyBundle {
    files: BTreeMap<String, Vec<u8>>,
}

impl PolicyBundle {
    /// Load and verify a bundle from a `.tar.gz` path. Returns `Err` on
    /// *any* problem — missing signature file, bad JWS, wrong `alg`, hash
    /// mismatch, or a file we need missing from the signed list. There is no
    /// "load anyway" fallback.
    pub fn load_signed(bundle_path: &Path, signing_key: &[u8]) -> Result<Self, PolicyError> {
        let files = read_tar_gz(bundle_path)
            .map_err(|e| PolicyError::BundleMalformed(format!("unreadable bundle archive: {e}")))?;

        let sig_bytes = files.get(".signatures.json").ok_or_else(|| {
            PolicyError::BundleSignatureInvalid(
                "bundle has no .signatures.json — refusing to load an unsigned bundle".into(),
            )
        })?;
        let signatures: SignaturesFile = serde_json::from_slice(sig_bytes).map_err(|e| {
            PolicyError::BundleSignatureInvalid(format!("malformed .signatures.json: {e}"))
        })?;
        let jws = signatures
            .signatures
            .first()
            .ok_or_else(|| PolicyError::BundleSignatureInvalid("no signatures present".into()))?;

        let signed_files = verify_jws_hs256(jws, signing_key)?;

        // Every signed file's declared hash must match the actual bytes we
        // read from the archive. A file present in the archive but absent
        // from (or mismatched against) the signed list is untrusted.
        for entry in &signed_files.files {
            let actual = files.get(entry.name.as_str()).ok_or_else(|| {
                PolicyError::BundleSignatureInvalid(format!(
                    "signed file '{}' missing from archive",
                    entry.name
                ))
            })?;
            if !entry.algorithm.eq_ignore_ascii_case("SHA-256") {
                return Err(PolicyError::BundleSignatureInvalid(format!(
                    "unsupported hash algorithm '{}' for '{}'",
                    entry.algorithm, entry.name
                )));
            }
            let actual_hash = sha256_hex(actual);
            if !actual_hash.eq_ignore_ascii_case(&entry.hash) {
                return Err(PolicyError::BundleSignatureInvalid(format!(
                    "hash mismatch for signed file '{}'",
                    entry.name
                )));
            }
        }

        // The one file this engine actually needs must be both present and
        // in the verified list — not just present in the tarball.
        let signed_names: std::collections::HashSet<&str> =
            signed_files.files.iter().map(|f| f.name.as_str()).collect();
        if !signed_names.contains("authz.rego") {
            return Err(PolicyError::BundleSignatureInvalid(
                "authz.rego is not part of the signed file list".into(),
            ));
        }

        Ok(PolicyBundle { files })
    }

    /// Build an in-memory bundle directly from Rego source, bypassing
    /// signature verification. **Test-only** (and explicitly named to make
    /// that obvious at call sites) — never reachable from a `load_signed`
    /// path a deployed engine would use.
    #[doc(hidden)]
    pub fn unsigned_for_tests(rego_source: impl Into<String>) -> Self {
        let mut files = BTreeMap::new();
        files.insert("authz.rego".to_string(), rego_source.into().into_bytes());
        PolicyBundle { files }
    }

    /// Same as [`Self::unsigned_for_tests`], plus `anomaly.rego` — needed by
    /// any test that exercises `authz.rego`'s anomaly structural deny rules
    /// (`data.mcp.anomaly.structural_deny_reasons`), which resolve to an
    /// empty set — silently, not an error — when no `anomaly.rego` module
    /// is loaded into the same engine.
    #[doc(hidden)]
    pub fn unsigned_for_tests_with_anomaly(authz_source: impl Into<String>, anomaly_source: impl Into<String>) -> Self {
        let mut files = BTreeMap::new();
        files.insert("authz.rego".to_string(), authz_source.into().into_bytes());
        files.insert("anomaly.rego".to_string(), anomaly_source.into().into_bytes());
        PolicyBundle { files }
    }

    pub fn rego_source(&self) -> Result<&str, PolicyError> {
        let bytes = self
            .files
            .get("authz.rego")
            .ok_or_else(|| PolicyError::BundleMalformed("authz.rego missing".into()))?;
        std::str::from_utf8(bytes)
            .map_err(|e| PolicyError::BundleMalformed(format!("authz.rego is not UTF-8: {e}")))
    }

    /// `anomaly.rego` is OPTIONAL in a bundle for backward compatibility: a
    /// bundle built before this file existed still loads and evaluates —
    /// `authz.rego`'s `data.mcp.anomaly.structural_deny_reasons` reference
    /// just resolves to an empty set (its `else := set()` fallback), same
    /// as today, rather than refusing to load. `None` means "not present",
    /// distinct from "present but malformed" (`Err`).
    pub fn anomaly_rego_source(&self) -> Result<Option<&str>, PolicyError> {
        match self.files.get("anomaly.rego") {
            None => Ok(None),
            Some(bytes) => std::str::from_utf8(bytes)
                .map(Some)
                .map_err(|e| PolicyError::BundleMalformed(format!("anomaly.rego is not UTF-8: {e}"))),
        }
    }

    /// The exact source this crate ships and expects to be signed — used by
    /// `mcphubd`/tests to sign+load the canonical bundle without needing an
    /// external `opa` binary in every environment.
    pub const EMBEDDED_AUTHZ_REGO: &'static str =
        include_str!("../policies/authz.rego");

    /// Companion to `EMBEDDED_AUTHZ_REGO` — see `anomaly.rego`'s own header
    /// comment for the `input.recent_calls` contract.
    pub const EMBEDDED_ANOMALY_REGO: &'static str =
        include_str!("../policies/anomaly.rego");
}

#[derive(Debug, Deserialize)]
struct SignaturesFile {
    signatures: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SignedFileEntry {
    name: String,
    hash: String,
    algorithm: String,
}

#[derive(Debug, Deserialize)]
struct SignedFilesPayload {
    files: Vec<SignedFileEntry>,
}

/// Verify a compact JWS (`header.payload.signature`, all base64url) against
/// an HS256 key, reject anything but `alg: HS256`, and return the decoded
/// payload's file list.
fn verify_jws_hs256(jws: &str, key: &[u8]) -> Result<SignedFilesPayload, PolicyError> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(PolicyError::BundleSignatureInvalid(
            "signature is not a 3-part compact JWS".into(),
        ));
    }
    let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| PolicyError::BundleSignatureInvalid(format!("bad JWS header b64: {e}")))?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| PolicyError::BundleSignatureInvalid(format!("bad JWS header json: {e}")))?;
    if header.alg != "HS256" {
        return Err(PolicyError::BundleSignatureInvalid(format!(
            "unsupported JWS alg '{}' — only HS256 is accepted",
            header.alg
        )));
    }

    let signature = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| PolicyError::BundleSignatureInvalid(format!("bad JWS signature b64: {e}")))?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    hmac_verify(key, signing_input.as_bytes(), &signature).map_err(|_| {
        PolicyError::BundleSignatureInvalid("HMAC signature verification failed".into())
    })?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| PolicyError::BundleSignatureInvalid(format!("bad JWS payload b64: {e}")))?;
    serde_json::from_slice(&payload_bytes)
        .map_err(|e| PolicyError::BundleSignatureInvalid(format!("bad JWS payload json: {e}")))
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: String,
}

fn read_tar_gz(path: &Path) -> std::io::Result<BTreeMap<String, Vec<u8>>> {
    let file = std::fs::File::open(path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let mut out = BTreeMap::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().trim_start_matches("./").to_string();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        out.insert(path, buf);
    }
    Ok(out)
}

/// Thin, local wrapper around `aws-lc-rs` primitives kept in one place so
/// `bundle.rs` doesn't scatter raw crypto calls.
mod aws_lc_ring_compat {
    use aws_lc_rs::{digest, hmac};

    pub fn sha256_hex(data: &[u8]) -> String {
        let d = digest::digest(&digest::SHA256, data);
        hex::encode(d.as_ref())
    }

    pub fn hmac_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<(), ()> {
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::verify(&k, data, expected_tag).map_err(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::hmac;
    use std::io::Write;

    fn build_signed_bundle_bytes(rego: &[u8], key: &[u8]) -> Vec<u8> {
        let hash = aws_lc_ring_compat::sha256_hex(rego);
        let payload = serde_json::json!({
            "files": [{"name": "authz.rego", "hash": hash, "algorithm": "SHA-256"}]
        });
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&k, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(tag.as_ref());
        let jws = format!("{signing_input}.{sig_b64}");
        let sigfile = serde_json::to_vec(&serde_json::json!({"signatures": [jws]})).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(rego.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, "authz.rego", rego).unwrap();

            let mut header2 = tar::Header::new_gnu();
            header2.set_size(sigfile.len() as u64);
            header2.set_cksum();
            builder
                .append_data(&mut header2, ".signatures.json", sigfile.as_slice())
                .unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn valid_signature_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tar.gz");
        let key = b"test-signing-key-material";
        std::fs::write(&path, build_signed_bundle_bytes(b"package mcp.authz\ndefault allow := false\n", key)).unwrap();

        let bundle = PolicyBundle::load_signed(&path, key).expect("should load");
        assert!(bundle.rego_source().unwrap().contains("default allow"));
    }

    #[test]
    fn wrong_key_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tar.gz");
        let key = b"right-key";
        std::fs::write(&path, build_signed_bundle_bytes(b"package mcp.authz\n", key)).unwrap();

        let result = PolicyBundle::load_signed(&path, b"wrong-key");
        assert!(result.is_err(), "a bundle signed with a different key must not load");
    }

    #[test]
    fn tampered_file_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tar.gz");
        let key = b"test-key";
        // Sign one payload, then overwrite the archive's rego content so the
        // hash in .signatures.json no longer matches — simulates tampering
        // after signing.
        let good = build_signed_bundle_bytes(b"package mcp.authz\ndefault allow := false\n", key);
        std::fs::write(&path, good).unwrap();
        let files = read_tar_gz(&path).unwrap();
        assert!(files.contains_key("authz.rego"));

        // Build a bundle where the signed hash is for one payload but the
        // stored file is different (hand-construct rather than mutate the
        // gzip stream directly).
        let hash = aws_lc_ring_compat::sha256_hex(b"package mcp.authz\ndefault allow := false\n");
        let payload = serde_json::json!({"files": [{"name": "authz.rego", "hash": hash, "algorithm": "SHA-256"}]});
        let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&k, signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(tag.as_ref());
        let jws = format!("{signing_input}.{sig_b64}");
        let sigfile = serde_json::to_vec(&serde_json::json!({"signatures": [jws]})).unwrap();

        let tampered_rego = b"package mcp.authz\ndefault allow := true\n"; // different bytes, same claimed hash
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(tampered_rego.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, "authz.rego", &tampered_rego[..]).unwrap();
            let mut header2 = tar::Header::new_gnu();
            header2.set_size(sigfile.len() as u64);
            header2.set_cksum();
            builder.append_data(&mut header2, ".signatures.json", sigfile.as_slice()).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        let bytes = gz.finish().unwrap();
        let path2 = dir.path().join("tampered.tar.gz");
        std::fs::write(&path2, bytes).unwrap();

        let result = PolicyBundle::load_signed(&path2, key);
        assert!(result.is_err(), "tampered file content must fail hash verification");
    }

    #[test]
    fn missing_signatures_file_refuses_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsigned.tar.gz");
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            let rego = b"package mcp.authz\ndefault allow := false\n";
            let mut header = tar::Header::new_gnu();
            header.set_size(rego.len() as u64);
            header.set_cksum();
            builder.append_data(&mut header, "authz.rego", &rego[..]).unwrap();
            builder.finish().unwrap();
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_buf).unwrap();
        std::fs::write(&path, gz.finish().unwrap()).unwrap();

        let result = PolicyBundle::load_signed(&path, b"any-key");
        assert!(result.is_err());
    }
}
