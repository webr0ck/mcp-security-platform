//! Full JWT validation: signature, `iss`, `aud`, `exp`, `nbf`, `iat` skew,
//! `alg` allowlist. This is the security core of the crate — every check
//! here maps a failure to a specific [`IdentityError`], and there is no path
//! that returns `Ok` without every check having passed.
//!
//! Key design point for alg-confusion resistance: `jsonwebtoken::Validation`
//! is built with `algorithms` set *only* to `idp.allowed_algs` (never derived
//! from the token header), and the crate's `KeyEntry` is constructed from
//! the issuer's JWKS with a fixed key family (RSA). `jsonwebtoken::decode`
//! rejects a token whose header `alg` is not in `validation.algorithms`
//! before it ever touches the key, and separately rejects a key/algorithm
//! family mismatch (e.g. an RSA `DecodingKey` asked to verify HS256) at the
//! verification step. Both layers must independently agree for a token to
//! verify.

use crate::config::IdpConfig;
use crate::error::{IdentityError, Result};
use crate::jwks::IssuerKeys;
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;

/// Validate `token` against `idp`'s configuration using already-fetched
/// `issuer_keys`. `now` is injected (not read from the system clock) so
/// tests are deterministic and the caller controls clock-skew scenarios.
pub fn validate_claims(token: &str, idp: &IdpConfig, issuer_keys: &IssuerKeys, now: i64) -> Result<Value> {
    // `jsonwebtoken::Algorithm` has no `none` variant at all, so a token
    // with `alg: "none"` fails to deserialize inside `decode_header` — a
    // safe rejection, but not a very informative one. Peek the raw header
    // JSON first (still unverified — this is routing/diagnostics only, real
    // enforcement happens below) so `alg: none` gets the precise
    // `AlgNotAllowed` error rather than a generic `Malformed`.
    if header_alg_is_literally_none(token) {
        return Err(IdentityError::AlgNotAllowed("none".to_string()));
    }
    let header = decode_header(token).map_err(|_| IdentityError::Malformed)?;

    // `none` and any algorithm outside the issuer's explicit allowlist are
    // rejected up front, independent of what jsonwebtoken's own algorithms
    // check would do — belt and suspenders, and gives a precise error.
    let allowed: Vec<Algorithm> = idp
        .allowed_algs
        .iter()
        .filter_map(|a| Algorithm::from_str(a).ok())
        .collect();
    if allowed.is_empty() {
        return Err(IdentityError::Internal("issuer has no usable allowed_algs configured".into()));
    }
    if header.alg == Algorithm::HS256 && !idp.allowed_algs.iter().any(|a| a == "HS256") {
        return Err(IdentityError::AlgNotAllowed(format!("{:?}", header.alg)));
    }
    if !allowed.contains(&header.alg) {
        return Err(IdentityError::AlgNotAllowed(format!("{:?}", header.alg)));
    }

    // Never select a key by anything in the header except `kid`, and never
    // trust `jku`/`x5u` even if present — we only ever look keys up in the
    // pre-fetched, host-pinned `issuer_keys` for this issuer.
    let kid = header.kid.ok_or(IdentityError::MissingKid)?;
    let key_entry = issuer_keys.keys_by_kid.get(&kid).ok_or(IdentityError::UnknownKid)?;

    let mut validation = Validation::new(header.alg);
    validation.algorithms = allowed;
    let issuers: Vec<String> = issuer_set(idp).into_iter().collect();
    validation.set_issuer(&issuers);
    validation.set_audience(&idp.audiences);
    // `exp`/`nbf` are validated by hand below against the INJECTED `now`,
    // not jsonwebtoken's own `SystemTime::now()` — this is the actual fix
    // for "time is not genuinely injectable": leaving jsonwebtoken's
    // built-in exp/nbf checks enabled meant `now` (and therefore
    // `clock_skew_seconds`, via `validation.leeway`) had no effect on the
    // two checks that matter most for testability and correctness, and
    // `leeway` silently extended `exp` as well as `nbf` — a common Entra
    // `clock_skew_seconds: 300` grants every token from that IDP five
    // extra minutes of life past its real expiry, which is not what
    // "clock skew" should mean. `clock_skew_seconds` below is applied only
    // to `nbf` (tolerating the verifier's clock running behind the IDP's)
    // and to the `iat`-in-the-future check; `exp` gets zero extension.
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.required_spec_claims = HashSet::from(["exp".to_string(), "iss".to_string(), "aud".to_string()]);

    let data = decode::<Value>(token, &key_entry.decoding_key, &validation).map_err(|e| map_jwt_error(e.kind()))?;

    let skew = idp.clock_skew_seconds as i64;

    // `exp`: strict against the injected `now`, no leeway extension. The
    // `required_spec_claims` check above already guarantees `exp` is
    // present and numeric-shaped enough to have decoded into `Value`; a
    // non-numeric `exp` would have failed `required_spec_claims`/decode
    // already, so treat an unreadable value here as malformed defensively.
    let exp = data.claims.get("exp").and_then(|v| v.as_i64()).ok_or(IdentityError::Malformed)?;
    if now >= exp {
        return Err(IdentityError::Expired);
    }

    // `nbf`: tolerant of the verifier's clock running up to `skew` seconds
    // behind the IDP's — a token becomes valid at `nbf`, and a slow local
    // clock might think `now < nbf` for a few seconds after it's genuinely
    // valid. Absent `nbf` entirely, there is nothing to check (RFC 7519:
    // `nbf` is optional).
    if let Some(nbf) = data.claims.get("nbf").and_then(|v| v.as_i64()) {
        if now + skew < nbf {
            return Err(IdentityError::NotYetValid);
        }
    }

    // iat skew: reject tokens claiming to be issued too far in the future
    // (clock-skew tolerant, but not an open door for arbitrarily-postdated
    // tokens). jsonwebtoken does not validate `iat` itself.
    if let Some(iat) = data.claims.get("iat").and_then(|v| v.as_i64()) {
        if iat > now + skew {
            return Err(IdentityError::IatOutOfSkew);
        }
    }

    Ok(data.claims)
}

fn header_alg_is_literally_none(token: &str) -> bool {
    let Some(header_b64) = token.split('.').next() else { return false };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64) else { return false };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { return false };
    matches!(v.get("alg").and_then(|a| a.as_str()), Some(alg) if alg.eq_ignore_ascii_case("none"))
}

fn issuer_set(idp: &IdpConfig) -> HashSet<String> {
    let mut set = HashSet::new();
    set.insert(idp.issuer.clone());
    set.extend(idp.issuer_aliases.iter().cloned());
    set
}

fn map_jwt_error(kind: &jsonwebtoken::errors::ErrorKind) -> IdentityError {
    use jsonwebtoken::errors::ErrorKind::*;
    match kind {
        ExpiredSignature => IdentityError::Expired,
        ImmatureSignature => IdentityError::NotYetValid,
        InvalidIssuer => IdentityError::UnknownIssuer,
        InvalidAudience => IdentityError::InvalidAudience,
        InvalidSignature | InvalidKeyFormat | InvalidAlgorithmName | InvalidAlgorithm => IdentityError::BadSignature,
        MissingRequiredClaim(_) => IdentityError::Malformed,
        _ => IdentityError::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::RoleMapping;
    use crate::config::AuthModeHint;
    use crate::jwks::KeyEntry;
    use base64::Engine;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde::Serialize;
    use std::collections::HashMap;

    const ISSUER: &str = "https://idp.example.com/realm";
    const AUD: &str = "mcphub";
    const KID: &str = "test-key-1";

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
        nbf: i64,
        iat: i64,
    }

    fn base_claims(now: i64) -> Claims {
        Claims { sub: "user-1".into(), iss: ISSUER.into(), aud: AUD.into(), exp: now + 300, nbf: now - 10, iat: now }
    }

    fn idp_config() -> IdpConfig {
        IdpConfig {
            issuer: ISSUER.to_string(),
            discovery_url: None,
            issuer_aliases: vec![],
            audiences: vec![AUD.to_string()],
            role_mapping: RoleMapping::default(),
            allowed_algs: vec!["RS256".to_string()],
            clock_skew_seconds: 60,
            auth_mode: AuthModeHint::SharedPassthrough,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: None,
            redirect_uri_allowlist: vec![],
            max_assertable_role: mcphub_types::Role::SuperAdmin,
        }
    }

    struct TestKeys {
        private_pem: String,
        n_b64: String,
        e_b64: String,
    }

    fn gen_rsa() -> TestKeys {
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pub_key = priv_key.to_public_key();

        use rsa::pkcs1::EncodeRsaPrivateKey;
        let private_pem = priv_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();

        let n = pub_key.n().to_bytes_be();
        let e = pub_key.e().to_bytes_be();
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n);
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e);
        // silence unused-import warning for EncodeRsaPublicKey in some cfg combos
        let _ = pub_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF);
        TestKeys { private_pem, n_b64, e_b64 }
    }

    /// RSA-2048 keygen is slow (~0.5-1s each) and almost every test in this
    /// module just needs *some* valid RSA keypair, not a fresh one — using a
    /// process-wide lazily-generated shared key here is what took this
    /// suite from ~51s to well under a second. Tests that specifically need
    /// two DISTINCT keys (key rotation) still call `gen_rsa()` directly for
    /// the second one.
    static SHARED_RSA: std::sync::OnceLock<TestKeys> = std::sync::OnceLock::new();
    fn shared_rsa() -> &'static TestKeys {
        SHARED_RSA.get_or_init(gen_rsa)
    }

    fn issuer_keys_from(test_keys: &TestKeys, kid: &str) -> IssuerKeys {
        let decoding_key =
            jsonwebtoken::DecodingKey::from_rsa_components(&test_keys.n_b64, &test_keys.e_b64).unwrap();
        let mut keys_by_kid = HashMap::new();
        keys_by_kid.insert(kid.to_string(), KeyEntry { decoding_key, jwks_alg: Some("RS256".into()) });
        IssuerKeys { keys_by_kid }
    }

    fn sign_rs256(test_keys: &TestKeys, kid: &str, claims: &Claims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let enc_key = EncodingKey::from_rsa_pem(test_keys.private_pem.as_bytes()).unwrap();
        encode(&header, claims, &enc_key).unwrap()
    }

    #[test]
    fn valid_token_is_accepted() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let token = sign_rs256(&tk, KID, &base_claims(now));
        let keys = issuer_keys_from(&tk, KID);
        let claims = validate_claims(&token, &idp_config(), &keys, now).unwrap();
        assert_eq!(claims.get("sub").and_then(|v| v.as_str()), Some("user-1"));
    }

    #[test]
    fn expired_token_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let mut c = base_claims(now);
        c.exp = now - 100;
        c.iat = now - 400;
        c.nbf = now - 400;
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp_config(), &keys, now).unwrap_err(), IdentityError::Expired);
    }

    /// `now` here is a fixed, arbitrary epoch — not derived from the system
    /// clock at all — proving `now` is genuinely the value that drives
    /// exp/nbf validation, not merely a parameter that happens to agree
    /// with `SystemTime::now()` in every other test.
    const FIXED_NOW: i64 = 1_700_000_000;

    #[test]
    fn clock_skew_leeway_does_not_extend_token_life_past_exp() {
        let tk = shared_rsa();
        let mut idp = idp_config();
        idp.clock_skew_seconds = 300; // a common Entra-style setting
        let mut c = base_claims(FIXED_NOW);
        c.exp = FIXED_NOW - 1; // already expired at FIXED_NOW, well within the 300s skew window
        c.nbf = FIXED_NOW - 400;
        c.iat = FIXED_NOW - 400;
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(
            validate_claims(&token, &idp, &keys, FIXED_NOW).unwrap_err(),
            IdentityError::Expired,
            "clock_skew_seconds must never grant a token extra life past its real exp"
        );
    }

    #[test]
    fn nbf_within_clock_skew_is_accepted() {
        let tk = shared_rsa();
        let mut idp = idp_config();
        idp.clock_skew_seconds = 300;
        let mut c = base_claims(FIXED_NOW);
        c.nbf = FIXED_NOW + 100; // not yet valid by wall clock, but within skew tolerance
        c.exp = FIXED_NOW + 500;
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert!(validate_claims(&token, &idp, &keys, FIXED_NOW).is_ok());
    }

    #[test]
    fn nbf_beyond_clock_skew_is_rejected() {
        // The direct mutation-catcher for "nbf enforcement silently
        // disabled": a token not valid for another 1000s, with only 60s of
        // configured skew tolerance, must be rejected.
        let tk = shared_rsa();
        let mut idp = idp_config();
        idp.clock_skew_seconds = 60;
        let mut c = base_claims(FIXED_NOW);
        c.nbf = FIXED_NOW + 1000;
        c.exp = FIXED_NOW + 2000;
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp, &keys, FIXED_NOW).unwrap_err(), IdentityError::NotYetValid);
    }

    #[test]
    fn exp_boundary_is_exclusive_at_now_equals_exp() {
        let tk = shared_rsa();
        let mut c = base_claims(FIXED_NOW);
        c.exp = FIXED_NOW; // exactly at the boundary
        c.nbf = FIXED_NOW - 10;
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp_config(), &keys, FIXED_NOW).unwrap_err(), IdentityError::Expired);
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let mut c = base_claims(now);
        c.aud = "some-other-service".into();
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp_config(), &keys, now).unwrap_err(), IdentityError::InvalidAudience);
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let mut c = base_claims(now);
        c.iss = "https://not-the-configured-idp.example.com".into();
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp_config(), &keys, now).unwrap_err(), IdentityError::UnknownIssuer);
    }

    #[test]
    fn unconfigured_issuer_never_reaches_key_lookup() {
        // Covered end-to-end in registry.rs; here we confirm that even with
        // a "valid-looking" signature, validate_claims still enforces iss
        // against the configured idp (defense in depth beyond registry
        // resolution, which is what actually stops key-source substitution).
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let mut c = base_claims(now);
        c.iss = "https://attacker.example.com".into();
        let token = sign_rs256(&tk, KID, &c);
        let keys = issuer_keys_from(&tk, KID);
        assert!(validate_claims(&token, &idp_config(), &keys, now).is_err());
    }

    #[test]
    fn alg_none_is_rejected() {
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let c = base_claims(now);
        // Hand-construct an `alg: none` token with an empty signature.
        let header_json = r#"{"alg":"none","typ":"JWT"}"#;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);
        let payload_json = serde_json::to_string(&c).unwrap();
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
        let token = format!("{header_b64}.{payload_b64}.");

        let tk = shared_rsa();
        let keys = issuer_keys_from(&tk, KID);
        let err = validate_claims(&token, &idp_config(), &keys, now).unwrap_err();
        // decode_header on an `alg: none` token succeeds; our allowlist check
        // (idp only allows RS256) must reject it before any signature logic.
        assert!(matches!(err, IdentityError::AlgNotAllowed(_)));
    }

    #[test]
    fn alg_confusion_hs256_signed_with_rsa_public_key_is_rejected() {
        // Classic attack: take the RSA public key's PEM bytes as an HMAC
        // secret and sign an HS256 token, hoping a naive verifier that
        // "looks up a key by kid and verifies with whatever alg the header
        // says" will treat the public key as a valid HMAC secret.
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let c = base_claims(now);

        let pub_pem = {
            let priv_key = jsonwebtoken::EncodingKey::from_rsa_pem(tk.private_pem.as_bytes()).unwrap();
            let _ = priv_key; // key material already generated above; reuse n/e bytes as the "leaked" secret
            format!("{}{}", tk.n_b64, tk.e_b64) // stand-in for "public key bytes" used as an HMAC secret
        };

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let hmac_key = EncodingKey::from_secret(pub_pem.as_bytes());
        let forged = encode(&header, &c, &hmac_key).unwrap();

        let keys = issuer_keys_from(&tk, KID); // only an RSA key registered under KID
        let err = validate_claims(&forged, &idp_config(), &keys, now).unwrap_err();
        assert!(matches!(err, IdentityError::AlgNotAllowed(_)), "expected AlgNotAllowed, got {err:?}");
    }

    /// The test above doesn't actually exercise alg-confusion resistance:
    /// `idp_config()`'s `allowed_algs` is `["RS256"]` only, so the generic
    /// allowlist check rejects the forged HS256 token before the
    /// key-family question is ever reached — an IDP allowlisting HS256
    /// would sail right past that same check. This test configures an IDP
    /// that LEGITIMATELY allows both RS256 and HS256 (a real, if unusual,
    /// configuration — e.g. an IDP migrating between algorithms), so the
    /// only thing standing between the forged token and acceptance is
    /// `jsonwebtoken`'s own key-family enforcement: an RSA `DecodingKey`
    /// must never be usable to verify an HS256 (HMAC) signature, no matter
    /// what the issuer's algorithm allowlist says.
    #[test]
    fn alg_confusion_is_rejected_even_when_hs256_is_a_legitimately_allowed_alg() {
        let tk = shared_rsa();
        let mut idp = idp_config();
        idp.allowed_algs = vec!["RS256".to_string(), "HS256".to_string()];
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let c = base_claims(now);

        // The "leaked" secret an attacker would use: the RSA key's own
        // public components, which are NOT secret and are exactly what an
        // attacker fetching the issuer's JWKS would have.
        let leaked_pub_bytes = format!("{}{}", tk.n_b64, tk.e_b64);

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let hmac_key = EncodingKey::from_secret(leaked_pub_bytes.as_bytes());
        let forged = encode(&header, &c, &hmac_key).unwrap();

        // Only an RSA key is registered under KID — there is no HMAC secret
        // in `issuer_keys` at all, by construction, matching real
        // production wiring (JWKS never contains `kty: "oct"` keys here).
        let keys = issuer_keys_from(&tk, KID);
        let err = validate_claims(&forged, &idp, &keys, now).unwrap_err();
        assert!(
            matches!(err, IdentityError::BadSignature | IdentityError::AlgNotAllowed(_)),
            "RSA key material must never verify an HS256 signature, even when HS256 is allowlisted; got {err:?}"
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let token = sign_rs256(&tk, KID, &base_claims(now));
        let mut parts: Vec<&str> = token.split('.').collect();
        // Swap in a payload claiming a different (still-configured) audience
        // without re-signing — the signature no longer matches.
        let mut tampered = base_claims(now);
        tampered.sub = "attacker".into();
        let tampered_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(&tampered).unwrap());
        parts[1] = &tampered_payload;
        let tampered_token = parts.join(".");

        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&tampered_token, &idp_config(), &keys, now).unwrap_err(), IdentityError::BadSignature);
    }

    #[test]
    fn missing_kid_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let header = Header::new(Algorithm::RS256); // no kid set
        let enc_key = EncodingKey::from_rsa_pem(tk.private_pem.as_bytes()).unwrap();
        let token = encode(&header, &base_claims(now), &enc_key).unwrap();
        let keys = issuer_keys_from(&tk, KID);
        assert_eq!(validate_claims(&token, &idp_config(), &keys, now).unwrap_err(), IdentityError::MissingKid);
    }

    #[test]
    fn unknown_kid_is_rejected() {
        let tk = shared_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        let token = sign_rs256(&tk, "some-other-kid", &base_claims(now));
        let keys = issuer_keys_from(&tk, KID); // registered under a different kid
        assert_eq!(validate_claims(&token, &idp_config(), &keys, now).unwrap_err(), IdentityError::UnknownKid);
    }

    #[test]
    fn rotated_key_scenario_old_kid_no_longer_present_is_rejected() {
        let old_tk = gen_rsa();
        let new_tk = gen_rsa();
        let now = jsonwebtoken::get_current_timestamp() as i64;
        // Token signed under the *old* key/kid...
        let token = sign_rs256(&old_tk, KID, &base_claims(now));
        // ...but the issuer has rotated: current JWKS only has the new key
        // under the same kid slot re-used, or the old kid evicted entirely.
        let keys = issuer_keys_from(&new_tk, KID);
        let err = validate_claims(&token, &idp_config(), &keys, now).unwrap_err();
        assert_eq!(err, IdentityError::BadSignature);
    }
}
