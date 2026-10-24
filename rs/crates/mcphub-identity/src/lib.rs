//! `mcphub-identity` — provider-agnostic OIDC identity resolution for the
//! MCP security gateway: discovery, JWKS caching, JWT validation, the
//! multi-issuer registry, RFC 8693 token exchange, `dedicated_port` listener
//! metadata, and the OAuth 2.1 PKCE browser flow. See `rs/ARCHITECTURE.md`
//! ("Multi-IDP architecture") for the binding contract this crate
//! implements.
//!
//! Fail-closed throughout: every public entry point returns
//! `Result<_, IdentityError>`, and every `IdentityError` variant is meant to
//! be mapped to `mcphub_types::DenyReason` by the gateway — there is no
//! variant here that represents "proceed with unverified identity".

#![forbid(unsafe_code)]

pub mod claims;
pub mod config;
pub mod discovery;
pub mod error;
pub mod exchange;
pub mod http;
pub mod jwks;
pub mod pkce;
pub mod ports;
pub mod registry;
pub mod validate;

#[cfg(test)]
pub(crate) mod testutil;

use error::{IdentityError, Result};
use mcphub_types::{Identity, IssuerId, TokenRef};

/// End-to-end resolution: unverified-`iss` routing → registry lookup
/// (hard deny on unknown issuer) → JWKS fetch (via `jwks_cache`, host-pinned
/// by the caller-supplied `jwks_uri`) → full cryptographic validation →
/// claim→role mapping → `mcphub_types::Identity`.
///
/// `jwks_uri_for` resolves an issuer to its (already host-pinned, via
/// `discovery::fetch_discovery`) JWKS URI — injected so this function has no
/// direct network dependency and stays unit-testable; production wiring in
/// `mcphub-gateway` supplies the discovery-backed resolver.
pub async fn resolve_identity(
    token: &str,
    registry: &registry::IssuerRegistry,
    jwks_cache: &jwks::JwksCache,
    jwks_uri_for: impl Fn(&config::IdpConfig) -> String,
    now: i64,
) -> Result<Identity> {
    if token.trim().is_empty() {
        return Err(IdentityError::MissingToken);
    }

    let unverified_iss = registry::peek_unverified_issuer(token)?;
    let idp = registry.resolve(&unverified_iss)?;

    let jwks_uri = jwks_uri_for(idp);
    let issuer_keys = jwks_cache.get(&idp.issuer, &jwks_uri).await?;

    let claims = validate::validate_claims(token, idp, &issuer_keys, now)?;

    let sub = claims.get("sub").and_then(|v| v.as_str()).ok_or(IdentityError::Malformed)?.to_string();
    let email = claims.get("email").and_then(|v| v.as_str()).map(String::from);
    let issuer_id = IssuerId::new(idp.issuer.clone());
    // Every resolved role is stamped with `issuer_id` (the CONFIGURED
    // issuer this `idp` entry answers for, never the token's raw `iss`) and
    // dropped if it exceeds `idp.max_assertable_role` — see claims.rs and
    // ARCHITECTURE.md's "Core types" section for why a bare `Role` with no
    // issuer binding was the root cause of "the weakest IDP can mint
    // SuperAdmin".
    let roles = idp.role_mapping.resolve(&claims, &issuer_id, idp.max_assertable_role);
    let groups = claims
        .get("groups")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|g| g.as_str().map(String::from)).collect())
        .unwrap_or_default();

    Ok(Identity {
        sub,
        issuer: issuer_id,
        email,
        roles,
        groups,
        token_ref: TokenRef::from_bearer(token),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::RoleMapping;
    use crate::config::AuthModeHint;
    use crate::config::IdpConfig;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use mcphub_types::Role;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
        nbf: i64,
        iat: i64,
        roles: Vec<String>,
    }

    fn cfg() -> IdpConfig {
        IdpConfig {
            issuer: "https://idp.example.com".into(),
            discovery_url: None,
            issuer_aliases: vec![],
            audiences: vec!["mcphub".into()],
            role_mapping: RoleMapping::default_for(crate::claims::ProviderHint::Generic),
            allowed_algs: vec!["RS256".into()],
            clock_skew_seconds: 60,
            auth_mode: AuthModeHint::SharedPassthrough,
            dedicated_port: None,
            supports_token_exchange: false,
            client_id: None,
            redirect_uri_allowlist: vec![],
            max_assertable_role: Role::SuperAdmin,
        }
    }

    struct TestRsaKey {
        priv_pem: String,
        n_b64: String,
        e_b64: String,
    }

    fn gen_test_rsa() -> TestRsaKey {
        use base64::Engine;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let pub_key = priv_key.to_public_key();
        let priv_pem = priv_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string();
        let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.n().to_bytes_be());
        let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_key.e().to_bytes_be());
        TestRsaKey { priv_pem, n_b64, e_b64 }
    }

    /// RSA-2048 keygen in an unoptimized (`dev`) build is the dominant cost
    /// of this crate's test suite (tens of seconds); every test in this
    /// module can share one process-wide key instead of generating its own.
    static SHARED_TEST_RSA: std::sync::OnceLock<TestRsaKey> = std::sync::OnceLock::new();
    fn shared_test_rsa() -> &'static TestRsaKey {
        SHARED_TEST_RSA.get_or_init(gen_test_rsa)
    }

    fn sign(key: &TestRsaKey, kid: &str, claims: &Claims) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let enc_key = EncodingKey::from_rsa_pem(key.priv_pem.as_bytes()).unwrap();
        encode(&header, claims, &enc_key).unwrap()
    }

    fn jwks_body(key: &TestRsaKey, kid: &str) -> String {
        serde_json::json!({
            "keys": [{ "kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": key.n_b64, "e": key.e_b64 }]
        })
        .to_string()
    }

    /// Defect 9: `resolve_identity` — the crate's ONLY public entry point —
    /// was never called by any test; the old
    /// `end_to_end_valid_token_resolves_identity_with_roles` called
    /// `validate::validate_claims` directly and admitted as much in a
    /// comment. This calls the real thing end to end: registry resolution,
    /// a real JWKS fetch over a loopback mock server, full validation, and
    /// role mapping.
    #[tokio::test]
    async fn resolve_identity_end_to_end_through_the_real_public_entry_point() {
        let key = shared_test_rsa();
        let base = crate::testutil::spawn(vec![crate::testutil::json_response(200, &jwks_body(&key, "kid-1"))]).await;
        let jwks_uri = format!("{base}/jwks");

        let now = jsonwebtoken::get_current_timestamp() as i64;
        let claims = Claims {
            sub: "alice".into(),
            iss: "https://idp.example.com".into(),
            aud: "mcphub".into(),
            exp: now + 300,
            nbf: now - 10,
            iat: now,
            roles: vec!["mcphub-employee".into()],
        };
        let token = sign(&key, "kid-1", &claims);

        let registry = registry::IssuerRegistry::from_configs(vec![cfg()]).unwrap();
        let jwks_cache = jwks::JwksCache::new().unwrap();

        let identity = resolve_identity(&token, &registry, &jwks_cache, |_idp| jwks_uri.clone(), now).await.unwrap();

        assert_eq!(identity.sub, "alice");
        assert_eq!(identity.issuer.0, "https://idp.example.com");
        assert_eq!(identity.roles, vec![mcphub_types::GrantedRole { role: Role::Employee, asserted_by: identity.issuer.clone() }]);
    }

    /// The JWKS lookup must key on the CONFIGURED issuer
    /// (`idp.issuer` — the registry entry's own canonical field, resolved
    /// via `registry.resolve`), never on whichever alias string the
    /// token's *unverified* `iss` happened to be. Proven behaviorally: two
    /// tokens, one asserting the primary issuer and one asserting an
    /// alias, must both resolve against the SAME cache entry (one JWKS
    /// fetch total) — if the cache were instead keyed on the raw token
    /// `iss`, this would be two entries and two fetches.
    #[tokio::test]
    async fn jwks_lookup_keys_on_configured_issuer_not_unverified_token_iss() {
        let key = shared_test_rsa();
        // Exactly one queued response: if resolve_identity ever keys the
        // JWKS cache on the token's raw `iss` instead of `idp.issuer`, the
        // second resolve_identity call below issues a second HTTP request
        // that this server has no response left to answer, and that call
        // fails — a hard, unambiguous signal, not a soft assertion.
        let base = crate::testutil::spawn(vec![crate::testutil::json_response(200, &jwks_body(&key, "kid-1"))]).await;
        let jwks_uri = format!("{base}/jwks");

        let mut idp = cfg();
        idp.issuer_aliases = vec!["https://alias.idp.example.com".to_string()];
        let registry = registry::IssuerRegistry::from_configs(vec![idp]).unwrap();
        let jwks_cache = jwks::JwksCache::new().unwrap();

        let now = jsonwebtoken::get_current_timestamp() as i64;
        let make_token = |iss: &str| {
            sign(
                &key,
                "kid-1",
                &Claims { sub: "alice".into(), iss: iss.into(), aud: "mcphub".into(), exp: now + 300, nbf: now - 10, iat: now, roles: vec![] },
            )
        };

        let via_alias = make_token("https://alias.idp.example.com");
        let via_primary = make_token("https://idp.example.com");

        let id1 = resolve_identity(&via_alias, &registry, &jwks_cache, |_idp| jwks_uri.clone(), now).await.unwrap();
        let id2 = resolve_identity(&via_primary, &registry, &jwks_cache, |_idp| jwks_uri.clone(), now).await.unwrap();
        assert_eq!(id1.sub, "alice");
        assert_eq!(id2.sub, "alice");
    }

    /// NEW-1 addendum: `GrantedRole.asserted_by` must be the CONFIGURED
    /// issuer (`idp.issuer` — here, the registry's primary issuer string),
    /// never the token's own unverified `iss` claim, even when the token
    /// authenticated via an alias. If this regressed to stamping the raw
    /// `iss`, a policy trusting "roles asserted by the primary issuer
    /// string" would be fooled by a token that merely asserted a
    /// configured alias.
    #[tokio::test]
    async fn granted_role_provenance_is_the_configured_issuer_not_the_tokens_raw_iss() {
        let key = shared_test_rsa();
        let base = crate::testutil::spawn(vec![crate::testutil::json_response(200, &jwks_body(&key, "kid-1"))]).await;
        let jwks_uri = format!("{base}/jwks");

        let mut idp = cfg();
        idp.issuer_aliases = vec!["https://alias.idp.example.com".to_string()];
        let registry = registry::IssuerRegistry::from_configs(vec![idp]).unwrap();
        let jwks_cache = jwks::JwksCache::new().unwrap();

        let now = jsonwebtoken::get_current_timestamp() as i64;
        let token = sign(
            &key,
            "kid-1",
            &Claims {
                sub: "alice".into(),
                iss: "https://alias.idp.example.com".into(), // authenticates via the ALIAS
                aud: "mcphub".into(),
                exp: now + 300,
                nbf: now - 10,
                iat: now,
                roles: vec!["mcphub-employee".into()],
            },
        );

        let identity = resolve_identity(&token, &registry, &jwks_cache, |_idp| jwks_uri.clone(), now).await.unwrap();
        assert_eq!(
            identity.roles[0].asserted_by,
            mcphub_types::IssuerId::new("https://idp.example.com"),
            "role provenance must be the configured primary issuer, not the alias the token happened to assert"
        );
    }
}
