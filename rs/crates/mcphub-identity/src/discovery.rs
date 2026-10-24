//! RFC 8414 (`.well-known/openid-configuration` / `oauth-authorization-server`)
//! discovery, with host-pinning: the `jwks_uri` returned by discovery MUST
//! share a host with the configured issuer (or an explicitly configured
//! alias host), otherwise a compromised/misconfigured discovery response — or
//! a redirect chain hijacking discovery — cannot smuggle in a different
//! signing-key source. This is the SSRF-via-discovery mitigation called out
//! in the task brief.
//!
//! Every URL this module reads out of a discovery document — `jwks_uri`,
//! and (via [`validate_endpoint_url`]) `authorization_endpoint` /
//! `token_endpoint` — is validated at this parse boundary: `https` only,
//! and (for `jwks_uri`) host-pinned. Nothing downstream of this module
//! should ever `Url::parse(...).expect(...)` a discovery-sourced string —
//! that string is remote-controlled input.

use crate::error::{IdentityError, Result};
use crate::http::{assert_final_url_host_matches, read_json_capped, HardenedClient};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

impl DiscoveryDocument {
    /// Startup-time probe: does this IDP advertise RFC 8693 token exchange?
    /// Recorded once per issuer in `IdpConfig::supports_token_exchange`.
    pub fn supports_token_exchange(&self) -> bool {
        self.grant_types_supported.iter().any(|g| g == TOKEN_EXCHANGE_GRANT)
    }

    /// Validate and return `authorization_endpoint` as a parsed [`Url`]:
    /// must be present, `https`, and share a host with the configured
    /// issuer (or an allowed alias host) — the same pin `jwks_uri` gets.
    /// `authorization_endpoint` is where the portal 302s the browser with
    /// `state`/`nonce`/`code_challenge` attached and `token_endpoint` is
    /// where the caller's subject token gets POSTed, so both are exactly as
    /// sensitive as `jwks_uri`, not "just a redirect target".
    pub fn validate_authorization_endpoint(&self, issuer: &str, allowed_hosts: &[String]) -> Result<Url> {
        validate_endpoint_url(self.authorization_endpoint.as_deref(), issuer, allowed_hosts)
    }

    pub fn validate_token_endpoint(&self, issuer: &str, allowed_hosts: &[String]) -> Result<Url> {
        validate_endpoint_url(self.token_endpoint.as_deref(), issuer, allowed_hosts)
    }
}

pub(crate) fn validate_endpoint_url(raw: Option<&str>, issuer: &str, allowed_hosts: &[String]) -> Result<Url> {
    let raw = raw.ok_or(IdentityError::InvalidEndpointUrl)?;
    let url = Url::parse(raw).map_err(|_| IdentityError::InvalidEndpointUrl)?;
    if url.scheme() != "https" {
        return Err(IdentityError::InvalidEndpointUrl);
    }
    if !host_is_pinned(&url, issuer, allowed_hosts) {
        return Err(IdentityError::InvalidEndpointUrl);
    }
    Ok(url)
}

fn host_is_pinned(url: &Url, issuer: &str, allowed_hosts: &[String]) -> bool {
    let issuer_host = Url::parse(issuer).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
    let host = url.host_str().unwrap_or("");
    host == issuer_host || allowed_hosts.iter().any(|h| h == host)
}

/// Fetch and validate a discovery document for `issuer`, enforcing:
/// - TLS only (`https://`)
/// - the document's own `issuer` field matches the configured issuer
///   (RFC 8414 mandates this; skipping it lets a discovery response for a
///   different issuer be substituted)
/// - `jwks_uri` host-pins to the issuer's host (or an explicit alias host)
/// - the response body is capped in size, and its final URL (always equal
///   to the requested URL under `HardenedClient`'s no-redirect policy) is
///   re-checked against the issuer host as defense in depth
pub async fn fetch_discovery(issuer: &str, allowed_jwks_hosts: &[String]) -> Result<DiscoveryDocument> {
    let http = HardenedClient::build()?;
    let issuer_url = Url::parse(issuer).map_err(|_| IdentityError::DiscoveryFailed)?;
    if issuer_url.scheme() != "https" {
        return Err(IdentityError::DiscoveryFailed);
    }

    let well_known = well_known_url(&issuer_url)?;
    let issuer_host = issuer_url.host_str().unwrap_or("").to_string();

    fetch_discovery_at(&http, well_known.as_str(), &issuer_host, issuer, allowed_jwks_hosts).await
}

/// The actual network fetch + validation, parameterized on the well-known
/// URL to hit and the issuer host to pin against, separately from the
/// `issuer` string's own scheme requirement — this split exists so tests
/// can exercise the real host-pin/issuer-match/redirect-rejection/body-cap
/// behavior over a plain-HTTP loopback listener (no TLS test fixture
/// available) while `fetch_discovery` itself still enforces `https` on the
/// issuer before ever reaching here.
async fn fetch_discovery_at(
    http: &HardenedClient,
    well_known_url: &str,
    issuer_host: &str,
    issuer: &str,
    allowed_jwks_hosts: &[String],
) -> Result<DiscoveryDocument> {
    let resp = http
        .get(well_known_url)
        .send()
        .await
        .map_err(|_| IdentityError::DependencyUnavailable("oidc_discovery"))?;
    if !resp.status().is_success() {
        return Err(IdentityError::DiscoveryFailed);
    }
    assert_final_url_host_matches(&resp, issuer_host).map_err(|_| IdentityError::DiscoveryFailed)?;
    let doc: DiscoveryDocument = read_json_capped(resp, IdentityError::DiscoveryFailed).await?;

    if doc.issuer != issuer {
        return Err(IdentityError::DiscoveryFailed);
    }

    let jwks_url = Url::parse(&doc.jwks_uri).map_err(|_| IdentityError::JwksHostMismatch)?;
    if jwks_url.scheme() != "https" {
        return Err(IdentityError::JwksHostMismatch);
    }
    let jwks_host = jwks_url.host_str().unwrap_or("");
    let host_ok = jwks_host == issuer_host || allowed_jwks_hosts.iter().any(|h| h == jwks_host);
    if !host_ok {
        return Err(IdentityError::JwksHostMismatch);
    }

    Ok(doc)
}

fn well_known_url(issuer_url: &Url) -> Result<Url> {
    let mut url = issuer_url.clone();
    let existing_path = url.path().trim_end_matches('/').to_string();
    url.set_path(&format!("{existing_path}/.well-known/openid-configuration"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn well_known_path_appended_correctly() {
        let u = Url::parse("https://login.example.com/tenant-id/v2.0").unwrap();
        let w = well_known_url(&u).unwrap();
        assert_eq!(w.as_str(), "https://login.example.com/tenant-id/v2.0/.well-known/openid-configuration");
    }

    #[test]
    fn token_exchange_detection() {
        let doc = DiscoveryDocument {
            issuer: "https://a".into(),
            jwks_uri: "https://a/jwks".into(),
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            grant_types_supported: vec![TOKEN_EXCHANGE_GRANT.to_string()],
            token_endpoint_auth_methods_supported: vec![],
        };
        assert!(doc.supports_token_exchange());

        let doc2 = DiscoveryDocument { grant_types_supported: vec!["authorization_code".into()], ..doc };
        assert!(!doc2.supports_token_exchange());
    }

    fn doc_json(issuer: &str, jwks_uri: &str) -> String {
        serde_json::json!({
            "issuer": issuer,
            "jwks_uri": jwks_uri,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
        })
        .to_string()
    }

    // `fetch_discovery_at` is the real network+validation logic, taking the
    // well-known URL and issuer host separately from `issuer`'s own https
    // requirement — this lets these tests exercise host-pin/issuer-match/
    // redirect-rejection/body-cap over a plain-HTTP loopback listener (no
    // TLS test fixture available in this crate). `fetch_discovery` itself
    // still enforces `https` on the issuer before ever calling this, and
    // `fetch_discovery_rejects_http_scheme_issuer` below proves that gate
    // directly.

    #[tokio::test]
    async fn fetch_discovery_accepts_matching_issuer_and_same_host_jwks_uri() {
        let base = testutil::spawn(vec!["placeholder".into()]).await;
        let issuer = base.replacen("http://", "https://", 1); // host string only; request itself still goes to `base` (plain http)
        let issuer_host = url::Url::parse(&issuer).unwrap().host_str().unwrap().to_string();
        let body = doc_json(&issuer, &format!("{issuer}/jwks"));
        let base2 = testutil::spawn(vec![testutil::json_response(200, &body)]).await;
        let http = HardenedClient::build().unwrap();
        let well_known = format!("{base2}/.well-known/openid-configuration");
        let doc = fetch_discovery_at(&http, &well_known, &issuer_host, &issuer, &[]).await.unwrap();
        assert_eq!(doc.issuer, issuer);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_issuer_mismatch() {
        // Document declares one issuer; we ask about a different one (host
        // pin still satisfied by allowlisting the mock's own host, so the
        // *only* thing that can fail is the RFC 8414 issuer==configured
        // check).
        let doc_issuer = "https://not-the-configured-issuer.example.com";
        let body = doc_json(doc_issuer, &format!("{doc_issuer}/jwks"));
        let base = testutil::spawn(vec![testutil::json_response(200, &body)]).await;
        let http = HardenedClient::build().unwrap();
        let well_known = format!("{base}/.well-known/openid-configuration");
        let issuer_host = url::Url::parse(&base).unwrap().host_str().unwrap().to_string();
        let err = fetch_discovery_at(&http, &well_known, &issuer_host, "https://the-configured-issuer.example.com", &[doc_issuer.trim_start_matches("https://").to_string()])
            .await
            .unwrap_err();
        assert_eq!(err, IdentityError::DiscoveryFailed);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_jwks_uri_on_unpinned_host() {
        let issuer = "https://good-idp.example.com";
        let body = doc_json(issuer, "https://attacker.example.com/jwks");
        let base = testutil::spawn(vec![testutil::json_response(200, &body)]).await;
        let http = HardenedClient::build().unwrap();
        let well_known = format!("{base}/.well-known/openid-configuration");
        let issuer_host = url::Url::parse(&base).unwrap().host_str().unwrap().to_string();
        let err = fetch_discovery_at(&http, &well_known, &issuer_host, issuer, &[]).await.unwrap_err();
        assert_eq!(err, IdentityError::JwksHostMismatch);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_a_redirect_instead_of_following_it() {
        let base = testutil::spawn(vec![testutil::redirect_response("https://attacker.example.com/openid-configuration")]).await;
        let http = HardenedClient::build().unwrap();
        let well_known = format!("{base}/.well-known/openid-configuration");
        let issuer_host = url::Url::parse(&base).unwrap().host_str().unwrap().to_string();
        let err = fetch_discovery_at(&http, &well_known, &issuer_host, "https://good-idp.example.com", &[]).await.unwrap_err();
        assert_eq!(err, IdentityError::DiscoveryFailed);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_oversized_document() {
        let huge = "x".repeat(crate::http::MAX_RESPONSE_BYTES + 1024);
        let body = format!("{{\"issuer\":\"https://a\",\"jwks_uri\":\"https://a/jwks\",\"padding\":\"{huge}\"}}");
        let base = testutil::spawn(vec![testutil::json_response(200, &body)]).await;
        let http = HardenedClient::build().unwrap();
        let well_known = format!("{base}/.well-known/openid-configuration");
        let issuer_host = url::Url::parse(&base).unwrap().host_str().unwrap().to_string();
        let err = fetch_discovery_at(&http, &well_known, &issuer_host, "https://a", &[]).await.unwrap_err();
        assert_eq!(err, IdentityError::ResponseTooLarge);
    }

    #[tokio::test]
    async fn fetch_discovery_rejects_http_scheme_issuer() {
        let err = fetch_discovery("http://insecure.example.com", &[]).await.unwrap_err();
        assert_eq!(err, IdentityError::DiscoveryFailed);
    }

    #[test]
    fn validate_authorization_endpoint_rejects_non_https_off_host_endpoint() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            authorization_endpoint: Some("http://attacker.tld/auth".into()),
            token_endpoint: Some("https://idp.example.com/token".into()),
            registration_endpoint: None,
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
        };
        let err = doc.validate_authorization_endpoint("https://idp.example.com", &[]).unwrap_err();
        assert_eq!(err, IdentityError::InvalidEndpointUrl);
    }

    /// Distinct from the non-https case above: an `https://` endpoint on a
    /// DIFFERENT host than the configured issuer must still be rejected —
    /// this is the actual host-pin check (`host_is_pinned`), not just the
    /// scheme check. Using `https://` here means the only thing that can
    /// reject this URL is host pinning; if `host_is_pinned` regresses to
    /// "always true", this is the test that catches it.
    #[test]
    fn validate_authorization_endpoint_rejects_https_but_off_host_endpoint() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            authorization_endpoint: Some("https://attacker.tld/auth".into()),
            token_endpoint: Some("https://idp.example.com/token".into()),
            registration_endpoint: None,
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
        };
        let err = doc.validate_authorization_endpoint("https://idp.example.com", &[]).unwrap_err();
        assert_eq!(err, IdentityError::InvalidEndpointUrl);
    }

    #[test]
    fn validate_authorization_endpoint_rejects_unparseable_url_instead_of_panicking() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            authorization_endpoint: Some("not a url".into()),
            token_endpoint: Some("https://idp.example.com/token".into()),
            registration_endpoint: None,
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
        };
        let err = doc.validate_authorization_endpoint("https://idp.example.com", &[]).unwrap_err();
        assert_eq!(err, IdentityError::InvalidEndpointUrl);
    }

    #[test]
    fn validate_authorization_endpoint_accepts_pinned_https_endpoint() {
        let doc = DiscoveryDocument {
            issuer: "https://idp.example.com".into(),
            jwks_uri: "https://idp.example.com/jwks".into(),
            authorization_endpoint: Some("https://idp.example.com/authorize".into()),
            token_endpoint: Some("https://idp.example.com/token".into()),
            registration_endpoint: None,
            grant_types_supported: vec![],
            token_endpoint_auth_methods_supported: vec![],
        };
        assert!(doc.validate_authorization_endpoint("https://idp.example.com", &[]).is_ok());
        assert!(doc.validate_token_endpoint("https://idp.example.com", &[]).is_ok());
    }
}
