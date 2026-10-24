//! A single hardened `reqwest::Client` constructor for every outbound HTTP
//! call this crate makes to IDP-controlled endpoints (discovery, JWKS,
//! token exchange, dynamic client registration).
//!
//! This crate must never accept a bare caller-supplied `reqwest::Client`
//! for these calls: an externally-built client could silently follow
//! redirects (defeating `discovery::fetch_discovery`'s host pin — a
//! same-host `jwks_uri` that 302s to `https://attacker.tld/keys` would be
//! followed, parsed, and cached), have no timeout (a hung IDP wedges the
//! caller forever), or omit a connect timeout. `HardenedClient` is the only
//! way to get a client into this crate's IDP-facing functions, and every
//! such function builds/owns one internally rather than taking one as a
//! parameter.
//!
//! Also provides [`read_json_capped`], which every `resp.json()` call in
//! this crate must go through instead of calling `.json()` directly — a
//! hostile or merely misconfigured IDP endpoint must never be able to
//! stream unbounded bytes into this process's allocator.

use crate::error::{IdentityError, Result};
use futures_util::StreamExt;

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Hard cap on any single IDP-controlled response body this crate will
/// parse (discovery documents, JWKS, token exchange responses, DCR
/// responses). Generous for any legitimate document of these kinds, tiny
/// next to what an attacker could otherwise stream.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Clone)]
pub struct HardenedClient(reqwest::Client);

impl HardenedClient {
    pub fn build() -> Result<Self> {
        let builder = reqwest::Client::builder()
            // No redirect-following, ever. Every host-pin check in this
            // crate (discovery.rs's jwks_uri pin, the issuer host check)
            // is performed against the REQUESTED url; if reqwest followed
            // redirects transparently, `resp.url()` could point somewhere
            // that check never saw. Disabling redirects here means "the
            // response we parse is always the response from the URL we
            // pinned" is true by construction, not by hoping every caller
            // remembers to re-check `resp.url()`.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT);

        // Private/enterprise CA support.
        //
        // reqwest's `rustls-tls` feature trusts the bundled Mozilla root set
        // ONLY. Entra and Zitadel are publicly-issued so they work out of the
        // box, but a self-hosted Keycloak behind a corporate CA — which is how
        // most on-prem deployments actually run — would fail every discovery
        // and JWKS fetch with an opaque TLS error, and the platform would look
        // broken rather than misconfigured.
        //
        // `MCPHUB_IDP_CA_BUNDLE` points at a PEM file of ADDITIONAL roots. It
        // is additive: the public roots stay trusted, so configuring this
        // cannot silently narrow trust either. A malformed or unreadable
        // bundle is a hard startup error — never a silent fallback to
        // public-roots-only, which would turn "my CA is trusted" into a belief
        // the operator has no way to check.
        let builder = match std::env::var("MCPHUB_IDP_CA_BUNDLE") {
            Ok(path) if !path.is_empty() => {
                let pem = std::fs::read(&path).map_err(|e| {
                    IdentityError::Internal(format!("MCPHUB_IDP_CA_BUNDLE {path:?} could not be read: {e}"))
                })?;
                let mut b = builder;
                for cert in reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                    IdentityError::Internal(format!("MCPHUB_IDP_CA_BUNDLE {path:?} is not valid PEM: {e}"))
                })? {
                    b = b.add_root_certificate(cert);
                }
                b
            }
            _ => builder,
        };

        let client = builder
            .build()
            .map_err(|e| IdentityError::Internal(format!("failed to build HTTP client: {e}")))?;
        Ok(Self(client))
    }

    pub fn get(&self, url: &str) -> reqwest::RequestBuilder {
        self.0.get(url)
    }

    pub fn post(&self, url: &str) -> reqwest::RequestBuilder {
        self.0.post(url)
    }
}

/// Assert that `resp.url()` (the URL the response actually came from) has
/// the same host as `expected_host`. With `HardenedClient`'s
/// `redirect::Policy::none()` this is always true by construction — no
/// redirect is ever followed — but it is checked explicitly anyway as
/// defense in depth against any future change to client construction, and
/// so the invariant is visible at every call site rather than only implied
/// by client configuration living elsewhere.
pub fn assert_final_url_host_matches(resp: &reqwest::Response, expected_host: &str) -> Result<()> {
    match resp.url().host_str() {
        Some(h) if h == expected_host => Ok(()),
        _ => Err(IdentityError::JwksHostMismatch),
    }
}

/// Read `resp`'s body as JSON, enforcing [`MAX_RESPONSE_BYTES`] regardless
/// of what (if anything) the server claims in `Content-Length` — a hostile
/// endpoint can lie about or omit that header, so the cap is enforced while
/// streaming, not just checked up front. `on_parse_err` is the error to
/// return for a transport/parse failure (callers pass their own domain
/// error, e.g. `JwksUnavailable` vs `DiscoveryFailed` vs `ExchangeFailed`);
/// exceeding the cap always yields `ResponseTooLarge` regardless.
pub async fn read_json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    on_parse_err: IdentityError,
) -> Result<T> {
    read_json_capped_with_limit(resp, MAX_RESPONSE_BYTES, on_parse_err).await
}

pub(crate) async fn read_json_capped_with_limit<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    max_bytes: usize,
    on_parse_err: IdentityError,
) -> Result<T> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(IdentityError::ResponseTooLarge);
        }
    }

    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| on_parse_err.clone())?;
        if buf.len() + chunk.len() > max_bytes {
            return Err(IdentityError::ResponseTooLarge);
        }
        buf.extend_from_slice(&chunk);
    }

    serde_json::from_slice(&buf).map_err(|_| on_parse_err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_client_builds() {
        assert!(HardenedClient::build().is_ok());
    }
}
