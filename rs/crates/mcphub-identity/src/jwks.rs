//! JWKS fetch + rotation + caching. Backed by `moka::future::Cache` using a
//! per-entry `moka::Expiry` so the TTL computed from the HTTP
//! `Cache-Control: max-age` header (clamped to `[MIN_TTL, MAX_TTL]`) is
//! actually the cache's expiry, not merely computed and discarded — a
//! fetched key must stop being trusted once its TTL elapses, otherwise key
//! revocation/rotation never takes effect for the life of the process.
//! `try_get_with` gives single-flight fetch-on-miss for free (concurrent
//! misses for the same issuer coalesce into one HTTP request).

use crate::error::{IdentityError, Result};
use crate::http::{assert_final_url_host_matches, read_json_capped, HardenedClient};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN_TTL: Duration = Duration::from_secs(60);
const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// A hostile or merely very large JWKS document must not be allowed to grow
/// the in-memory key map without bound.
const MAX_JWKS_KEYS: usize = 256;

#[derive(Debug, Deserialize)]
struct JwkRaw {
    kty: String,
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[serde(rename = "use")]
    #[serde(default)]
    use_: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSetRaw {
    keys: Vec<JwkRaw>,
}

/// A verified, decodable key plus the `alg` the issuer's JWKS declared for
/// it (if any) — used as a *secondary* check alongside `IdpConfig::allowed_algs`,
/// never as the sole gate (a JWKS `alg` field is advisory per RFC 7517).
#[derive(Clone)]
pub struct KeyEntry {
    pub decoding_key: DecodingKey,
    pub jwks_alg: Option<String>,
}

pub struct IssuerKeys {
    pub keys_by_kid: HashMap<String, KeyEntry>,
}

/// Cache value: the fetched keys plus the TTL they were fetched with, so a
/// `moka::Expiry` impl can read the per-entry TTL back out at insert time.
struct CachedKeys {
    keys: Arc<IssuerKeys>,
    ttl: Duration,
}

struct KeysExpiry;

impl moka::Expiry<String, Arc<CachedKeys>> for KeysExpiry {
    fn expire_after_create(&self, _key: &String, value: &Arc<CachedKeys>, _created_at: Instant) -> Option<Duration> {
        Some(value.ttl)
    }
}

pub struct JwksCache {
    cache: Cache<String, Arc<CachedKeys>>,
    http: HardenedClient,
    min_ttl: Duration,
    max_ttl: Duration,
}

impl JwksCache {
    /// Builds its own [`HardenedClient`] — this type deliberately does not
    /// accept a caller-supplied `reqwest::Client`. See `http.rs` for why.
    pub fn new() -> Result<Self> {
        Self::with_ttl_bounds(MIN_TTL, MAX_TTL)
    }

    /// Test-only: the production `[MIN_TTL, MAX_TTL]` bounds (60s..24h) make
    /// it impractical to prove natural (non-`invalidate`-forced) expiry
    /// without a genuinely slow test. This lets a test pin both bounds to
    /// the same tiny duration so a real, unforced TTL expiry is observable
    /// in milliseconds — exercising the exact `expire_after(KeysExpiry)`
    /// wiring this module exists to fix, not a substitute for it.
    #[cfg(test)]
    pub(crate) fn new_for_test(ttl: Duration) -> Result<Self> {
        Self::with_ttl_bounds(ttl, ttl)
    }

    fn with_ttl_bounds(min_ttl: Duration, max_ttl: Duration) -> Result<Self> {
        Ok(Self {
            cache: Cache::builder().max_capacity(1024).expire_after(KeysExpiry).build(),
            http: HardenedClient::build()?,
            min_ttl,
            max_ttl,
        })
    }

    /// Get keys for `issuer`'s `jwks_uri`, fetching (single-flight) on miss
    /// or after TTL expiry. `jwks_uri` must already be host-pinned by the
    /// caller (see `discovery::fetch_discovery`) — this function does not
    /// re-derive it from the token, but it does re-check the response's
    /// final URL host against `jwks_uri`'s host as defense in depth.
    pub async fn get(&self, issuer: &str, jwks_uri: &str) -> Result<Arc<IssuerKeys>> {
        let http = self.http.clone();
        let jwks_uri = jwks_uri.to_string();
        let key = issuer.to_string();
        let (min_ttl, max_ttl) = (self.min_ttl, self.max_ttl);
        // moka's try_get_with coalesces concurrent misses (single-flight).
        let cached = self
            .cache
            .try_get_with(key, async move { fetch_and_parse(&http, &jwks_uri, min_ttl, max_ttl).await })
            .await
            .map_err(|e: Arc<IdentityError>| (*e).clone())?;
        Ok(cached.keys.clone())
    }

    /// Force-evict cached keys for `issuer` — called when a `kid` lookup
    /// misses, in case the upstream just rotated ahead of our TTL. Bounded:
    /// callers should retry the fetch exactly once, never loop.
    pub async fn invalidate(&self, issuer: &str) {
        self.cache.invalidate(issuer).await;
    }
}

async fn fetch_and_parse(http: &HardenedClient, jwks_uri: &str, min_ttl: Duration, max_ttl: Duration) -> Result<Arc<CachedKeys>> {
    let expected_host = url::Url::parse(jwks_uri).ok().and_then(|u| u.host_str().map(str::to_string));

    let resp = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|_| IdentityError::DependencyUnavailable("jwks"))?;
    if !resp.status().is_success() {
        return Err(IdentityError::JwksUnavailable);
    }
    if let Some(expected_host) = &expected_host {
        assert_final_url_host_matches(&resp, expected_host)?;
    }
    let ttl = ttl_from_headers(resp.headers(), min_ttl, max_ttl);
    let raw: JwkSetRaw = read_json_capped(resp, IdentityError::JwksUnavailable).await?;

    let mut keys_by_kid = HashMap::new();
    for jwk in raw.keys {
        if keys_by_kid.len() >= MAX_JWKS_KEYS {
            break;
        }
        if jwk.kty != "RSA" {
            // Only RSA is wired for v1; EC support is a straightforward
            // follow-up (DecodingKey::from_ec_components) but out of scope
            // for this pass — never silently accept an unsupported kty as a
            // usable key.
            continue;
        }
        let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else { continue };
        if let Some(u) = &jwk.use_ {
            if u != "sig" {
                continue;
            }
        }
        let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) else { continue };
        let kid = jwk.kid.clone().unwrap_or_default();
        if kid.is_empty() {
            continue;
        }
        keys_by_kid.insert(kid, KeyEntry { decoding_key, jwks_alg: jwk.alg.clone() });
    }

    if keys_by_kid.is_empty() {
        return Err(IdentityError::JwksUnavailable);
    }

    Ok(Arc::new(CachedKeys { keys: Arc::new(IssuerKeys { keys_by_kid }), ttl }))
}

fn ttl_from_headers(headers: &reqwest::header::HeaderMap, min_ttl: Duration, max_ttl: Duration) -> Duration {
    let max_age = headers
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_max_age);
    match max_age {
        Some(secs) => Duration::from_secs(secs).clamp(min_ttl, max_ttl),
        None => DEFAULT_TTL.clamp(min_ttl, max_ttl),
    }
}

fn parse_max_age(cache_control: &str) -> Option<u64> {
    cache_control.split(',').find_map(|part| {
        let part = part.trim();
        part.strip_prefix("max-age=").and_then(|v| v.parse::<u64>().ok())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn max_age_parsed_and_clamped_low() {
        assert_eq!(parse_max_age("max-age=5, must-revalidate"), Some(5));
        assert_eq!(Duration::from_secs(5).clamp(MIN_TTL, MAX_TTL), MIN_TTL);
    }

    #[test]
    fn max_age_clamped_high() {
        assert_eq!(Duration::from_secs(999_999).clamp(MIN_TTL, MAX_TTL), MAX_TTL);
    }

    #[test]
    fn missing_cache_control_uses_default() {
        assert_eq!(parse_max_age("no-store"), None);
    }

    fn jwks_body() -> String {
        serde_json::json!({
            "keys": [{
                "kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
                "n": valid_n_b64(), "e": "AQAB"
            }]
        })
        .to_string()
    }

    /// A syntactically valid (properly-padded-when-decoded) base64url RSA
    /// modulus fragment — big enough to round-trip through
    /// `DecodingKey::from_rsa_components` without erroring on malformed
    /// base64. Its numeric value is not a real RSA modulus and these tests
    /// never use it to verify a signature, only to exercise cache
    /// fetch/expiry/rotation plumbing.
    fn valid_n_b64() -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x42u8; 32])
    }

    /// The core fix for defect 1: an entry whose TTL has genuinely elapsed
    /// must be refetched, not served from cache forever. Production bounds
    /// (`[MIN_TTL, MAX_TTL]` = 60s..24h) make that impractical to observe
    /// directly in a fast test, so this uses `JwksCache::new_for_test` to
    /// pin BOTH bounds to a few milliseconds — the exact same
    /// `expire_after(KeysExpiry)` wiring production uses, just with a
    /// test-friendly TTL. Critically, this does NOT call `invalidate()`:
    /// the second `.get()` must see the rotated key purely because the
    /// entry's TTL elapsed on its own, which is the actual thing that was
    /// broken (`invalidate()` already had callers-of-convenience working
    /// even before this fix; natural expiry did not, since the computed TTL
    /// was discarded and the cache had no `time_to_live`/`expire_after` at
    /// all).
    ///
    /// (moka's own `Clock` mock is `pub(crate)`-only inside the moka crate
    /// and not reachable from a downstream crate, so a short bounded real
    /// sleep — capped at ~120ms total here — is the only way to observe
    /// expiry through moka's public API.)
    #[tokio::test]
    async fn cached_entry_actually_expires_after_its_ttl_without_being_invalidated() {
        let old_kid_body = jwks_body();
        let rotated_body = serde_json::json!({
            "keys": [{ "kty": "RSA", "kid": "k2-rotated", "alg": "RS256", "use": "sig", "n": valid_n_b64(), "e": "AQAB" }]
        })
        .to_string();

        let base = testutil::spawn(vec![
            testutil::json_response(200, &old_kid_body),
            testutil::json_response(200, &rotated_body),
        ])
        .await;
        let jwks_uri = format!("{base}/jwks");

        let cache = JwksCache::new_for_test(Duration::from_millis(30)).unwrap();
        let keys1 = cache.get("issuer-1", &jwks_uri).await.unwrap();
        assert!(keys1.keys_by_kid.contains_key("k1"));

        // No `invalidate()` call here — only real elapsed time.
        tokio::time::sleep(Duration::from_millis(120)).await;

        let keys2 = cache.get("issuer-1", &jwks_uri).await.unwrap();
        assert!(
            keys2.keys_by_kid.contains_key("k2-rotated"),
            "the entry must have expired on its own TTL and been refetched — got the same stale keys instead"
        );
        assert!(!keys2.keys_by_kid.contains_key("k1"), "old kid must no longer verify once its cache entry naturally expired and rotated away");
    }

    /// `invalidate()` is a separate, always-worked mechanism (force-evict on
    /// an `UnknownKid`, retried once) — kept as its own test so a
    /// regression there is distinguishable from a regression in natural TTL
    /// expiry (the test above).
    #[tokio::test]
    async fn invalidate_forces_a_refetch_regardless_of_remaining_ttl() {
        let old_kid_body = jwks_body();
        let rotated_body = serde_json::json!({
            "keys": [{ "kty": "RSA", "kid": "k2-rotated", "alg": "RS256", "use": "sig", "n": valid_n_b64(), "e": "AQAB" }]
        })
        .to_string();

        let base = testutil::spawn(vec![
            testutil::json_response_with_headers(200, &[("Cache-Control", "max-age=60")], &old_kid_body),
            testutil::json_response_with_headers(200, &[("Cache-Control", "max-age=60")], &rotated_body),
        ])
        .await;
        let jwks_uri = format!("{base}/jwks");

        let cache = JwksCache::new().unwrap();
        let keys1 = cache.get("issuer-1", &jwks_uri).await.unwrap();
        assert!(keys1.keys_by_kid.contains_key("k1"));
        assert!(!keys1.keys_by_kid.contains_key("k2-rotated"));

        cache.invalidate("issuer-1").await;
        let keys2 = cache.get("issuer-1", &jwks_uri).await.unwrap();
        assert!(keys2.keys_by_kid.contains_key("k2-rotated"), "rotated key must be visible after invalidate+refetch");
        assert!(!keys2.keys_by_kid.contains_key("k1"), "old kid must no longer verify once rotated away");
    }

    #[tokio::test]
    async fn jwks_fetch_rejects_response_from_unexpected_final_host() {
        // Since HardenedClient never follows redirects, a redirect response
        // is simply not a success status and is rejected outright — this
        // proves that path, which is the practical enforcement of "never
        // trust a response that didn't come from the pinned host".
        let base = testutil::spawn(vec![testutil::redirect_response("https://attacker.example.com/keys")]).await;
        let jwks_uri = format!("{base}/jwks");
        let cache = JwksCache::new().unwrap();
        let err = cache.get("issuer-1", &jwks_uri).await.err().unwrap();
        assert_eq!(err, IdentityError::JwksUnavailable);
    }

    #[tokio::test]
    async fn oversized_jwks_response_is_rejected() {
        let huge = "x".repeat(crate::http::MAX_RESPONSE_BYTES + 1024);
        let body = format!("{{\"keys\":[],\"padding\":\"{huge}\"}}");
        let base = testutil::spawn(vec![testutil::json_response(200, &body)]).await;
        let jwks_uri = format!("{base}/jwks");
        let cache = JwksCache::new().unwrap();
        let err = cache.get("issuer-1", &jwks_uri).await.err().unwrap();
        assert_eq!(err, IdentityError::ResponseTooLarge);
    }

    /// The test above is satisfied by the `Content-Length` precheck alone
    /// (the mock server reports its size honestly). A hostile endpoint can
    /// omit or lie about `Content-Length` — this uses a chunked response
    /// with NO `Content-Length` header at all, so the ONLY thing that can
    /// catch the oversized body is the cap enforced while actually
    /// streaming (`read_json_capped_with_limit`'s per-chunk check).
    #[tokio::test]
    async fn oversized_jwks_response_with_no_content_length_header_is_still_rejected() {
        let huge = "x".repeat(crate::http::MAX_RESPONSE_BYTES + 1024);
        let body = format!("{{\"keys\":[],\"padding\":\"{huge}\"}}");
        let base = testutil::spawn(vec![testutil::chunked_response(200, &body)]).await;
        let jwks_uri = format!("{base}/jwks");
        let cache = JwksCache::new().unwrap();
        let err = cache.get("issuer-1", &jwks_uri).await.err().unwrap();
        assert_eq!(err, IdentityError::ResponseTooLarge);
    }
}
