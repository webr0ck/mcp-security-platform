//! RFC 8693 token exchange for `shared_exchange` mode: the caller's platform
//! token is exchanged for a downstream token scoped to a specific MCP
//! server. Cached per `(sub, issuer, server, audience, scopes)` — the
//! exchange *target* is part of the key, not just the identity, so
//! narrowing a server's permitted scopes can never keep serving a
//! previously-minted broader-scoped token out of the cache — with a TTL
//! strictly below the downstream token's `exp`, using `moka`'s single-flight
//! `try_get_with` so concurrent calls for the same key coalesce into one
//! exchange request instead of stampeding the IDP (a naive get-then-insert,
//! which this module used to do, lets N concurrent misses on the same key
//! each independently call the IDP). The cache key embeds `sub`, so a cache
//! hit can never be served across identities.

use crate::error::{IdentityError, Result};
use base64::Engine;
use mcphub_types::{IssuerId, ServerId, Secret};
use moka::future::Cache;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const REQUESTED_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// TTL is exp-derived but never allowed within this margin of the actual
/// expiry, so a cached token is never handed out with less than this much
/// remaining validity.
const MIN_SAFETY_MARGIN: Duration = Duration::from_secs(15);

/// Hard upper bound on how long an exchanged token is ever cached,
/// regardless of what `expires_in` an IDP response claims. Without this, a
/// hostile or merely misconfigured IDP returning e.g. `expires_in:
/// u64::MAX` would cache a live downstream bearer token for the effective
/// lifetime of the process — this is the real security boundary; the IDP's
/// claimed `expires_in` is untrusted input, not a fact.
const MAX_EXCHANGE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExchangeKey {
    sub: String,
    issuer: String,
    server: ServerId,
    audience: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ExchangedToken {
    pub access_token: Secret<String>,
    pub expires_in: u64,
    /// Cache lifetime: derived from the downstream token's real `exp` when
    /// parseable, otherwise from the IDP-claimed `expires_in` — either way
    /// clamped to `[1s, MAX_EXCHANGE_TTL]` and reduced by
    /// [`MIN_SAFETY_MARGIN`]. Always strictly less than the downstream
    /// token's actual `exp` when that claim is honest, and never more than
    /// `MAX_EXCHANGE_TTL` even when it is not.
    pub ttl: Duration,
}

struct TtlExpiry;

impl moka::Expiry<ExchangeKey, Arc<ExchangedToken>> for TtlExpiry {
    fn expire_after_create(
        &self,
        _key: &ExchangeKey,
        value: &Arc<ExchangedToken>,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// What the caller is asking to exchange *into* — the downstream audience
/// and scopes this server's registry row permits. `resource`/`audience`
/// bound the exchange so a caller can never walk away with a token scoped
/// beyond what this server's row allows (ARCHITECTURE.md: "must not be
/// usable to escalate audience/scope beyond what the server row permits").
#[derive(Debug)]
pub struct ExchangeTarget {
    pub audience: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenExchangeResponse {
    access_token: String,
    #[serde(default = "default_expires_in")]
    expires_in: u64,
    #[serde(default)]
    issued_token_type: Option<String>,
    /// RFC 8693 §2.2.1: the AS MAY return `scope` to indicate the actual
    /// (possibly narrowed) scope granted. When present, every granted scope
    /// must be a subset of what was requested — an IDP handing back MORE
    /// than was asked for is a scope-escalation signal, not something to
    /// silently accept and cache.
    #[serde(default)]
    scope: Option<String>,
}

fn default_expires_in() -> u64 {
    300
}

#[async_trait::async_trait]
pub trait ExchangeBackend: Send + Sync {
    /// Perform the actual RFC 8693 exchange call against the IDP's token
    /// endpoint. Implemented against `reqwest` in production; swapped for a
    /// stub in tests.
    async fn exchange(
        &self,
        subject_token: &str,
        target: &ExchangeTarget,
    ) -> Result<TokenExchangeResponse>;
}

pub struct HttpExchangeBackend {
    http: crate::http::HardenedClient,
    pub token_endpoint: String,
    pub client_id: String,
}

impl HttpExchangeBackend {
    /// Builds its own [`crate::http::HardenedClient`] internally — this
    /// type never accepts a caller-supplied `reqwest::Client` (see
    /// `http.rs`: no redirect-following, bounded timeouts, capped response
    /// bodies, all non-negotiable for a call carrying a live bearer token).
    pub fn new(token_endpoint: String, client_id: String) -> Result<Self> {
        Ok(Self { http: crate::http::HardenedClient::build()?, token_endpoint, client_id })
    }
}

#[async_trait::async_trait]
impl ExchangeBackend for HttpExchangeBackend {
    async fn exchange(&self, subject_token: &str, target: &ExchangeTarget) -> Result<TokenExchangeResponse> {
        let params = [
            ("grant_type", GRANT_TYPE),
            ("subject_token", subject_token),
            ("subject_token_type", SUBJECT_TOKEN_TYPE),
            ("requested_token_type", REQUESTED_TOKEN_TYPE),
            ("audience", target.audience.as_str()),
            ("scope", &target.scopes.join(" ")),
            ("client_id", self.client_id.as_str()),
        ];
        let resp = self
            .http
            .post(&self.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|_| IdentityError::DependencyUnavailable("token_exchange"))?;
        if !resp.status().is_success() {
            return Err(IdentityError::ExchangeFailed);
        }
        crate::http::read_json_capped(resp, IdentityError::ExchangeFailed).await
    }
}

pub struct TokenExchangeCache {
    cache: Cache<ExchangeKey, Arc<ExchangedToken>>,
}

impl Default for TokenExchangeCache {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenExchangeCache {
    pub fn new() -> Self {
        Self { cache: Cache::builder().max_capacity(10_000).expire_after(TtlExpiry).build() }
    }

    /// Exchange (or return the cached exchange for) `sub`'s token, scoped to
    /// `(server, allowed_target)`. `allowed_target` is looked up by the
    /// caller from the server registry row *before* calling this — this
    /// function does not itself decide what's permitted, it only forwards
    /// `allowed_target` to the backend and caches the result. Callers must
    /// not construct `allowed_target` from caller-supplied input.
    ///
    /// Single-flight via `try_get_with`: concurrent misses on the same key
    /// coalesce into exactly one call to `backend.exchange`, instead of each
    /// concurrent caller independently hitting the IDP (at 3000-agent
    /// scale, enough concurrent misses trip the IDP's own rate limiting and
    /// fail the whole `shared_exchange` fleet closed).
    pub async fn get_or_exchange(
        &self,
        backend: &dyn ExchangeBackend,
        sub: &str,
        issuer: &IssuerId,
        server: ServerId,
        subject_token: &str,
        allowed_target: &ExchangeTarget,
    ) -> Result<Arc<ExchangedToken>> {
        let mut scopes = allowed_target.scopes.clone();
        scopes.sort();
        let key = ExchangeKey {
            sub: sub.to_string(),
            issuer: issuer.0.clone(),
            server,
            audience: allowed_target.audience.clone(),
            scopes,
        };

        self.cache
            .try_get_with(key, async move {
                let resp = backend.exchange(subject_token, allowed_target).await?;

                if let Some(t) = &resp.issued_token_type {
                    if t != REQUESTED_TOKEN_TYPE {
                        return Err(IdentityError::ExchangeFailed);
                    }
                }

                if let Some(granted) = &resp.scope {
                    let granted_set: std::collections::HashSet<&str> = granted.split_whitespace().collect();
                    let allowed_set: std::collections::HashSet<&str> =
                        allowed_target.scopes.iter().map(String::as_str).collect();
                    if !granted_set.is_subset(&allowed_set) {
                        return Err(IdentityError::ExchangeScopeEscalation);
                    }
                }

                let ttl = safe_ttl(resp.expires_in, &resp.access_token);
                Ok(Arc::new(ExchangedToken {
                    access_token: Secret::new(resp.access_token),
                    expires_in: resp.expires_in,
                    ttl,
                }))
            })
            .await
            .map_err(|e: Arc<IdentityError>| (*e).clone())
    }
}

/// TTL is derived from the downstream token's REAL `exp` claim when the
/// token is a parseable (unverified-signature-read-only — we have no key to
/// verify a foreign downstream token with, and don't need one: this is
/// purely a cache-lifetime hint, never a trust decision) JWT, falling back
/// to the IDP-claimed `expires_in` otherwise. Either way the result is
/// clamped to `[1s, MAX_EXCHANGE_TTL]` and reduced by [`MIN_SAFETY_MARGIN`]
/// — so a hostile/misconfigured IDP claiming `expires_in: u64::MAX` (or a
/// downstream token whose real `exp` implies the same) can never pin a
/// cached bearer token beyond `MAX_EXCHANGE_TTL`.
fn safe_ttl(expires_in: u64, access_token: &str) -> Duration {
    let claimed = match unverified_exp_seconds_remaining(access_token) {
        Some(remaining) if remaining > 0 => remaining as u64,
        _ => expires_in,
    };
    let clamped = claimed.min(MAX_EXCHANGE_TTL.as_secs());
    let ttl = Duration::from_secs(clamped).saturating_sub(MIN_SAFETY_MARGIN);
    if ttl.is_zero() {
        Duration::from_secs(1)
    } else {
        ttl
    }
}

/// Best-effort, unverified read of a JWT's `exp` claim, returned as seconds
/// remaining from now. Returns `None` for anything that isn't a
/// three-segment JWT with a numeric `exp` — callers must treat that as "no
/// hint available", never as an error, since the downstream token is not
/// guaranteed to be a JWT at all.
fn unverified_exp_seconds_remaining(token: &str) -> Option<i64> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    parts.next()?; // signature segment must be present (three-segment JWT shape)
    if parts.next().is_some() {
        return None; // more than 3 segments — not a JWT
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    let exp = claims.get("exp")?.as_i64()?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(exp - now)
}

impl Clone for ExchangeTarget {
    fn clone(&self) -> Self {
        Self { audience: self.audience.clone(), scopes: self.scopes.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcphub_types::Secret as SecretT;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend {
        calls: AtomicUsize,
        expires_in: u64,
    }

    #[async_trait::async_trait]
    impl ExchangeBackend for CountingBackend {
        async fn exchange(&self, _subject_token: &str, target: &ExchangeTarget) -> Result<TokenExchangeResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(TokenExchangeResponse {
                access_token: format!("downstream-token-for-{}-{}", target.audience, self.calls.load(Ordering::SeqCst)),
                expires_in: self.expires_in,
                issued_token_type: Some(REQUESTED_TOKEN_TYPE.to_string()),
                scope: None,
            })
        }
    }

    fn target() -> ExchangeTarget {
        ExchangeTarget { audience: "downstream-server".into(), scopes: vec!["read".into()] }
    }

    #[tokio::test]
    async fn caches_per_sub_and_server_avoiding_duplicate_exchange() {
        let backend = CountingBackend { calls: AtomicUsize::new(0), expires_in: 300 };
        let cache = TokenExchangeCache::new();
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());

        let t1 = cache.get_or_exchange(&backend, "alice", &issuer, server, "alice-token", &target()).await.unwrap();
        let t2 = cache.get_or_exchange(&backend, "alice", &issuer, server, "alice-token", &target()).await.unwrap();
        assert_eq!(t1.access_token, t2.access_token);
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "second call must be served from cache");
    }

    /// Defect 4(a): concurrent misses on the SAME key must coalesce into a
    /// single backend call, not stampede the IDP. Fires N concurrent
    /// requests at an empty cache and asserts the backend was called
    /// exactly once. Against the pre-fix get-then-insert implementation
    /// this is flaky-but-usually-fails (a real race); asserting exactly 1
    /// pins the single-flight behavior deterministically enough to catch a
    /// regression back to get-then-insert.
    #[tokio::test]
    async fn concurrent_misses_on_same_key_are_single_flighted_not_stampeded() {
        struct SlowBackend {
            calls: AtomicUsize,
        }
        #[async_trait::async_trait]
        impl ExchangeBackend for SlowBackend {
            async fn exchange(&self, _s: &str, _t: &ExchangeTarget) -> Result<TokenExchangeResponse> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                Ok(TokenExchangeResponse {
                    access_token: "shared-downstream-token".into(),
                    expires_in: 300,
                    issued_token_type: Some(REQUESTED_TOKEN_TYPE.to_string()),
                    scope: None,
                })
            }
        }
        let backend = Arc::new(SlowBackend { calls: AtomicUsize::new(0) });
        let cache = Arc::new(TokenExchangeCache::new());
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());

        let mut handles = Vec::new();
        for _ in 0..20 {
            let backend = backend.clone();
            let cache = cache.clone();
            let issuer = issuer.clone();
            handles.push(tokio::spawn(async move {
                cache.get_or_exchange(backend.as_ref(), "alice", &issuer, server, "alice-token", &target()).await.unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1, "20 concurrent misses on the same key must yield exactly 1 IDP call");
    }

    #[tokio::test]
    async fn never_shares_cache_across_identities() {
        let backend = CountingBackend { calls: AtomicUsize::new(0), expires_in: 300 };
        let cache = TokenExchangeCache::new();
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());

        let alice = cache.get_or_exchange(&backend, "alice", &issuer, server, "alice-token", &target()).await.unwrap();
        let bob = cache.get_or_exchange(&backend, "bob", &issuer, server, "bob-token", &target()).await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 2, "different subs must never share a cache entry");
        assert_ne!(
            alice.access_token, bob.access_token,
            "a correct backend mints a per-subject token; alice and bob must never end up with the same one"
        );
    }

    #[tokio::test]
    async fn narrowing_scopes_is_not_served_the_previously_cached_broader_token() {
        // Defect 4(c): ExchangeTarget must be part of the cache key. Exchange
        // once for a broad scope set, then again for a narrower one for the
        // SAME sub/server — this must be a cache MISS (a fresh backend call),
        // not a hit returning the broader-scoped token.
        let backend = CountingBackend { calls: AtomicUsize::new(0), expires_in: 300 };
        let cache = TokenExchangeCache::new();
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());

        let broad = ExchangeTarget { audience: "downstream-server".into(), scopes: vec!["read".into(), "write".into()] };
        let narrow = ExchangeTarget { audience: "downstream-server".into(), scopes: vec!["read".into()] };

        cache.get_or_exchange(&backend, "alice", &issuer, server, "alice-token", &broad).await.unwrap();
        cache.get_or_exchange(&backend, "alice", &issuer, server, "alice-token", &narrow).await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 2, "a narrowed scope target must never be served from the broader-scoped cache entry");
    }

    #[tokio::test]
    async fn idp_granting_more_scope_than_requested_is_rejected_as_escalation() {
        struct EscalatingBackend;
        #[async_trait::async_trait]
        impl ExchangeBackend for EscalatingBackend {
            async fn exchange(&self, _s: &str, _t: &ExchangeTarget) -> Result<TokenExchangeResponse> {
                Ok(TokenExchangeResponse {
                    access_token: "x".into(),
                    expires_in: 300,
                    issued_token_type: Some(REQUESTED_TOKEN_TYPE.to_string()),
                    scope: Some("read write admin".to_string()), // "admin" was never requested
                })
            }
        }
        let cache = TokenExchangeCache::new();
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());
        let requested = ExchangeTarget { audience: "downstream-server".into(), scopes: vec!["read".into(), "write".into()] };
        let err = cache.get_or_exchange(&EscalatingBackend, "alice", &issuer, server, "tok", &requested).await.unwrap_err();
        assert_eq!(err, IdentityError::ExchangeScopeEscalation);
    }

    #[test]
    fn cache_ttl_is_strictly_below_token_expiry() {
        let ttl = safe_ttl(300, "not-a-jwt");
        assert!(ttl < Duration::from_secs(300));
        assert_eq!(ttl, Duration::from_secs(300 - 15));
    }

    #[test]
    fn cache_ttl_floors_at_one_second_for_near_expired_tokens() {
        assert_eq!(safe_ttl(5, "not-a-jwt"), Duration::from_secs(1));
    }

    /// Defect 4(b): a hostile/misconfigured IDP claiming an enormous
    /// `expires_in` must never pin the cache entry beyond `MAX_EXCHANGE_TTL`.
    #[test]
    fn cache_ttl_is_hard_clamped_regardless_of_idp_claimed_expires_in() {
        let ttl = safe_ttl(u64::MAX, "not-a-jwt");
        assert!(ttl <= MAX_EXCHANGE_TTL, "ttl {ttl:?} must never exceed MAX_EXCHANGE_TTL {MAX_EXCHANGE_TTL:?}");
    }

    /// Defect 4(b), second half: when the downstream token IS a JWT, its
    /// real `exp` — not the IDP's `expires_in` claim — drives the TTL.
    #[test]
    fn cache_ttl_prefers_the_tokens_real_exp_over_claimed_expires_in() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{}}}"#, now + 50));
        let fake_jwt = format!("{header}.{payload}.sig");

        // expires_in CLAIMS 300s remaining, but the token's real exp says
        // only ~50s remain — the real exp must win.
        let ttl = safe_ttl(300, &fake_jwt);
        assert!(ttl <= Duration::from_secs(50), "ttl {ttl:?} must respect the token's real (shorter) exp, not the claimed expires_in");
    }

    #[tokio::test]
    async fn wrong_issued_token_type_is_rejected() {
        struct BadTypeBackend;
        #[async_trait::async_trait]
        impl ExchangeBackend for BadTypeBackend {
            async fn exchange(&self, _s: &str, _t: &ExchangeTarget) -> Result<TokenExchangeResponse> {
                Ok(TokenExchangeResponse {
                    access_token: "x".into(),
                    expires_in: 300,
                    issued_token_type: Some("urn:ietf:params:oauth:token-type:refresh_token".into()),
                    scope: None,
                })
            }
        }
        let cache = TokenExchangeCache::new();
        let issuer = IssuerId::new("platform");
        let server = ServerId::new(uuid::Uuid::nil());
        let result = cache.get_or_exchange(&BadTypeBackend, "alice", &issuer, server, "tok", &target()).await;
        assert!(result.is_err());
    }

    #[test]
    fn secret_access_token_is_redacted_in_debug() {
        let t = ExchangedToken { access_token: SecretT::new("live-downstream-bearer-token".to_string()), expires_in: 300, ttl: Duration::from_secs(60) };
        let debug = format!("{t:?}");
        assert!(!debug.contains("live-downstream-bearer-token"), "ExchangedToken's Debug must never print the raw bearer token: {debug}");
    }
}
