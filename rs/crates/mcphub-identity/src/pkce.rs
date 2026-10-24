//! OAuth 2.1 PKCE browser flow (authorization code + PKCE S256 only, no
//! implicit) for the portal login, plus RFC 7591 dynamic client
//! registration since MCP clients need it. `state` and `nonce` are random,
//! opaque, single-use, and checked on callback; `redirect_uri` is checked
//! against a strict per-IDP allowlist — never accepted as freeform input.

use crate::error::{IdentityError, Result};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use url::Url;

const CODE_VERIFIER_BYTES: usize = 32; // 256 bits, well above RFC 7636's 43-char minimum once base64url-encoded
const STATE_NONCE_BYTES: usize = 32;
const FLOW_TTL: Duration = Duration::from_secs(600);

/// Upper bound on concurrently in-flight login attempts. Unauthenticated
/// hits on `/login` (each allocates a `PendingFlow`) must never be able to
/// grow this store without bound — that is an unauthenticated OOM /
/// fail-closed-outage vector, not just a memory-hygiene nit.
const MAX_PENDING_FLOWS: usize = 2_000;

/// Parse `raw` as an authorization/token endpoint URL, rejecting anything
/// that isn't a well-formed `https://` URL. This is the parse-boundary
/// check for URLs that ultimately come from a remote-controlled discovery
/// document: `authorization_endpoint` is where the browser gets 302'd with
/// `state`/`nonce`/`code_challenge` attached, and an unvalidated string
/// here was previously `Url::parse(..).expect(..)`'d — a malformed value
/// panicked the login path, and a well-formed-but-attacker-hosted value
/// silently became an open redirect carrying live PKCE flow secrets.
/// Callers should prefer passing an endpoint already validated (and
/// host-pinned to the issuer) by `discovery::DiscoveryDocument::validate_*`;
/// this is enforced again here regardless, since `start_login` must never
/// be the thing that turns a bad string into a panic no matter what a
/// caller upstream did or didn't check.
fn parse_endpoint_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| IdentityError::InvalidEndpointUrl)?;
    if url.scheme() != "https" {
        return Err(IdentityError::InvalidEndpointUrl);
    }
    Ok(url)
}

#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String, // S256 only — plain is not supported
}

pub fn generate_pkce_pair() -> PkcePair {
    let mut buf = [0u8; CODE_VERIFIER_BYTES];
    rand::thread_rng().fill_bytes(&mut buf);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
    PkcePair { verifier, challenge }
}

fn random_opaque(len: usize) -> String {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// A started, in-flight login attempt awaiting the IDP callback. Single-use:
/// `PendingFlowStore::consume` removes it, so replaying the same `state`
/// twice fails.
#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub state: String,
    pub nonce: String,
    pub pkce: PkcePair,
    pub redirect_uri: String,
    started_at: Instant,
}

/// Authorization request the portal redirects the browser to. Always
/// `response_type=code`, always `code_challenge_method=S256` — there is no
/// implicit-flow or plain-PKCE code path in this module at all, so it can't
/// be accidentally selected.
#[derive(Debug)]
pub struct AuthorizationRequest {
    pub authorization_endpoint: Url,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

impl AuthorizationRequest {
    /// Infallible by construction: `authorization_endpoint` was already
    /// validated (parsed + scheme-checked) in `start_login`, so building
    /// the redirect URL here can never panic on attacker-controlled input.
    pub fn to_url(&self) -> String {
        let mut url = self.authorization_endpoint.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", &self.scope)
            .append_pair("state", &self.state)
            .append_pair("nonce", &self.nonce)
            .append_pair("code_challenge", &self.code_challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }
}

/// Start a login: validate `authorization_endpoint` at the parse boundary
/// (must be a well-formed `https://` URL — see `parse_endpoint_url`),
/// allocate state/nonce/PKCE, validate `redirect_uri` against the strict
/// allowlist, and return both the browser-bound request and the
/// server-side pending-flow record to stash (session/redis) until
/// callback. Returns `Err` instead of panicking on a malformed
/// `authorization_endpoint` — callers should also prefer passing an
/// endpoint already host-pinned via
/// `discovery::DiscoveryDocument::validate_authorization_endpoint`.
pub fn start_login(
    authorization_endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    redirect_uri_allowlist: &[String],
    scope: &str,
) -> Result<(AuthorizationRequest, PendingFlow)> {
    let authorization_endpoint = parse_endpoint_url(authorization_endpoint)?;

    if !redirect_uri_allowlist.iter().any(|allowed| allowed == redirect_uri) {
        return Err(IdentityError::RedirectUriNotAllowed);
    }

    let pkce = generate_pkce_pair();
    let state = random_opaque(STATE_NONCE_BYTES);
    let nonce = random_opaque(STATE_NONCE_BYTES);

    let req = AuthorizationRequest {
        authorization_endpoint,
        client_id: client_id.to_string(),
        redirect_uri: redirect_uri.to_string(),
        scope: scope.to_string(),
        state: state.clone(),
        nonce: nonce.clone(),
        code_challenge: pkce.challenge.clone(),
    };
    let pending =
        PendingFlow { state, nonce, pkce, redirect_uri: redirect_uri.to_string(), started_at: Instant::now() };
    Ok((req, pending))
}

/// Validate a callback against its `PendingFlow`. `returned_state` and
/// `returned_nonce` (the latter re-derived from the ID token once decoded)
/// must both match exactly, the flow must not have exceeded `FLOW_TTL`, and
/// `callback_redirect_uri` (the `redirect_uri` presented at callback time)
/// must equal the one the flow was started with — a `PendingFlow` recorded
/// its `redirect_uri` but nothing previously compared it against anything,
/// so a callback could complete a flow started for a different redirect
/// target than the one actually used.
pub fn validate_callback(
    pending: &PendingFlow,
    returned_state: &str,
    id_token_nonce: &str,
    callback_redirect_uri: &str,
) -> Result<()> {
    if pending.started_at.elapsed() > FLOW_TTL {
        return Err(IdentityError::PkceStateMismatch);
    }
    // Constant-time-ish comparison isn't load-bearing here (state/nonce are
    // single-use, high-entropy, and not secrets an attacker can brute force
    // via timing within one flow's TTL), but exact match is mandatory.
    if pending.state != returned_state
        || pending.nonce != id_token_nonce
        || pending.redirect_uri != callback_redirect_uri
    {
        return Err(IdentityError::PkceStateMismatch);
    }
    Ok(())
}

/// In-memory pending-flow store keyed by `state`. Production wiring backs
/// this with Redis (short TTL) via `mcphub-store`; this default impl exists
/// so the crate is independently testable and usable standalone.
///
/// Bounded: `insert` first evicts anything past `FLOW_TTL` (a lazy sweep,
/// no background task needed) and then refuses to grow past
/// `MAX_PENDING_FLOWS`. Without this, unauthenticated hits on `/login`
/// (each one allocates a `PendingFlow` and nothing ever required a
/// completed callback to remove it) would grow this map without bound —
/// an unauthenticated OOM that becomes a fail-closed outage.
#[derive(Default)]
pub struct PendingFlowStore {
    flows: std::collections::HashMap<String, PendingFlow>,
}

impl PendingFlowStore {
    pub fn insert(&mut self, flow: PendingFlow) -> Result<()> {
        self.evict_expired();
        if self.flows.len() >= MAX_PENDING_FLOWS {
            return Err(IdentityError::Internal("pending login flow store is at capacity".into()));
        }
        self.flows.insert(flow.state.clone(), flow);
        Ok(())
    }

    fn evict_expired(&mut self) {
        self.flows.retain(|_, f| f.started_at.elapsed() <= FLOW_TTL);
    }

    /// Single-use: removes the flow so replay of the same `state` fails.
    pub fn consume(&mut self, state: &str) -> Result<PendingFlow> {
        self.flows.remove(state).ok_or(IdentityError::PkceStateMismatch)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }
}

// --- Authorization code -> token redemption ----------------------------

fn default_expires_in() -> u64 {
    300
}

/// The token endpoint's response to a redeemed authorization code. `id_token`
/// is the only field the portal login flow actually needs — it's what gets
/// run through `mcphub_identity::resolve_identity` (the crate's one real
/// validation path) to produce a trusted `Identity`. `access_token` is kept
/// only in case a caller wants it for a follow-on API call; the portal
/// itself never forwards it anywhere.
#[derive(Debug, serde::Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default = "default_expires_in")]
    pub expires_in: u64,
}

/// Redeem an authorization code for tokens (RFC 6749 §4.1.3 + PKCE §4.6 —
/// `code_verifier` proves possession of the same client that started the
/// flow, without a client secret since this is a public client). Builds its
/// own [`crate::http::HardenedClient`] internally, same discipline as
/// `register_client`: no bare `reqwest::Client`, no redirect-following, a
/// capped response body. `token_endpoint` must already be host-pinned —
/// callers should pass the `Url` returned by
/// `discovery::DiscoveryDocument::validate_token_endpoint`, never a raw
/// string.
pub async fn exchange_authorization_code(
    token_endpoint: &Url,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse> {
    let http = crate::http::HardenedClient::build()?;
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("code_verifier", code_verifier),
    ];
    let resp = http
        .post(token_endpoint.as_str())
        .form(&params)
        .send()
        .await
        .map_err(|_| IdentityError::ExchangeFailed)?;
    if !resp.status().is_success() {
        return Err(IdentityError::ExchangeFailed);
    }
    crate::http::read_json_capped(resp, IdentityError::ExchangeFailed).await
}

// --- RFC 7591 dynamic client registration -----------------------------

#[derive(Debug, Clone, serde::Serialize)]
pub struct DynamicClientRegistrationRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub token_endpoint_auth_method: String,
}

impl DynamicClientRegistrationRequest {
    pub fn for_mcp_client(client_name: &str, redirect_uris: Vec<String>) -> Self {
        Self {
            client_name: client_name.to_string(),
            redirect_uris,
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(), // public client + PKCE
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DynamicClientRegistrationResponse {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
}

/// Builds its own [`HardenedClient`] internally — never accepts a
/// caller-supplied `reqwest::Client` (see `http.rs`). `registration_endpoint`
/// is validated at the parse boundary the same way `start_login` validates
/// `authorization_endpoint`.
pub async fn register_client(
    registration_endpoint: &str,
    req: &DynamicClientRegistrationRequest,
) -> Result<DynamicClientRegistrationResponse> {
    let endpoint = parse_endpoint_url(registration_endpoint)?;

    // Redirect URIs offered for dynamic registration must themselves be
    // https (or a loopback dev exception), never bare — this mirrors the
    // strict allowlist check in start_login and stops registration being
    // used to smuggle an open-redirect-shaped client in.
    let all_valid = req.redirect_uris.iter().all(|u| is_acceptable_redirect_uri(u));
    if !all_valid {
        return Err(IdentityError::RedirectUriNotAllowed);
    }

    let http = crate::http::HardenedClient::build()?;
    let resp = http
        .post(endpoint.as_str())
        .json(req)
        .send()
        .await
        .map_err(|_| IdentityError::DependencyUnavailable("dcr"))?;
    if !resp.status().is_success() {
        return Err(IdentityError::RegistrationFailed);
    }
    crate::http::read_json_capped(resp, IdentityError::RegistrationFailed).await
}

fn is_acceptable_redirect_uri(uri: &str) -> bool {
    match url::Url::parse(uri) {
        Ok(u) => u.scheme() == "https" || (u.scheme() == "http" && matches!(u.host_str(), Some("127.0.0.1") | Some("localhost"))),
        Err(_) => false,
    }
}

/// Every allowlisted redirect_uri must itself already be one of these
/// acceptable forms — checked once at `IdpConfig` load time, not per-request,
/// but exposed here so config validation and the DCR path share one rule.
pub fn validate_redirect_uri_allowlist(allowlist: &[String]) -> Result<()> {
    let unique: HashSet<&String> = allowlist.iter().collect();
    if unique.len() != allowlist.len() {
        return Err(IdentityError::Internal("duplicate entries in redirect_uri_allowlist".into()));
    }
    if allowlist.iter().any(|u| !is_acceptable_redirect_uri(u)) {
        return Err(IdentityError::RedirectUriNotAllowed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_sha256_of_verifier_not_plain() {
        let pair = generate_pkce_pair();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(pair.verifier.as_bytes()));
        assert_eq!(pair.challenge, expected);
        assert_ne!(pair.challenge, pair.verifier);
    }

    #[test]
    fn start_login_rejects_redirect_uri_outside_allowlist() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let result = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://attacker.example.com/callback",
            &allowlist,
            "openid",
        );
        assert_eq!(result.unwrap_err(), IdentityError::RedirectUriNotAllowed);
    }

    #[test]
    fn start_login_accepts_allowlisted_redirect_uri_and_forces_s256() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        assert!(req.to_url().contains("code_challenge_method=S256"));
        assert!(req.to_url().contains("response_type=code"));
        assert_eq!(pending.state, req.state);
    }

    #[test]
    fn callback_state_mismatch_is_rejected() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (_req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        let result = validate_callback(&pending, "attacker-supplied-state", &pending.nonce, &pending.redirect_uri);
        assert_eq!(result.unwrap_err(), IdentityError::PkceStateMismatch);
    }

    #[test]
    fn callback_nonce_mismatch_is_rejected() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (_req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        let result = validate_callback(&pending, &pending.state, "wrong-nonce", &pending.redirect_uri);
        assert_eq!(result.unwrap_err(), IdentityError::PkceStateMismatch);
    }

    #[test]
    fn callback_redirect_uri_mismatch_is_rejected() {
        // `redirect_uri` was recorded on the pending flow but nothing
        // previously compared it against the callback's actual
        // `redirect_uri` — this is the defect 8 fix.
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (_req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        let result = validate_callback(&pending, &pending.state, &pending.nonce, "https://a-different-callback.example.com");
        assert_eq!(result.unwrap_err(), IdentityError::PkceStateMismatch);
    }

    #[test]
    fn valid_callback_passes() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (_req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        assert!(validate_callback(&pending, &pending.state, &pending.nonce, &pending.redirect_uri).is_ok());
    }

    #[test]
    fn start_login_rejects_malformed_authorization_endpoint_instead_of_panicking() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let result = start_login("not a url", "client-1", "https://portal.example.com/callback", &allowlist, "openid");
        assert_eq!(result.unwrap_err(), IdentityError::InvalidEndpointUrl);
    }

    #[test]
    fn start_login_rejects_non_https_authorization_endpoint() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let result = start_login(
            "http://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        );
        assert_eq!(result.unwrap_err(), IdentityError::InvalidEndpointUrl);
    }

    #[test]
    fn pending_flow_is_single_use() {
        let allowlist = vec!["https://portal.example.com/callback".to_string()];
        let (_req, pending) = start_login(
            "https://idp.example.com/authorize",
            "client-1",
            "https://portal.example.com/callback",
            &allowlist,
            "openid",
        )
        .unwrap();
        let state = pending.state.clone();
        let mut store = PendingFlowStore::default();
        store.insert(pending).unwrap();
        assert!(store.consume(&state).is_ok());
        assert!(store.consume(&state).is_err(), "replaying the same state must fail");
    }

    #[test]
    fn pending_flow_store_refuses_to_grow_past_its_cap() {
        let mut store = PendingFlowStore::default();
        for i in 0..MAX_PENDING_FLOWS {
            let flow = PendingFlow {
                state: format!("state-{i}"),
                nonce: "n".into(),
                pkce: generate_pkce_pair(),
                redirect_uri: "https://portal.example.com/callback".into(),
                started_at: Instant::now(),
            };
            store.insert(flow).unwrap();
        }
        assert_eq!(store.len(), MAX_PENDING_FLOWS);

        let one_more = PendingFlow {
            state: "one-more".into(),
            nonce: "n".into(),
            pkce: generate_pkce_pair(),
            redirect_uri: "https://portal.example.com/callback".into(),
            started_at: Instant::now(),
        };
        assert!(store.insert(one_more).is_err(), "store must refuse to grow past MAX_PENDING_FLOWS");
    }

    #[test]
    fn dcr_rejects_non_https_non_loopback_redirect_uri() {
        let req = DynamicClientRegistrationRequest::for_mcp_client(
            "evil-client",
            vec!["http://attacker.example.com/callback".to_string()],
        );
        assert!(validate_redirect_uri_allowlist(&req.redirect_uris).is_err());
    }

    #[test]
    fn dcr_accepts_https_and_loopback() {
        let uris = vec!["https://portal.example.com/callback".to_string(), "http://127.0.0.1:8901/callback".to_string()];
        assert!(validate_redirect_uri_allowlist(&uris).is_ok());
    }
}
