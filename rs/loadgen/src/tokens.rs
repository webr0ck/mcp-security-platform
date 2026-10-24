use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// One pre-minted credential, as produced by an out-of-band script that
/// drives the real IDP's client-credentials or password grant against the
/// target platform's realm/tenant. Loadgen never mints tokens itself -- the
/// point of using real tokens per agent is to exercise JWKS lookup / cache
/// behaviour under 3000 distinct `sub` claims, which a single reused token
/// would hide entirely.
#[derive(Debug, Clone, Deserialize)]
pub struct MintedToken {
    pub sub: String,
    pub access_token: String,
    /// Unix seconds.
    pub expires_at: i64,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenFile {
    pub token_endpoint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub tokens: Vec<MintedToken>,
}

struct Inner {
    tokens: Vec<MintedToken>,
    token_endpoint: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// Round-robins pre-minted tokens across agents and refreshes them in the
/// background as they approach expiry, so a long-running load test doesn't
/// degrade into every request 401'ing once the initial batch expires.
pub struct TokenPool {
    inner: Arc<RwLock<Inner>>,
}

impl TokenPool {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let file: TokenFile = serde_json::from_str(&raw)?;
        if file.tokens.is_empty() {
            anyhow::bail!("token file {path} contains zero tokens");
        }
        info!(count = file.tokens.len(), "loaded pre-minted tokens");
        Ok(Self {
            inner: Arc::new(RwLock::new(Inner {
                tokens: file.tokens,
                token_endpoint: file.token_endpoint,
                client_id: file.client_id,
                client_secret: file.client_secret,
            })),
        })
    }

    /// A pool with a single synthetic unauthenticated "token" for
    /// echo-server self-validation runs only.
    pub fn insecure_noauth() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner {
                tokens: vec![MintedToken {
                    sub: "insecure".into(),
                    access_token: String::new(),
                    expires_at: i64::MAX,
                    refresh_token: None,
                }],
                token_endpoint: None,
                client_id: None,
                client_secret: None,
            })),
        }
    }

    pub async fn token_for_agent(&self, agent_idx: usize) -> MintedToken {
        let inner = self.inner.read().await;
        let n = inner.tokens.len();
        inner.tokens[agent_idx % n].clone()
    }

    /// Background task: every `interval_secs`, scans for tokens expiring
    /// within the next 60s and refreshes them via the configured token
    /// endpoint. No-op (logs once) if no token_endpoint was configured.
    pub async fn run_refresh_loop(self: Arc<Self>, interval_secs: u64) {
        let (endpoint, client_id, client_secret) = {
            let inner = self.inner.read().await;
            (
                inner.token_endpoint.clone(),
                inner.client_id.clone(),
                inner.client_secret.clone(),
            )
        };
        let Some(endpoint) = endpoint else {
            warn!("no oauth_token_endpoint configured; tokens will not be refreshed mid-run");
            return;
        };
        let http = reqwest_like_client();
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let due: Vec<(usize, MintedToken)> = {
                let inner = self.inner.read().await;
                inner
                    .tokens
                    .iter()
                    .enumerate()
                    .filter(|(_, t)| t.expires_at - now < 60 && t.refresh_token.is_some())
                    .map(|(i, t)| (i, t.clone()))
                    .collect()
            };
            if due.is_empty() {
                continue;
            }
            info!(due = due.len(), "refreshing tokens nearing expiry");
            for (idx, tok) in due {
                match refresh_one(
                    &http,
                    &endpoint,
                    client_id.as_deref(),
                    client_secret.as_deref(),
                    &tok,
                )
                .await
                {
                    Ok(fresh) => {
                        let mut inner = self.inner.write().await;
                        if idx < inner.tokens.len() {
                            inner.tokens[idx] = fresh;
                        }
                    }
                    Err(e) => warn!(sub = %tok.sub, error = %e, "token refresh failed"),
                }
            }
        }
    }
}

// A minimal blocking-free form client kept local to avoid pulling in a full
// reqwest dependency graph collision with hyper-util in this crate; uses
// hyper directly the same way the request path does.
fn reqwest_like_client() -> hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Full<bytes::Bytes>,
> {
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new())
}

async fn refresh_one(
    client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<bytes::Bytes>,
    >,
    endpoint: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    tok: &MintedToken,
) -> anyhow::Result<MintedToken> {
    use http_body_util::{BodyExt, Full};
    let refresh_token = tok
        .refresh_token
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no refresh_token"))?;
    let mut form = format!(
        "grant_type=refresh_token&refresh_token={}",
        urlencode(refresh_token)
    );
    if let Some(id) = client_id {
        form.push_str(&format!("&client_id={}", urlencode(id)));
    }
    if let Some(secret) = client_secret {
        form.push_str(&format!("&client_secret={}", urlencode(secret)));
    }
    let uri: hyper::Uri = endpoint.parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Full::new(bytes::Bytes::from(form)))?;
    let resp = client.request(req).await?;
    let body = resp.into_body().collect().await?.to_bytes();
    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    let access_token = parsed["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no access_token in refresh response"))?
        .to_string();
    let expires_in = parsed["expires_in"].as_i64().unwrap_or(300);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    Ok(MintedToken {
        sub: tok.sub.clone(),
        access_token,
        expires_at: now + expires_in,
        refresh_token: parsed["refresh_token"]
            .as_str()
            .map(String::from)
            .or_else(|| tok.refresh_token.clone()),
    })
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
