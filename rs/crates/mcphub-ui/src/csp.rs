//! Strict Content-Security-Policy with a per-request nonce. No
//! `unsafe-inline`, ever — the one `<script>` this crate ships (small,
//! vanilla, progressive-enhancement only) carries the nonce, and nothing
//! else is permitted to run.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;

#[derive(Clone, Copy)]
pub struct CspNonce(pub [u8; 16]);

impl CspNonce {
    fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn as_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }
}

pub async fn csp_layer(mut req: Request, next: Next) -> Response {
    let nonce = CspNonce::generate();
    req.extensions_mut().insert(nonce);

    let mut resp = next.run(req).await;

    let policy = format!(
        "default-src 'self'; script-src 'self' 'nonce-{n}'; style-src 'self' 'nonce-{n}'; \
         img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; \
         base-uri 'none'; form-action 'self'; object-src 'none'",
        n = nonce.as_b64()
    );
    resp.headers_mut().insert("content-security-policy", HeaderValue::from_str(&policy).unwrap());
    resp.headers_mut().insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    resp.headers_mut().insert("x-frame-options", HeaderValue::from_static("DENY"));
    resp.headers_mut().insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    resp
}
