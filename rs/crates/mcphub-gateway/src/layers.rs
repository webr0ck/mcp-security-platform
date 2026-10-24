//! Tower layer stack, applied outermost-first: request-id → tracing span →
//! panic-catch → timeout → concurrency limit → body limit → the router.
//! Composition, not ad-hoc middleware — matches the reference standard
//! (linkerd2-proxy) called out in ARCHITECTURE.md.

use axum::error_handling::HandleErrorLayer;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{BoxError, Router};
use std::time::Duration;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;

pub const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB — generous for a tool-call payload, small enough to bound memory.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_CONCURRENT_REQUESTS: usize = 4096;

/// Wraps `router` with the full layer stack. Kept as a single function (not
/// scattered `.layer()` calls at each call site) so there is exactly one
/// place that defines "what every request goes through", mirroring the
/// single-choke-point discipline applied to `invocation::invoke`.
///
/// `TimeoutLayer` and `ConcurrencyLimitLayer` produce a boxed `Error`
/// rather than an infallible `Response`, so they're wrapped in a
/// `ServiceBuilder` fronted by `HandleErrorLayer` — that converts their
/// error into a `Response` (a fixed, non-leaking timeout/overload body)
/// before it ever reaches `Router::layer`, which requires an infallible
/// service.
pub fn apply(router: Router) -> Router {
    let fallible_middleware = ServiceBuilder::new()
        .layer(HandleErrorLayer::new(handle_middleware_error))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::new(REQUEST_TIMEOUT));

    router
        .layer(fallible_middleware)
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
}

/// A panic anywhere in a handler returns 500 with a fixed, non-leaking body
/// — never the panic message (which could contain request-derived content
/// or internal state) and never a stack trace.
fn handle_panic(_err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// Converts a `TimeoutLayer`/`ConcurrencyLimitLayer` error into a fixed,
/// non-leaking response. Neither layer's error type carries request content,
/// but this still never forwards the raw error `Display` to the body — same
/// no-internal-detail discipline as `DenyReason::code()`.
async fn handle_middleware_error(err: BoxError) -> Response {
    if err.is::<tower::timeout::error::Elapsed>() {
        (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "service overloaded").into_response()
    }
}

/// Exercises the panic-catch layer end to end against a handler that always
/// panics, asserting the response body never contains the panic message.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn panics() -> &'static str {
        panic!("leaking-secret-value-should-never-reach-the-client");
    }

    #[tokio::test]
    async fn panic_is_caught_and_body_never_leaks_the_panic_message() {
        let app = apply(Router::new().route("/boom", get(panics)));
        let response = app
            .oneshot(Request::builder().uri("/boom").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body);
        assert!(!body_str.contains("leaking-secret-value"));
    }
}
