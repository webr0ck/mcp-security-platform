use crate::routers::{health, mcp, rest};
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;

/// Builds the full axum application: both enforcement routers plus health
/// endpoints, wrapped in the standard layer stack. This is the only place
/// routes are registered — `POST /api/v1/tools/{id}/invoke` and
/// `POST /mcp` are the sole request entry points, and both are wired to
/// call `invocation::invoke` (directly, or via `resolve_tool_by_name` then
/// `invoke`).
pub fn build(state: AppState) -> Router {
    let router = Router::new()
        .route("/healthz/live", get(health::live))
        .route("/healthz/ready", get(health::ready))
        .route("/api/v1/tools/:id/invoke", post(rest::invoke_tool))
        .route("/mcp", post(mcp::handle))
        .with_state(state);

    crate::layers::apply(router)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invocation::Gates;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn liveness_is_ok_even_with_deny_all_gates() {
        let app = build(AppState::new(Gates::deny_all()));
        let resp = app
            .oneshot(Request::builder().uri("/healthz/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invoke_with_deny_all_gates_is_denied_not_500() {
        let app = build(AppState::new(Gates::deny_all()));
        let body = serde_json::json!({"server_id": "00000000-0000-0000-0000-000000000000", "params": {}});
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tools/echo/invoke")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // 401 (Unauthenticated is the first gate DenyAll's authenticator
        // hits) — never a 2xx, and never an unhandled panic (500 from
        // CatchPanicLayer would also be acceptable evidence of fail-closed,
        // but a bare service failure would not be).
        assert!(resp.status().is_client_error() || resp.status() == StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_is_ok_by_default_and_unavailable_when_audit_sink_reports_unhealthy() {
        let app = build(AppState::new(Gates::deny_all()));
        let resp = app
            .oneshot(Request::builder().uri("/healthz/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "DenyAll's default AuditSink::is_healthy() is true — no writer to be dead yet");

        // Proves `/healthz/ready` actually reads `AuditSink::is_healthy()`,
        // not just always-OK — the "surface the writer-supervisor signal"
        // fix, unit-tested independent of a live PgRedisAuditSink.
        struct UnhealthyAudit;
        #[async_trait::async_trait]
        impl crate::traits::AuditSink for UnhealthyAudit {
            async fn emit(&self, _record: crate::traits::AuditRecord) -> Result<(), mcphub_types::GateError> {
                Ok(())
            }
            fn is_healthy(&self) -> bool {
                false
            }
        }
        let mut gates = Gates::deny_all();
        gates.audit = std::sync::Arc::new(UnhealthyAudit);
        let app = build(AppState::new(gates));
        let resp = app
            .oneshot(Request::builder().uri("/healthz/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "an unhealthy audit sink must make /healthz/ready report not-ready");
    }
}
