use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde_json::json;

/// Liveness: process is up and serving. Never depends on downstream health
/// — a liveness probe that fails closed on a downstream outage would cause
/// the orchestrator to kill and restart a perfectly healthy process during
/// a transient Postgres/Redis blip.
pub async fn live() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "live" })))
}

/// Readiness: checks the audit sink's health (`AuditSink::is_healthy`),
/// which is what surfaces `PgRedisAuditSink`'s writer-supervisor signal —
/// before this, "the audit writer task died" denied every request forever
/// with nothing observing or reporting it. Deliberately narrow for now:
/// this is the one dependency whose failure mode was silent and total
/// (every request denies), which made it the priority to wire first. DB/
/// redis/policy-bundle reachability are NOT checked here yet — those
/// failures are already visible per-request via `DenyReason::
/// DependencyUnavailable`, so they're a real gap but not the SAME class of
/// silent-forever failure this closes.
///
/// TODO: extend with DB/redis/OPA-bundle reachability checks.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if state.gates.audit.is_healthy() {
        (StatusCode::OK, Json(json!({ "status": "ready" })))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "not_ready", "reason": "audit_sink_unhealthy" })))
    }
}
