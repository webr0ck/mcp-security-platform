//! Role-gating 403 matrix: for every gated route, every role that is NOT
//! listed as permitted must get a real 403, not a redirect, not a 200, not
//! a silently empty page. This is what backs the "server-side authorization
//! is the source of truth" requirement — nav visibility is UX only.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use mcphub_ui::auth::InMemorySessionStore;
use mcphub_ui::data::InMemoryUiData;
use mcphub_ui::state::AppState;

fn app() -> axum::Router {
    let state = AppState::new(Arc::new(InMemoryUiData::default()), Arc::new(InMemorySessionStore::default()), Arc::new(mcphub_ui::testutil::UnavailableOidcLogin));
    mcphub_ui::router(state)
}

async fn get_as(cookie: Option<&str>, path: &str) -> (StatusCode, String) {
    let app = app();
    let mut req = Request::builder().uri(path).method("GET");
    if let Some(c) = cookie {
        req = req.header("cookie", format!("mcphub_session={c}"));
    }
    let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

const ALL_SESSIONS: &[&str] = &["sess-admin", "sess-owner", "sess-security", "sess-employee"];

/// (route, session cookie that IS permitted)
const GATED_GET_ROUTES: &[(&str, &str)] = &[
    ("/catalog", "sess-employee"),
    ("/me/grants", "sess-employee"),
    ("/owner/servers", "sess-owner"),
    ("/security/audit", "sess-security"),
    ("/security/policy", "sess-security"),
    ("/security/quarantine", "sess-security"),
    ("/security/anomalies", "sess-security"),
    ("/admin/idps", "sess-admin"),
    ("/admin/idps/new", "sess-admin"),
    ("/admin/servers", "sess-admin"),
    ("/admin/limits", "sess-admin"),
    ("/admin/grants", "sess-admin"),
];

#[tokio::test]
async fn every_gated_route_403s_for_every_non_permitted_role() {
    for (route, permitted) in GATED_GET_ROUTES {
        for session in ALL_SESSIONS {
            let (status, body) = get_as(Some(session), route).await;
            if session == permitted {
                assert_eq!(status, StatusCode::OK, "expected 200 for permitted session {session} on {route}, got {status}");
            } else {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "expected 403 for non-permitted session {session} on {route}, got {status}"
                );
                assert!(
                    body.contains("You do not have permission to"),
                    "403 body for {route} as {session} should explain the denial, got: {body}"
                );
            }
        }
    }
}

#[tokio::test]
async fn unauthenticated_request_is_redirected_to_login() {
    for (route, _) in GATED_GET_ROUTES {
        let (status, _) = get_as(None, route).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "expected redirect for unauthenticated GET {route}");
    }
}

#[tokio::test]
async fn direct_admin_url_as_employee_is_403_not_200_or_redirect() {
    // The exact scenario the brief calls out: a direct GET to an admin URL
    // as an employee must be a 403, never a redirect and never a silent
    // empty screen.
    let (status, body) = get_as(Some("sess-employee"), "/admin/servers").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("You do not have permission to"));
}

#[tokio::test]
async fn owner_cannot_view_another_owners_server_detail_even_though_role_matches() {
    // Route-level role gate passes (both are ServerOwner) but the resource
    // itself isn't theirs — this must still 403, per-resource, not just
    // per-route.
    let state = AppState::new(Arc::new(InMemoryUiData::default()), Arc::new(InMemorySessionStore::default()), Arc::new(mcphub_ui::testutil::UnavailableOidcLogin));
    let app = mcphub_ui::router(state);

    // server id `1` (github-mcp) is owned by owner-1 == sess-owner, so this
    // should succeed...
    let uuid_a = uuid::Uuid::from_u128(1);
    let req = Request::builder()
        .uri(format!("/owner/servers/{uuid_a}"))
        .header("cookie", "mcphub_session=sess-owner")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ...but a server owned by someone else must 403 even for a valid
    // ServerOwner session.
    let uuid_missing = uuid::Uuid::from_u128(999);
    let req = Request::builder()
        .uri(format!("/owner/servers/{uuid_missing}"))
        .header("cookie", "mcphub_session=sess-owner")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
