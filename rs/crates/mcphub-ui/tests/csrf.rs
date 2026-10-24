//! CSRF: every mutating form must carry a valid synchronizer token tied to
//! the caller's session. A forged or missing token must be rejected with a
//! 403, and the mutation must NOT have happened.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use mcphub_ui::auth::InMemorySessionStore;
use mcphub_ui::data::{InMemoryUiData, UiData};
use mcphub_ui::state::AppState;

async fn get_valid_csrf_token(app: axum::Router, cookie: &str, page: &str) -> String {
    let req = Request::builder().uri(page).header("cookie", format!("mcphub_session={cookie}")).body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    // Pull the value out of `name="csrf_token" value="...">`.
    let marker = "name=\"csrf_token\" value=\"";
    let start = body.find(marker).expect("page should render a csrf_token field") + marker.len();
    let end = body[start..].find('"').unwrap() + start;
    body[start..end].to_string()
}

#[tokio::test]
async fn quarantine_release_without_csrf_token_is_rejected_and_does_not_mutate() {
    let data = Arc::new(InMemoryUiData::default());
    let state = AppState::new(data.clone(), Arc::new(InMemorySessionStore::default()), Arc::new(mcphub_ui::testutil::UnavailableOidcLogin));
    let app = mcphub_ui::router(state);

    let before = data.quarantine_entries().await.len();
    assert!(before > 0, "fixture should seed at least one quarantine entry");

    let form = "csrf_token=not-a-real-token&server_id=00000000-0000-0000-0000-000000000002&tool_name=export_contacts";
    let req = Request::builder()
        .method("POST")
        .uri("/security/quarantine/release")
        .header("cookie", "mcphub_session=sess-security")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    assert_eq!(data.quarantine_entries().await.len(), before, "rejected CSRF submission must not mutate state");
}

#[tokio::test]
async fn quarantine_release_with_valid_csrf_token_succeeds() {
    let data = Arc::new(InMemoryUiData::default());
    let state = AppState::new(data.clone(), Arc::new(InMemorySessionStore::default()), Arc::new(mcphub_ui::testutil::UnavailableOidcLogin));
    let app = mcphub_ui::router(state.clone());

    let token = get_valid_csrf_token(mcphub_ui::router(state), "sess-security", "/security/quarantine").await;

    let before = data.quarantine_entries().await.len();
    let form = format!("csrf_token={token}&server_id=00000000-0000-0000-0000-000000000002&tool_name=export_contacts");
    let req = Request::builder()
        .method("POST")
        .uri("/security/quarantine/release")
        .header("cookie", "mcphub_session=sess-security")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "valid CSRF submission should succeed and redirect");
    assert_eq!(data.quarantine_entries().await.len(), before - 1);
}

#[tokio::test]
async fn csrf_token_from_a_different_session_is_rejected() {
    let data = Arc::new(InMemoryUiData::default());
    let state = AppState::new(data.clone(), Arc::new(InMemorySessionStore::default()), Arc::new(mcphub_ui::testutil::UnavailableOidcLogin));

    // A valid token, but minted for a *different* session than the one
    // presenting the cookie.
    let token = get_valid_csrf_token(mcphub_ui::router(state.clone()), "sess-admin", "/admin/idps").await;

    let app = mcphub_ui::router(state);
    let form = format!("csrf_token={token}&server_id=00000000-0000-0000-0000-000000000002&tool_name=export_contacts");
    let req = Request::builder()
        .method("POST")
        .uri("/security/quarantine/release")
        .header("cookie", "mcphub_session=sess-security")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
