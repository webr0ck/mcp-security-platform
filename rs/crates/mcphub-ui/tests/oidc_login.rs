//! The real OIDC login flow, at the HTTP-router level this crate owns:
//! `/login` redirects, `/callback` mints a real session on success and
//! rejects a mismatched/replayed `state`, a forged session cookie never
//! authenticates, and an expired session is treated exactly like no
//! session at all. `mcphub-identity`'s own PKCE/JWT crypto is covered by
//! its own test suite, not re-tested here — see `testutil::StubOidcLogin`'s
//! doc comment for the split.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mcphub_types::{Identity, IssuerId, Role, TokenRef};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

use mcphub_ui::auth::{BoundedSessionStore, SessionStore};
use mcphub_ui::data::InMemoryUiData;
use mcphub_ui::state::AppState;
use mcphub_ui::testutil::StubOidcLogin;

fn employee_identity() -> Identity {
    Identity {
        sub: "tester".into(),
        issuer: IssuerId::new("https://idp.example.com"),
        email: Some("tester@example.com".into()),
        roles: vec![mcphub_types::GrantedRole { role: Role::Employee, asserted_by: IssuerId::new("https://idp.example.com") }],
        groups: vec![],
        token_ref: TokenRef::none(),
    }
}

fn extract_cookie_value(resp: &axum::response::Response) -> String {
    let raw = resp.headers().get("set-cookie").expect("callback must set a cookie").to_str().unwrap();
    let kv = raw.split(';').next().unwrap();
    kv.strip_prefix("mcphub_session=").unwrap().to_string()
}

#[tokio::test]
async fn full_login_flow_mints_a_working_session_cookie() {
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(BoundedSessionStore::default()),
        Arc::new(StubOidcLogin::new(employee_identity())),
    );

    // GET /login -> redirect to the IDP, allocating the pending flow.
    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // GET /callback?code=...&state=... -> real session minted, cookie set.
    let req = Request::builder().uri("/callback?code=abc123&state=stub-flow-state").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state.clone()).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "successful callback should redirect to /");
    assert_eq!(resp.headers().get("location").unwrap(), "/");
    let cookie_header = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(cookie_header.contains("HttpOnly"), "session cookie must be HttpOnly");
    assert!(cookie_header.contains("SameSite=Lax"), "session cookie must be SameSite=Lax");
    assert!(cookie_header.contains("Secure"), "session cookie must be Secure by default");
    let session_id = extract_cookie_value(&resp);
    assert!(session_id.len() >= 32, "session id should be high-entropy, not a short/predictable value, got: {session_id}");

    // The minted cookie actually authenticates a gated page.
    let req = Request::builder().uri("/catalog").header("cookie", format!("mcphub_session={session_id}")).body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn callback_with_mismatched_state_is_rejected() {
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(BoundedSessionStore::default()),
        Arc::new(StubOidcLogin::new(employee_identity())),
    );

    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let _ = mcphub_ui::router(state.clone()).oneshot(req).await.unwrap();

    let req = Request::builder().uri("/callback?code=abc123&state=attacker-supplied-state").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(!body.to_lowercase().contains("state"), "error body must not leak which check failed: {body}");
}

#[tokio::test]
async fn callback_state_is_single_use_replay_is_rejected() {
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(BoundedSessionStore::default()),
        Arc::new(StubOidcLogin::new(employee_identity())),
    );
    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let _ = mcphub_ui::router(state.clone()).oneshot(req).await.unwrap();

    let first = Request::builder().uri("/callback?code=abc123&state=stub-flow-state").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state.clone()).oneshot(first).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let replay = Request::builder().uri("/callback?code=abc123&state=stub-flow-state").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(replay).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "replaying the same state must fail the second time");
}

#[tokio::test]
async fn callback_missing_code_or_state_is_rejected() {
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(BoundedSessionStore::default()),
        Arc::new(StubOidcLogin::new(employee_identity())),
    );
    let req = Request::builder().uri("/callback?state=stub-flow-state").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_forged_or_never_issued_session_cookie_never_authenticates() {
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(BoundedSessionStore::default()),
        Arc::new(StubOidcLogin::new(employee_identity())),
    );
    // No login flow ever ran; this cookie value was never returned by
    // `create()` — a guessed or hand-crafted session id.
    let req = Request::builder().uri("/catalog").header("cookie", "mcphub_session=guessed-or-forged-session-id").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "an unknown session id must be treated as unauthenticated, not trusted");
    assert_eq!(resp.headers().get("location").unwrap(), "/login");
}

#[tokio::test]
async fn expired_session_is_rejected_like_no_session_at_all() {
    let store = BoundedSessionStore::with_limits(Duration::from_millis(20), 100);
    let session_id = store.create(employee_identity()).await.expect("store has capacity");
    assert!(store.resolve(&session_id).await.is_some(), "sanity: session resolves before it expires");

    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(store.resolve(&session_id).await.is_none(), "session must not resolve once past its TTL");

    let state = AppState::new(Arc::new(InMemoryUiData::default()), Arc::new(store), Arc::new(StubOidcLogin::new(employee_identity())));
    let req = Request::builder().uri("/catalog").header("cookie", format!("mcphub_session={session_id}")).body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers().get("location").unwrap(), "/login");
}

#[tokio::test]
async fn logout_destroys_the_session_server_side_not_just_the_cookie() {
    let store = Arc::new(BoundedSessionStore::default());
    let session_id = store.create(employee_identity()).await.unwrap();
    let state = AppState::new(Arc::new(InMemoryUiData::default()), store.clone(), Arc::new(StubOidcLogin::new(employee_identity())));

    // Grab a valid CSRF token off any gated page first.
    let req = Request::builder().uri("/catalog").header("cookie", format!("mcphub_session={session_id}")).body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state.clone()).oneshot(req).await.unwrap();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    let marker = "name=\"csrf_token\" value=\"";
    let start = body.find(marker).unwrap() + marker.len();
    let end = body[start..].find('"').unwrap() + start;
    let csrf_token = body[start..end].to_string();

    let form = format!("csrf_token={csrf_token}");
    let req = Request::builder()
        .method("POST")
        .uri("/logout")
        .header("cookie", format!("mcphub_session={session_id}"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // The session must be gone from the store itself, not just uncookied.
    assert!(store.resolve(&session_id).await.is_none(), "logout must destroy the session server-side");
}
