//! Every template must actually render for its intended persona, with real
//! landmarks and no server error. This also guards against silently
//! shipping a template that fails to compile-time-bind to its context
//! (askama catches most of that at compile time, but empty-state and
//! Option/match branches only get exercised at render time).

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

async fn body_of(cookie: &str, path: &str) -> String {
    let req = Request::builder().uri(path).header("cookie", format!("mcphub_session={cookie}")).body(Body::empty()).unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET {path} as {cookie} should render 200");
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).to_string()
}

const PAGES: &[(&str, &str)] = &[
    // Help is reachable by every role, so it is smoke-tested from the
    // least-privileged session as well as an admin one.
    ("sess-employee", "/help"),
    ("sess-admin", "/help"),
    ("sess-employee", "/catalog"),
    ("sess-employee", "/me/grants"),
    ("sess-owner", "/owner/servers"),
    ("sess-security", "/security/audit"),
    ("sess-security", "/security/policy"),
    ("sess-security", "/security/quarantine"),
    ("sess-security", "/security/anomalies"),
    ("sess-admin", "/admin/idps"),
    ("sess-admin", "/admin/idps/new"),
    ("sess-admin", "/admin/servers"),
    ("sess-admin", "/admin/limits"),
    ("sess-admin", "/admin/grants"),
];

#[tokio::test]
async fn every_persona_page_renders_with_one_h1_and_main_landmark() {
    for (session, path) in PAGES {
        let body = body_of(session, path).await;
        assert_eq!(body.matches("<h1").count(), 1, "{path} should have exactly one h1, got body: {body}");
        assert!(body.contains("<main"), "{path} should have a <main> landmark");
        assert!(body.contains("<nav"), "{path} should render the nav");
    }
}

#[tokio::test]
async fn login_redirects_to_the_idp_without_a_session() {
    let identity = mcphub_types::Identity {
        sub: "whoever".into(),
        issuer: mcphub_types::IssuerId::new("platform"),
        email: None,
        roles: vec![],
        groups: vec![],
        token_ref: mcphub_types::TokenRef::none(),
    };
    let state = AppState::new(
        Arc::new(InMemoryUiData::default()),
        Arc::new(InMemorySessionStore::default()),
        Arc::new(mcphub_ui::testutil::StubOidcLogin::new(identity)),
    );
    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let resp = mcphub_ui::router(state).oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers().get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with("https://idp.example.com/authorize"), "unexpected redirect target: {location}");
}

#[tokio::test]
async fn login_shows_a_real_error_when_the_idp_is_unreachable() {
    let req = Request::builder().uri("/login").body(Body::empty()).unwrap();
    let resp = app().oneshot(req).await.unwrap(); // app() wires UnavailableOidcLogin
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[cfg(feature = "dev_login")]
#[tokio::test]
async fn dev_login_picker_renders_at_its_own_path_not_login() {
    let req = Request::builder().uri("/dev/login").body(Body::empty()).unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_route_renders_a_real_404_not_a_blank_page() {
    let req = Request::builder()
        .uri("/this/route/does/not/exist")
        .header("cookie", "mcphub_session=sess-admin")
        .body(Body::empty())
        .unwrap();
    let resp = app().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("Page not found"));
}

#[tokio::test]
async fn nothing_is_escaped_out_via_the_safe_filter() {
    // Grep-style guard: the design brief requires autoescaping to stay on
    // everywhere. If a future edit adds `| safe` on user-controlled data,
    // this test should be extended into a real XSS-payload check; for now
    // it pins that no template in this crate opts out of escaping at all.
    let templates_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
    for entry in std::fs::read_dir(templates_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("html") {
            let contents = std::fs::read_to_string(&path).unwrap();
            assert!(!contents.contains("| safe"), "{path:?} must not use the `safe` filter");
        }
    }
}

/// The Help page is mostly links into the rest of the portal. A link that 404s
/// is worse than no link: it tells someone the feature doesn't exist. This
/// asserts every internal href it advertises is a route the router actually
/// serves.
#[tokio::test]
async fn every_internal_link_on_the_help_page_points_at_a_real_route() {
    let body = body_of("sess-admin", "/help").await;
    let mut hrefs: Vec<String> = Vec::new();
    for chunk in body.split("href=\"").skip(1) {
        if let Some(end) = chunk.find('"') {
            let href = &chunk[..end];
            // Skip in-page anchors and anything external.
            if href.starts_with('/') {
                hrefs.push(href.to_string());
            }
        }
    }
    assert!(!hrefs.is_empty(), "help page should link into the portal");
    for href in hrefs {
        let req = Request::builder()
            .uri(&href)
            .header("cookie", "mcphub_session=sess-admin")
            .body(Body::empty())
            .unwrap();
        let resp = app().oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::NOT_FOUND,
            "help page links to {href}, which the router does not serve"
        );
    }
}
