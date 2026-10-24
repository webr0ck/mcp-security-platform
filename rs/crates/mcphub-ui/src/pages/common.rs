use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use mcphub_types::Role;
use serde::Deserialize;

use crate::auth::{verify_csrf, CurrentUser};
use crate::state::AppState;
use crate::templates::NotFoundTemplate;

pub async fn home(user: Option<CurrentUser>) -> Response {
    let Some(user) = user else {
        return Redirect::to("/login").into_response();
    };
    let dest = if user.identity.has_role(Role::SuperAdmin) {
        "/admin/idps"
    } else if user.identity.has_role(Role::ServerOwner) {
        "/owner/servers"
    } else if user.identity.has_role(Role::SecurityAnalyst) {
        "/security/audit"
    } else {
        "/catalog"
    };
    Redirect::to(dest).into_response()
}

/// Start a real OIDC PKCE login: ask `state.oidc` to allocate a pending
/// flow and hand back the browser's redirect target.
pub async fn login(State(state): State<AppState>) -> Response {
    match state.oidc.start().await {
        Ok(redirect_url) => Redirect::to(&redirect_url).into_response(),
        Err(_) => {
            (StatusCode::BAD_GATEWAY, "Unable to reach the identity provider. Please try again shortly.").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    /// The IDP reports errors (user cancelled, `access_denied`, ...) via
    /// this query param instead of `code`. Not a bug in our flow — send the
    /// user back to `/login` rather than treating it as an invalid callback.
    #[serde(default)]
    pub error: Option<String>,
}

/// Redeem the callback, mint a real session, set the cookie. Every failure
/// path here must be indistinguishable in its response from every other —
/// state mismatch, expired flow, and a token the endpoint rejected all
/// collapse into the same "login could not be completed" response, via
/// `OidcLoginError`'s single `InvalidCallback` variant.
pub async fn callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    if q.error.is_some() {
        return Redirect::to("/login").into_response();
    }
    let (Some(code), Some(oauth_state)) = (q.code, q.state) else {
        return (StatusCode::BAD_REQUEST, "Missing code or state.").into_response();
    };

    let identity = match state.oidc.complete(&code, &oauth_state).await {
        Ok(identity) => identity,
        Err(_) => {
            return (
                StatusCode::FORBIDDEN,
                "Login could not be completed — the request may have expired or already been used. Please try again.",
            )
                .into_response();
        }
    };

    let Some(session_id) = state.sessions.create(identity).await else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Too many active sessions right now. Please try again shortly.")
            .into_response();
    };

    let mut resp = Redirect::to("/").into_response();
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&session_cookie(&state, &session_id)).unwrap());
    resp
}

fn session_cookie(state: &AppState, session_id: &str) -> String {
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    format!("mcphub_session={session_id}; Path=/; HttpOnly; SameSite=Lax{secure}")
}

#[derive(Deserialize)]
pub struct LogoutForm {
    pub csrf_token: String,
}

pub async fn logout(State(state): State<AppState>, user: CurrentUser, axum::extract::Form(form): axum::extract::Form<LogoutForm>) -> Response {
    if let Err(resp) = verify_csrf(&state, &user, &form.csrf_token) {
        return resp;
    }
    state.sessions.destroy(&user.session_id).await;
    let mut resp = Redirect::to("/login").into_response();
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    let cookie = format!("mcphub_session=; Path=/; HttpOnly; SameSite=Lax{secure}; Max-Age=0");
    resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, NotFoundTemplate).into_response()
}

/// TEMP dev-only session picker, compiled only under this crate's own
/// `dev_login` feature (see `router.rs` and `auth`'s module doc — the
/// route lives at `/dev/login`, never `/login`, so it can never collide
/// with or shadow the real OIDC flow above even if this feature were
/// mistakenly left on somewhere).
#[cfg(feature = "dev_login")]
pub mod dev {
    use axum::extract::{Extension, Form, State};
    use axum::http::{header, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Redirect, Response};
    use serde::Deserialize;

    use crate::csp::CspNonce;
    use crate::state::AppState;
    use crate::templates::LoginTemplate;

    pub async fn login_form(Extension(nonce): Extension<CspNonce>) -> Response {
        LoginTemplate { csp_nonce: nonce.as_b64(), error: None }.into_response()
    }

    #[derive(Deserialize)]
    pub struct LoginForm {
        pub session: String,
    }

    pub async fn login_submit(
        State(state): State<AppState>,
        Extension(nonce): Extension<CspNonce>,
        Form(form): Form<LoginForm>,
    ) -> Response {
        if state.sessions.resolve(&form.session).await.is_none() {
            let body = LoginTemplate { csp_nonce: nonce.as_b64(), error: Some("Unrecognized development session.".to_string()) };
            return (StatusCode::UNAUTHORIZED, body).into_response();
        }
        let mut resp = Redirect::to("/").into_response();
        let cookie = format!("mcphub_session={}; Path=/; HttpOnly; SameSite=Strict", form.session);
        resp.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
        resp
    }
}

/// The Help page. Deliberately available to every authenticated role — it
/// explains denials and profile management, which employees hit far more often
/// than admins do. It renders no data of its own, so there is nothing here to
/// leak across roles; the in-page links are ordinary hrefs and each target
/// still enforces its own `require_role`, so a link an employee cannot use
/// gives them a 403 rather than access.
pub async fn help(
    axum::extract::State(state): axum::extract::State<crate::state::AppState>,
    user: crate::auth::CurrentUser,
    axum::extract::Extension(nonce): axum::extract::Extension<crate::csp::CspNonce>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let chrome = crate::chrome::build(&state, &user.identity, &user.session_id, "/help", nonce, None);
    crate::templates::HelpTemplate { chrome }.into_response()
}
