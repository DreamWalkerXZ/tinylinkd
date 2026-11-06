use askama::Template;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::app::AppState;
use crate::redirect::{ClientIp, client_ip};
use crate::sessions;
use crate::users::{self, Role};

use super::common::{error_page, html_response};

/// The User behind the browser session cookie. A missing, invalid, expired, or
/// revoked session redirects to the login page.
pub struct SessionUser {
    pub session: sessions::Session,
    pub user: users::User,
}

impl SessionUser {
    pub(super) fn id(&self) -> i64 {
        self.user.id
    }

    pub(super) fn is_admin(&self) -> bool {
        self.user.role == Role::Admin
    }
}

pub enum SessionRejection {
    Login,
    Forbidden,
    Internal,
}

impl IntoResponse for SessionRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Login => {
                let mut response = StatusCode::SEE_OTHER.into_response();
                response
                    .headers_mut()
                    .insert(header::LOCATION, HeaderValue::from_static("/_/login"));
                response
            }
            Self::Forbidden => error_page(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "You do not have permission to access this page.",
            ),
            Self::Internal => error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            ),
        }
    }
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = SessionRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(token) = sessions::cookie_value(&parts.headers, sessions::SESSION_COOKIE_NAME)
        else {
            return Err(SessionRejection::Login);
        };
        match sessions::authenticate(&state.db, &token).await {
            Ok(Some((session, user))) => Ok(Self { session, user }),
            Ok(None) => Err(SessionRejection::Login),
            Err(error) => {
                tracing::error!(error = %error, "failed to authenticate a browser session");
                Err(SessionRejection::Internal)
            }
        }
    }
}

/// The Admin behind a browser session. A signed-in non-Admin gets 403; an
/// unauthenticated browser is redirected to the login page.
pub struct AdminUser(pub SessionUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = SessionRejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session_user = SessionUser::from_request_parts(parts, state).await?;
        if !session_user.is_admin() {
            return Err(SessionRejection::Forbidden);
        }
        Ok(Self(session_user))
    }
}
/// The root path: send a signed-in browser to the Link list and everyone else
/// to the login page.
pub(super) async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let authenticated = match sessions::cookie_value(&headers, sessions::SESSION_COOKIE_NAME) {
        Some(token) => matches!(sessions::authenticate(&state.db, &token).await, Ok(Some(_))),
        None => false,
    };
    let target = if authenticated {
        "/_/links"
    } else {
        "/_/login"
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static(target));
    response
}

#[derive(Template)]
#[template(path = "admin_login.html")]
struct LoginTemplate<'a> {
    csrf_token: &'a str,
    username: &'a str,
    error: Option<&'a str>,
}

pub(super) async fn login_page(State(state): State<AppState>) -> Response {
    let Ok(csrf_token) = sessions::generate_token() else {
        tracing::error!("failed to generate a login CSRF token");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let secure = state.config.base_url.scheme() == "https";
    let set_cookie = sessions::login_csrf_set_cookie(&csrf_token, secure);
    let template = LoginTemplate {
        csrf_token: &csrf_token,
        username: "",
        error: None,
    };
    let mut response = render_login(&template, StatusCode::OK);
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&set_cookie).expect("the login CSRF cookie is a valid header value"),
    );
    response
}

#[derive(Debug, Deserialize)]
pub(super) struct CsrfForm {
    pub(super) csrf_token: String,
}

/// Reject a state-changing form whose CSRF token does not match the session.
pub(super) fn require_csrf(session: &sessions::Session, submitted: &str) -> Option<Response> {
    if session.csrf_matches(submitted) {
        None
    } else {
        Some(error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        ))
    }
}

pub(super) async fn logout(
    State(state): State<AppState>,
    session_user: SessionUser,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The form's CSRF token is missing or invalid.",
        );
    };
    if let Some(response) = require_csrf(&session_user.session, &form.csrf_token) {
        return response;
    }
    if let Err(error) = sessions::revoke(&state.db, session_user.session.id).await {
        tracing::error!(error = %error, "failed to revoke a browser session");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "An unexpected error occurred.",
        );
    }
    let secure = state.config.base_url.scheme() == "https";
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/_/login"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::clear_session_cookie(secure))
            .expect("the cleared session cookie is a valid header value"),
    );
    response
}

#[derive(Debug, Deserialize)]
pub(super) struct LoginForm {
    csrf_token: String,
    username: String,
    password: String,
}

pub(super) async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    client: ClientIp,
    form: Result<Form<LoginForm>, FormRejection>,
) -> Response {
    let Some(csrf_cookie) = sessions::cookie_value(&headers, sessions::LOGIN_CSRF_COOKIE_NAME)
    else {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The login form is missing its CSRF token.",
        );
    };
    let Ok(Form(form)) = form else {
        return login_failure(
            &csrf_cookie,
            "",
            "Enter a username and password.",
            StatusCode::BAD_REQUEST,
        );
    };
    if !sessions::csrf_matches(&csrf_cookie, &form.csrf_token) {
        return error_page(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "The login form's CSRF token is invalid.",
        );
    }

    let ip = client_ip(client.0, &headers, state.config.trust_proxy);
    if let Some(retry_after) = state.login_limiter.check(&ip) {
        return login_rate_limited(&csrf_cookie, retry_after);
    }

    let user = match users::authenticate(&state.db, &form.username, &form.password).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            state.login_limiter.record_failure(&ip);
            return login_failure(
                &csrf_cookie,
                &form.username,
                "Invalid username or password.",
                StatusCode::UNAUTHORIZED,
            );
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to authenticate a browser login");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };

    let previous_token = sessions::cookie_value(&headers, sessions::SESSION_COOKIE_NAME);
    let created =
        match sessions::create_session(&state.db, user.id, previous_token.as_deref()).await {
            Ok(created) => created,
            Err(error) => {
                tracing::error!(error = %error, "failed to create a browser session");
                return error_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    "An unexpected error occurred.",
                );
            }
        };

    let secure = state.config.base_url.scheme() == "https";
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, HeaderValue::from_static("/_/links"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::session_set_cookie(&created.plaintext, secure))
            .expect("the session cookie is a valid header value"),
    );
    response
}

fn login_rate_limited(csrf_token: &str, retry_after: u64) -> Response {
    let mut response = login_failure(
        csrf_token,
        "",
        "Too many failed attempts. Try again later.",
        StatusCode::TOO_MANY_REQUESTS,
    );
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())
            .expect("a seconds value is a valid header value"),
    );
    response
}

fn login_failure(csrf_token: &str, username: &str, message: &str, status: StatusCode) -> Response {
    let template = LoginTemplate {
        csrf_token,
        username,
        error: Some(message),
    };
    render_login(&template, status)
}

fn render_login(template: &LoginTemplate<'_>, status: StatusCode) -> Response {
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the login page");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
        }
    }
}
