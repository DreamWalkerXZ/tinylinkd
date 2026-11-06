use askama::Template;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;

use crate::app::AppState;
use crate::timeutil;
use crate::users;

use super::auth::{AdminUser, CsrfForm, SessionUser, require_csrf};
use super::common::{
    Nav, PageQuery, UI_PAGE_LIMIT, error_page, html_response, load_settings_or_error, see_other,
};

#[derive(Debug, Clone)]
struct UserRow {
    id: i64,
    username: String,
    email: Option<String>,
    role: &'static str,
    disabled: bool,
    disabled_at: Option<String>,
    created_at: String,
    updated_at: String,
    link_count: i64,
}

#[derive(Template)]
#[template(path = "admin_users.html")]
struct UsersTemplate<'a> {
    nav: Nav<'a>,
    users: Vec<UserRow>,
    total: i64,
    page: i64,
    has_previous: bool,
    has_next: bool,
    error: Option<&'a str>,
    csrf_token: &'a str,
}

pub(super) async fn users_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Query(query): Query<PageQuery>,
) -> Response {
    render_users(
        &state,
        &session_user,
        query.page.unwrap_or(1).max(1),
        None,
        StatusCode::OK,
    )
    .await
}

async fn render_users(
    state: &AppState,
    session_user: &SessionUser,
    page: i64,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let instance_settings = match load_settings_or_error(state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let offset = (page - 1).saturating_mul(UI_PAGE_LIMIT);
    let (found, total) = match users::list_users(&state.db, UI_PAGE_LIMIT, offset).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "failed to list Users");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let counts = match link_counts(&state.db).await {
        Ok(counts) => counts,
        Err(error) => {
            tracing::error!(error = %error, "failed to count the Links owned by each User");
            std::collections::HashMap::new()
        }
    };
    let rows = found
        .into_iter()
        .map(|user| {
            let disabled = user.disabled_at.is_some();
            let timezone = instance_settings.timezone_tz();
            UserRow {
                id: user.id,
                username: user.username,
                email: user.email,
                role: user.role.as_str(),
                disabled,
                disabled_at: user
                    .disabled_at
                    .as_deref()
                    .map(|timestamp| timeutil::format_in_timezone(&timezone, timestamp)),
                created_at: timeutil::format_in_timezone(&timezone, &user.created_at),
                updated_at: timeutil::format_in_timezone(&timezone, &user.updated_at),
                link_count: counts.get(&user.id).copied().unwrap_or(0),
            }
        })
        .collect::<Vec<_>>();
    let template = UsersTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        users: rows,
        total,
        page,
        has_previous: page > 1,
        has_next: offset + UI_PAGE_LIMIT < total,
        error,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Users page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn link_counts(
    db: &crate::db::Database,
) -> Result<std::collections::HashMap<i64, i64>, sqlx::Error> {
    let rows: Vec<(i64, i64)> =
        sqlx::query_as("SELECT owner_id, COUNT(*) FROM links GROUP BY owner_id")
            .fetch_all(db.read_pool())
            .await?;
    Ok(rows.into_iter().collect())
}

pub(super) async fn user_disable(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    set_user_disabled(state, session_user, user_id, true, form).await
}

pub(super) async fn user_enable(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    set_user_disabled(state, session_user, user_id, false, form).await
}

async fn set_user_disabled(
    state: AppState,
    session_user: SessionUser,
    user_id: i64,
    disabled: bool,
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
    match users::update_user(
        &state.db,
        user_id,
        users::UserChanges {
            email: None,
            disabled: Some(disabled),
        },
    )
    .await
    {
        Ok(_) => see_other("/_/users"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The User does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_users(&state, &session_user, 1, Some(&message), error.status()).await
        }
        Err(error) => {
            tracing::error!(error = %error, user_id, "failed to change a User's disabled status");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteUserForm {
    csrf_token: String,
    #[serde(default)]
    confirm: Option<String>,
}

pub(super) async fn user_delete(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(user_id): Path<i64>,
    form: Result<Form<DeleteUserForm>, FormRejection>,
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
    if form.confirm.is_none() {
        return error_page(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Confirmation required",
            "Confirm that you want to delete this User before submitting the form.",
        );
    }
    match users::delete_user(&state.db, user_id).await {
        Ok(()) => see_other("/_/users"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The User does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_users(&state, &session_user, 1, Some(&message), error.status()).await
        }
        Err(error) => {
            tracing::error!(error = %error, user_id, "failed to delete a User");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}
