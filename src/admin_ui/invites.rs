use askama::Template;
use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;

use crate::app::AppState;
use crate::invites;
use crate::timeutil;
use crate::users;

use super::auth::{AdminUser, CsrfForm, SessionUser, require_csrf};
use super::common::{
    Nav, PageQuery, UI_PAGE_LIMIT, error_page, html_response, load_settings_or_error, see_other,
};

#[derive(Debug, Clone)]
struct InviteRow {
    id: i64,
    status: &'static str,
    created_at: String,
    expires_at: String,
    used_at: Option<String>,
    revoked_at: Option<String>,
    created_by: String,
    can_revoke: bool,
}

/// The one-time Invite credential rendered immediately after creation. It is
/// held only for this response; the database stores just its hash.
#[derive(Debug, Clone)]
struct CreatedInviteView {
    token: String,
    expires_at: String,
}

#[derive(Template)]
#[template(path = "admin_invites.html")]
struct InvitesTemplate<'a> {
    nav: Nav<'a>,
    invites: Vec<InviteRow>,
    total: i64,
    page: i64,
    has_previous: bool,
    has_next: bool,
    created: Option<CreatedInviteView>,
    error: Option<&'a str>,
    csrf_token: &'a str,
}

pub(super) async fn invites_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Query(query): Query<PageQuery>,
) -> Response {
    render_invites(
        &state,
        &session_user,
        query.page.unwrap_or(1).max(1),
        None,
        None,
        StatusCode::OK,
    )
    .await
}

async fn render_invites(
    state: &AppState,
    session_user: &SessionUser,
    page: i64,
    created: Option<CreatedInviteView>,
    error: Option<&str>,
    status: StatusCode,
) -> Response {
    let instance_settings = match load_settings_or_error(state).await {
        Ok(settings) => settings,
        Err(response) => return response,
    };
    let offset = (page - 1).saturating_mul(UI_PAGE_LIMIT);
    let (found, total) = match invites::list_invites(&state.db, UI_PAGE_LIMIT, offset).await {
        Ok(result) => result,
        Err(error) => {
            tracing::error!(error = %error, "failed to list Invites");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            );
        }
    };
    let created_by: std::collections::HashMap<i64, String> =
        match users::list_users(&state.db, 10_000, 0).await {
            Ok((users, _)) => users
                .into_iter()
                .map(|user| (user.id, user.username))
                .collect(),
            Err(error) => {
                tracing::error!(error = %error, "failed to list Users for the Invite list");
                std::collections::HashMap::new()
            }
        };
    let timezone = instance_settings.timezone_tz();
    let created = created.map(|mut view| {
        view.expires_at = timeutil::format_in_timezone(&timezone, &view.expires_at);
        view
    });
    let rows = found
        .into_iter()
        .map(|invite| {
            let can_revoke = invite.used_at.is_none() && invite.revoked_at.is_none();
            InviteRow {
                id: invite.id,
                status: invite.status.as_str(),
                created_at: timeutil::format_in_timezone(&timezone, &invite.created_at),
                expires_at: timeutil::format_in_timezone(&timezone, &invite.expires_at),
                used_at: invite
                    .used_at
                    .as_deref()
                    .map(|timestamp| timeutil::format_in_timezone(&timezone, timestamp)),
                revoked_at: invite
                    .revoked_at
                    .as_deref()
                    .map(|timestamp| timeutil::format_in_timezone(&timezone, timestamp)),
                created_by: created_by
                    .get(&invite.created_by)
                    .cloned()
                    .unwrap_or_else(|| format!("User #{}", invite.created_by)),
                can_revoke,
            }
        })
        .collect::<Vec<_>>();
    let template = InvitesTemplate {
        nav: Nav::new(
            &instance_settings.instance_name,
            &session_user.session,
            &session_user.user,
        ),
        invites: rows,
        total,
        page,
        has_previous: page > 1,
        has_next: offset + UI_PAGE_LIMIT < total,
        created,
        error,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Invites page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

pub(super) async fn invite_create(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
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
    match invites::create_invite(&state.db, session_user.id()).await {
        Ok(created) => {
            let view = CreatedInviteView {
                token: created.plaintext,
                expires_at: created.expires_at,
            };
            render_invites(
                &state,
                &session_user,
                1,
                Some(view),
                None,
                StatusCode::CREATED,
            )
            .await
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to create an Invite");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

pub(super) async fn invite_revoke(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    Path(invite_id): Path<i64>,
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
    match invites::revoke_invite(&state.db, invite_id).await {
        Ok(()) => see_other("/_/invites"),
        Err(error) if error.status() == StatusCode::NOT_FOUND => error_page(
            StatusCode::NOT_FOUND,
            "Not Found",
            "The Invite does not exist.",
        ),
        Err(error) if error.status().is_client_error() => {
            let message = error.to_string();
            render_invites(
                &state,
                &session_user,
                1,
                None,
                Some(&message),
                error.status(),
            )
            .await
        }
        Err(error) => {
            tracing::error!(error = %error, invite_id, "failed to revoke an Invite");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}
