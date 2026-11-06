use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;

use crate::app::AppState;
use crate::error::ApiError;
use crate::settings;

use super::auth::{AdminUser, SessionUser, require_csrf};
use super::common::{Nav, error_page, html_response, load_settings_or_error, see_other};

/// The editable Instance settings as shown in the form. Values are kept as
/// submitted strings so an invalid entry can be redisplayed unchanged.
#[derive(Debug, Clone)]
struct SettingsFormValues {
    instance_name: String,
    timezone: String,
    click_retention_days: String,
    password_unlock_ttl_seconds: String,
}

impl SettingsFormValues {
    fn from_settings(settings: &settings::InstanceSettings) -> Self {
        Self {
            instance_name: settings.instance_name.clone(),
            timezone: settings.timezone.clone(),
            click_retention_days: settings.click_retention_days.to_string(),
            password_unlock_ttl_seconds: settings.password_unlock_ttl_seconds.to_string(),
        }
    }
}

/// Validation messages for the Settings form, grouped by field. Anything
/// unrecognized is shown as a general form error.
#[derive(Debug, Default)]
struct SettingsFormErrors {
    instance_name: Option<String>,
    timezone: Option<String>,
    click_retention_days: Option<String>,
    password_unlock_ttl_seconds: Option<String>,
    general: Option<String>,
}

impl SettingsFormErrors {
    fn from_api_error(error: &ApiError) -> Self {
        let detail = error.to_string();
        let mut errors = Self::default();
        match error.code() {
            Some("invalid_instance_name") => errors.instance_name = Some(detail),
            Some("invalid_timezone") => errors.timezone = Some(detail),
            Some("invalid_click_retention_days") => {
                errors.click_retention_days = Some(detail);
            }
            Some("invalid_password_unlock_ttl") => {
                errors.password_unlock_ttl_seconds = Some(detail);
            }
            _ => errors.general = Some(detail),
        }
        errors
    }
}

#[derive(Template)]
#[template(path = "admin_settings.html")]
struct SettingsTemplate<'a> {
    nav: Nav<'a>,
    values: SettingsFormValues,
    errors: SettingsFormErrors,
    csrf_token: &'a str,
}

fn render_settings_page(
    session_user: &SessionUser,
    instance_name: &str,
    values: SettingsFormValues,
    errors: SettingsFormErrors,
    status: StatusCode,
) -> Response {
    let template = SettingsTemplate {
        nav: Nav::new(instance_name, &session_user.session, &session_user.user),
        values,
        errors,
        csrf_token: &session_user.session.csrf_token,
    };
    match template.render() {
        Ok(html) => html_response(status, html),
        Err(error) => {
            tracing::error!(error = %error, "failed to render the Settings page");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}

async fn render_settings_error(
    state: &AppState,
    session_user: &SessionUser,
    values: SettingsFormValues,
    errors: SettingsFormErrors,
    status: StatusCode,
) -> Response {
    match load_settings_or_error(state).await {
        Ok(current) => {
            render_settings_page(session_user, &current.instance_name, values, errors, status)
        }
        Err(response) => response,
    }
}

pub(super) async fn settings_page(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
) -> Response {
    match load_settings_or_error(&state).await {
        Ok(current) => {
            let values = SettingsFormValues::from_settings(&current);
            render_settings_page(
                &session_user,
                &current.instance_name,
                values,
                SettingsFormErrors::default(),
                StatusCode::OK,
            )
        }
        Err(response) => response,
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct SettingsForm {
    csrf_token: String,
    instance_name: String,
    timezone: String,
    click_retention_days: String,
    password_unlock_ttl_seconds: String,
}

pub(super) async fn settings_update(
    State(state): State<AppState>,
    AdminUser(session_user): AdminUser,
    form: Result<Form<SettingsForm>, FormRejection>,
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
    let values = SettingsFormValues {
        instance_name: form.instance_name.clone(),
        timezone: form.timezone.clone(),
        click_retention_days: form.click_retention_days.clone(),
        password_unlock_ttl_seconds: form.password_unlock_ttl_seconds.clone(),
    };
    let click_retention_days = match form.click_retention_days.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            return render_settings_error(
                &state,
                &session_user,
                values,
                SettingsFormErrors {
                    click_retention_days: Some(
                        "click_retention_days must be a whole number of days.".to_string(),
                    ),
                    ..SettingsFormErrors::default()
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };
    let password_unlock_ttl_seconds = match form.password_unlock_ttl_seconds.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => {
            return render_settings_error(
                &state,
                &session_user,
                values,
                SettingsFormErrors {
                    password_unlock_ttl_seconds: Some(
                        "password_unlock_ttl_seconds must be a whole number of seconds."
                            .to_string(),
                    ),
                    ..SettingsFormErrors::default()
                },
                StatusCode::UNPROCESSABLE_ENTITY,
            )
            .await;
        }
    };
    let changes = settings::SettingsChanges {
        instance_name: Some(form.instance_name),
        timezone: Some(form.timezone),
        click_retention_days: Some(click_retention_days),
        password_unlock_ttl_seconds: Some(password_unlock_ttl_seconds),
    };
    match settings::update(&state.db, changes).await {
        Ok(_) => see_other("/_/settings"),
        Err(error) if error.status().is_client_error() => {
            let status = error.status();
            let errors = SettingsFormErrors::from_api_error(&error);
            render_settings_error(&state, &session_user, values, errors, status).await
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to update Instance settings");
            error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected error occurred.",
            )
        }
    }
}
