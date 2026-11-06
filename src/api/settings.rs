use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::app::AppState;
use crate::auth::AdminUser;
use crate::problems::ProblemDetails;
use crate::settings;

use super::{ApiPath, ProblemContext};

/// The mutable Instance settings. The HMAC signing key and the `secrets`
/// table are never part of this response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SettingsResponse {
    pub instance_name: String,
    /// The IANA timezone used for daily Click buckets and display.
    pub timezone: String,
    pub click_retention_days: i64,
    pub password_unlock_ttl_seconds: i64,
}

impl From<settings::InstanceSettings> for SettingsResponse {
    fn from(settings: settings::InstanceSettings) -> Self {
        Self {
            instance_name: settings.instance_name,
            timezone: settings.timezone,
            click_retention_days: settings.click_retention_days,
            password_unlock_ttl_seconds: settings.password_unlock_ttl_seconds,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    /// A non-empty Instance name.
    pub instance_name: Option<String>,
    /// An IANA timezone name, for example `Europe/London`.
    pub timezone: Option<String>,
    /// The Click retention window in days. Must be positive.
    pub click_retention_days: Option<i64>,
    /// The password-unlock cookie lifetime in seconds. Must be positive.
    pub password_unlock_ttl_seconds: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/_/api/v1/settings",
    tag = "settings",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "The mutable Instance settings.", body = SettingsResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
) -> Result<Json<SettingsResponse>, ProblemDetails> {
    let settings = settings::load(&state.db).await.problem(&uri)?;
    Ok(Json(SettingsResponse::from(settings)))
}

#[utoipa::path(
    patch,
    path = "/_/api/v1/settings",
    tag = "settings",
    security(("bearerAuth" = [])),
    request_body = UpdateSettingsRequest,
    responses(
        (status = 200, description = "The complete updated Instance settings.", body = SettingsResponse),
        (status = 401, description = "Missing, invalid, revoked, or expired API token.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 403, description = "The current User is not an Admin.", body = ProblemDetails, content_type = "application/problem+json"),
        (status = 422, description = "A setting is invalid or the body is malformed.", body = ProblemDetails, content_type = "application/problem+json")
    )
)]
pub(super) async fn update_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
    uri: ApiPath,
    payload: Result<Json<UpdateSettingsRequest>, JsonRejection>,
) -> Result<Json<SettingsResponse>, ProblemDetails> {
    let Json(payload) = payload.problem(&uri)?;
    let settings = settings::update(
        &state.db,
        settings::SettingsChanges {
            instance_name: payload.instance_name,
            timezone: payload.timezone,
            click_retention_days: payload.click_retention_days,
            password_unlock_ttl_seconds: payload.password_unlock_ttl_seconds,
        },
    )
    .await
    .problem(&uri)?;
    Ok(Json(SettingsResponse::from(settings)))
}
