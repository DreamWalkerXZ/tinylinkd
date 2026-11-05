use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::ToSchema;

/// An RFC 9457 Problem Details response with a machine-readable `code`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: &'static str,
    pub title: &'static str,
    pub status: u16,
    pub detail: String,
    pub instance: String,
    pub code: &'static str,
}

impl ProblemDetails {
    pub fn new(
        status: StatusCode,
        code: &'static str,
        title: &'static str,
        detail: impl Into<String>,
        instance: impl Into<String>,
    ) -> Self {
        Self {
            type_uri: "about:blank",
            title,
            status: status.as_u16(),
            detail: detail.into(),
            instance: instance.into(),
            code,
        }
    }

    pub fn unauthorized(code: &'static str, detail: impl Into<String>, instance: &str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            code,
            "Unauthorized",
            detail,
            instance,
        )
    }

    pub fn not_found(detail: impl Into<String>, instance: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "not_found",
            "Not Found",
            detail,
            instance,
        )
    }

    pub fn internal_error(instance: &str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Internal Server Error",
            "An unexpected error occurred.",
            instance,
        )
    }
}

impl IntoResponse for ProblemDetails {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let is_unauthorized = status == StatusCode::UNAUTHORIZED;
        let mut response = (status, Json(self)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        if is_unauthorized {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
