use std::fmt;

use axum::http::StatusCode;

use crate::problems::ProblemDetails;

/// An error from an application service, mapped to an RFC 9457 Problem Details
/// response at the HTTP boundary and to a plain message in the CLI.
#[derive(Debug)]
pub enum ApiError {
    Validation { code: &'static str, detail: String },
    Conflict { code: &'static str, detail: String },
    NotFound { detail: String },
    Database(sqlx::Error),
    Internal(String),
}

impl ApiError {
    pub fn validation(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Validation {
            code,
            detail: detail.into(),
        }
    }

    pub fn conflict(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            detail: detail.into(),
        }
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::NotFound {
            detail: detail.into(),
        }
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::Internal(detail.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict { .. } => StatusCode::CONFLICT,
            Self::NotFound { .. } => StatusCode::NOT_FOUND,
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn into_problem(self, instance: &str) -> ProblemDetails {
        let status = self.status();
        match self {
            Self::Validation { code, detail } => {
                ProblemDetails::new(status, code, "Unprocessable Entity", detail, instance)
            }
            Self::Conflict { code, detail } => {
                ProblemDetails::new(status, code, "Conflict", detail, instance)
            }
            Self::NotFound { detail } => ProblemDetails::not_found(detail, instance),
            Self::Database(error) => {
                tracing::error!(error = %error, "database error");
                ProblemDetails::internal_error(instance)
            }
            Self::Internal(detail) => {
                tracing::error!(detail = %detail, "internal error");
                ProblemDetails::internal_error(instance)
            }
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation { detail, .. }
            | Self::Conflict { detail, .. }
            | Self::NotFound { detail } => formatter.write_str(detail),
            Self::Database(error) => write!(formatter, "database error: {error}"),
            Self::Internal(detail) => formatter.write_str(detail),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
