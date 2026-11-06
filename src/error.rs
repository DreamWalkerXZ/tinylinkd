use std::fmt;

use axum::http::StatusCode;

use crate::problems::ProblemDetails;

/// An error from an application service, mapped to an RFC 9457 Problem Details
/// response at the HTTP boundary and to a plain message in the CLI.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized { code: &'static str, detail: String },
    Validation { code: &'static str, detail: String },
    Forbidden { detail: String },
    Conflict { code: &'static str, detail: String },
    Gone { code: &'static str, detail: String },
    NotFound { detail: String },
    Database(sqlx::Error),
    Internal(String),
}

/// The HTTP and form-facing metadata for an [`ApiError`].
///
/// Every boundary reads its status, Problem Details code and title, form error
/// code, and client-facing detail from the same place, so a new variant cannot
/// drift between the JSON API and the Admin UI.
struct ErrorMetadata<'a> {
    status: StatusCode,
    problem_code: &'static str,
    /// The code exposed to form handlers that place a message next to a field;
    /// `None` for errors that belong in a general form message.
    form_code: Option<&'static str>,
    title: &'static str,
    /// The detail to show API clients and forms. Internal errors set this too
    /// so `Display` can show it, but [`ApiError::into_problem`] hides it.
    detail: Option<&'a str>,
}

impl ApiError {
    fn metadata(&self) -> ErrorMetadata<'_> {
        match self {
            Self::Unauthorized { code, detail } => ErrorMetadata {
                status: StatusCode::UNAUTHORIZED,
                problem_code: code,
                form_code: Some(code),
                title: "Unauthorized",
                detail: Some(detail),
            },
            Self::Validation { code, detail } => ErrorMetadata {
                status: StatusCode::UNPROCESSABLE_ENTITY,
                problem_code: code,
                form_code: Some(code),
                title: "Unprocessable Entity",
                detail: Some(detail),
            },
            Self::Forbidden { detail } => ErrorMetadata {
                status: StatusCode::FORBIDDEN,
                problem_code: "forbidden",
                form_code: None,
                title: "Forbidden",
                detail: Some(detail),
            },
            Self::Conflict { code, detail } => ErrorMetadata {
                status: StatusCode::CONFLICT,
                problem_code: code,
                form_code: Some(code),
                title: "Conflict",
                detail: Some(detail),
            },
            Self::Gone { code, detail } => ErrorMetadata {
                status: StatusCode::GONE,
                problem_code: code,
                form_code: Some(code),
                title: "Gone",
                detail: Some(detail),
            },
            Self::NotFound { detail } => ErrorMetadata {
                status: StatusCode::NOT_FOUND,
                problem_code: "not_found",
                form_code: None,
                title: "Not Found",
                detail: Some(detail),
            },
            Self::Database(_) => ErrorMetadata {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                problem_code: "internal_error",
                form_code: None,
                title: "Internal Server Error",
                detail: None,
            },
            Self::Internal(detail) => ErrorMetadata {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                problem_code: "internal_error",
                form_code: None,
                title: "Internal Server Error",
                detail: Some(detail),
            },
        }
    }

    pub fn unauthorized(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Unauthorized {
            code,
            detail: detail.into(),
        }
    }

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

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::Forbidden {
            detail: detail.into(),
        }
    }

    pub fn gone(code: &'static str, detail: impl Into<String>) -> Self {
        Self::Gone {
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
        self.metadata().status
    }

    /// The machine-readable code, when this error has one. The admin UI uses
    /// it to place a validation message next to the offending form field.
    pub fn code(&self) -> Option<&'static str> {
        self.metadata().form_code
    }

    pub fn into_problem(self, instance: &str) -> ProblemDetails {
        let metadata = self.metadata();
        if metadata.status.is_server_error() {
            match &self {
                Self::Database(error) => tracing::error!(error = %error, "database error"),
                Self::Internal(detail) => tracing::error!(detail = %detail, "internal error"),
                _ => {}
            }
            return ProblemDetails::internal_error(instance);
        }
        ProblemDetails::new(
            metadata.status,
            metadata.problem_code,
            metadata.title,
            metadata.detail.unwrap_or_default(),
            instance,
        )
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(formatter, "database error: {error}"),
            _ => formatter.write_str(self.metadata().detail.unwrap_or_default()),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}
