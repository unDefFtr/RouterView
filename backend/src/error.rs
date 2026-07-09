use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Unified application error type.
///
/// All errors that can surface in HTTP handlers or the poll engine
/// are represented here.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Router API error: {0}")]
    RouterApi(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    #[error("Router unreachable")]
    RouterUnreachable,

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::RouterApi(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            AppError::HttpError(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
            AppError::Serialization(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::Config(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::RouterUnreachable => {
                (StatusCode::SERVICE_UNAVAILABLE, "Router is unreachable".into())
            }
            AppError::Database(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            AppError::InvalidData(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = Json(json!({
            "error": true,
            "message": message,
            "status": status.as_u16(),
        }));

        (status, body).into_response()
    }
}
