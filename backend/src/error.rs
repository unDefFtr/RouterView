use axum::{
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        FromRequest, FromRequestParts, Path, Query, Request,
    },
    http::{header, request::Parts, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use serde_json::json;

/// JSON extractor that preserves Axum's status while using the application error envelope.
pub struct ApiJson<T>(pub T);

pub struct ApiQuery<T>(pub T);

pub struct ApiPath<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|rejection: JsonRejection| AppError::InvalidRequest {
                status: rejection.status(),
                code: "invalid_json",
                message: rejection.body_text(),
            })
    }
}

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| Self(value))
            .map_err(|rejection: QueryRejection| AppError::InvalidRequest {
                status: rejection.status(),
                code: "invalid_query",
                message: rejection.body_text(),
            })
    }
}

impl<S, T> FromRequestParts<S> for ApiPath<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|rejection: PathRejection| AppError::InvalidRequest {
                status: rejection.status(),
                code: "invalid_path",
                message: rejection.body_text(),
            })
    }
}

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

    #[error("Invalid request: {message}")]
    InvalidRequest {
        status: StatusCode,
        code: &'static str,
        message: String,
    },

    #[error("Authentication required")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Too many requests")]
    RateLimited { retry_after_secs: u64 },

    #[error("Route not found")]
    NotFound,

    #[error("Method not allowed")]
    MethodNotAllowed,

    #[error("Secret storage error: {0}")]
    Secret(String),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::RouterApi(_) => (
                StatusCode::BAD_GATEWAY,
                "router_api_error",
                "The router request failed".to_string(),
            ),
            AppError::HttpError(_) => (
                StatusCode::BAD_GATEWAY,
                "router_unreachable",
                "The router request failed".to_string(),
            ),
            AppError::Serialization(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "serialization_error",
                "An internal serialization error occurred".to_string(),
            ),
            AppError::Config(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                e.to_string(),
            ),
            AppError::RouterUnreachable => (
                StatusCode::SERVICE_UNAVAILABLE,
                "router_unreachable",
                "Router is unreachable".into(),
            ),
            AppError::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "A database operation failed".to_string(),
            ),
            AppError::InvalidData(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_data",
                msg.clone(),
            ),
            AppError::InvalidRequest {
                status,
                code,
                message,
            } => (*status, *code, message.clone()),
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required".to_string(),
            ),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            AppError::RateLimited { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many authentication attempts".to_string(),
            ),
            AppError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "Route not found".to_string(),
            ),
            AppError::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "Method not allowed".to_string(),
            ),
            AppError::Secret(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret_error",
                "Credential storage is unavailable".to_string(),
            ),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An internal error occurred".to_string(),
            ),
        };

        if status.is_server_error() {
            tracing::error!(error = %self, "request failed");
        }

        let request_id = uuid::Uuid::new_v4().to_string();

        let body = Json(json!({
            "error": {
                "code": code,
                "message": message,
                "fields": {},
                "request_id": request_id,
            }
        }));

        let mut response = (status, body).into_response();
        if let AppError::RateLimited { retry_after_secs } = self {
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
        }
        response
    }
}

pub async fn not_found() -> AppError {
    AppError::NotFound
}

pub async fn method_not_allowed() -> AppError {
    AppError::MethodNotAllowed
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct ExampleBody {
        _name: String,
    }

    #[tokio::test]
    async fn api_json_maps_rejections_to_app_error() {
        let request = Request::builder()
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        let error = ApiJson::<ExampleBody>::from_request(request, &())
            .await
            .err()
            .unwrap();
        assert!(matches!(
            error,
            AppError::InvalidRequest {
                status: StatusCode::BAD_REQUEST,
                code: "invalid_json",
                ..
            }
        ));
    }

    #[test]
    fn rate_limit_response_has_retry_after() {
        let response = AppError::RateLimited {
            retry_after_secs: 7,
        }
        .into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "7");
    }

    #[test]
    fn fallback_errors_have_expected_statuses() {
        assert_eq!(
            AppError::NotFound.into_response().status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::MethodNotAllowed.into_response().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
}
