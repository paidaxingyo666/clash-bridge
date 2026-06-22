use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;
use tracing::error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden")]
    Forbidden,

    #[error("not found")]
    NotFound,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    /// 该订阅 / 格式组合无法表达 (如含 relay 链路的 profile 请求不支持 detour 的格式) → 415。
    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),

    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    #[error(transparent)]
    SerdeYaml(#[from] serde_yaml::Error),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("argon error: {0}")]
    Argon(argon2::password_hash::Error),

    #[error("{0}")]
    Internal(String),
}

impl From<anyhow::Error> for AppError {
    fn from(value: anyhow::Error) -> Self {
        AppError::Internal(value.to_string())
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(value: argon2::password_hash::Error) -> Self {
        AppError::Argon(value)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Upstream(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            AppError::Unsupported(m) => (StatusCode::UNSUPPORTED_MEDIA_TYPE, m.clone()),
            AppError::Sqlx(e) => {
                error!(error = ?e, "sqlx error");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
            }
            AppError::Reqwest(e) => {
                error!(error = ?e, "reqwest error");
                (StatusCode::BAD_GATEWAY, "upstream request failed".into())
            }
            AppError::SerdeYaml(e) => (StatusCode::BAD_REQUEST, format!("yaml error: {e}")),
            AppError::SerdeJson(e) => (StatusCode::BAD_REQUEST, format!("json error: {e}")),
            AppError::Jwt(_) => (StatusCode::UNAUTHORIZED, "invalid token".into()),
            AppError::Argon(_) => (StatusCode::INTERNAL_SERVER_ERROR, "hash error".into()),
            AppError::Internal(m) => {
                error!(message = %m, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, m.clone())
            }
        };

        (status, Json(json!({ "error": msg }))).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
