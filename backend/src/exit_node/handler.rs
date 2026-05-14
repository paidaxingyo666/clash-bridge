use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::exit_node::{model::*, repo, service};
use crate::middleware::AuthUser;
use crate::state::AppState;

pub async fn list(
    State(s): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<ExitNode>>> {
    Ok(Json(repo::list_by_user(&s.db, user.id).await?))
}

pub async fn create(
    State(s): State<AppState>,
    user: AuthUser,
    Json(input): Json<ExitNodeInput>,
) -> AppResult<Json<ExitNode>> {
    if input.name.trim().is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    service::validate_proxy_yaml(&input.proxy_yaml)?;
    let row = repo::create(
        &s.db,
        user.id,
        input.name.trim(),
        &input.proxy_yaml,
        input.enabled.unwrap_or(true),
    )
    .await?;
    Ok(Json(row))
}

pub async fn update(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<ExitNodeInput>,
) -> AppResult<Json<ExitNode>> {
    service::validate_proxy_yaml(&input.proxy_yaml)?;
    let row = repo::update(
        &s.db,
        user.id,
        id,
        input.name.trim(),
        &input.proxy_yaml,
        input.enabled.unwrap_or(true),
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

pub async fn delete(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let n = repo::delete(&s.db, user.id, id).await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": n })))
}
