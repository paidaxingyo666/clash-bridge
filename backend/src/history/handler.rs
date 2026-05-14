use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::history::{model::*, repo};
use crate::middleware::AuthUser;
use crate::profile::repo as profile_repo;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct HistoryItemView {
    pub id: Uuid,
    pub content_hash: String,
    pub proxy_count: i32,
    pub trigger_kind: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub has_previous: bool,
}

/// GET /api/profiles/:pid/history
pub async fn list(
    State(s): State<AppState>,
    user: AuthUser,
    Path(pid): Path<Uuid>,
) -> AppResult<Json<Vec<HistoryItemView>>> {
    // 鉴权: 确保 profile 属于当前用户
    profile_repo::find(&s.db, user.id, pid)
        .await?
        .ok_or(AppError::NotFound)?;
    let rows = repo::list_by_profile(&s.db, pid).await?;
    // 列表是按 fetched_at DESC, 最后一条没有 previous
    let n = rows.len();
    let out: Vec<HistoryItemView> = rows
        .iter()
        .enumerate()
        .map(|(i, h)| {
            let summary = UpstreamHistorySummary::from(h);
            HistoryItemView {
                id: summary.id,
                content_hash: summary.content_hash,
                proxy_count: summary.proxy_count,
                trigger_kind: summary.trigger_kind,
                fetched_at: summary.fetched_at,
                has_previous: i < n - 1, // DESC 排序, i 不是最后一个 = 有更早的
            }
        })
        .collect();
    Ok(Json(out))
}

/// GET /api/profiles/:pid/history/:hid -> 返回 yaml text
pub async fn get_yaml(
    State(s): State<AppState>,
    user: AuthUser,
    Path((pid, hid)): Path<(Uuid, Uuid)>,
) -> AppResult<axum::response::Response> {
    profile_repo::find(&s.db, user.id, pid)
        .await?
        .ok_or(AppError::NotFound)?;
    let h = repo::find(&s.db, pid, hid).await?.ok_or(AppError::NotFound)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        h.yaml,
    )
        .into_response())
}

/// GET /api/profiles/:pid/history/:hid/previous -> 该条历史的前一版 (供 diff)
pub async fn get_previous_yaml(
    State(s): State<AppState>,
    user: AuthUser,
    Path((pid, hid)): Path<(Uuid, Uuid)>,
) -> AppResult<axum::response::Response> {
    profile_repo::find(&s.db, user.id, pid)
        .await?
        .ok_or(AppError::NotFound)?;
    let prev = repo::find_previous(&s.db, pid, hid)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        prev.yaml,
    )
        .into_response())
}
