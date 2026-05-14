use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct UpstreamHistory {
    pub id: Uuid,
    pub profile_id: Uuid,
    pub yaml: String,
    pub content_hash: String,
    pub proxy_count: i32,
    pub trigger_kind: String,
    pub fetched_at: DateTime<Utc>,
}

/// 列表视图: 不带 yaml 大字段
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamHistorySummary {
    pub id: Uuid,
    pub content_hash: String,
    pub proxy_count: i32,
    pub trigger_kind: String,
    pub fetched_at: DateTime<Utc>,
}

impl From<&UpstreamHistory> for UpstreamHistorySummary {
    fn from(h: &UpstreamHistory) -> Self {
        Self {
            id: h.id,
            content_hash: h.content_hash.clone(),
            proxy_count: h.proxy_count,
            trigger_kind: h.trigger_kind.clone(),
            fetched_at: h.fetched_at,
        }
    }
}
