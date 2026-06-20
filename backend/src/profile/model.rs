use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::types::Json as SqlxJson;
use sqlx::FromRow;
use uuid::Uuid;

/// 行级 — 直接从 DB 取出
#[derive(Debug, Clone, FromRow)]
pub struct OutputProfile {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub sub_token: String,

    pub upstream_url: String,
    pub last_upstream_yaml: Option<String>,
    pub last_upstream_fetched_at: Option<DateTime<Utc>>,
    pub last_upstream_fetch_status: Option<String>,
    pub last_upstream_fetch_error: Option<String>,

    pub bridge_node_names: SqlxJson<Vec<String>>,
    pub exit_node_ids: SqlxJson<Vec<Uuid>>,

    /// 拉取上游订阅时, 经此 exit_node (必须是 socks5 / http 类型) 出去.
    /// 用于绕过上游对数据中心 IP 的封禁. NULL = 直连.
    pub fetch_via_exit_node_id: Option<Uuid>,

    pub custom_rules: Option<String>,
    pub enabled: bool,

    pub cached_yaml: Option<String>,
    pub cached_upstream_count: i32,
    pub cached_bridge_count: i32,
    pub cached_chain_count: i32,
    pub cached_missing_bridges: SqlxJson<Vec<String>>,
    pub cached_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 给前端的视图 — 不含大文本 (yaml)
#[derive(Debug, Clone, Serialize)]
pub struct OutputProfileView {
    pub id: Uuid,
    pub name: String,
    pub sub_token: String,

    pub upstream_url: String,
    pub last_upstream_fetched_at: Option<DateTime<Utc>>,
    pub last_upstream_fetch_status: Option<String>,
    pub last_upstream_fetch_error: Option<String>,

    pub bridge_node_names: Vec<String>,
    pub exit_node_ids: Vec<Uuid>,
    pub fetch_via_exit_node_id: Option<Uuid>,

    pub custom_rules: Option<String>,
    pub enabled: bool,

    pub cached_upstream_count: i32,
    pub cached_bridge_count: i32,
    pub cached_chain_count: i32,
    pub cached_missing_bridges: Vec<String>,
    pub cached_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&OutputProfile> for OutputProfileView {
    fn from(p: &OutputProfile) -> Self {
        Self {
            id: p.id,
            name: p.name.clone(),
            sub_token: p.sub_token.clone(),
            upstream_url: p.upstream_url.clone(),
            last_upstream_fetched_at: p.last_upstream_fetched_at,
            last_upstream_fetch_status: p.last_upstream_fetch_status.clone(),
            last_upstream_fetch_error: p.last_upstream_fetch_error.clone(),
            bridge_node_names: p.bridge_node_names.0.clone(),
            exit_node_ids: p.exit_node_ids.0.clone(),
            fetch_via_exit_node_id: p.fetch_via_exit_node_id,
            custom_rules: p.custom_rules.clone(),
            enabled: p.enabled,
            cached_upstream_count: p.cached_upstream_count,
            cached_bridge_count: p.cached_bridge_count,
            cached_chain_count: p.cached_chain_count,
            cached_missing_bridges: p.cached_missing_bridges.0.clone(),
            cached_at: p.cached_at,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ProfileInput {
    pub name: String,
    pub upstream_url: String,
    pub bridge_node_names: Vec<String>,
    pub exit_node_ids: Vec<Uuid>,
    #[serde(default)]
    pub fetch_via_exit_node_id: Option<Uuid>,
    pub custom_rules: Option<String>,
    pub enabled: Option<bool>,
}

/// /api/profiles/:id/nodes 返回的单个节点
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamNode {
    pub name: String,
    pub r#type: Option<String>,
    pub server: Option<String>,
    pub port: Option<i64>,
}
