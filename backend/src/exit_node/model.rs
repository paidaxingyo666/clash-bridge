use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ExitNode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub proxy_yaml: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ExitNodeInput {
    pub name: String,
    pub proxy_yaml: String,
    pub enabled: Option<bool>,
}
