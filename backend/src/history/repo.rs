use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::history::model::UpstreamHistory;

pub async fn list_by_profile(db: &PgPool, profile_id: Uuid) -> AppResult<Vec<UpstreamHistory>> {
    let rows = sqlx::query_as::<_, UpstreamHistory>(
        "SELECT * FROM upstream_history WHERE profile_id = $1 ORDER BY fetched_at DESC",
    )
    .bind(profile_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn find(db: &PgPool, profile_id: Uuid, id: Uuid) -> AppResult<Option<UpstreamHistory>> {
    let row = sqlx::query_as::<_, UpstreamHistory>(
        "SELECT * FROM upstream_history WHERE profile_id = $1 AND id = $2",
    )
    .bind(profile_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn latest_hash(db: &PgPool, profile_id: Uuid) -> AppResult<Option<String>> {
    let row = sqlx::query_scalar::<_, String>(
        "SELECT content_hash FROM upstream_history WHERE profile_id=$1 ORDER BY fetched_at DESC LIMIT 1",
    )
    .bind(profile_id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

/// 返回某条历史的"前一条" (fetched_at 更早的一条), 用于 diff
pub async fn find_previous(
    db: &PgPool,
    profile_id: Uuid,
    id: Uuid,
) -> AppResult<Option<UpstreamHistory>> {
    let row = sqlx::query_as::<_, UpstreamHistory>(
        "SELECT * FROM upstream_history \
         WHERE profile_id=$1 \
           AND fetched_at < (SELECT fetched_at FROM upstream_history WHERE id=$2) \
         ORDER BY fetched_at DESC LIMIT 1",
    )
    .bind(profile_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn create(
    db: &PgPool,
    profile_id: Uuid,
    yaml: &str,
    content_hash: &str,
    proxy_count: i32,
    trigger_kind: &str,
) -> AppResult<UpstreamHistory> {
    let row = sqlx::query_as::<_, UpstreamHistory>(
        "INSERT INTO upstream_history (profile_id, yaml, content_hash, proxy_count, trigger_kind) \
         VALUES ($1,$2,$3,$4,$5) RETURNING *",
    )
    .bind(profile_id)
    .bind(yaml)
    .bind(content_hash)
    .bind(proxy_count)
    .bind(trigger_kind)
    .fetch_one(db)
    .await?;
    Ok(row)
}

pub fn hash_yaml(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

pub fn count_proxies(yaml: &str) -> i32 {
    let v: Option<serde_yaml::Value> = serde_yaml::from_str(yaml).ok();
    v.and_then(|v| v.get("proxies").and_then(|p| p.as_sequence()).map(|s| s.len() as i32))
        .unwrap_or(0)
}
