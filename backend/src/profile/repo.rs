use chrono::{DateTime, Utc};
use sqlx::types::Json as SqlxJson;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::profile::model::OutputProfile;

pub async fn list_all_enabled(db: &PgPool) -> AppResult<Vec<OutputProfile>> {
    let rows = sqlx::query_as::<_, OutputProfile>(
        "SELECT * FROM output_profiles WHERE enabled = TRUE",
    )
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn list_by_user(db: &PgPool, user_id: Uuid) -> AppResult<Vec<OutputProfile>> {
    let rows = sqlx::query_as::<_, OutputProfile>(
        "SELECT * FROM output_profiles WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn find(db: &PgPool, user_id: Uuid, id: Uuid) -> AppResult<Option<OutputProfile>> {
    let row = sqlx::query_as::<_, OutputProfile>(
        "SELECT * FROM output_profiles WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn find_by_token(db: &PgPool, token: &str) -> AppResult<Option<OutputProfile>> {
    let row = sqlx::query_as::<_, OutputProfile>(
        "SELECT * FROM output_profiles WHERE sub_token = $1",
    )
    .bind(token)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    name: &str,
    sub_token: &str,
    upstream_url: &str,
    upstream_format: Option<&str>,
    bridge_node_names: &[String],
    exit_node_ids: &[Uuid],
    fetch_via_exit_node_id: Option<Uuid>,
    custom_rules: Option<&str>,
    enabled: bool,
) -> AppResult<OutputProfile> {
    let row = sqlx::query_as::<_, OutputProfile>(
        "INSERT INTO output_profiles \
         (user_id, name, sub_token, upstream_url, upstream_format, bridge_node_names, exit_node_ids, \
          fetch_via_exit_node_id, custom_rules, enabled) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *",
    )
    .bind(user_id)
    .bind(name)
    .bind(sub_token)
    .bind(upstream_url)
    .bind(upstream_format.unwrap_or("auto"))
    .bind(SqlxJson(bridge_node_names.to_vec()))
    .bind(SqlxJson(exit_node_ids.to_vec()))
    .bind(fetch_via_exit_node_id)
    .bind(custom_rules)
    .bind(enabled)
    .fetch_one(db)
    .await?;
    Ok(row)
}

pub async fn update(
    db: &PgPool,
    user_id: Uuid,
    id: Uuid,
    name: &str,
    upstream_url: &str,
    upstream_format: Option<&str>,
    bridge_node_names: &[String],
    exit_node_ids: &[Uuid],
    fetch_via_exit_node_id: Option<Uuid>,
    custom_rules: Option<&str>,
    enabled: bool,
) -> AppResult<Option<OutputProfile>> {
    let row = sqlx::query_as::<_, OutputProfile>(
        "UPDATE output_profiles SET \
            name=$1, upstream_url=$2, upstream_format=$3, bridge_node_names=$4, exit_node_ids=$5, \
            fetch_via_exit_node_id=$6, custom_rules=$7, enabled=$8, updated_at=NOW() \
         WHERE user_id=$9 AND id=$10 RETURNING *",
    )
    .bind(name)
    .bind(upstream_url)
    .bind(upstream_format.unwrap_or("auto"))
    .bind(SqlxJson(bridge_node_names.to_vec()))
    .bind(SqlxJson(exit_node_ids.to_vec()))
    .bind(fetch_via_exit_node_id)
    .bind(custom_rules)
    .bind(enabled)
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn delete(db: &PgPool, user_id: Uuid, id: Uuid) -> AppResult<u64> {
    let r = sqlx::query("DELETE FROM output_profiles WHERE user_id=$1 AND id=$2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}

pub async fn reset_token(
    db: &PgPool,
    user_id: Uuid,
    id: Uuid,
    new_token: &str,
) -> AppResult<Option<OutputProfile>> {
    let row = sqlx::query_as::<_, OutputProfile>(
        "UPDATE output_profiles SET sub_token=$1, updated_at=NOW() \
         WHERE user_id=$2 AND id=$3 RETURNING *",
    )
    .bind(new_token)
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn save_upstream_fetch(
    db: &PgPool,
    id: Uuid,
    yaml: Option<&str>,
    status: &str,
    error: Option<&str>,
    fetched_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE output_profiles SET \
            last_upstream_yaml = COALESCE($1, last_upstream_yaml), \
            last_upstream_fetched_at = $2, \
            last_upstream_fetch_status = $3, \
            last_upstream_fetch_error = $4, \
            updated_at = NOW() \
         WHERE id = $5",
    )
    .bind(yaml)
    .bind(fetched_at)
    .bind(status)
    .bind(error)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn save_generated(
    db: &PgPool,
    id: Uuid,
    yaml: &str,
    upstream_count: i32,
    bridge_count: i32,
    chain_count: i32,
    missing: &[String],
    generated_at: DateTime<Utc>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE output_profiles SET \
            cached_yaml=$1, cached_upstream_count=$2, cached_bridge_count=$3, \
            cached_chain_count=$4, cached_missing_bridges=$5, cached_at=$6, updated_at=NOW() \
         WHERE id=$7",
    )
    .bind(yaml)
    .bind(upstream_count)
    .bind(bridge_count)
    .bind(chain_count)
    .bind(SqlxJson(missing.to_vec()))
    .bind(generated_at)
    .bind(id)
    .execute(db)
    .await?;
    Ok(())
}

pub fn gen_sub_token() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
