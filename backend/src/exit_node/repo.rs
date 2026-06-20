use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::exit_node::model::ExitNode;

pub async fn list_by_user(db: &PgPool, user_id: Uuid) -> AppResult<Vec<ExitNode>> {
    let rows = sqlx::query_as::<_, ExitNode>(
        "SELECT * FROM exit_nodes WHERE user_id = $1 ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn list_enabled_by_user(db: &PgPool, user_id: Uuid) -> AppResult<Vec<ExitNode>> {
    let rows = sqlx::query_as::<_, ExitNode>(
        "SELECT * FROM exit_nodes WHERE user_id = $1 AND enabled = TRUE",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

pub async fn find(db: &PgPool, user_id: Uuid, id: Uuid) -> AppResult<Option<ExitNode>> {
    let row = sqlx::query_as::<_, ExitNode>(
        "SELECT * FROM exit_nodes WHERE user_id = $1 AND id = $2",
    )
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn create(
    db: &PgPool,
    user_id: Uuid,
    name: &str,
    proxy_yaml: &str,
    enabled: bool,
) -> AppResult<ExitNode> {
    let row = sqlx::query_as::<_, ExitNode>(
        "INSERT INTO exit_nodes (user_id, name, proxy_yaml, enabled) \
         VALUES ($1,$2,$3,$4) RETURNING *",
    )
    .bind(user_id)
    .bind(name)
    .bind(proxy_yaml)
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
    proxy_yaml: &str,
    enabled: bool,
) -> AppResult<Option<ExitNode>> {
    let row = sqlx::query_as::<_, ExitNode>(
        "UPDATE exit_nodes SET name=$1, proxy_yaml=$2, enabled=$3, updated_at=NOW() \
         WHERE user_id=$4 AND id=$5 RETURNING *",
    )
    .bind(name)
    .bind(proxy_yaml)
    .bind(enabled)
    .bind(user_id)
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn delete(db: &PgPool, user_id: Uuid, id: Uuid) -> AppResult<u64> {
    let r = sqlx::query("DELETE FROM exit_nodes WHERE user_id=$1 AND id=$2")
        .bind(user_id)
        .bind(id)
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}
