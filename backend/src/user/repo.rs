use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppResult;
use crate::user::model::User;

pub async fn find_by_id(db: &PgPool, id: Uuid) -> AppResult<Option<User>> {
    let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await?;
    Ok(row)
}

pub async fn find_by_username(db: &PgPool, username: &str) -> AppResult<Option<User>> {
    let row = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(db)
        .await?;
    Ok(row)
}

pub async fn create(db: &PgPool, username: &str, password_hash: &str) -> AppResult<User> {
    let row = sqlx::query_as::<_, User>(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *",
    )
    .bind(username)
    .bind(password_hash)
    .fetch_one(db)
    .await?;
    Ok(row)
}
