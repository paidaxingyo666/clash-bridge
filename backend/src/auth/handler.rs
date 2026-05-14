use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::{jwt, password, turnstile};
use crate::error::{AppError, AppResult};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::user::{model::UserView, repo as user_repo};

#[derive(Debug, Deserialize)]
pub struct AuthInput {
    pub username: String,
    pub password: String,
    /// Cloudflare Turnstile token, 仅注册接口校验. 若 env 没配 TURNSTILE_SECRET_KEY
    /// 则跳过(向后兼容本地开发).
    #[serde(default)]
    pub cf_turnstile_token: Option<String>,
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-connecting-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, Serialize)]
pub struct AuthOutput {
    pub token: String,
    pub user: UserView,
}

const USERNAME_MIN: usize = 3;
const USERNAME_MAX: usize = 32;
const PASSWORD_MIN: usize = 6;
const PASSWORD_MAX: usize = 128;

/// 规范化用户名: trim + 小写. 所有比较 / 存储都用规范化后的形式.
fn normalize_username(s: &str) -> String {
    s.trim().to_lowercase()
}

fn validate_username(s: &str) -> AppResult<()> {
    if s.len() < USERNAME_MIN || s.len() > USERNAME_MAX {
        return Err(AppError::BadRequest(format!(
            "用户名长度需 {USERNAME_MIN}-{USERNAME_MAX} 位"
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(AppError::BadRequest(
            "用户名只能含字母、数字、下划线、点和短横线".into(),
        ));
    }
    Ok(())
}

fn validate_password(s: &str) -> AppResult<()> {
    let n = s.len();
    if n < PASSWORD_MIN {
        return Err(AppError::BadRequest(format!("密码至少 {PASSWORD_MIN} 位")));
    }
    if n > PASSWORD_MAX {
        return Err(AppError::BadRequest(format!(
            "密码不能超过 {PASSWORD_MAX} 字节"
        )));
    }
    Ok(())
}

fn is_unique_violation(e: &AppError) -> bool {
    if let AppError::Sqlx(sqlx::Error::Database(db_err)) = e {
        db_err.code().as_deref() == Some("23505")
    } else {
        false
    }
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<AuthInput>,
) -> AppResult<Json<AuthOutput>> {
    let username = normalize_username(&input.username);
    validate_username(&username)?;
    validate_password(&input.password)?;

    // 若配了 Turnstile secret, 强制校验; 否则跳过(向后兼容)
    if let Some(secret) = state.config.turnstile_secret_key.as_deref() {
        let token = input
            .cf_turnstile_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AppError::BadRequest("缺少验证码".into()))?;
        let ip = client_ip(&headers);
        turnstile::verify(&state.http, secret, token, ip.as_deref()).await?;
    }

    let hash = password::hash_password(&input.password)?;
    let user = match user_repo::create(&state.db, &username, &hash).await {
        Ok(u) => u,
        // 并发同名注册时, 第二个会撞 unique index → 转友好错误
        Err(e) if is_unique_violation(&e) => {
            return Err(AppError::Conflict("用户名已被占用".into()));
        }
        Err(e) => return Err(e),
    };

    let token = jwt::issue_token(&state.config.jwt_secret, user.id, state.config.jwt_expire_hours)?;
    Ok(Json(AuthOutput {
        token,
        user: UserView::from(&user),
    }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(input): Json<AuthInput>,
) -> AppResult<Json<AuthOutput>> {
    let username = normalize_username(&input.username);
    if username.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let user = user_repo::find_by_username(&state.db, &username)
        .await?
        .ok_or(AppError::Unauthorized)?;
    if !password::verify_password(&input.password, &user.password_hash)? {
        return Err(AppError::Unauthorized);
    }
    let token = jwt::issue_token(&state.config.jwt_secret, user.id, state.config.jwt_expire_hours)?;
    Ok(Json(AuthOutput {
        token,
        user: UserView::from(&user),
    }))
}

pub async fn me(State(state): State<AppState>, user: AuthUser) -> AppResult<Json<UserView>> {
    let u = user_repo::find_by_id(&state.db, user.id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(UserView::from(&u)))
}
