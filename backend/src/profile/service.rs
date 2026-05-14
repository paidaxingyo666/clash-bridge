use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::history::repo as history_repo;
use crate::profile::model::OutputProfile;
use crate::profile::repo;

pub const TRIGGER_MANUAL: &str = "manual";
pub const TRIGGER_AUTO: &str = "auto";
/// 由客户端访问 /sub URL 触发的拉取
pub const TRIGGER_CLIENT: &str = "client_fetch";

/// 拉取上游订阅，把 yaml 文本存到 profile.last_upstream_yaml。
/// 并在内容 hash 与上一条历史不同时，写一条新历史记录。
pub async fn refresh_upstream_by_profile(
    db: &PgPool,
    http: &reqwest::Client,
    profile: &OutputProfile,
    trigger: &str,
) -> AppResult<()> {
    match http.get(&profile.upstream_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if !status.is_success() {
                let err = format!("http {} — {}", status.as_u16(), snippet(&text));
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now())
                    .await?;
                return Err(AppError::Upstream(err));
            }
            if text.trim().is_empty() {
                let err = "upstream returned empty body".to_string();
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now())
                    .await?;
                return Err(AppError::Upstream(err));
            }
            // 写 profile 的 last_upstream_yaml
            repo::save_upstream_fetch(db, profile.id, Some(&text), "success", None, Utc::now())
                .await?;
            // dedup 写历史
            let hash = history_repo::hash_yaml(&text);
            let prev = history_repo::latest_hash(db, profile.id).await?;
            if prev.as_deref() != Some(hash.as_str()) {
                let cnt = history_repo::count_proxies(&text);
                history_repo::create(db, profile.id, &text, &hash, cnt, trigger).await?;
            }
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            repo::save_upstream_fetch(db, profile.id, None, "error", Some(&msg), Utc::now())
                .await?;
            Err(AppError::Upstream(msg))
        }
    }
}

/// handler 用: 先按 user_id 查 profile, 再调 _by_profile
pub async fn refresh_upstream(
    db: &PgPool,
    http: &reqwest::Client,
    user_id: Uuid,
    profile_id: Uuid,
    trigger: &str,
) -> AppResult<()> {
    let profile = repo::find(db, user_id, profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    refresh_upstream_by_profile(db, http, &profile, trigger).await
}

fn snippet(s: &str) -> String {
    let trimmed = s.trim();
    let take: String = trimmed.chars().take(200).collect();
    if trimmed.chars().count() > 200 {
        format!("{take}…")
    } else {
        take
    }
}
