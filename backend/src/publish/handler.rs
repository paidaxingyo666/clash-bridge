use axum::extract::{Path, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::generator::service as gen_service;
use crate::profile::{repo as profile_repo, service as profile_service};
use crate::state::AppState;

/// 客户端访问 /sub 时, 距上次成功拉取上游不到这个秒数就不再实时拉, 用缓存的 last_upstream_yaml 重新生成.
/// 防止客户端高频拉订阅时反复打机场 / 被 ban IP.
const SUB_MIN_REFRESH_SECS: i64 = 30;

/// GET /sub/:token/clash.yaml — 公开. 每次请求实时拉上游 + 实时生成 yaml.
/// 失败 (上游不可达 / 解析失败 etc) 时回退到 cached_yaml.
pub async fn public_subscription(
    State(s): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<axum::response::Response> {
    let profile = profile_repo::find_by_token(&s.db, &token)
        .await?
        .ok_or(AppError::NotFound)?;
    if !profile.enabled {
        return Err(AppError::NotFound);
    }

    // 1. 实时拉一次上游 (受 SUB_MIN_REFRESH_SECS 节流). 失败不致命.
    let should_refresh = match profile.last_upstream_fetched_at {
        Some(t) => (Utc::now() - t).num_seconds() >= SUB_MIN_REFRESH_SECS,
        None => true,
    };
    if should_refresh {
        if let Err(e) = profile_service::refresh_upstream_by_profile(
            &s.db,
            &s.http,
            &profile,
            profile_service::TRIGGER_CLIENT,
        )
        .await
        {
            // 拉取失败不直接返回错误, 后面会尝试用上次成功的 last_upstream_yaml 生成
            warn!(
                profile_id = %profile.id,
                error = ?e,
                "/sub: upstream refresh failed, will try cached"
            );
        }
    }

    // 2. 重新读 profile (last_upstream_yaml / 时间可能刚被刷新), 然后实时生成
    let user_id = profile.user_id;
    let profile_id = profile.id;
    match gen_service::build_and_cache(&s.db, user_id, profile_id).await {
        Ok(out) => Ok(yaml_response(&profile.name, out.yaml)),
        Err(e) => {
            warn!(error = ?e, "/sub: live generate failed, fallback to cached_yaml");
            // 重新读最新的 cached_yaml (因为 build_and_cache 可能没机会写, 用之前的)
            let refreshed = profile_repo::find_by_token(&s.db, &token).await?;
            let cached = refreshed
                .and_then(|p| p.cached_yaml)
                .ok_or_else(|| AppError::BadRequest(format!(
                    "无法实时生成订阅且无缓存可用: {e}"
                )))?;
            Ok(yaml_response(&profile.name, cached))
        }
    }
}

fn yaml_response(profile_name: &str, body: String) -> axum::response::Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/yaml; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, build_content_disposition(profile_name)),
            // mihomo / Clash Verge 通过这个 header 显示流量配额；我们没有真实数据，给一个空头骨架
            (
                header::HeaderName::from_static("subscription-userinfo"),
                "upload=0; download=0; total=0; expire=0".to_string(),
            ),
        ],
        body,
    )
        .into_response()
}

/// RFC 6266 Content-Disposition. 不带引号; 含中文等非 ASCII 时再带 RFC 5987 `filename*=UTF-8''…`.
fn build_content_disposition(profile_name: &str) -> String {
    let ascii = sanitize_ascii(profile_name);
    let all_safe_ascii = profile_name
        .chars()
        .all(|c| c.is_ascii() && safe_ascii_char(c));
    if all_safe_ascii && !profile_name.is_empty() {
        format!("attachment; filename={ascii}.yaml")
    } else {
        let pct = percent_encode_utf8(profile_name);
        format!("attachment; filename={ascii}.yaml; filename*=UTF-8''{pct}.yaml")
    }
}

fn safe_ascii_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

fn sanitize_ascii(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if safe_ascii_char(c) { c } else { '_' })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "subscription".into()
    } else {
        trimmed.to_string()
    }
}

fn percent_encode_utf8(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
