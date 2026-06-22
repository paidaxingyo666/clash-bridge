use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::header;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use chrono::Utc;
use dashmap::DashMap;
use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::generator::service as gen_service;
use crate::profile::{repo as profile_repo, service as profile_service};
use crate::state::AppState;

/// 客户端访问 /sub 时, 距上次成功拉取上游不到这个秒数就不再实时拉, 用缓存的 last_upstream_yaml 重新生成.
/// 防止客户端高频拉订阅时反复打机场 / 被 ban IP.
const SUB_MIN_REFRESH_SECS: i64 = 30;

/// 每个 sub_token 一分钟内允许的访问次数. 超过的请求**不会被拒绝**, 但会跳过
/// 实时拉上游, 直接走 cached_yaml — 这样能保证客户端拉订阅永远不失败, 同时
/// 防止 token 泄漏后被高频拉、拖累机场 / 我们的服务.
const SUB_RATE_PER_MIN: usize = 5;

static SUB_HITS: OnceLock<DashMap<String, Vec<Instant>>> = OnceLock::new();

/// 记录这次访问, 返回"是否仍在配额内 (可以实时拉机场)".
fn within_sub_rate(token: &str) -> bool {
    let map = SUB_HITS.get_or_init(DashMap::new);
    let now = Instant::now();
    let window = Duration::from_secs(60);
    let mut entry = map.entry(token.to_string()).or_default();
    entry.retain(|t| now.duration_since(*t) < window);
    let allowed = entry.len() < SUB_RATE_PER_MIN;
    entry.push(now);
    allowed
}

/// GET /sub/:token/clash.yaml — 公开. 每次请求实时拉上游 + 实时生成 yaml.
/// 失败 (上游不可达 / 解析失败 etc) 时回退到 cached_yaml.
/// 静态段路由, 等价于 format=clash.yaml; 保留以向后兼容旧链接 + cached fallback.
pub async fn public_subscription(
    State(s): State<AppState>,
    Path(token): Path<String>,
) -> AppResult<axum::response::Response> {
    serve_subscription(s, token, "clash.yaml").await
}

/// GET /sub/:token/:format — 公开. 多格式订阅.
/// format ∈ {clash.yaml, singbox.json, sub.txt, surge.conf, quanx.conf}.
/// clash.yaml 走 cached fallback; 其他格式实时生成失败直接报错 (不把 clash YAML 当 json 返回).
pub async fn public_subscription_fmt(
    State(s): State<AppState>,
    Path((token, format)): Path<(String, String)>,
) -> AppResult<axum::response::Response> {
    serve_subscription(s, token, &format).await
}

async fn serve_subscription(
    s: AppState,
    token: String,
    format: &str,
) -> AppResult<axum::response::Response> {
    let profile = profile_repo::find_by_token(&s.db, &token)
        .await?
        .ok_or(AppError::NotFound)?;
    if !profile.enabled {
        return Err(AppError::NotFound);
    }

    // 1. 实时拉一次上游, 受三层节流:
    //    a) SUB_MIN_REFRESH_SECS:  距上次成功拉 < 30s 不重拉
    //    b) within_sub_rate:        每 token 每分钟最多 SUB_RATE_PER_MIN 次实时拉,
    //                              超过则走 cached_yaml (不拒绝客户端)
    let rate_ok = within_sub_rate(&token);
    let recent_enough = match profile.last_upstream_fetched_at {
        Some(t) => (Utc::now() - t).num_seconds() < SUB_MIN_REFRESH_SECS,
        None => false,
    };
    let should_refresh = rate_ok && !recent_enough;
    if !rate_ok {
        warn!(
            sub_token_prefix = &token[..token.len().min(8)],
            "/sub: token rate limit hit, serving from cache"
        );
    }
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

    // 2. 重新读 profile (last_upstream_yaml / userinfo / 时间可能刚被刷新), 然后实时生成.
    //    重读拿到最新的 last_upstream_userinfo, 透传给客户端做流量条.
    let user_id = profile.user_id;
    let profile_id = profile.id;
    let refreshed = profile_repo::find_by_token(&s.db, &token).await?;
    let upstream_userinfo = refreshed
        .as_ref()
        .and_then(|p| p.last_upstream_userinfo.clone())
        .or_else(|| profile.last_upstream_userinfo.clone());

    match gen_service::build_and_cache_fmt(&s.db, user_id, profile_id, format).await {
        Ok(out) => Ok(rendered_response(
            &profile.name,
            out.rendered,
            upstream_userinfo.as_deref(),
        )),
        Err(e) => {
            // 非 clash 格式: 失败不回退 cached_yaml (cached 是 clash YAML, 当 json 返回会让客户端连不上).
            // 415 / 404 / 暂未实现 等明确错误也直接抛出.
            if format != "clash.yaml" || matches!(e, AppError::Unsupported(_) | AppError::NotFound) {
                return Err(e);
            }
            warn!(error = ?e, "/sub: live generate failed, fallback to cached_yaml");
            // 复用上面重读的 refreshed 取 cached_yaml (build_and_cache 失败时没机会写, 用之前缓存的)
            let cached = refreshed
                .and_then(|p| p.cached_yaml)
                .ok_or_else(|| AppError::BadRequest(format!(
                    "无法实时生成订阅且无缓存可用: {e}"
                )))?;
            let rendered = crate::generator::render::RenderedSub::new(
                cached,
                "application/yaml; charset=utf-8",
                "yaml",
            );
            Ok(rendered_response(&profile.name, rendered, upstream_userinfo.as_deref()))
        }
    }
}

/// 计算回给客户端的 `subscription-userinfo` 头值: 优先透传上游真实配额, 空/None 才回退默认 0 骨架.
/// 抽成纯函数便于单测.
fn subscription_userinfo_header(upstream: Option<&str>) -> String {
    match upstream {
        Some(u) if !u.trim().is_empty() => u.to_string(),
        // mihomo / Clash Verge 通过这个 header 显示流量配额; 无上游数据时给空头骨架.
        _ => "upload=0; download=0; total=0; expire=0".to_string(),
    }
}

/// 泛化的订阅响应: Content-Type / Content-Disposition 由 RenderedSub 决定;
/// 渲染时被跳过的协议经 `X-Skipped-Protocols` 头透出, 避免静默丢节点.
fn rendered_response(
    profile_name: &str,
    rendered: crate::generator::render::RenderedSub,
    upstream_userinfo: Option<&str>,
) -> axum::response::Response {
    let mut resp = (StatusCode::OK, rendered.body).into_response();
    let h = resp.headers_mut();
    if let Ok(v) = header::HeaderValue::from_str(rendered.content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = header::HeaderValue::from_str(&build_content_disposition(
        profile_name,
        rendered.filename_ext,
    )) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    if let Ok(v) = header::HeaderValue::from_str(&subscription_userinfo_header(upstream_userinfo)) {
        h.insert(
            header::HeaderName::from_static("subscription-userinfo"),
            v,
        );
    }
    if !rendered.skipped.is_empty() {
        // skipped 项可能含上游节点名 (非 ASCII / 控制字符), 直接进 header 会让 from_str 失败、
        // 整条头丢失。逐项 sanitize 为可见 ASCII, 保证头一定能设上。
        let safe = sanitize_skipped_header(&rendered.skipped);
        if let Ok(v) = header::HeaderValue::from_str(&safe) {
            h.insert(header::HeaderName::from_static("x-skipped-protocols"), v);
        }
    }
    resp
}

/// 把 skipped 列表拼成 header-safe 字符串: 每项非 ASCII / 控制字符替换为 '_',
/// 保留可见 ASCII (含冒号分隔的类型前缀如 `ssr` / `tuic-v4` / `rule-dangling-target`)。
fn sanitize_skipped_header(skipped: &[String]) -> String {
    skipped
        .iter()
        .map(|s| {
            s.chars()
                .map(|c| {
                    if c.is_ascii() && !c.is_ascii_control() {
                        c
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// RFC 6266 Content-Disposition. 不带引号; 含中文等非 ASCII 时再带 RFC 5987 `filename*=UTF-8''…`.
/// `ext` 为文件扩展名 (不含点), 如 `yaml` / `json` / `conf`.
fn build_content_disposition(profile_name: &str, ext: &str) -> String {
    let ascii = sanitize_ascii(profile_name);
    let all_safe_ascii = profile_name
        .chars()
        .all(|c| c.is_ascii() && safe_ascii_char(c));
    if all_safe_ascii && !profile_name.is_empty() {
        format!("attachment; filename={ascii}.{ext}")
    } else {
        let pct = percent_encode_utf8(profile_name);
        format!("attachment; filename={ascii}.{ext}; filename*=UTF-8''{pct}.{ext}")
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

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_SKELETON: &str = "upload=0; download=0; total=0; expire=0";

    #[test]
    fn userinfo_passthrough_when_upstream_present() {
        // 有上游 userinfo → 原样透传 (真实流量配额)
        let upstream = "upload=123; download=456; total=1000000; expire=1700000000";
        assert_eq!(
            subscription_userinfo_header(Some(upstream)),
            upstream
        );
    }

    #[test]
    fn userinfo_fallback_when_none() {
        // None → 回退默认 0 骨架
        assert_eq!(subscription_userinfo_header(None), DEFAULT_SKELETON);
    }

    #[test]
    fn userinfo_fallback_when_empty_or_blank() {
        // 空串 / 纯空白 → 回退默认 0 骨架
        assert_eq!(subscription_userinfo_header(Some("")), DEFAULT_SKELETON);
        assert_eq!(subscription_userinfo_header(Some("   ")), DEFAULT_SKELETON);
    }

    #[test]
    fn skipped_header_sanitizes_non_ascii() {
        // 含中文 / 控制字符的节点名 → 非 ASCII 替换为 '_', 整条头仍可设上。
        let skipped = vec![
            "ssr:香港节点".to_string(),
            "tuic-v4:JP\u{7}01".to_string(),
            "rule-dangling-target:Proxies".to_string(),
        ];
        let s = sanitize_skipped_header(&skipped);
        // 结果必须是合法 header value。
        assert!(header::HeaderValue::from_str(&s).is_ok());
        assert!(s.contains("ssr:"));
        assert!(s.contains("tuic-v4:JP_01"));
        assert!(s.contains("rule-dangling-target:Proxies"));
        // 不含任何非 ASCII / 控制字符。
        assert!(s.chars().all(|c| c.is_ascii() && !c.is_ascii_control()));
    }
}
