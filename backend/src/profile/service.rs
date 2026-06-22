use std::time::Duration;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::exit_node::{repo as exit_repo, service as exit_service};
use crate::history::repo as history_repo;
use crate::parser::{self, SubFormat};
use crate::profile::model::OutputProfile;
use crate::profile::repo;

pub const TRIGGER_MANUAL: &str = "manual";
pub const TRIGGER_AUTO: &str = "auto";
/// 由客户端访问 /sub URL 触发的拉取
pub const TRIGGER_CLIENT: &str = "client_fetch";

/// 上游订阅 body 大小上限 (8 MiB). 超过即拒绝, 防止内存被超大响应撑爆.
const MAX_UPSTREAM_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// 拉取上游订阅，把 yaml 文本存到 profile.last_upstream_yaml。
/// 并在内容 hash 与上一条历史不同时，写一条新历史记录。
///
/// 若 profile.fetch_via_exit_node_id 非空, 现场构造一个走该 exit_node 出口
/// 的临时 reqwest client (仅 socks5 / http 类型节点可用), 用一次即丢.
/// 这样不污染全局 http; 不同 profile 互不影响.
pub async fn refresh_upstream_by_profile(
    db: &PgPool,
    http: &reqwest::Client,
    profile: &OutputProfile,
    trigger: &str,
) -> AppResult<()> {
    // 决定本次用哪个 client. 若 exit_node 配置坏, 直接把错误落库并返回.
    let client_holder: Option<reqwest::Client> = match profile.fetch_via_exit_node_id {
        None => None,
        Some(node_id) => match build_proxied_client(db, profile.user_id, node_id).await {
            Ok(c) => Some(c),
            Err(e) => {
                let msg = format!("exit_node 代理不可用: {e}");
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&msg), Utc::now())
                    .await?;
                return Err(e);
            }
        },
    };
    let client = client_holder.as_ref().unwrap_or(http);

    match client.get(&profile.upstream_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            // body 大小上限 (第一保险): Content-Length 已超过即拒, 不读 body.
            if let Some(len) = resp.content_length() {
                if len > MAX_UPSTREAM_BODY_BYTES {
                    let err = format!(
                        "上游响应体过大 ({} 字节 > {} 字节上限), 拒绝处理",
                        len, MAX_UPSTREAM_BODY_BYTES
                    );
                    repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now())
                        .await?;
                    return Err(AppError::Upstream(err));
                }
            }
            let text = resp.text().await.unwrap_or_default();
            // body 大小上限 (第二保险, 防 chunked 无 Content-Length).
            if text.len() as u64 > MAX_UPSTREAM_BODY_BYTES {
                let err = format!(
                    "上游响应体过大 ({} 字节 > {} 字节上限), 拒绝处理",
                    text.len(),
                    MAX_UPSTREAM_BODY_BYTES
                );
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now())
                    .await?;
                return Err(AppError::Upstream(err));
            }
            if !status.is_success() {
                let err = format_http_error(status.as_u16(), &text);
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

            // 归一化层: 把任意订阅格式 (clash/base64/uri/sip008) 转成统一 IR =
            // {proxies: [...]} 的 Clash YAML, 再存库. 下游 generator/extract_nodes 不变.
            let hint = SubFormat::from_opt(profile.upstream_format.as_deref());
            let clash_yaml = match parser::normalize_to_clash_yaml(&text, hint) {
                Ok((yaml, _count)) => yaml,
                Err(e) => {
                    // 归一化失败: 不覆盖旧缓存 (yaml=None → COALESCE 保留), 仅落 error 状态.
                    let err = format!("订阅格式解析失败: {e}");
                    repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now())
                        .await?;
                    return Err(AppError::BadRequest(err));
                }
            };

            // 写 profile 的 last_upstream_yaml (归一化后的 Clash YAML)
            repo::save_upstream_fetch(db, profile.id, Some(&clash_yaml), "success", None, Utc::now())
                .await?;
            // dedup 写历史 (基于归一化后的内容 hash)
            let hash = history_repo::hash_yaml(&clash_yaml);
            let prev = history_repo::latest_hash(db, profile.id).await?;
            if prev.as_deref() != Some(hash.as_str()) {
                let cnt = history_repo::count_proxies(&clash_yaml);
                history_repo::create(db, profile.id, &clash_yaml, &hash, cnt, trigger).await?;
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

/// 按 exit_node 现场构造一次性 reqwest client. 走代理时 RTT 会高,
/// 超时给宽到 45s, 保留 mihomo UA (大量机场按 UA 分发 yaml 格式).
async fn build_proxied_client(
    db: &PgPool,
    user_id: Uuid,
    node_id: Uuid,
) -> AppResult<reqwest::Client> {
    let node = exit_repo::find(db, user_id, node_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("fetch_via_exit_node 不存在".into()))?;
    let proxy_url = exit_service::proxy_url_from_yaml(&node.proxy_yaml)?;
    let proxy = reqwest::Proxy::all(proxy_url)
        .map_err(|e| AppError::Internal(format!("构造 reqwest::Proxy 失败: {e}")))?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(45))
        .user_agent("clash.meta/1.18.0")
        .redirect(reqwest::redirect::Policy::limited(3))
        .proxy(proxy)
        .build()
        .map_err(|e| AppError::Internal(format!("构造代理 client 失败: {e}")))
}

/// 把上游返回的失败 body 翻成给用户看的短消息.
/// 识别 cloudflare bot challenge / 普通 4xx-5xx, 避免巨型 HTML 塞满 last_upstream_fetch_error 字段.
fn format_http_error(code: u16, body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    let is_cf_challenge = lower.contains("cdn-cgi/challenge-platform")
        || lower.contains("just a moment")
        || lower.contains("cf-ray")
        || lower.contains("__cf$cv$params");
    let is_html = lower.contains("<!doctype html") || lower.contains("<html");

    if is_cf_challenge {
        return format!("上游 Cloudflare 反爬拦截 (HTTP {code}). 此机场对非浏览器请求做了 JS challenge, 服务器拉不到 — 请用客户端缓存或换订阅源.");
    }
    if is_html {
        // HTML 错误页, body 大概率是装修页, 只保留 title 或前若干字
        let title = extract_html_title(body)
            .unwrap_or_else(|| snippet(body, 120));
        return format!("HTTP {code}: {title}");
    }
    // 纯文本错误, 直接截断
    format!("HTTP {code}: {}", snippet(body, 200))
}

fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + 7;
    let rest = &html[start..];
    let end = rest.to_ascii_lowercase().find("</title>")?;
    let title = rest[..end].trim();
    if title.is_empty() {
        None
    } else {
        Some(title.to_string())
    }
}

fn snippet(s: &str, max_chars: usize) -> String {
    let trimmed = s.trim();
    let take: String = trimmed.chars().take(max_chars).collect();
    if trimmed.chars().count() > max_chars {
        format!("{take}…")
    } else {
        take
    }
}
