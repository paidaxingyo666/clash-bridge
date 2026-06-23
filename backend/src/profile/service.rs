use std::time::Duration;

use chrono::Utc;
use futures_util::StreamExt;
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
/// 用户在自己浏览器拉到上游内容后手动粘贴更新 (绕过机场封服务器 IP)
pub const TRIGGER_MANUAL_PASTE: &str = "manual_paste";

/// 上游订阅 body 大小上限 (8 MiB). 超过即拒绝, 防止内存被超大响应撑爆.
/// handler 的「手动粘贴上游内容」端点也复用此上限做 body 大小校验.
pub const MAX_UPSTREAM_BODY_BYTES: u64 = 8 * 1024 * 1024;

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
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&msg), Utc::now(), None)
                    .await?;
                return Err(e);
            }
        },
    };
    let client = client_holder.as_ref().unwrap_or(http);

    match client.get(&profile.upstream_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            // 借用顺序: 先从 resp.headers() (只读借用) 抽出 owned String, 之后才把 resp move 给
            // read_body_limited (消费 resp). 必须在 move 之前抽, 否则借用已失效.
            // subscription-userinfo = 上游真实流量配额; profile-update-interval 顺带抽 (当前未单独存,
            // 但抽出确保 resp 还在时一次性拿全, 不残留借用问题).
            let upstream_userinfo: Option<String> = resp
                .headers()
                .get("subscription-userinfo")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let _upstream_update_interval: Option<String> = resp
                .headers()
                .get("profile-update-interval")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            // body 大小上限 (第一保险): Content-Length 已超过即拒, 不读 body.
            if let Some(len) = resp.content_length() {
                if len > MAX_UPSTREAM_BODY_BYTES {
                    let err = format!(
                        "上游响应体过大 ({} 字节 > {} 字节上限), 拒绝处理",
                        len, MAX_UPSTREAM_BODY_BYTES
                    );
                    repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now(), None)
                        .await?;
                    return Err(AppError::Upstream(err));
                }
            }
            // body 大小上限 (第二保险, 防 chunked 无 Content-Length):
            // 流式边读边累计, 超限立即中止, 不把整个 body 读进内存.
            let text = match read_body_limited(resp, MAX_UPSTREAM_BODY_BYTES).await {
                Ok(t) => t,
                Err(e) => {
                    let err = e.to_string();
                    repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now(), None)
                        .await?;
                    return Err(e);
                }
            };
            if !status.is_success() {
                let err = format_http_error(status.as_u16(), &text);
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now(), None)
                    .await?;
                return Err(AppError::Upstream(err));
            }
            if text.trim().is_empty() {
                let err = "upstream returned empty body".to_string();
                repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now(), None)
                    .await?;
                return Err(AppError::Upstream(err));
            }

            // 归一化 → 存库 → 写历史. 这后半段被抽成公共函数, reqwest 拉取路径与
            // 「手动粘贴上游内容」端点共用同一套处理.
            // userinfo 透传规则与抽取前完全一致: 成功路径传 Some(抽到的值或空串"") —— 上游没给
            // 头时显式清空, 避免节点已换源仍展示旧机场过期配额. 用 as_deref 借成 Option<&str>.
            ingest_normalized_yaml(
                db,
                profile,
                &text,
                Some(upstream_userinfo.as_deref().unwrap_or("")),
                trigger,
            )
            .await?;
            Ok(())
        }
        Err(e) => {
            let msg = e.to_string();
            repo::save_upstream_fetch(db, profile.id, None, "error", Some(&msg), Utc::now(), None)
                .await?;
            Err(AppError::Upstream(msg))
        }
    }
}

/// 归一化 → 存库 → 写历史 (公共后半段).
///
/// 从 `refresh_upstream_by_profile` 抽出, 供 reqwest 自动拉取与「手动粘贴上游内容」共用:
/// 1. 按 profile.upstream_format 提示把 `raw` 归一化成 Clash `{proxies: [...]}` YAML;
///    失败则落 error 状态 (yaml=None → COALESCE 保留旧缓存) 并返回 Err.
/// 2. 成功则写 last_upstream_yaml + last_upstream_userinfo (userinfo 按调用方语义:
///    reqwest 路径传 Some(头值或"") 显式清空, 手动粘贴无响应头传 None → COALESCE 保留旧值).
/// 3. dedup 写历史 (基于归一化后内容 hash, 与上一条不同才写, 标 `trigger`).
///
/// 返回归一化后解析出的节点数.
pub async fn ingest_normalized_yaml(
    db: &PgPool,
    profile: &OutputProfile,
    raw: &str,
    upstream_userinfo: Option<&str>,
    trigger: &str,
) -> AppResult<usize> {
    // 归一化层: 把任意订阅格式 (clash/base64/uri/sip008) 转成统一 IR =
    // {proxies: [...]} 的 Clash YAML, 再存库. 下游 generator/extract_nodes 不变.
    let (clash_yaml, count) = match normalize_for_profile(profile, raw) {
        Ok((yaml, count)) => (yaml, count),
        Err(e) => {
            // 归一化失败: 不覆盖旧缓存 (yaml=None → COALESCE 保留), 仅落 error 状态.
            // userinfo 也传 None 保留旧值 (这次没拉成功的有效订阅, 不应覆盖流量配额).
            let err = format!("订阅格式解析失败: {e}");
            repo::save_upstream_fetch(db, profile.id, None, "error", Some(&err), Utc::now(), None)
                .await?;
            return Err(AppError::BadRequest(err));
        }
    };

    // 写 profile 的 last_upstream_yaml (归一化后的 Clash YAML).
    repo::save_upstream_fetch(
        db,
        profile.id,
        Some(&clash_yaml),
        "success",
        None,
        Utc::now(),
        upstream_userinfo,
    )
    .await?;
    // dedup 写历史 (基于归一化后的内容 hash)
    let hash = history_repo::hash_yaml(&clash_yaml);
    let prev = history_repo::latest_hash(db, profile.id).await?;
    if prev.as_deref() != Some(hash.as_str()) {
        let cnt = history_repo::count_proxies(&clash_yaml);
        history_repo::create(db, profile.id, &clash_yaml, &hash, cnt, trigger).await?;
    }
    Ok(count)
}

/// 按 profile 的 upstream_format 提示, 把上游原文归一化成 Clash `{proxies: [...]}` YAML.
/// 返回 `(clash_yaml, node_count)`. 不触库 — 抽出来便于单测「喂内容 → 节点数」的核心契约.
fn normalize_for_profile(profile: &OutputProfile, raw: &str) -> AppResult<(String, usize)> {
    let hint = SubFormat::from_opt(profile.upstream_format.as_deref());
    parser::normalize_to_clash_yaml(raw, hint)
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

/// 流式读取响应体, 累计字节超过 `max` 立即返回 Err, 不把整个 body 读进内存.
/// 读取错误也返回 Err (不静默吞掉). 与 Content-Length 第一保险互补:
/// 第一保险快速拒绝声明了超大长度的响应; 本函数兜底 chunked / 无 Content-Length 的情况.
async fn read_body_limited(resp: reqwest::Response, max: u64) -> AppResult<String> {
    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut total: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| AppError::Upstream(format!("读取上游响应体失败: {e}")))?;
        total += chunk.len() as u64;
        if total > max {
            return Err(AppError::Upstream(format!(
                "上游响应体过大 (>{max} 字节上限), 拒绝处理"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    // 上游订阅是文本 (YAML / base64 / JSON / URI 列表); 非法 UTF-8 用 lossy 容错,
    // 后续归一化层会再做格式校验.
    Ok(String::from_utf8_lossy(&buf).into_owned())
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sqlx::types::Json as SqlxJson;
    use uuid::Uuid;

    /// 构造一个最小可用的 OutputProfile (只填归一化路径用到的字段, 其余给默认).
    fn profile_with_format(fmt: Option<&str>) -> OutputProfile {
        OutputProfile {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            name: "t".into(),
            sub_token: "tok".into(),
            upstream_url: "https://example.com/sub".into(),
            upstream_format: fmt.map(str::to_string),
            last_upstream_yaml: None,
            last_upstream_fetched_at: None,
            last_upstream_fetch_status: None,
            last_upstream_fetch_error: None,
            last_upstream_userinfo: None,
            bridge_node_names: SqlxJson(vec![]),
            exit_node_ids: SqlxJson(vec![]),
            fetch_via_exit_node_id: None,
            custom_rules: None,
            enabled: true,
            cached_yaml: None,
            cached_upstream_count: 0,
            cached_bridge_count: 0,
            cached_chain_count: 0,
            cached_missing_bridges: SqlxJson(vec![]),
            cached_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// ingest_normalized_yaml 的核心契约 = normalize_for_profile 把粘贴内容算出正确节点数.
    /// (存库 / 写历史需 PgPool, 不在单测覆盖; 这里锁定「喂内容 → 节点数」这段纯逻辑.)
    #[test]
    fn normalize_for_profile_counts_clash_nodes() {
        let raw = "proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}\n  - {name: b, type: ss, server: 5.6.7.8, port: 8388, cipher: aes-256-gcm, password: pw}\n";
        // 显式 clash 提示
        let (_yaml, n) = normalize_for_profile(&profile_with_format(Some("clash")), raw).unwrap();
        assert_eq!(n, 2);
        // auto 探测也应识别同样的 clash 内容
        let (_yaml, n_auto) = normalize_for_profile(&profile_with_format(Some("auto")), raw).unwrap();
        assert_eq!(n_auto, 2);
    }

    #[test]
    fn normalize_for_profile_counts_base64_nodes() {
        use base64::Engine;
        let inner = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#n1\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@5.6.7.8:8388#n2";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let (_yaml, n) = normalize_for_profile(&profile_with_format(Some("base64")), &b64).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn normalize_for_profile_rejects_garbage() {
        // CF challenge HTML 之类的垃圾内容: 既非合法订阅, 应报错而非误判成 0 节点成功.
        let html = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-ray</body></html>";
        assert!(normalize_for_profile(&profile_with_format(Some("auto")), html).is_err());
    }
}
