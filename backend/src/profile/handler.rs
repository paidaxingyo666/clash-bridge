use axum::extract::{Path, State};
use axum::http::{header, HeaderMap};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::generator::{service as gen_service, yaml as gen_yaml};
use crate::middleware::AuthUser;
use crate::profile::{model::*, repo, service};
use crate::state::AppState;

pub async fn list(
    State(s): State<AppState>,
    user: AuthUser,
) -> AppResult<Json<Vec<OutputProfileView>>> {
    let rows = repo::list_by_user(&s.db, user.id).await?;
    Ok(Json(rows.iter().map(OutputProfileView::from).collect()))
}

fn validate_input(input: &ProfileInput) -> AppResult<()> {
    if input.name.trim().is_empty() {
        return Err(AppError::BadRequest("name required".into()));
    }
    if input.upstream_url.trim().is_empty() {
        return Err(AppError::BadRequest("upstream_url required".into()));
    }
    // custom_rules 写时强语法校验 (段数 / RULE-TYPE / target 非空 / 静态白名单);
    // 组名引用留生成时软校验.
    crate::generator::rules::validate_syntax(input.custom_rules.as_deref())?;
    Ok(())
}

pub async fn create(
    State(s): State<AppState>,
    user: AuthUser,
    Json(input): Json<ProfileInput>,
) -> AppResult<Json<OutputProfileView>> {
    validate_input(&input)?;
    let row = repo::create(
        &s.db,
        user.id,
        input.name.trim(),
        &repo::gen_sub_token(),
        input.upstream_url.trim(),
        input.upstream_format.as_deref(),
        &input.bridge_node_names,
        &input.exit_node_ids,
        input.fetch_via_exit_node_id,
        input.custom_rules.as_deref(),
        input.enabled.unwrap_or(true),
    )
    .await?;
    Ok(Json(OutputProfileView::from(&row)))
}

pub async fn update(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    Json(input): Json<ProfileInput>,
) -> AppResult<Json<OutputProfileView>> {
    validate_input(&input)?;
    let row = repo::update(
        &s.db,
        user.id,
        id,
        input.name.trim(),
        input.upstream_url.trim(),
        input.upstream_format.as_deref(),
        &input.bridge_node_names,
        &input.exit_node_ids,
        input.fetch_via_exit_node_id,
        input.custom_rules.as_deref(),
        input.enabled.unwrap_or(true),
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(Json(OutputProfileView::from(&row)))
}

pub async fn delete(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<serde_json::Value>> {
    let n = repo::delete(&s.db, user.id, id).await?;
    if n == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Json(serde_json::json!({ "deleted": n })))
}

#[derive(Debug, Serialize)]
pub struct TokenView {
    pub sub_token: String,
}

pub async fn reset_token(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<TokenView>> {
    let new_token = repo::gen_sub_token();
    let row = repo::reset_token(&s.db, user.id, id, &new_token)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(TokenView {
        sub_token: row.sub_token,
    }))
}

pub async fn refresh_upstream(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<OutputProfileView>> {
    service::refresh_upstream(&s.db, &s.http, user.id, id, service::TRIGGER_MANUAL).await?;
    let row = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(OutputProfileView::from(&row)))
}

/// 手动粘贴上游订阅内容更新 (绕过机场封服务器 IP / 人机验证).
///
/// 用户在自己浏览器打开订阅 URL (本地放行 IP), 全选复制整页内容粘贴过来,
/// 后端走与自动拉取相同的归一化处理. 无响应头, userinfo 传 None (COALESCE 保留旧配额).
///
/// extractor 顺序: State / AuthUser 都是 FromRequestParts (只读 parts), 必须在 body 之前;
/// `body: String` 是 FromRequest, 会消费整个请求体, 必须放在最后一个参数.
/// 路由层另套 DefaultBodyLimit 在进 handler 前就拦超大 body; 此处再按 byte 长度二次校验.
pub async fn ingest_upstream_content(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
    body: String,
) -> AppResult<Json<serde_json::Value>> {
    if body.trim().is_empty() {
        return Err(AppError::BadRequest("粘贴内容为空".into()));
    }
    if body.len() as u64 > service::MAX_UPSTREAM_BODY_BYTES {
        return Err(AppError::BadRequest(format!(
            "粘贴内容过大 ({} 字节 > {} 字节上限)",
            body.len(),
            service::MAX_UPSTREAM_BODY_BYTES
        )));
    }
    // 双匹配鉴权: 找不到当作 NotFound (与 /profiles/:id 端点一致, 不泄露归属).
    let profile = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let n = service::ingest_normalized_yaml(
        &s.db,
        &profile,
        &body,
        None,
        service::TRIGGER_MANUAL_PASTE,
    )
    .await?;
    Ok(Json(serde_json::json!({ "node_count": n })))
}

/// 返回 profile 上次拉到的上游中所有节点 (供前端复选框 UI)
pub async fn list_upstream_nodes(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<Json<Vec<UpstreamNode>>> {
    let profile = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let yaml = profile
        .last_upstream_yaml
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("no cached upstream yaml. refresh first.".into()))?;
    Ok(Json(gen_yaml::extract_nodes(yaml)?))
}

/// 返回 profile 最近一次拉到的上游 yaml 原文 (供前端 diff 对照展示)
pub async fn get_upstream_yaml(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<axum::response::Response> {
    let profile = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let yaml = profile
        .last_upstream_yaml
        .ok_or_else(|| AppError::BadRequest("no cached upstream yaml. refresh first.".into()))?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        yaml,
    )
        .into_response())
}

#[derive(Debug, Serialize)]
pub struct GenerateView {
    pub upstream_count: i32,
    pub bridge_count: i32,
    pub chain_count: i32,
    pub missing_bridges: Vec<String>,
    pub sub_url: String,
}

/// 优先从请求头反推用户当前访问的 base URL (host + scheme), fallback 到 PUBLIC_BASE_URL 配置.
/// 这样无论部署在哪个域名后面 (kaiyu.uk / clash.kaiyu.uk / 直连 IP), 生成的订阅 URL 都跟用户当前
/// 访问的域名一致. cloudflare / nginx / next.js rewrite 都会带 X-Forwarded-* 头.
fn resolve_base_url(headers: &HeaderMap, fallback: &str) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|h| h.to_str().ok());
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("https");
    match host {
        Some(h) if !h.is_empty() => format!("{scheme}://{h}"),
        _ => fallback.to_string(),
    }
}

fn sub_url(base: &str, token: &str) -> String {
    format!("{}/sub/{}/clash.yaml", base.trim_end_matches('/'), token)
}

/// 生成并写入缓存
pub async fn generate(
    State(s): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> AppResult<Json<GenerateView>> {
    let out = gen_service::build_and_cache(&s.db, user.id, id).await?;
    let p = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let base = resolve_base_url(&headers, &s.config.public_base_url);
    Ok(Json(GenerateView {
        upstream_count: out.upstream_count,
        bridge_count: out.bridge_count,
        chain_count: out.chain_count,
        missing_bridges: out.missing_bridges,
        sub_url: sub_url(&base, &p.sub_token),
    }))
}

/// 临时生成并返回 yaml 文本 (不写库)
pub async fn preview(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<Uuid>,
) -> AppResult<axum::response::Response> {
    let p = repo::find(&s.db, user.id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let out = gen_service::build_for_profile(&s.db, user.id, &p).await?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
        out.yaml,
    )
        .into_response())
}
