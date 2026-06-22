use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::exit_node::repo as exit_repo;
use crate::generator::render::{pick_renderer, RenderedSub};
use crate::generator::yaml::{build_model, GenerateInput};
use crate::profile::model::OutputProfile;
use crate::profile::repo as profile_repo;

/// 多格式构建结果: 渲染产物 + 统计字段 (从 InjectModel 取)。
#[derive(Debug)]
pub struct BuildResult {
    pub rendered: RenderedSub,
    pub upstream_count: i32,
    pub bridge_count: i32,
    pub chain_count: i32,
    pub missing_bridges: Vec<String>,
}

/// 把 profile 拼成 GenerateInput 所需的入参 (上游 yaml + 选中出口 yaml + custom_rules)。
async fn collect_inputs<'a>(
    db: &PgPool,
    user_id: Uuid,
    profile: &'a OutputProfile,
) -> AppResult<(&'a str, Vec<String>)> {
    let upstream_yaml = profile
        .last_upstream_yaml
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("no cached upstream yaml. refresh first.".into()))?;

    let exits = exit_repo::list_by_user(db, user_id).await?;
    let selected_exits: Vec<String> = profile
        .exit_node_ids
        .0
        .iter()
        .filter_map(|id| exits.iter().find(|e| e.id == *id && e.enabled))
        .map(|e| e.proxy_yaml.clone())
        .collect();

    if selected_exits.is_empty() {
        return Err(AppError::BadRequest(
            "no exit node selected (or selected ones are disabled)".into(),
        ));
    }
    Ok((upstream_yaml, selected_exits))
}

/// 按 profile + format 构建订阅 (不写库)。
///
/// 流程: build_model (含 custom_rules) → pick_renderer → 若 has_relay_chain 且渲染器不支持 relay
/// 则返回 415 → render。
/// - 未知格式 → 404 (NotFound)。
/// - 可用格式: clash.yaml / singbox.json / sub.txt / surge.conf / quanx.conf。
pub async fn build_for_profile_fmt(
    db: &PgPool,
    user_id: Uuid,
    profile: &OutputProfile,
    format: &str,
) -> AppResult<BuildResult> {
    let renderer = match pick_renderer(format) {
        Some(r) => r,
        None => return Err(AppError::NotFound),
    };

    let (upstream_yaml, selected_exits) = collect_inputs(db, user_id, profile).await?;
    let exit_refs: Vec<&str> = selected_exits.iter().map(|s| s.as_str()).collect();

    let model = build_model(GenerateInput {
        upstream_yaml,
        selected_bridge_names: &profile.bridge_node_names.0,
        exit_node_yamls: exit_refs,
        custom_rules: profile.custom_rules.as_deref(),
    })?;

    if model.has_relay_chain && !renderer.supports_relay_chain() {
        return Err(AppError::Unsupported(format!(
            "此订阅含固定出口链路(relay), {format} 格式无法表达链路, 请用 clash.yaml 或 singbox.json"
        )));
    }

    let rendered = renderer.render(&model)?;
    Ok(BuildResult {
        rendered,
        upstream_count: model.upstream_count,
        bridge_count: model.bridge_count,
        chain_count: model.chain_count,
        missing_bridges: model.missing_bridges,
    })
}

/// 兼容旧接口: 默认 clash.yaml, 返回 GenerateOutput (yaml 文本)。
/// 供 profile handler 的 preview / generate 复用。
pub async fn build_for_profile(
    db: &PgPool,
    user_id: Uuid,
    profile: &OutputProfile,
) -> AppResult<crate::generator::yaml::GenerateOutput> {
    let r = build_for_profile_fmt(db, user_id, profile, "clash.yaml").await?;
    Ok(crate::generator::yaml::GenerateOutput {
        yaml: r.rendered.body,
        upstream_count: r.upstream_count,
        bridge_count: r.bridge_count,
        chain_count: r.chain_count,
        missing_bridges: r.missing_bridges,
    })
}

/// 生成 clash.yaml 并写入 profile.cached_* (cached_yaml 始终缓存 Clash 输出, 向后兼容 /sub fallback)。
pub async fn build_and_cache(
    db: &PgPool,
    user_id: Uuid,
    profile_id: Uuid,
) -> AppResult<crate::generator::yaml::GenerateOutput> {
    let profile = profile_repo::find(db, user_id, profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let out = build_for_profile(db, user_id, &profile).await?;
    profile_repo::save_generated(
        db,
        profile.id,
        &out.yaml,
        out.upstream_count,
        out.bridge_count,
        out.chain_count,
        &out.missing_bridges,
        Utc::now(),
    )
    .await?;
    Ok(out)
}

/// 多格式版生成 + (仅 clash) 写缓存。
/// clash.yaml: 渲染并写 cached_yaml (向后兼容)。其他格式: 实时渲染, 不写缓存。
pub async fn build_and_cache_fmt(
    db: &PgPool,
    user_id: Uuid,
    profile_id: Uuid,
    format: &str,
) -> AppResult<BuildResult> {
    let profile = profile_repo::find(db, user_id, profile_id)
        .await?
        .ok_or(AppError::NotFound)?;
    let result = build_for_profile_fmt(db, user_id, &profile, format).await?;
    if format == "clash.yaml" {
        profile_repo::save_generated(
            db,
            profile.id,
            &result.rendered.body,
            result.upstream_count,
            result.bridge_count,
            result.chain_count,
            &result.missing_bridges,
            Utc::now(),
        )
        .await?;
    }
    Ok(result)
}
