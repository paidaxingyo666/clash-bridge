use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::exit_node::repo as exit_repo;
use crate::generator::yaml::{generate, GenerateInput, GenerateOutput};
use crate::profile::model::OutputProfile;
use crate::profile::repo as profile_repo;

/// 按 profile 构建 yaml (不写库)
pub async fn build_for_profile(
    db: &PgPool,
    user_id: Uuid,
    profile: &OutputProfile,
) -> AppResult<GenerateOutput> {
    let upstream_yaml = profile
        .last_upstream_yaml
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("no cached upstream yaml. refresh first.".into()))?;

    // 加载选中的 exit_nodes
    let exits = exit_repo::list_by_user(db, user_id).await?;
    let selected_exits: Vec<&str> = profile
        .exit_node_ids
        .0
        .iter()
        .filter_map(|id| exits.iter().find(|e| e.id == *id && e.enabled))
        .map(|e| e.proxy_yaml.as_str())
        .collect();

    if selected_exits.is_empty() {
        return Err(AppError::BadRequest(
            "no exit node selected (or selected ones are disabled)".into(),
        ));
    }

    generate(GenerateInput {
        upstream_yaml,
        selected_bridge_names: &profile.bridge_node_names.0,
        exit_node_yamls: selected_exits,
    })
}

/// 生成并写入 profile.cached_*
pub async fn build_and_cache(
    db: &PgPool,
    user_id: Uuid,
    profile_id: Uuid,
) -> AppResult<GenerateOutput> {
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
