//! ClashRenderer — 字节等价路径。
//!
//! **绝不从 InjectModel 重建 YAML**。clone `upstream_root`, 在 clone 上【原样执行历史
//! generate() 的原地注入序列】:
//!   1. injected_proxies push 进 proxies;
//!   2. injected_groups 转 Mapping push 进 proxy-groups;
//!   3. Bridge-Exit 名 insert 到每个原 type=select 组 proxies 首位;
//!   4. custom_rules (原样 Clash 行) + MATCH 兜底追加进 rules。
//! 再 `serde_yaml::to_string`。与历史输出逐字节一致, 唯一新增是 custom_rules 行。

use serde_yaml::{Mapping, Value};

use crate::error::{AppError, AppResult};
use crate::generator::model::{GroupKind, InjectGroup, InjectModel};
use crate::generator::render::{RenderedSub, Renderer};

pub struct ClashRenderer;

impl Renderer for ClashRenderer {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub> {
        // clone 上游原始 root, 所有注入在 clone 上做。
        let mut root = model.upstream_root.clone();
        let root_map = root
            .as_mapping_mut()
            .ok_or_else(|| AppError::BadRequest("上游 YAML 顶层必须是 mapping".into()))?;

        // 1. injected_proxies push 进 proxies 末尾。
        let proxies_key = Value::String("proxies".into());
        let proxies_seq = root_map
            .get_mut(&proxies_key)
            .and_then(|v| v.as_sequence_mut())
            .ok_or_else(|| AppError::BadRequest("上游 YAML 里没有 'proxies' 数组".into()))?;
        for m in &model.injected_proxies {
            proxies_seq.push(Value::Mapping(m.clone()));
        }

        // 2. injected_groups 转 Mapping push 进 proxy-groups。
        let groups_key = Value::String("proxy-groups".into());
        if !root_map.contains_key(&groups_key) {
            root_map.insert(groups_key.clone(), Value::Sequence(Vec::new()));
        }
        let groups_seq = root_map
            .get_mut(&groups_key)
            .and_then(|v| v.as_sequence_mut())
            .ok_or_else(|| AppError::BadRequest("'proxy-groups' 不是数组".into()))?;
        let original_groups_len = groups_seq.len();
        for g in &model.injected_groups {
            groups_seq.push(Value::Mapping(inject_group_to_mapping(g)));
        }

        // 3. 把 Bridge-Exit 注入到每个原 type=select 的分组首位 (只处理原 group)。
        let select_target = &model.select_inject_target;
        for i in 0..original_groups_len {
            let Some(g) = groups_seq[i].as_mapping_mut() else {
                continue;
            };
            let is_select = g
                .get(&Value::String("type".into()))
                .and_then(|v| v.as_str())
                == Some("select");
            if !is_select {
                continue;
            }
            let group_proxies_key = Value::String("proxies".into());
            if !g.contains_key(&group_proxies_key) {
                g.insert(group_proxies_key.clone(), Value::Sequence(Vec::new()));
            }
            if let Some(arr) = g.get_mut(&group_proxies_key).and_then(|v| v.as_sequence_mut()) {
                let already = arr.iter().any(|v| v.as_str() == Some(select_target.as_str()));
                if !already {
                    arr.insert(0, Value::String(select_target.clone()));
                }
            }
        }

        // 4. rules: 先 custom_rules (原样 Clash 行, 在 MATCH 兜底之前), 再 MATCH 兜底。
        let rules_key = Value::String("rules".into());
        if !root_map.contains_key(&rules_key) {
            root_map.insert(rules_key.clone(), Value::Sequence(Vec::new()));
        }
        if let Some(rules_seq) = root_map.get_mut(&rules_key).and_then(|v| v.as_sequence_mut()) {
            for spec in &model.custom_rules {
                rules_seq.push(Value::String(spec.to_clash_line()));
            }
            let fallback = format!("MATCH,{}", model.fallback_target);
            let already = rules_seq
                .iter()
                .any(|r| r.as_str().map(|s| s.trim() == fallback).unwrap_or(false));
            if !already {
                rules_seq.push(Value::String(fallback));
            }
        }

        let yaml = serde_yaml::to_string(&root)?;
        Ok(RenderedSub::new(
            yaml,
            "application/yaml; charset=utf-8",
            "yaml",
        ))
    }

    fn supports_relay_chain(&self) -> bool {
        true
    }

    fn format_id(&self) -> &'static str {
        "clash.yaml"
    }
}

/// 把 InjectGroup 转成 Clash proxy-group Mapping。
/// 键插入顺序必须与历史 generate() 完全一致 (name → type → [url → interval] → proxies),
/// 否则 serde_yaml 输出字节不等价。
fn inject_group_to_mapping(g: &InjectGroup) -> Mapping {
    let mut m = Mapping::new();
    m.insert(Value::String("name".into()), Value::String(g.name.clone()));
    match &g.kind {
        GroupKind::UrlTest { url, interval } => {
            m.insert(Value::String("type".into()), Value::String("url-test".into()));
            m.insert(Value::String("url".into()), Value::String(url.clone()));
            m.insert(
                Value::String("interval".into()),
                Value::Number((*interval as u64).into()),
            );
        }
        GroupKind::Select => {
            m.insert(Value::String("type".into()), Value::String("select".into()));
        }
    }
    m.insert(
        Value::String("proxies".into()),
        Value::Sequence(g.proxies.iter().cloned().map(Value::String).collect()),
    );
    m
}
