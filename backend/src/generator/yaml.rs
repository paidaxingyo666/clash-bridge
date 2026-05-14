use std::collections::HashSet;

use serde_yaml::{Mapping, Value};

use crate::error::{AppError, AppResult};

pub struct GenerateInput<'a> {
    pub upstream_yaml: &'a str,
    pub selected_bridge_names: &'a [String],
    /// 出口节点的 proxy_yaml 文本列表
    pub exit_node_yamls: Vec<&'a str>,
}

#[derive(Debug)]
pub struct GenerateOutput {
    pub yaml: String,
    pub upstream_count: i32,
    pub bridge_count: i32,
    pub chain_count: i32,
    /// 用户勾选了但在最新上游里找不到的 name 列表
    pub missing_bridges: Vec<String>,
}

const BRIDGE_GROUP_NAME: &str = "Bridge-Exit";

/// 注入式生成：保留上游 yaml 的 proxies / proxy-groups / rules / 顶层字段不变，
/// 仅追加: 链路节点 + per-exit auto 组 + 聚合 Bridge-Exit 组,
/// 并把 Bridge-Exit 名注入到所有原 type=select 分组的 proxies 数组首位。
pub fn generate(input: GenerateInput<'_>) -> AppResult<GenerateOutput> {
    // 1. 解析上游为 Value，保留全部结构
    let mut root: Value = serde_yaml::from_str(input.upstream_yaml).map_err(|e| {
        AppError::BadRequest(format!(
            "上游不是合法 YAML: {e}。前 200 字符: {}",
            preview_text(input.upstream_yaml)
        ))
    })?;
    let root_map = root.as_mapping_mut().ok_or_else(|| {
        AppError::BadRequest("上游 YAML 顶层必须是 mapping".into())
    })?;

    // 2. 取出 proxies 数组(必须存在)
    let proxies_key = Value::String("proxies".into());
    let proxies_seq = root_map
        .get_mut(&proxies_key)
        .and_then(|v| v.as_sequence_mut())
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "上游 YAML 里没有 'proxies' 数组。机场常根据 User-Agent 返回不同格式，\
                 本服务以 mihomo 身份请求；若仍是 base64 或 HTML，请确认订阅是 Clash/Mihomo 兼容。前 200 字符: {}",
                preview_text(input.upstream_yaml)
            ))
        })?;
    let upstream_count = proxies_seq.len() as i32;

    // 收集所有已存在的节点名 (用于命名去重)
    let mut existing_proxy_names: HashSet<String> = HashSet::new();
    let mut bridge_map: std::collections::HashMap<String, Mapping> =
        std::collections::HashMap::new();
    for p in proxies_seq.iter() {
        if let Some(m) = p.as_mapping() {
            if let Some(n) = mapping_string(m, "name") {
                existing_proxy_names.insert(n.clone());
                bridge_map.entry(n).or_insert_with(|| m.clone());
            }
        }
    }

    // 3. 按勾选 name 命中跳板
    let mut bridges: Vec<(String, Mapping)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for name in input.selected_bridge_names {
        match bridge_map.get(name) {
            Some(m) => bridges.push((name.clone(), m.clone())),
            None => missing.push(name.clone()),
        }
    }
    let bridge_count = bridges.len() as i32;

    // 4. 解析出口节点
    let exits: Vec<Mapping> = input
        .exit_node_yamls
        .iter()
        .map(|y| serde_yaml::from_str::<Value>(y))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| AppError::BadRequest(format!("出口节点 yaml 不合法: {e}")))?
        .into_iter()
        .filter_map(|v| v.as_mapping().cloned())
        .collect();

    if exits.is_empty() {
        return Err(AppError::BadRequest("未选择固定出口节点".into()));
    }
    if bridges.is_empty() {
        return Err(AppError::BadRequest(
            "勾选的跳板节点在最新上游里全部找不到，请先刷新上游或重新勾选".into(),
        ));
    }

    // 5. 生成链路节点，追加到 proxies 末尾。同时收集 per-exit 的 chain names
    let mut per_exit_chains: Vec<(String, Vec<String>)> = Vec::new();
    let mut chain_total = 0usize;
    for exit in &exits {
        let exit_name = mapping_string(exit, "name").unwrap_or_else(|| "exit".into());
        let mut chains: Vec<String> = Vec::new();
        for (bridge_name, _) in &bridges {
            let raw = format!("{exit_name}-via-{bridge_name}");
            let chain_name = unique_name(&raw, &mut existing_proxy_names);
            let mut m = exit.clone();
            m.insert(
                Value::String("name".into()),
                Value::String(chain_name.clone()),
            );
            m.insert(
                Value::String("dialer-proxy".into()),
                Value::String(bridge_name.clone()),
            );
            proxies_seq.push(Value::Mapping(m));
            chains.push(chain_name);
            chain_total += 1;
        }
        per_exit_chains.push((exit_name, chains));
    }
    let chain_count = chain_total as i32;

    // 6. 准备 proxy-groups：若不存在则新建空 sequence
    let groups_key = Value::String("proxy-groups".into());
    if !root_map.contains_key(&groups_key) {
        root_map.insert(groups_key.clone(), Value::Sequence(Vec::new()));
    }
    let groups_seq = root_map
        .get_mut(&groups_key)
        .and_then(|v| v.as_sequence_mut())
        .ok_or_else(|| AppError::BadRequest("'proxy-groups' 不是数组".into()))?;

    // 在追加新组之前, 记下原长度 — 用于步骤 7 区分"哪些是原 group, 哪些是我们新加的"
    let original_groups_len = groups_seq.len();

    // 收集已存在的 group 名 (避免重名)
    let mut existing_group_names: HashSet<String> = groups_seq
        .iter()
        .filter_map(|g| g.as_mapping().and_then(|m| mapping_string(m, "name")))
        .collect();

    // 6a. 每个 exit 一个 url-test 子组 (固定 IP, 自动选跳板)
    let mut auto_group_names: Vec<String> = Vec::new();
    let mut all_chain_names: Vec<String> = Vec::new();
    for (exit_name, chains) in &per_exit_chains {
        let gname = unique_name(&format!("{exit_name}-auto"), &mut existing_group_names);
        let mut g = Mapping::new();
        g.insert(Value::String("name".into()), Value::String(gname.clone()));
        g.insert(Value::String("type".into()), Value::String("url-test".into()));
        g.insert(
            Value::String("url".into()),
            Value::String("https://www.gstatic.com/generate_204".into()),
        );
        g.insert(Value::String("interval".into()), Value::Number(300.into()));
        g.insert(
            Value::String("proxies".into()),
            Value::Sequence(chains.iter().cloned().map(Value::String).collect()),
        );
        groups_seq.push(Value::Mapping(g));
        auto_group_names.push(gname);
        all_chain_names.extend(chains.iter().cloned());
    }

    // 6b. 扁平 url-test 组 Bridge-Exit-auto: 跨所有 exit / 跳板, 全自动选最快链路
    let bridge_auto_name = unique_name("Bridge-Exit-auto", &mut existing_group_names);
    let mut bridge_auto_group = Mapping::new();
    bridge_auto_group.insert(
        Value::String("name".into()),
        Value::String(bridge_auto_name.clone()),
    );
    bridge_auto_group.insert(
        Value::String("type".into()),
        Value::String("url-test".into()),
    );
    bridge_auto_group.insert(
        Value::String("url".into()),
        Value::String("https://www.gstatic.com/generate_204".into()),
    );
    bridge_auto_group.insert(
        Value::String("interval".into()),
        Value::Number(300.into()),
    );
    bridge_auto_group.insert(
        Value::String("proxies".into()),
        Value::Sequence(
            all_chain_names
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    groups_seq.push(Value::Mapping(bridge_auto_group));

    // 6c. 聚合 select 组 Bridge-Exit
    // 顺序: Bridge-Exit-auto (默认全自动) 在最前, 然后是 per-exit auto, 再 DIRECT
    let bridge_group_name = unique_name(BRIDGE_GROUP_NAME, &mut existing_group_names);
    let mut bridge_group = Mapping::new();
    bridge_group.insert(
        Value::String("name".into()),
        Value::String(bridge_group_name.clone()),
    );
    bridge_group.insert(Value::String("type".into()), Value::String("select".into()));
    // 选项顺序:
    //   1) Bridge-Exit-auto         — 全自动 (跨出口跨跳板)
    //   2) {exit}-auto              — 固定出口 IP, 自动跳板
    //   3) 所有 chain 节点           — 指定出口 + 指定跳板 (完全手动)
    //   4) DIRECT                   — 不走代理
    let mut select_opts: Vec<Value> = vec![Value::String(bridge_auto_name.clone())];
    select_opts.extend(auto_group_names.iter().cloned().map(Value::String));
    select_opts.extend(all_chain_names.iter().cloned().map(Value::String));
    select_opts.push(Value::String("DIRECT".into()));
    bridge_group.insert(
        Value::String("proxies".into()),
        Value::Sequence(select_opts),
    );
    groups_seq.push(Value::Mapping(bridge_group));

    // 7. 把 Bridge-Exit 注入到每个原 type=select 的分组首位 (只处理原 group, 不动我们新加的)
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
        let proxies_key = Value::String("proxies".into());
        if !g.contains_key(&proxies_key) {
            g.insert(proxies_key.clone(), Value::Sequence(Vec::new()));
        }
        if let Some(arr) = g.get_mut(&proxies_key).and_then(|v| v.as_sequence_mut()) {
            let already = arr.iter().any(|v| v.as_str() == Some(bridge_group_name.as_str()));
            if !already {
                arr.insert(0, Value::String(bridge_group_name.clone()));
            }
        }
    }

    // 8. rules 末尾追加 MATCH,Bridge-Exit 作兜底.
    //    Clash 按顺序匹配, 第一条 MATCH 命中即终止. 若原 yaml 已经有 MATCH,
    //    我们这条不会生效但也无害 — 用户能看到"有这个兜底选项", 想强制走时
    //    把原 MATCH 删掉或改成指向 Bridge-Exit 即可.
    let rules_key = Value::String("rules".into());
    if !root_map.contains_key(&rules_key) {
        root_map.insert(rules_key.clone(), Value::Sequence(Vec::new()));
    }
    if let Some(rules_seq) = root_map.get_mut(&rules_key).and_then(|v| v.as_sequence_mut()) {
        let fallback = format!("MATCH,{bridge_group_name}");
        let already = rules_seq
            .iter()
            .any(|r| r.as_str().map(|s| s.trim() == fallback).unwrap_or(false));
        if !already {
            rules_seq.push(Value::String(fallback));
        }
    }

    let yaml = serde_yaml::to_string(&root)?;
    Ok(GenerateOutput {
        yaml,
        upstream_count,
        bridge_count,
        chain_count,
        missing_bridges: missing,
    })
}

fn mapping_string(m: &Mapping, key: &str) -> Option<String> {
    m.get(Value::String(key.into()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn preview_text(s: &str) -> String {
    let trimmed = s.trim();
    let take: String = trimmed.chars().take(200).collect();
    if trimmed.chars().count() > 200 {
        format!("{take}…")
    } else {
        take
    }
}

fn unique_name(base: &str, seen: &mut HashSet<String>) -> String {
    if seen.insert(base.to_string()) {
        return base.to_string();
    }
    for i in 2..u32::MAX {
        let n = format!("{base}-{i}");
        if seen.insert(n.clone()) {
            return n;
        }
    }
    base.to_string()
}

/// 解析上游 yaml，返回简化节点列表 (供前端复选框 UI)
pub fn extract_nodes(upstream_yaml: &str) -> AppResult<Vec<crate::profile::model::UpstreamNode>> {
    let val: Value = serde_yaml::from_str(upstream_yaml).map_err(|e| {
        AppError::BadRequest(format!(
            "上游不是合法 YAML: {e}。前 200 字符: {}",
            preview_text(upstream_yaml)
        ))
    })?;
    let seq = val.get("proxies").and_then(|v| v.as_sequence()).ok_or_else(|| {
        AppError::BadRequest(format!(
            "上游 YAML 里没有 'proxies' 字段。\
             机场常根据 User-Agent 返回不同格式，本服务以 mihomo 身份请求；\
             若仍是 base64 或 HTML，请确认订阅链接是 Clash/Mihomo 兼容的。前 200 字符: {}",
            preview_text(upstream_yaml)
        ))
    })?;
    let mut out = Vec::with_capacity(seq.len());
    for p in seq {
        if let Some(m) = p.as_mapping() {
            let name = mapping_string(m, "name");
            if let Some(name) = name {
                let r#type = mapping_string(m, "type");
                let server = mapping_string(m, "server");
                let port = m
                    .get(Value::String("port".into()))
                    .and_then(|v| v.as_i64());
                out.push(crate::profile::model::UpstreamNode {
                    name,
                    r#type,
                    server,
                    port,
                });
            }
        }
    }
    Ok(out)
}
