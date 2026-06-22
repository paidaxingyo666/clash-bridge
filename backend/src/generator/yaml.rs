use std::collections::HashSet;

use serde_yaml::{Mapping, Value};

use crate::error::{AppError, AppResult};
use crate::generator::model::{GroupKind, InjectGroup, InjectModel};
use crate::generator::render::clash::ClashRenderer;
use crate::generator::render::Renderer;

pub struct GenerateInput<'a> {
    pub upstream_yaml: &'a str,
    pub selected_bridge_names: &'a [String],
    /// 出口节点的 proxy_yaml 文本列表
    pub exit_node_yamls: Vec<&'a str>,
    /// 用户自定义规则原文 (每行一条 Clash 规则)。None / 空串 = 无。
    pub custom_rules: Option<&'a str>,
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

pub(crate) const BRIDGE_GROUP_NAME: &str = "Bridge-Exit";

/// url-test 子组的测速地址。
/// 不用 Google 系 HTTPS(gstatic/google): 其 TLS 握手包较大, 经固定出口隧道易撞 MTU,
/// 导致延迟测试误报 timeout(节点实际可正常使用)。改用 Cloudflare anycast 的 generate_204:
/// 握手包小、全球就近、无 DNS 污染, 实测经固定出口稳定可测。
pub(crate) const LATENCY_TEST_URL: &str = "https://cp.cloudflare.com/generate_204";

/// url-test 默认刷新间隔 (秒)。
pub(crate) const LATENCY_TEST_INTERVAL: u32 = 300;

/// 兼容旧调用: 直接产出 Clash YAML。
/// 等价于 `ClashRenderer.render(build_model(input))` + 统计字段填充。
pub fn generate(input: GenerateInput<'_>) -> AppResult<GenerateOutput> {
    let model = build_model(input)?;
    let rendered = ClashRenderer.render(&model)?;
    Ok(GenerateOutput {
        yaml: rendered.body,
        upstream_count: model.upstream_count,
        bridge_count: model.bridge_count,
        chain_count: model.chain_count,
        missing_bridges: model.missing_bridges,
    })
}

/// 三层重构的 parse + inject 阶段: 解析上游、命中跳板、解析出口、算 per-exit chains + 三类组,
/// 产出 [`InjectModel`] 补丁清单, **不对 upstream_root 原地 mutate** (mutate 在 ClashRenderer 内做)。
pub fn build_model(input: GenerateInput<'_>) -> AppResult<InjectModel> {
    // 1. 解析上游为 Value，保留全部结构 (upstream_root 原值, 供 ClashRenderer clone 后原地注入)
    let root: Value = serde_yaml::from_str(input.upstream_yaml).map_err(|e| {
        AppError::BadRequest(format!(
            "上游不是合法 YAML: {e}。前 200 字符: {}",
            preview_text(input.upstream_yaml)
        ))
    })?;
    let root_map = root.as_mapping().ok_or_else(|| {
        AppError::BadRequest("上游 YAML 顶层必须是 mapping".into())
    })?;

    // 2. 取出 proxies 数组(必须存在)
    let proxies_key = Value::String("proxies".into());
    let proxies_seq = root_map
        .get(&proxies_key)
        .and_then(|v| v.as_sequence())
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

    // 5. 生成链路节点 (收集到 injected_proxies, 不再原地 push)。同时收集 per-exit 的 chain names
    let mut injected_proxies: Vec<Mapping> = Vec::new();
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
            injected_proxies.push(m);
            chains.push(chain_name);
            chain_total += 1;
        }
        per_exit_chains.push((exit_name, chains));
    }
    let chain_count = chain_total as i32;

    // 6. 计算注入组的名字 (基于上游已存在的 group 名去重, 不原地 mutate root)
    let groups_key = Value::String("proxy-groups".into());
    let mut existing_group_names: HashSet<String> = root_map
        .get(&groups_key)
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|g| g.as_mapping().and_then(|m| mapping_string(m, "name")))
                .collect()
        })
        .unwrap_or_default();

    let mut injected_groups: Vec<InjectGroup> = Vec::new();

    // 6a. 每个 exit 一个 url-test 子组 (固定 IP, 自动选跳板)
    let mut auto_group_names: Vec<String> = Vec::new();
    let mut all_chain_names: Vec<String> = Vec::new();
    for (exit_name, chains) in &per_exit_chains {
        let gname = unique_name(&format!("{exit_name}-auto"), &mut existing_group_names);
        injected_groups.push(InjectGroup {
            name: gname.clone(),
            kind: GroupKind::UrlTest {
                url: LATENCY_TEST_URL.into(),
                interval: LATENCY_TEST_INTERVAL,
            },
            proxies: chains.clone(),
        });
        auto_group_names.push(gname);
        all_chain_names.extend(chains.iter().cloned());
    }

    // 6b. 扁平 url-test 组 Bridge-Exit-auto: 跨所有 exit / 跳板, 全自动选最快链路
    let bridge_auto_name = unique_name("Bridge-Exit-auto", &mut existing_group_names);
    injected_groups.push(InjectGroup {
        name: bridge_auto_name.clone(),
        kind: GroupKind::UrlTest {
            url: LATENCY_TEST_URL.into(),
            interval: LATENCY_TEST_INTERVAL,
        },
        proxies: all_chain_names.clone(),
    });

    // 6c. 聚合 select 组 Bridge-Exit
    // 选项顺序:
    //   1) Bridge-Exit-auto         — 全自动 (跨出口跨跳板)
    //   2) {exit}-auto              — 固定出口 IP, 自动跳板
    //   3) 所有 chain 节点           — 指定出口 + 指定跳板 (完全手动)
    //   4) DIRECT                   — 不走代理
    let bridge_group_name = unique_name(BRIDGE_GROUP_NAME, &mut existing_group_names);
    let mut select_opts: Vec<String> = vec![bridge_auto_name.clone()];
    select_opts.extend(auto_group_names.iter().cloned());
    select_opts.extend(all_chain_names.iter().cloned());
    select_opts.push("DIRECT".into());
    injected_groups.push(InjectGroup {
        name: bridge_group_name.clone(),
        kind: GroupKind::Select,
        proxies: select_opts,
    });

    // 7. custom_rules 软校验 + 翻成 RuleSpec。
    //    已知组名集合 = 上游组名 + 我们注入的组名 (用于悬空 target 校验)。
    let mut known_groups: HashSet<String> = root_map
        .get(&groups_key)
        .and_then(|v| v.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|g| g.as_mapping().and_then(|m| mapping_string(m, "name")))
                .collect()
        })
        .unwrap_or_default();
    for g in &injected_groups {
        known_groups.insert(g.name.clone());
    }
    let custom_rules = match input.custom_rules {
        Some(text) if !text.trim().is_empty() => {
            crate::generator::rules::parse_custom_rules(text, &known_groups)
        }
        _ => Vec::new(),
    };

    Ok(InjectModel {
        upstream_root: root,
        injected_proxies,
        injected_groups,
        select_inject_target: bridge_group_name.clone(),
        custom_rules,
        fallback_target: bridge_group_name,
        upstream_count,
        bridge_count,
        chain_count,
        missing_bridges: missing,
        has_relay_chain: chain_count > 0,
    })
}

pub(crate) fn mapping_string(m: &Mapping, key: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 重构前历史 generate() 的原地注入逻辑, 逐字节复刻为基准。
    /// 用于 golden 测试: 断言重构后 ClashRenderer(custom_rules 空) 与它字节相等。
    fn legacy_generate(input: GenerateInput<'_>) -> AppResult<String> {
        let mut root: Value = serde_yaml::from_str(input.upstream_yaml)?;
        let root_map = root.as_mapping_mut().unwrap();

        let proxies_key = Value::String("proxies".into());
        let proxies_seq = root_map
            .get_mut(&proxies_key)
            .and_then(|v| v.as_sequence_mut())
            .unwrap();

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
        let mut bridges: Vec<(String, Mapping)> = Vec::new();
        for name in input.selected_bridge_names {
            if let Some(m) = bridge_map.get(name) {
                bridges.push((name.clone(), m.clone()));
            }
        }
        let exits: Vec<Mapping> = input
            .exit_node_yamls
            .iter()
            .map(|y| serde_yaml::from_str::<Value>(y))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter_map(|v| v.as_mapping().cloned())
            .collect();

        let mut per_exit_chains: Vec<(String, Vec<String>)> = Vec::new();
        for exit in &exits {
            let exit_name = mapping_string(exit, "name").unwrap_or_else(|| "exit".into());
            let mut chains: Vec<String> = Vec::new();
            for (bridge_name, _) in &bridges {
                let raw = format!("{exit_name}-via-{bridge_name}");
                let chain_name = unique_name(&raw, &mut existing_proxy_names);
                let mut m = exit.clone();
                m.insert(Value::String("name".into()), Value::String(chain_name.clone()));
                m.insert(
                    Value::String("dialer-proxy".into()),
                    Value::String(bridge_name.clone()),
                );
                proxies_seq.push(Value::Mapping(m));
                chains.push(chain_name);
            }
            per_exit_chains.push((exit_name, chains));
        }

        let groups_key = Value::String("proxy-groups".into());
        if !root_map.contains_key(&groups_key) {
            root_map.insert(groups_key.clone(), Value::Sequence(Vec::new()));
        }
        let groups_seq = root_map
            .get_mut(&groups_key)
            .and_then(|v| v.as_sequence_mut())
            .unwrap();
        let original_groups_len = groups_seq.len();
        let mut existing_group_names: HashSet<String> = groups_seq
            .iter()
            .filter_map(|g| g.as_mapping().and_then(|m| mapping_string(m, "name")))
            .collect();

        let mut auto_group_names: Vec<String> = Vec::new();
        let mut all_chain_names: Vec<String> = Vec::new();
        for (exit_name, chains) in &per_exit_chains {
            let gname = unique_name(&format!("{exit_name}-auto"), &mut existing_group_names);
            let mut g = Mapping::new();
            g.insert(Value::String("name".into()), Value::String(gname.clone()));
            g.insert(Value::String("type".into()), Value::String("url-test".into()));
            g.insert(Value::String("url".into()), Value::String(LATENCY_TEST_URL.into()));
            g.insert(Value::String("interval".into()), Value::Number(300.into()));
            g.insert(
                Value::String("proxies".into()),
                Value::Sequence(chains.iter().cloned().map(Value::String).collect()),
            );
            groups_seq.push(Value::Mapping(g));
            auto_group_names.push(gname);
            all_chain_names.extend(chains.iter().cloned());
        }

        let bridge_auto_name = unique_name("Bridge-Exit-auto", &mut existing_group_names);
        let mut bridge_auto_group = Mapping::new();
        bridge_auto_group.insert(Value::String("name".into()), Value::String(bridge_auto_name.clone()));
        bridge_auto_group.insert(Value::String("type".into()), Value::String("url-test".into()));
        bridge_auto_group.insert(Value::String("url".into()), Value::String(LATENCY_TEST_URL.into()));
        bridge_auto_group.insert(Value::String("interval".into()), Value::Number(300.into()));
        bridge_auto_group.insert(
            Value::String("proxies".into()),
            Value::Sequence(all_chain_names.iter().cloned().map(Value::String).collect()),
        );
        groups_seq.push(Value::Mapping(bridge_auto_group));

        let bridge_group_name = unique_name(BRIDGE_GROUP_NAME, &mut existing_group_names);
        let mut bridge_group = Mapping::new();
        bridge_group.insert(Value::String("name".into()), Value::String(bridge_group_name.clone()));
        bridge_group.insert(Value::String("type".into()), Value::String("select".into()));
        let mut select_opts: Vec<Value> = vec![Value::String(bridge_auto_name.clone())];
        select_opts.extend(auto_group_names.iter().cloned().map(Value::String));
        select_opts.extend(all_chain_names.iter().cloned().map(Value::String));
        select_opts.push(Value::String("DIRECT".into()));
        bridge_group.insert(Value::String("proxies".into()), Value::Sequence(select_opts));
        groups_seq.push(Value::Mapping(bridge_group));

        for i in 0..original_groups_len {
            let Some(g) = groups_seq[i].as_mapping_mut() else { continue };
            let is_select = g
                .get(&Value::String("type".into()))
                .and_then(|v| v.as_str())
                == Some("select");
            if !is_select {
                continue;
            }
            let pk = Value::String("proxies".into());
            if !g.contains_key(&pk) {
                g.insert(pk.clone(), Value::Sequence(Vec::new()));
            }
            if let Some(arr) = g.get_mut(&pk).and_then(|v| v.as_sequence_mut()) {
                let already = arr.iter().any(|v| v.as_str() == Some(bridge_group_name.as_str()));
                if !already {
                    arr.insert(0, Value::String(bridge_group_name.clone()));
                }
            }
        }

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
        Ok(serde_yaml::to_string(&root)?)
    }

    const SAMPLE_UPSTREAM: &str = r#"port: 7890
mode: rule
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
  - name: SG02
    type: trojan
    server: sg02.example.com
    port: 443
    password: pw2
    sni: sg02.example.com
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - SG01
      - SG02
  - name: AutoFast
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - SG01
      - SG02
rules:
  - DOMAIN-SUFFIX,google.com,Proxies
  - GEOIP,CN,DIRECT
"#;

    const EXIT_VMESS: &str = r#"name: JP01
type: vmess
server: jp01.example.com
port: 443
uuid: abc-uuid
alterId: 0
cipher: auto
tls: true
servername: jp01.example.com
"#;

    const EXIT_SS: &str = r#"name: US01
type: ss
server: us01.example.com
port: 8388
cipher: aes-256-gcm
password: pwus
"#;

    /// golden 字节等价 helper: 断言重构后 ClashRenderer(custom_rules 空) 与历史
    /// legacy_generate 逐字节相等。各边角上游复用此 helper。
    fn assert_golden(upstream: &str, bridges: &[String], exits: Vec<&str>) {
        let legacy = legacy_generate(GenerateInput {
            upstream_yaml: upstream,
            selected_bridge_names: bridges,
            exit_node_yamls: exits.clone(),
            custom_rules: None,
        })
        .unwrap();
        let new = generate(GenerateInput {
            upstream_yaml: upstream,
            selected_bridge_names: bridges,
            exit_node_yamls: exits,
            custom_rules: None,
        })
        .unwrap()
        .yaml;
        assert_eq!(new, legacy, "ClashRenderer 输出与历史 generate() 不字节等价");
    }

    /// golden 字节等价: 重构后 ClashRenderer(custom_rules 空) 必须与历史 generate() 逐字节相等。
    #[test]
    fn golden_clash_byte_equivalence() {
        let bridges = vec!["SG01".to_string(), "SG02".to_string()];
        assert_golden(SAMPLE_UPSTREAM, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 上游无 proxy-groups (legacy 会新建空 sequence 再注入)。
    #[test]
    fn golden_no_proxy_groups() {
        let upstream = r#"port: 7890
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
rules:
  - GEOIP,CN,DIRECT
"#;
        let bridges = vec!["SG01".to_string()];
        assert_golden(upstream, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 上游无 rules (legacy 会新建空 sequence 再补 MATCH)。
    #[test]
    fn golden_no_rules() {
        let upstream = r#"port: 7890
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - SG01
"#;
        let bridges = vec!["SG01".to_string()];
        assert_golden(upstream, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 上游 rules 已含 MATCH (不应重复追加)。
    #[test]
    fn golden_existing_match() {
        let upstream = r#"port: 7890
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - SG01
rules:
  - DOMAIN-SUFFIX,google.com,Proxies
  - MATCH,Bridge-Exit
"#;
        let bridges = vec!["SG01".to_string()];
        assert_golden(upstream, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 上游已存在同名 Bridge-Exit 组 (我们注入的组名需去重为 Bridge-Exit-2)。
    #[test]
    fn golden_existing_bridge_exit_group() {
        let upstream = r#"port: 7890
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
proxy-groups:
  - name: Bridge-Exit
    type: select
    proxies:
      - SG01
rules:
  - GEOIP,CN,DIRECT
"#;
        let bridges = vec!["SG01".to_string()];
        assert_golden(upstream, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 上游多个 select 组 (Bridge-Exit 应注入每个 select 组首位)。
    #[test]
    fn golden_multiple_select_groups() {
        let upstream = r#"port: 7890
proxies:
  - name: SG01
    type: ss
    server: sg01.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw1
proxy-groups:
  - name: Proxies
    type: select
    proxies:
      - SG01
  - name: Streaming
    type: select
    proxies:
      - SG01
      - DIRECT
  - name: AutoFast
    type: url-test
    url: https://www.gstatic.com/generate_204
    interval: 600
    proxies:
      - SG01
rules:
  - GEOIP,CN,DIRECT
"#;
        let bridges = vec!["SG01".to_string()];
        assert_golden(upstream, &bridges, vec![EXIT_VMESS]);
    }

    /// 边角: 多 exit (per-exit url-test 子组 + 扁平组叉乘链路)。
    #[test]
    fn golden_multiple_exits() {
        let bridges = vec!["SG01".to_string(), "SG02".to_string()];
        assert_golden(SAMPLE_UPSTREAM, &bridges, vec![EXIT_VMESS, EXIT_SS]);
    }

    /// custom_rules 注入: 自定义规则出现在 MATCH 兜底之前, 历史规则之后。
    #[test]
    fn clash_custom_rules_injected_before_match() {
        let bridges = vec!["SG01".to_string()];
        let out = generate(GenerateInput {
            upstream_yaml: SAMPLE_UPSTREAM,
            selected_bridge_names: &bridges,
            exit_node_yamls: vec![EXIT_VMESS],
            custom_rules: Some("DOMAIN-SUFFIX,custom.com,DIRECT\n# comment\nIP-CIDR,10.0.0.0/8,Bridge-Exit"),
        })
        .unwrap()
        .yaml;

        let parsed: Value = serde_yaml::from_str(&out).unwrap();
        let rules: Vec<String> = parsed["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();

        let custom_idx = rules.iter().position(|r| r == "DOMAIN-SUFFIX,custom.com,DIRECT").unwrap();
        let custom2_idx = rules.iter().position(|r| r == "IP-CIDR,10.0.0.0/8,Bridge-Exit").unwrap();
        let match_idx = rules.iter().position(|r| r == "MATCH,Bridge-Exit").unwrap();
        // 历史规则在前, custom 在历史之后、MATCH 之前
        assert!(custom_idx < match_idx);
        assert!(custom2_idx < match_idx);
        assert!(custom_idx > 0); // GEOIP,CN,DIRECT 等历史规则在前
    }

    /// custom_rules 含悬空 target (不存在的组名) → 生成时跳过, 不进 rules。
    #[test]
    fn clash_custom_rules_skips_dangling() {
        let bridges = vec!["SG01".to_string()];
        let out = generate(GenerateInput {
            upstream_yaml: SAMPLE_UPSTREAM,
            selected_bridge_names: &bridges,
            exit_node_yamls: vec![EXIT_VMESS],
            custom_rules: Some("DOMAIN,a.com,GhostGroup\nDOMAIN,b.com,Proxies"),
        })
        .unwrap()
        .yaml;
        assert!(!out.contains("GhostGroup"));
        assert!(out.contains("DOMAIN,b.com,Proxies")); // 上游已有 Proxies 组, 放行
    }

    /// build_model 含链路 → has_relay_chain=true; sing-box 渲染含 detour + urltest/selector + route.final。
    #[test]
    fn singbox_render_relay_chain() {
        use crate::generator::render::singbox::SingboxRenderer;
        use crate::generator::render::Renderer;

        let bridges = vec!["SG01".to_string()];
        let model = build_model(GenerateInput {
            upstream_yaml: SAMPLE_UPSTREAM,
            selected_bridge_names: &bridges,
            exit_node_yamls: vec![EXIT_VMESS],
            custom_rules: Some("DOMAIN-SUFFIX,custom.com,DIRECT"),
        })
        .unwrap();
        assert!(model.has_relay_chain);

        let rendered = SingboxRenderer.render(&model).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered.body).unwrap();

        // detour=SG01 出现在链路 outbound 上
        let outbounds = json["outbounds"].as_array().unwrap();
        let chain = outbounds
            .iter()
            .find(|o| o["tag"].as_str() == Some("JP01-via-SG01"))
            .expect("链路 outbound 应存在");
        assert_eq!(chain["detour"], serde_json::json!("SG01"));
        assert_eq!(chain["type"], serde_json::json!("vmess"));

        // 跳板 SG01 是普通 outbound, 无 detour
        let bridge = outbounds.iter().find(|o| o["tag"].as_str() == Some("SG01")).unwrap();
        assert!(bridge.get("detour").is_none());
        assert_eq!(bridge["type"], serde_json::json!("shadowsocks"));

        // urltest 组 (JP01-auto) + selector (Bridge-Exit)
        let urltest = outbounds.iter().find(|o| o["tag"].as_str() == Some("JP01-auto")).unwrap();
        assert_eq!(urltest["type"], serde_json::json!("urltest"));
        assert_eq!(urltest["interval"], serde_json::json!("5m0s"));
        let selector = outbounds.iter().find(|o| o["tag"].as_str() == Some("Bridge-Exit")).unwrap();
        assert_eq!(selector["type"], serde_json::json!("selector"));
        assert_eq!(selector["default"], serde_json::json!("Bridge-Exit-auto"));

        // route.final = Bridge-Exit; custom_rules 进 route.rules
        assert_eq!(json["route"]["final"], serde_json::json!("Bridge-Exit"));
        let route_rules = json["route"]["rules"].as_array().unwrap();
        assert!(route_rules.iter().any(|r| r["domain_suffix"] == serde_json::json!(["custom.com"])
            && r["outbound"] == serde_json::json!("DIRECT")));
    }
}
