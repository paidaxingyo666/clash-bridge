//! SurgeRenderer — Surge `.conf` (ini): `[Proxy]` / `[Proxy Group]` / `[Rule]`。
//!
//! 行格式: `Name = protocol, host, port, key=value, ...`。
//! 只渲染无链路场景 (`supports_relay_chain()=false`, 含链路 profile 由 service 415 拦截)。
//! Surge 原生不支持的协议 (vless / ssr) 跳过并记 `skipped`。
//!
//! - `[Proxy]`: 上游 proxies → Surge 协议行 (ss/vmess/trojan/tuic/hysteria2)。
//! - `[Proxy Group]`: injected_groups (url-test / select) + 一个汇总 select。
//! - `[Rule]`: custom_rules 翻 Surge DSL + `FINAL,<fallback>`。

use serde_yaml::{Mapping, Value as Yaml};

use crate::error::AppResult;
use crate::generator::model::{GroupKind, InjectGroup, InjectModel, RuleType};
use crate::generator::render::{RenderedSub, Renderer};

pub struct SurgeRenderer;

impl Renderer for SurgeRenderer {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub> {
        let mut skipped: Vec<String> = Vec::new();
        // 成功渲染出的节点名 (供 group 成员过滤)。
        let mut live_nodes: std::collections::HashSet<String> = std::collections::HashSet::new();

        // ---- [Proxy] ----
        let mut proxy_lines: Vec<String> = Vec::new();
        let upstream_proxies = model
            .upstream_root
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .map(|s| s.as_slice())
            .unwrap_or(&[]);
        for p in upstream_proxies {
            let Some(m) = p.as_mapping() else { continue };
            match proxy_to_surge(m) {
                Ok(Some((name, line))) => {
                    live_nodes.insert(name);
                    proxy_lines.push(line);
                }
                Ok(None) => {}
                Err(reason) => skipped.push(reason),
            }
        }

        // ---- [Proxy Group] ----
        // injected_groups 的成员可能引用被 skip 的节点 → 过滤; 过滤后为空的组跳过。
        // 内置目标 DIRECT/REJECT 始终合法。组名本身也算 live (后续 select 组可引用)。
        let mut group_lines: Vec<String> = Vec::new();
        let mut live_targets: std::collections::HashSet<String> = live_nodes.clone();
        live_targets.insert("DIRECT".into());
        live_targets.insert("REJECT".into());
        for g in &model.injected_groups {
            let members: Vec<String> = g
                .proxies
                .iter()
                .filter(|p| live_targets.contains(*p))
                .cloned()
                .collect();
            if members.is_empty() {
                skipped.push(format!("group-empty:{}", g.name));
                continue;
            }
            live_targets.insert(g.name.clone());
            group_lines.push(surge_group_line(g, &members));
        }

        // ---- [Rule] ----
        let mut rule_lines: Vec<String> = Vec::new();
        for spec in &model.custom_rules {
            // target 必须落在 live_targets 内 (否则 Surge 引用不存在的 policy)。
            if !live_targets.contains(&spec.target) {
                skipped.push(format!("rule-dangling-target:{}", spec.target));
                continue;
            }
            match rule_spec_to_surge(&spec.rule_type, spec.matcher.as_deref(), &spec.target) {
                Some(line) => rule_lines.push(line),
                None => skipped.push(format!("rule:{}", spec.to_clash_line())),
            }
        }
        // FINAL 兜底: fallback_target 若存活则用之, 否则 DIRECT。
        let final_target = if live_targets.contains(&model.fallback_target) {
            model.fallback_target.clone()
        } else {
            "DIRECT".into()
        };
        rule_lines.push(format!("FINAL,{final_target}"));

        let mut out = String::new();
        out.push_str("[Proxy]\n");
        for l in &proxy_lines {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("\n[Proxy Group]\n");
        for l in &group_lines {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("\n[Rule]\n");
        for l in &rule_lines {
            out.push_str(l);
            out.push('\n');
        }

        let mut rendered = RenderedSub::new(out, "text/plain; charset=utf-8", "conf");
        rendered.skipped = skipped;
        Ok(rendered)
    }

    fn supports_relay_chain(&self) -> bool {
        false
    }

    fn format_id(&self) -> &'static str {
        "surge.conf"
    }
}

// ---------- 取值工具 ----------

fn ystr(m: &Mapping, key: &str) -> Option<String> {
    m.get(Yaml::String(key.into()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ybool(m: &Mapping, key: &str) -> Option<bool> {
    m.get(Yaml::String(key.into())).and_then(|v| v.as_bool())
}

fn yport(m: &Mapping) -> Option<u64> {
    let v = m.get(Yaml::String("port".into()))?;
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn ysub<'a>(m: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    m.get(Yaml::String(key.into())).and_then(|v| v.as_mapping())
}

/// hysteria2 带宽: 整数或 "200 Mbps" 字符串 → Mbps 整数。
fn ymbps(m: &Mapping, key: &str) -> Option<u64> {
    let v = m.get(Yaml::String(key.into()))?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?.trim();
    s.strip_suffix(" Mbps")
        .or_else(|| s.strip_suffix("Mbps"))
        .unwrap_or(s)
        .trim()
        .parse()
        .ok()
}

/// ws transport: 返回 (path, host)。
fn ws_path_host(m: &Mapping) -> (Option<String>, Option<String>) {
    let ws = ysub(m, "ws-opts");
    let path = ws.and_then(|w| ystr(w, "path"));
    let host = ws
        .and_then(|w| ysub(w, "headers"))
        .and_then(|h| ystr(h, "Host").or_else(|| ystr(h, "host")));
    (path, host)
}

// ---------- proxy 行 ----------

/// Clash proxy → Surge 行。Ok(Some((name, line))) 成功; Ok(None) 无名跳过; Err(reason) 不支持。
fn proxy_to_surge(m: &Mapping) -> Result<Option<(String, String)>, String> {
    let name = match ystr(m, "name") {
        Some(n) => n,
        None => return Ok(None),
    };
    let ptype = ystr(m, "type").unwrap_or_default();
    let server = ystr(m, "server").unwrap_or_default();
    let port = yport(m).unwrap_or(0);
    if server.trim().is_empty() || port == 0 {
        return Err(format!("missing-server-or-port:{name}"));
    }

    let mut params: Vec<String> = Vec::new();
    match ptype.as_str() {
        "ss" => {
            if let Some(c) = ystr(m, "cipher") {
                params.push(format!("encrypt-method={c}"));
            }
            if let Some(pw) = ystr(m, "password") {
                params.push(format!("password={pw}"));
            }
            if ybool(m, "udp").unwrap_or(false) {
                params.push("udp-relay=true".into());
            }
            // obfs plugin → obfs / obfs-host / obfs-uri。
            // 仅 obfs/simple-obfs 才映射 (v2ray-plugin 等 Surge 不支持, 跳过 obfs 字段)。
            let is_obfs_plugin = matches!(
                ystr(m, "plugin").as_deref(),
                Some("obfs") | Some("simple-obfs")
            );
            if is_obfs_plugin {
                if let Some(opts) = ysub(m, "plugin-opts") {
                    if let Some(mode) = ystr(opts, "mode") {
                        params.push(format!("obfs={mode}"));
                    }
                    if let Some(host) = ystr(opts, "host") {
                        params.push(format!("obfs-host={host}"));
                    }
                    if let Some(uri) = ystr(opts, "uri") {
                        params.push(format!("obfs-uri={uri}"));
                    }
                }
            }
            Ok(Some((name.clone(), surge_line("ss", &name, &server, port, params))))
        }
        "vmess" => {
            if let Some(u) = ystr(m, "uuid") {
                params.push(format!("username={u}"));
            }
            let tls_on = ybool(m, "tls").unwrap_or(false);
            if tls_on {
                params.push("tls=true".into());
                if let Some(sni) = ystr(m, "servername").or_else(|| ystr(m, "sni")) {
                    if !sni.is_empty() {
                        params.push(format!("sni={sni}"));
                    }
                }
            }
            if ystr(m, "network").as_deref() == Some("ws") {
                params.push("ws=true".into());
                let (path, host) = ws_path_host(m);
                if let Some(p) = path {
                    params.push(format!("ws-path={p}"));
                }
                if let Some(h) = host {
                    params.push(format!("ws-headers=Host:{h}"));
                }
            }
            if ybool(m, "skip-cert-verify").unwrap_or(false) {
                params.push("skip-cert-verify=true".into());
            }
            params.push("vmess-aead=true".into());
            Ok(Some((name.clone(), surge_line("vmess", &name, &server, port, params))))
        }
        "trojan" => {
            if let Some(pw) = ystr(m, "password") {
                params.push(format!("password={pw}"));
            }
            if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")) {
                if !sni.is_empty() {
                    params.push(format!("sni={sni}"));
                }
            }
            if ybool(m, "skip-cert-verify").unwrap_or(false) {
                params.push("skip-cert-verify=true".into());
            }
            if ystr(m, "network").as_deref() == Some("ws") {
                params.push("ws=true".into());
                let (path, host) = ws_path_host(m);
                if let Some(p) = path {
                    params.push(format!("ws-path={p}"));
                }
                if let Some(h) = host {
                    params.push(format!("ws-headers=Host:{h}"));
                }
            }
            Ok(Some((name.clone(), surge_line("trojan", &name, &server, port, params))))
        }
        "tuic" => {
            // Surge TUIC 区分 v4/v5:
            // - v5 (uuid + password): `uuid=<uuid>, password=<password>, version=5` (官方 Surge v5 语法)。
            // - v4 (仅 token, 无 uuid): `token=<token>`。
            let uuid = ystr(m, "uuid").filter(|s| !s.is_empty());
            let password = ystr(m, "password").filter(|s| !s.is_empty());
            match (uuid, password) {
                (Some(u), Some(pw)) => {
                    // v5: 同时有 uuid 与 password。
                    params.push(format!("uuid={u}"));
                    params.push(format!("password={pw}"));
                    params.push("version=5".into());
                }
                (Some(u), None) => {
                    // 只有 uuid (无 password): 退化按 v4 token 处理 (uuid 当 token)。
                    params.push(format!("token={u}"));
                }
                (None, _) => {
                    // 无 uuid: v4 token 形态。
                    if let Some(t) = ystr(m, "token").filter(|s| !s.is_empty()) {
                        params.push(format!("token={t}"));
                    }
                }
            }
            if let Some(alpn) = surge_alpn(m) {
                params.push(format!("alpn={alpn}"));
            }
            if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")) {
                if !sni.is_empty() {
                    params.push(format!("sni={sni}"));
                }
            }
            if ybool(m, "skip-cert-verify").unwrap_or(false) {
                params.push("skip-cert-verify=true".into());
            }
            Ok(Some((name.clone(), surge_line("tuic", &name, &server, port, params))))
        }
        "hysteria2" => {
            if let Some(pw) = ystr(m, "password") {
                params.push(format!("password={pw}"));
            }
            if let Some(down) = ymbps(m, "down") {
                params.push(format!("download-bandwidth={down}"));
            }
            if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")) {
                if !sni.is_empty() {
                    params.push(format!("sni={sni}"));
                }
            }
            if ybool(m, "skip-cert-verify").unwrap_or(false) {
                params.push("skip-cert-verify=true".into());
            }
            if let Some(opw) = ystr(m, "obfs-password").filter(|s| !s.is_empty()) {
                params.push(format!("salamander-password={opw}"));
            }
            Ok(Some((name.clone(), surge_line("hysteria2", &name, &server, port, params))))
        }
        "vless" => Err(format!("vless-unsupported-in-surge:{name}")),
        "ssr" => Err(format!("ssr-unsupported-in-surge:{name}")),
        other => Err(format!("{other}:{name}")),
    }
}

/// alpn 数组 → 逗号拼接。
fn surge_alpn(m: &Mapping) -> Option<String> {
    let v = m.get(Yaml::String("alpn".into()))?;
    let arr = v.as_sequence()?;
    let items: Vec<String> = arr
        .iter()
        .filter_map(|x| x.as_str().map(|s| s.to_string()))
        .collect();
    if items.is_empty() {
        None
    } else {
        Some(items.join(","))
    }
}

fn surge_line(proto: &str, name: &str, server: &str, port: u64, params: Vec<String>) -> String {
    let mut line = format!("{name} = {proto}, {server}, {port}");
    for p in params {
        line.push_str(", ");
        line.push_str(&p);
    }
    line
}

// ---------- group 行 ----------

fn surge_group_line(g: &InjectGroup, members: &[String]) -> String {
    match &g.kind {
        GroupKind::UrlTest { url, interval } => {
            format!(
                "{} = url-test, {}, url={url}, interval={interval}, tolerance=50",
                g.name,
                members.join(", ")
            )
        }
        GroupKind::Select => {
            format!("{} = select, {}", g.name, members.join(", "))
        }
    }
}

// ---------- rule 行 ----------

/// RuleSpec → Surge DSL 行。无 Surge 等价返回 None。
fn rule_spec_to_surge(rule_type: &RuleType, matcher: Option<&str>, target: &str) -> Option<String> {
    let m = matcher?;
    let kw = match rule_type {
        RuleType::Domain => "DOMAIN",
        RuleType::DomainSuffix => "DOMAIN-SUFFIX",
        RuleType::DomainKeyword => "DOMAIN-KEYWORD",
        RuleType::IpCidr => "IP-CIDR",
        RuleType::IpCidr6 => "IP-CIDR6",
        RuleType::GeoIp => "GEOIP",
        RuleType::Process => "PROCESS-NAME",
        RuleType::DstPort => "DST-PORT",
        RuleType::SrcPort => "SRC-PORT",
        // GeoSite / Other / Match: 无简单 Surge 等价, 跳过 (Match 已在 service/上游单独处理)。
        _ => return None,
    };
    Some(format!("{kw},{m},{target}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::model::{GroupKind, InjectGroup, RuleSpec};
    use serde_yaml::Value as Yaml;

    fn ymap(s: &str) -> Mapping {
        serde_yaml::from_str::<Yaml>(s).unwrap().as_mapping().unwrap().clone()
    }

    fn make_model(custom_rules: Vec<RuleSpec>, upstream_yaml: &str, groups: Vec<InjectGroup>) -> InjectModel {
        let root: Yaml = serde_yaml::from_str(upstream_yaml).unwrap();
        InjectModel {
            upstream_root: root,
            injected_proxies: Vec::new(),
            injected_groups: groups,
            select_inject_target: "Bridge-Exit".into(),
            custom_rules,
            fallback_target: "Bridge-Exit".into(),
            upstream_count: 0,
            bridge_count: 0,
            chain_count: 0,
            missing_bridges: Vec::new(),
            has_relay_chain: false,
        }
    }

    #[test]
    fn ss_proxy_line() {
        let m = ymap("name: SS1\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw\nudp: true");
        let (name, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert_eq!(name, "SS1");
        assert_eq!(line, "SS1 = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pw, udp-relay=true");
    }

    #[test]
    fn vmess_ws_tls_line() {
        let m = ymap("name: VM\ntype: vmess\nserver: a.com\nport: 443\nuuid: u\ntls: true\nservername: a.com\nnetwork: ws\nws-opts:\n  path: /ray\n  headers:\n    Host: a.com");
        let (_, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert!(line.contains("vmess, a.com, 443"));
        assert!(line.contains("username=u"));
        assert!(line.contains("tls=true"));
        assert!(line.contains("ws=true"));
        assert!(line.contains("ws-path=/ray"));
        assert!(line.contains("ws-headers=Host:a.com"));
    }

    #[test]
    fn tuic_v5_outputs_uuid_password_version() {
        // v5: uuid + password → uuid=, password=, version=5 (不输出 token=)。
        let m = ymap("name: TU5\ntype: tuic\nserver: h.com\nport: 443\nuuid: b831381d-6324-4d53-ad4f-8cda48b30811\npassword: secret\nalpn:\n  - h3\nsni: h.com");
        let (_, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert!(line.contains("tuic, h.com, 443"));
        assert!(line.contains("uuid=b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert!(line.contains("password=secret"));
        assert!(line.contains("version=5"));
        assert!(!line.contains("token="));
        assert!(line.contains("alpn=h3"));
        assert!(line.contains("sni=h.com"));
    }

    #[test]
    fn tuic_v4_keeps_token() {
        // v4: 仅 token (无 uuid) → token=, 不出现 version=5。
        let m = ymap("name: TU4\ntype: tuic\nserver: h.com\nport: 443\ntoken: tok123");
        let (_, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert!(line.contains("token=tok123"));
        assert!(!line.contains("version=5"));
        assert!(!line.contains("uuid="));
    }

    #[test]
    fn ss_v2ray_plugin_no_obfs() {
        // plugin=v2ray-plugin, mode=websocket → 不应产生 obfs 行 (Surge 不支持)。
        let m = ymap("name: SSV\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw\nplugin: v2ray-plugin\nplugin-opts:\n  mode: websocket\n  host: x.com");
        let (_, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert!(!line.contains("obfs="));
        assert!(!line.contains("obfs-host="));
    }

    #[test]
    fn ss_obfs_plugin_maps_obfs() {
        // plugin=obfs (simple-obfs 系) → 正常映射 obfs。
        let m = ymap("name: SSO\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw\nplugin: obfs\nplugin-opts:\n  mode: http\n  host: bing.com");
        let (_, line) = proxy_to_surge(&m).unwrap().unwrap();
        assert!(line.contains("obfs=http"));
        assert!(line.contains("obfs-host=bing.com"));
    }

    #[test]
    fn vless_skipped() {
        let m = ymap("name: VL\ntype: vless\nserver: a.com\nport: 443\nuuid: u");
        assert!(proxy_to_surge(&m).unwrap_err().starts_with("vless-unsupported-in-surge:"));
    }

    #[test]
    fn ssr_skipped() {
        let m = ymap("name: SR\ntype: ssr\nserver: a.com\nport: 443");
        assert!(proxy_to_surge(&m).unwrap_err().starts_with("ssr-unsupported-in-surge:"));
    }

    #[test]
    fn rule_match_to_final() {
        // 渲染整体, 验证 FINAL 出现。
        let groups = vec![InjectGroup {
            name: "Bridge-Exit".into(),
            kind: GroupKind::Select,
            proxies: vec!["SS1".into(), "DIRECT".into()],
        }];
        let specs = vec![
            RuleSpec { rule_type: RuleType::DomainSuffix, matcher: Some("google.com".into()), target: "Bridge-Exit".into() },
            RuleSpec { rule_type: RuleType::GeoIp, matcher: Some("CN".into()), target: "DIRECT".into() },
        ];
        let upstream = "proxies:\n  - name: SS1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
        let model = make_model(specs, upstream, groups);
        let rendered = SurgeRenderer.render(&model).unwrap();
        assert!(rendered.body.contains("[Proxy]"));
        assert!(rendered.body.contains("[Proxy Group]"));
        assert!(rendered.body.contains("[Rule]"));
        assert!(rendered.body.contains("DOMAIN-SUFFIX,google.com,Bridge-Exit"));
        assert!(rendered.body.contains("GEOIP,CN,DIRECT"));
        assert!(rendered.body.contains("FINAL,Bridge-Exit"));
        assert!(rendered.body.contains("Bridge-Exit = select, SS1, DIRECT"));
    }

    #[test]
    fn dangling_rule_target_skipped() {
        let groups = vec![InjectGroup {
            name: "Bridge-Exit".into(),
            kind: GroupKind::Select,
            proxies: vec!["SS1".into()],
        }];
        let specs = vec![RuleSpec {
            rule_type: RuleType::Domain,
            matcher: Some("a.com".into()),
            target: "GhostGroup".into(),
        }];
        let upstream = "proxies:\n  - name: SS1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
        let model = make_model(specs, upstream, groups);
        let rendered = SurgeRenderer.render(&model).unwrap();
        assert!(!rendered.body.contains("GhostGroup"));
        assert!(rendered.skipped.iter().any(|s| s == "rule-dangling-target:GhostGroup"));
    }

    #[test]
    fn group_with_dead_member_filtered() {
        // group 引用 vless 节点 (被 skip), 应过滤掉。
        let groups = vec![InjectGroup {
            name: "Bridge-Exit".into(),
            kind: GroupKind::Select,
            proxies: vec!["VL".into(), "SS1".into(), "DIRECT".into()],
        }];
        let upstream = "proxies:\n  - name: VL\n    type: vless\n    server: a.com\n    port: 443\n    uuid: u\n  - name: SS1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
        let model = make_model(Vec::new(), upstream, groups);
        let rendered = SurgeRenderer.render(&model).unwrap();
        // VL 被过滤, 只剩 SS1, DIRECT。
        assert!(rendered.body.contains("Bridge-Exit = select, SS1, DIRECT"));
        assert!(!rendered.body.contains(", VL,"));
        assert!(rendered.skipped.iter().any(|s| s.starts_with("vless-unsupported-in-surge:")));
    }
}
