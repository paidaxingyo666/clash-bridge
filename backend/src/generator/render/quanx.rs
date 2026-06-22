//! QuanXRenderer — Quantumult X: `[server_local]` / `[policy]` / `[filter_local]`。
//!
//! 行格式: `protocol=host:port, key=val, ..., tag=Name` (协议在 `=` 左边)。
//! 只渲染无链路场景 (`supports_relay_chain()=false`, 含链路 profile 由 service 415 拦截)。
//!
//! 协议支持 (设计 others section):
//! - shadowsocks / vmess / trojan: 支持。
//! - vless: QX 支持状态不稳 → 输出注释 `; vless not supported in QX` 跳过。
//! - hysteria2 / tuic / ssr: QX 不支持 → 跳过记 skipped。
//!
//! 文件开头注释丢失节点数。

use serde_yaml::{Mapping, Value as Yaml};

use crate::error::AppResult;
use crate::generator::model::{GroupKind, InjectGroup, InjectModel, RuleType};
use crate::generator::render::{RenderedSub, Renderer};

pub struct QuanXRenderer;

impl Renderer for QuanXRenderer {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub> {
        let mut skipped: Vec<String> = Vec::new();
        let mut live_nodes: std::collections::HashSet<String> = std::collections::HashSet::new();

        // ---- [server_local] ----
        let mut server_lines: Vec<String> = Vec::new();
        // vless 在 QX 行为不稳: 输出注释行而非静默丢, 但不计入 live_nodes (组成员会被过滤)。
        let mut vless_comment_lines: Vec<String> = Vec::new();
        let mut dropped = 0usize;

        let upstream_proxies = model
            .upstream_root
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .map(|s| s.as_slice())
            .unwrap_or(&[]);
        for p in upstream_proxies {
            let Some(m) = p.as_mapping() else { continue };
            match proxy_to_quanx(m) {
                Ok(Some((name, line))) => {
                    live_nodes.insert(name);
                    server_lines.push(line);
                }
                Ok(None) => {}
                Err(QxSkip::Vless(name)) => {
                    vless_comment_lines.push(format!("; vless not supported in QX: {name}"));
                    skipped.push(format!("vless-unsupported-in-qx:{name}"));
                    dropped += 1;
                }
                Err(QxSkip::Unsupported(reason)) => {
                    skipped.push(reason);
                    dropped += 1;
                }
            }
        }

        // ---- [policy] ----
        let mut policy_lines: Vec<String> = Vec::new();
        let mut live_targets: std::collections::HashSet<String> = live_nodes.clone();
        // QX 内置策略 (小写 direct/reject)。
        live_targets.insert("direct".into());
        live_targets.insert("reject".into());
        for g in &model.injected_groups {
            let members: Vec<String> = g
                .proxies
                .iter()
                .map(|p| qx_policy_ref(p))
                .filter(|p| live_targets.contains(p))
                .collect();
            if members.is_empty() {
                skipped.push(format!("group-empty:{}", g.name));
                continue;
            }
            live_targets.insert(g.name.clone());
            policy_lines.push(qx_policy_line(g, &members));
        }

        // ---- [filter_local] ----
        let mut filter_lines: Vec<String> = Vec::new();
        for spec in &model.custom_rules {
            let target = qx_policy_ref(&spec.target);
            if !live_targets.contains(&target) {
                skipped.push(format!("rule-dangling-target:{}", spec.target));
                continue;
            }
            match rule_spec_to_quanx(&spec.rule_type, spec.matcher.as_deref(), &target) {
                Some(line) => filter_lines.push(line),
                None => skipped.push(format!("rule:{}", spec.to_clash_line())),
            }
        }
        let final_target = if live_targets.contains(&qx_policy_ref(&model.fallback_target)) {
            qx_policy_ref(&model.fallback_target)
        } else {
            "direct".into()
        };
        filter_lines.push(format!("final, {final_target}"));

        // ---- 组装 ----
        let mut out = String::new();
        if dropped > 0 {
            out.push_str(&format!(
                "; clash-bridge: {dropped} node(s) skipped (QX unsupported: vless/hysteria2/tuic/ssr)\n"
            ));
        }
        out.push_str("[server_local]\n");
        for l in &server_lines {
            out.push_str(l);
            out.push('\n');
        }
        for l in &vless_comment_lines {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("\n[policy]\n");
        for l in &policy_lines {
            out.push_str(l);
            out.push('\n');
        }
        out.push_str("\n[filter_local]\n");
        for l in &filter_lines {
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
        "quanx.conf"
    }
}

/// 跳过原因。
#[derive(Debug)]
enum QxSkip {
    /// vless: 输出注释保留, 但不渲染为可用节点。
    Vless(String),
    /// 协议不支持 (hysteria2 / tuic / ssr / 未知): 直接丢。
    Unsupported(String),
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

fn ws_path_host(m: &Mapping) -> (Option<String>, Option<String>) {
    let ws = ysub(m, "ws-opts");
    let path = ws.and_then(|w| ystr(w, "path"));
    let host = ws
        .and_then(|w| ysub(w, "headers"))
        .and_then(|h| ystr(h, "Host").or_else(|| ystr(h, "host")));
    (path, host)
}

/// QX 用 tls-verification (skip-cert-verify 反义): skip=true → verify=false。
fn tls_verification(m: &Mapping) -> &'static str {
    if ybool(m, "skip-cert-verify").unwrap_or(false) {
        "false"
    } else {
        "true"
    }
}

// ---------- server 行 ----------

/// Clash proxy → QX server_local 行。
fn proxy_to_quanx(m: &Mapping) -> Result<Option<(String, String)>, QxSkip> {
    let name = match ystr(m, "name") {
        Some(n) => n,
        None => return Ok(None),
    };
    let ptype = ystr(m, "type").unwrap_or_default();
    let server = ystr(m, "server").unwrap_or_default();
    let port = yport(m).unwrap_or(0);
    if server.trim().is_empty() || port == 0 {
        return Err(QxSkip::Unsupported(format!("missing-server-or-port:{name}")));
    }
    // IPv6 server (含 ':' 且未加方括号) 需 `[server]:port` 消歧。
    let hp = if server.contains(':') && !server.starts_with('[') {
        format!("[{server}]:{port}")
    } else {
        format!("{server}:{port}")
    };

    match ptype.as_str() {
        "ss" => {
            let mut parts: Vec<String> = vec![format!("shadowsocks={hp}")];
            if let Some(c) = ystr(m, "cipher") {
                parts.push(format!("method={c}"));
            }
            if let Some(pw) = ystr(m, "password") {
                parts.push(format!("password={pw}"));
            }
            // 仅 obfs/simple-obfs 才映射 plugin-opts.mode→obfs;
            // v2ray-plugin 等 QX 不支持 ss 插件, 跳过 obfs 字段。
            let is_obfs_plugin = matches!(
                ystr(m, "plugin").as_deref(),
                Some("obfs") | Some("simple-obfs")
            );
            if is_obfs_plugin {
                if let Some(opts) = ysub(m, "plugin-opts") {
                    if let Some(mode) = ystr(opts, "mode") {
                        parts.push(format!("obfs={mode}"));
                    }
                    if let Some(host) = ystr(opts, "host") {
                        parts.push(format!("obfs-host={host}"));
                    }
                    if let Some(uri) = ystr(opts, "uri") {
                        parts.push(format!("obfs-uri={uri}"));
                    }
                }
            }
            if ybool(m, "udp").unwrap_or(false) {
                parts.push("udp-relay=true".into());
            }
            parts.push(format!("tag={name}"));
            Ok(Some((name.clone(), parts.join(", "))))
        }
        "vmess" => {
            let mut parts: Vec<String> = vec![format!("vmess={hp}")];
            // QX vmess: method 默认 chacha20-ietf-poly1305 / aes-128-gcm; 用 cipher 或回退 auto→aes-128-gcm。
            let method = match ystr(m, "cipher").as_deref() {
                Some("auto") | None | Some("") => "chacha20-ietf-poly1305".to_string(),
                Some(other) => other.to_string(),
            };
            parts.push(format!("method={method}"));
            if let Some(u) = ystr(m, "uuid") {
                parts.push(format!("password={u}"));
            }
            // obfs: ws+tls → wss; ws → ws; tcp+tls → over-tls; 否则不写。
            let tls_on = ybool(m, "tls").unwrap_or(false);
            let is_ws = ystr(m, "network").as_deref() == Some("ws");
            let obfs = match (is_ws, tls_on) {
                (true, true) => Some("wss"),
                (true, false) => Some("ws"),
                (false, true) => Some("over-tls"),
                (false, false) => None,
            };
            if let Some(o) = obfs {
                parts.push(format!("obfs={o}"));
                if let Some(sni) = ystr(m, "servername").or_else(|| ystr(m, "sni")) {
                    if !sni.is_empty() {
                        parts.push(format!("obfs-host={sni}"));
                    }
                }
                if is_ws {
                    let (path, host) = ws_path_host(m);
                    if let Some(p) = path {
                        parts.push(format!("obfs-uri={p}"));
                    }
                    if obfs == Some("ws") || obfs == Some("wss") {
                        // host header 已在 obfs-host (用 servername); 若 ws header Host 更具体则覆盖。
                        if let Some(h) = host {
                            // 仅当 servername 为空时补 obfs-host。
                            if ystr(m, "servername").unwrap_or_default().is_empty()
                                && ystr(m, "sni").unwrap_or_default().is_empty()
                            {
                                parts.push(format!("obfs-host={h}"));
                            }
                        }
                    }
                }
            }
            if tls_on {
                parts.push(format!("tls-verification={}", tls_verification(m)));
            }
            if ybool(m, "udp").unwrap_or(false) {
                parts.push("udp-relay=true".into());
            }
            parts.push(format!("tag={name}"));
            Ok(Some((name.clone(), parts.join(", "))))
        }
        "trojan" => {
            let mut parts: Vec<String> = vec![format!("trojan={hp}")];
            if let Some(pw) = ystr(m, "password") {
                parts.push(format!("password={pw}"));
            }
            let sni = ystr(m, "sni").or_else(|| ystr(m, "servername")).filter(|s| !s.is_empty());
            // QX trojan: over-tls 与 obfs=wss 互斥, 按 network 二分。
            if ystr(m, "network").as_deref() == Some("ws") {
                // websocket: 只写 obfs=wss / obfs-host / obfs-uri (不写 over-tls / tls-host)。
                let (path, host) = ws_path_host(m);
                parts.push("obfs=wss".into());
                // obfs-host 优先 sni, 回退 ws header Host。
                if let Some(h) = sni.clone().or(host) {
                    parts.push(format!("obfs-host={h}"));
                }
                if let Some(p) = path {
                    parts.push(format!("obfs-uri={p}"));
                }
            } else {
                // 非 ws: 普通 over-tls。
                parts.push("over-tls=true".into());
                if let Some(sni) = sni {
                    parts.push(format!("tls-host={sni}"));
                }
            }
            parts.push(format!("tls-verification={}", tls_verification(m)));
            if ybool(m, "udp").unwrap_or(false) {
                parts.push("udp-relay=true".into());
            }
            parts.push(format!("tag={name}"));
            Ok(Some((name.clone(), parts.join(", "))))
        }
        "vless" => Err(QxSkip::Vless(name)),
        "hysteria2" => Err(QxSkip::Unsupported(format!("hysteria2-unsupported-in-qx:{name}"))),
        "tuic" => Err(QxSkip::Unsupported(format!("tuic-unsupported-in-qx:{name}"))),
        "ssr" => Err(QxSkip::Unsupported(format!("ssr-unsupported-in-qx:{name}"))),
        other => Err(QxSkip::Unsupported(format!("{other}:{name}"))),
    }
}

// ---------- policy 行 ----------

/// 把 Clash 内置策略名映射成 QX 习惯 (DIRECT→direct, REJECT→reject)。其余 (组名/节点名) 原样。
fn qx_policy_ref(name: &str) -> String {
    match name {
        "DIRECT" => "direct".to_string(),
        "REJECT" => "reject".to_string(),
        other => other.to_string(),
    }
}

fn qx_policy_line(g: &InjectGroup, members: &[String]) -> String {
    match &g.kind {
        GroupKind::UrlTest { url, interval } => {
            // url-test → url-latency-benchmark。QX 用 check-interval (秒)。
            let _ = url;
            format!(
                "url-latency-benchmark = {}, {}, check-interval={interval}, alive-checking=false",
                g.name,
                members.join(", ")
            )
        }
        GroupKind::Select => {
            format!("static = {}, {}", g.name, members.join(", "))
        }
    }
}

// ---------- filter 行 ----------

/// RuleSpec → QX filter_local 行。无等价返回 None。
fn rule_spec_to_quanx(rule_type: &RuleType, matcher: Option<&str>, target: &str) -> Option<String> {
    let m = matcher?;
    let line = match rule_type {
        RuleType::Domain => format!("host, {m}, {target}"),
        RuleType::DomainSuffix => format!("host-suffix, {m}, {target}"),
        RuleType::DomainKeyword => format!("host-keyword, {m}, {target}"),
        RuleType::IpCidr | RuleType::IpCidr6 => format!("ip-cidr, {m}, {target}"),
        RuleType::GeoIp => format!("geoip, {}, {target}", m.to_ascii_lowercase()),
        // Process / DstPort / GeoSite / Other / Match: 无 QX filter_local 等价, 跳过。
        _ => return None,
    };
    Some(line)
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
    fn ss_server_line() {
        let m = ymap("name: SS-HK\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: chacha20-ietf-poly1305\npassword: pw\nudp: true");
        let (name, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert_eq!(name, "SS-HK");
        assert_eq!(line, "shadowsocks=1.2.3.4:8388, method=chacha20-ietf-poly1305, password=pw, udp-relay=true, tag=SS-HK");
    }

    #[test]
    fn trojan_server_line() {
        let m = ymap("name: TJ\ntype: trojan\nserver: jp.com\nport: 443\npassword: tpw\nsni: jp.com");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(line.starts_with("trojan=jp.com:443"));
        assert!(line.contains("password=tpw"));
        assert!(line.contains("over-tls=true"));
        assert!(line.contains("tls-host=jp.com"));
        assert!(line.contains("tls-verification=true"));
        assert!(line.ends_with("tag=TJ"));
    }

    #[test]
    fn vmess_ws_tls_wss() {
        let m = ymap("name: VM\ntype: vmess\nserver: sg.com\nport: 443\nuuid: uuid-x\ncipher: auto\ntls: true\nservername: sg.com\nnetwork: ws\nws-opts:\n  path: /ray");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(line.starts_with("vmess=sg.com:443"));
        assert!(line.contains("password=uuid-x"));
        assert!(line.contains("obfs=wss"));
        assert!(line.contains("obfs-host=sg.com"));
        assert!(line.contains("obfs-uri=/ray"));
        assert!(line.contains("tls-verification=true"));
    }

    #[test]
    fn trojan_ws_uses_obfs_wss_no_over_tls() {
        // trojan + ws: 只写 obfs=wss / obfs-host / obfs-uri, 不写 over-tls / tls-host。
        let m = ymap("name: TJW\ntype: trojan\nserver: jp.com\nport: 443\npassword: tpw\nsni: jp.com\nnetwork: ws\nws-opts:\n  path: /tj\n  headers:\n    Host: cdn.jp.com");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(line.starts_with("trojan=jp.com:443"));
        assert!(line.contains("password=tpw"));
        assert!(line.contains("obfs=wss"));
        // obfs-host 优先 sni。
        assert!(line.contains("obfs-host=jp.com"));
        assert!(line.contains("obfs-uri=/tj"));
        assert!(!line.contains("over-tls"));
        assert!(!line.contains("tls-host"));
        assert!(line.contains("tls-verification=true"));
    }

    #[test]
    fn trojan_non_ws_uses_over_tls() {
        // 非 ws trojan 保持 over-tls / tls-host, 不出现 obfs=wss。
        let m = ymap("name: TJ\ntype: trojan\nserver: jp.com\nport: 443\npassword: tpw\nsni: jp.com");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(line.contains("over-tls=true"));
        assert!(line.contains("tls-host=jp.com"));
        assert!(!line.contains("obfs=wss"));
    }

    #[test]
    fn ipv6_server_bracketed() {
        // IPv6 server 应加方括号消歧。
        let m = ymap("name: V6\ntype: ss\nserver: '2001:db8::1'\nport: 8388\ncipher: aes-256-gcm\npassword: pw");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(line.starts_with("shadowsocks=[2001:db8::1]:8388"));
    }

    #[test]
    fn ss_v2ray_plugin_no_obfs() {
        // plugin=v2ray-plugin → 不产 obfs 行 (QX 不支持 ss+v2ray-plugin)。
        let m = ymap("name: SSV\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw\nplugin: v2ray-plugin\nplugin-opts:\n  mode: websocket\n  host: x.com");
        let (_, line) = proxy_to_quanx(&m).unwrap().unwrap();
        assert!(!line.contains("obfs="));
        assert!(!line.contains("obfs-host="));
    }

    #[test]
    fn vless_returns_comment_skip() {
        let m = ymap("name: VL\ntype: vless\nserver: a.com\nport: 443\nuuid: u");
        match proxy_to_quanx(&m) {
            Err(QxSkip::Vless(n)) => assert_eq!(n, "VL"),
            _ => panic!("vless 应返回 Vless skip"),
        }
    }

    #[test]
    fn hysteria2_tuic_skipped() {
        let hy = ymap("name: HY\ntype: hysteria2\nserver: a.com\nport: 443\npassword: p");
        assert!(matches!(proxy_to_quanx(&hy), Err(QxSkip::Unsupported(_))));
        let tu = ymap("name: TU\ntype: tuic\nserver: a.com\nport: 443\nuuid: u\npassword: p");
        assert!(matches!(proxy_to_quanx(&tu), Err(QxSkip::Unsupported(_))));
    }

    #[test]
    fn full_render_sections_and_final() {
        let groups = vec![
            InjectGroup {
                name: "Auto".into(),
                kind: GroupKind::UrlTest { url: "https://cp.cloudflare.com/generate_204".into(), interval: 300 },
                proxies: vec!["SS-HK".into()],
            },
            InjectGroup {
                name: "Bridge-Exit".into(),
                kind: GroupKind::Select,
                proxies: vec!["Auto".into(), "SS-HK".into(), "DIRECT".into()],
            },
        ];
        let specs = vec![
            RuleSpec { rule_type: RuleType::DomainSuffix, matcher: Some("google.com".into()), target: "Bridge-Exit".into() },
            RuleSpec { rule_type: RuleType::GeoIp, matcher: Some("CN".into()), target: "DIRECT".into() },
        ];
        let upstream = "proxies:\n  - name: SS-HK\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: chacha20-ietf-poly1305\n    password: pw\n";
        let model = make_model(specs, upstream, groups);
        let rendered = QuanXRenderer.render(&model).unwrap();
        let body = &rendered.body;
        assert!(body.contains("[server_local]"));
        assert!(body.contains("[policy]"));
        assert!(body.contains("[filter_local]"));
        assert!(body.contains("url-latency-benchmark = Auto, SS-HK, check-interval=300"));
        assert!(body.contains("static = Bridge-Exit, Auto, SS-HK, direct"));
        assert!(body.contains("host-suffix, google.com, Bridge-Exit"));
        assert!(body.contains("geoip, cn, DIRECT") || body.contains("geoip, cn, direct"));
        assert!(body.contains("final, Bridge-Exit"));
    }

    #[test]
    fn vless_node_filtered_from_group_and_commented() {
        let groups = vec![InjectGroup {
            name: "Bridge-Exit".into(),
            kind: GroupKind::Select,
            proxies: vec!["VL".into(), "SS-HK".into(), "DIRECT".into()],
        }];
        let upstream = "proxies:\n  - name: VL\n    type: vless\n    server: a.com\n    port: 443\n    uuid: u\n  - name: SS-HK\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: chacha20-ietf-poly1305\n    password: pw\n";
        let model = make_model(Vec::new(), upstream, groups);
        let rendered = QuanXRenderer.render(&model).unwrap();
        // vless 注释行出现, 节点不进 policy。
        assert!(rendered.body.contains("; vless not supported in QX: VL"));
        assert!(rendered.body.contains("static = Bridge-Exit, SS-HK, direct"));
        assert!(rendered.body.contains("; clash-bridge: 1 node(s) skipped"));
        assert!(rendered.skipped.iter().any(|s| s.starts_with("vless-unsupported-in-qx:")));
    }
}
