//! SingboxRenderer — 从 [`InjectModel`] 从零构造 sing-box JSON。
//!
//! 不复用上游 proxy-groups (sing-box 用 outbounds + route)。设计见 cb-multiout-design.md 的
//! singbox section。映射不了的协议 (ssr / tuic-v4 token) 跳过该节点并记入 `skipped`,
//! 不静默丢字段导致连不上。

use std::collections::HashSet;

use serde_json::{json, Map, Value as Json};
use serde_yaml::{Mapping, Value as Yaml};

use crate::error::AppResult;
use crate::generator::model::{GroupKind, InjectGroup, InjectModel, RuleType};
use crate::generator::render::{RenderedSub, Renderer};

pub struct SingboxRenderer;

impl Renderer for SingboxRenderer {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub> {
        let mut skipped: Vec<String> = Vec::new();

        // 合法 outbound tag 集合: custom_rule 的 target 必须落在此集合内, 否则会产生
        // 悬空引用让 sing-box 整份配置加载失败。内置 3 个 + 所有实际渲染出的 outbound tag。
        let mut valid_outbound_tags: HashSet<String> = HashSet::new();
        valid_outbound_tags.insert("DIRECT".into());
        valid_outbound_tags.insert("REJECT".into());
        valid_outbound_tags.insert("dns-out".into());

        // 1. 固定内置 outbound。
        let mut outbounds: Vec<Json> = vec![
            json!({ "type": "direct", "tag": "DIRECT" }),
            json!({ "type": "block", "tag": "REJECT" }),
            json!({ "type": "dns", "tag": "dns-out" }),
        ];

        // 2. 上游 proxies → outbounds。
        let upstream_proxies = model
            .upstream_root
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .map(|s| s.as_slice())
            .unwrap_or(&[]);
        for p in upstream_proxies {
            if let Some(m) = p.as_mapping() {
                match clash_proxy_to_singbox(m) {
                    Ok(Some(ob)) => {
                        if let Some(tag) = ob.get("tag").and_then(|t| t.as_str()) {
                            valid_outbound_tags.insert(tag.to_string());
                        }
                        outbounds.push(ob);
                    }
                    Ok(None) => {}
                    Err(reason) => skipped.push(reason),
                }
            }
        }

        // 3. 链路节点 (injected_proxies): 正常映射后追加 detour=<bridge tag>。
        //    detour 指向跳板 outbound; 若该跳板因协议不支持被 skip (不在 valid_outbound_tags),
        //    则 detour 悬空 → sing-box 拒绝加载, 故此处一并跳过该 chain 并记 skipped。
        //    上游节点已在 step 2 全部渲染完, 此时 valid_outbound_tags 含全部存活跳板 tag。
        for m in &model.injected_proxies {
            match clash_proxy_to_singbox(m) {
                Ok(Some(mut ob)) => {
                    let bridge = m
                        .get(Yaml::String("dialer-proxy".into()))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    if let Some(bridge) = &bridge {
                        if !valid_outbound_tags.contains(bridge) {
                            let tag = ob
                                .get("tag")
                                .and_then(|t| t.as_str())
                                .unwrap_or("?")
                                .to_string();
                            skipped.push(format!("chain-dangling-detour:{tag}"));
                            continue;
                        }
                        if let Some(obj) = ob.as_object_mut() {
                            obj.insert("detour".into(), json!(bridge));
                        }
                    }
                    if let Some(tag) = ob.get("tag").and_then(|t| t.as_str()) {
                        valid_outbound_tags.insert(tag.to_string());
                    }
                    outbounds.push(ob);
                }
                Ok(None) => {}
                Err(reason) => skipped.push(reason),
            }
        }

        // 4. injected_groups → urltest / selector。
        //    组成员可能引用被 skip 的 chain (悬空成员同样让配置加载失败), 故只保留在
        //    valid_outbound_tags 内的成员; 过滤后为空的组整体跳过 (空 outbounds 也非法)。
        //    按 injected_groups 顺序处理 (子 url-test 组先于 Bridge-Exit select 组),
        //    存活组的名字才进 valid_outbound_tags, 让后续 select 组的成员过滤能识别死组。
        for g in &model.injected_groups {
            let live: Vec<String> = g
                .proxies
                .iter()
                .filter(|p| valid_outbound_tags.contains(*p))
                .cloned()
                .collect();
            if live.is_empty() {
                skipped.push(format!("group-empty:{}", g.name));
                continue;
            }
            valid_outbound_tags.insert(g.name.clone());
            outbounds.push(inject_group_to_outbound(g, &live));
        }

        // 5. route.rules + route.final。
        let mut rules: Vec<Json> = vec![
            json!({ "protocol": "dns", "outbound": "dns-out" }),
            json!({ "ip_is_private": true, "outbound": "DIRECT" }),
        ];
        for spec in &model.custom_rules {
            // 5a. target 悬空校验: parse_custom_rules 放行了上游 proxy-group 名,
            //     但 sing-box 没有这些 outbound, 不校验会让整份配置加载失败。
            if !valid_outbound_tags.contains(&spec.target) {
                skipped.push(format!("rule-dangling-target:{}", spec.target));
                continue;
            }
            match rule_spec_to_singbox(&spec.rule_type, spec.matcher.as_deref(), &spec.target) {
                Some(r) => rules.push(r),
                None => {
                    // GeoIp 在新版 sing-box 已无等价字段, 单独标注; 其余无等价类型统一记 rule。
                    if spec.rule_type == RuleType::GeoIp {
                        skipped.push(format!(
                            "rule-geoip-unsupported:{}",
                            spec.matcher.as_deref().unwrap_or("")
                        ));
                    } else {
                        skipped.push(format!("rule:{}", spec.to_clash_line()));
                    }
                }
            }
        }

        // 5b. 上游机场原分流规则: sing-box MVP 模式 (固定出口 + custom_rules) 不迁移,
        //     非空时标注让用户知晓 (有意取舍; Clash 输出才保留上游 rules)。
        let upstream_rules_count = model
            .upstream_root
            .get("rules")
            .and_then(|v| v.as_sequence())
            .map(|s| s.len())
            .unwrap_or(0);
        if upstream_rules_count > 0 {
            skipped.push(format!("upstream-rules-not-migrated:{upstream_rules_count}"));
        }

        let config = json!({
            "log": { "level": "info", "timestamp": true },
            "dns": {
                "servers": [
                    { "tag": "remote", "address": "tls://1.1.1.1", "detour": model.fallback_target },
                    { "tag": "local", "address": "https://223.5.5.5/dns-query", "detour": "DIRECT" }
                ],
                "rules": [
                    { "outbound": "any", "server": "local" },
                    { "clash_mode": "direct", "server": "local" },
                    { "clash_mode": "global", "server": "remote" }
                ],
                "final": "remote"
            },
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 2080,
                    "set_system_proxy": false
                }
            ],
            "outbounds": outbounds,
            "route": {
                "rules": rules,
                "final": model.fallback_target,
                "auto_detect_interface": true
            }
        });

        let body = serde_json::to_string_pretty(&config)?;
        let mut rendered = RenderedSub::new(body, "application/json; charset=utf-8", "json");
        rendered.skipped = skipped;
        Ok(rendered)
    }

    fn supports_relay_chain(&self) -> bool {
        true
    }

    fn format_id(&self) -> &'static str {
        "singbox.json"
    }
}

// ------- proxy 协议映射 -------

fn ystr(m: &Mapping, key: &str) -> Option<String> {
    m.get(Yaml::String(key.into()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ybool(m: &Mapping, key: &str) -> Option<bool> {
    m.get(Yaml::String(key.into())).and_then(|v| v.as_bool())
}

/// port: Clash 可能是整数或字符串。
fn yport(m: &Mapping) -> Option<u64> {
    let v = m.get(Yaml::String("port".into()))?;
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// packet_encoding (vmess/vless): 上游可能写 "packet-encoding" 或 "packet_encoding"。非空才返回。
fn ypacket_encoding(m: &Mapping) -> Option<String> {
    let v = ystr(m, "packet-encoding").or_else(|| ystr(m, "packet_encoding"))?;
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// 带宽字段 (hysteria2 up/down): 整数直接取; 字符串 strip 尾部 " Mbps"/"Mbps" 后 parse。
fn ymbps(m: &Mapping, key: &str) -> Option<u64> {
    let v = m.get(Yaml::String(key.into()))?;
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    let s = v.as_str()?.trim();
    let num = s
        .strip_suffix(" Mbps")
        .or_else(|| s.strip_suffix("Mbps"))
        .unwrap_or(s)
        .trim();
    num.parse().ok()
}

/// alpn (Sequence) → JSON 数组。
fn yalpn(m: &Mapping) -> Option<Json> {
    let v = m.get(Yaml::String("alpn".into()))?;
    let arr = v.as_sequence()?;
    let items: Vec<Json> = arr
        .iter()
        .filter_map(|x| x.as_str().map(|s| json!(s)))
        .collect();
    if items.is_empty() { None } else { Some(Json::Array(items)) }
}

/// 取嵌套 mapping (如 ws-opts / reality-opts)。
fn ysub<'a>(m: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    m.get(Yaml::String(key.into())).and_then(|v| v.as_mapping())
}

/// 粗判一个地址是否是 IP 字面量 (而非域名)。用于决定是否拿它当 TLS SNI。
/// IPv4: 只含数字和点; IPv6: 含冒号。两者都不是合法 SNI。
fn looks_like_ip(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    if s.contains(':') {
        // IPv6 (可能带 [] 或 zone), 一律不当 SNI。
        return true;
    }
    // IPv4: 仅由数字和点构成。
    s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// 构造 tls 子对象。`tls_enabled` 为协议层强制开启时传 true。
/// reality-opts 存在则嵌入 tls.reality。返回 None 表示该节点无 TLS。
fn build_tls(m: &Mapping, force_tls: bool, server_name_keys: &[&str]) -> Option<Json> {
    let reality = ysub(m, "reality-opts");
    let tls_on = force_tls
        || ybool(m, "tls").unwrap_or(false)
        || reality.is_some();
    if !tls_on {
        return None;
    }
    let mut tls = Map::new();
    tls.insert("enabled".into(), json!(true));

    // server_name: 按优先级取 (servername / sni / server)。
    // 注意: 当候选来自 "server" 键 (节点地址) 且看起来是 IP 时跳过 —— 拿 IP 当 SNI 会被很多
    // 服务器拒绝。显式的 servername / sni 字段不受此限制。
    let mut server_name: Option<String> = None;
    for k in server_name_keys {
        if let Some(v) = ystr(m, k) {
            if *k == "server" && looks_like_ip(&v) {
                continue;
            }
            server_name = Some(v);
            break;
        }
    }
    if let Some(sn) = server_name {
        tls.insert("server_name".into(), json!(sn));
    }

    if let Some(true) = ybool(m, "skip-cert-verify") {
        tls.insert("insecure".into(), json!(true));
    }
    if let Some(alpn) = yalpn(m) {
        tls.insert("alpn".into(), alpn);
    }
    if let Some(fp) = ystr(m, "client-fingerprint") {
        if !fp.is_empty() {
            tls.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
        }
    }
    if let Some(r) = reality {
        let mut rj = Map::new();
        rj.insert("enabled".into(), json!(true));
        if let Some(pk) = ystr(r, "public-key") {
            rj.insert("public_key".into(), json!(pk));
        }
        if let Some(sid) = ystr(r, "short-id") {
            rj.insert("short_id".into(), json!(sid));
        }
        tls.insert("reality".into(), Json::Object(rj));
    }
    Some(Json::Object(tls))
}

/// transport 子对象 (ws / grpc / http)。network=tcp 或缺省返回 None。
fn build_transport(m: &Mapping) -> Option<Json> {
    let network = ystr(m, "network").unwrap_or_default();
    match network.as_str() {
        "ws" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            if let Some(ws) = ysub(m, "ws-opts") {
                if let Some(path) = ystr(ws, "path") {
                    t.insert("path".into(), json!(path));
                }
                if let Some(headers) = ysub(ws, "headers") {
                    let mut hm = Map::new();
                    for (k, v) in headers {
                        if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                            hm.insert(k.to_string(), json!(v));
                        }
                    }
                    if !hm.is_empty() {
                        t.insert("headers".into(), Json::Object(hm));
                    }
                }
            }
            Some(Json::Object(t))
        }
        "grpc" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("grpc"));
            if let Some(grpc) = ysub(m, "grpc-opts") {
                if let Some(svc) = ystr(grpc, "grpc-service-name") {
                    t.insert("service_name".into(), json!(svc));
                }
            }
            Some(Json::Object(t))
        }
        "h2" | "http" => {
            let mut t = Map::new();
            t.insert("type".into(), json!("http"));
            if let Some(h2) = ysub(m, "h2-opts") {
                if let Some(path) = ystr(h2, "path") {
                    t.insert("path".into(), json!(path));
                }
                if let Some(host) = h2.get(Yaml::String("host".into())) {
                    if let Some(arr) = host.as_sequence() {
                        let hosts: Vec<Json> =
                            arr.iter().filter_map(|x| x.as_str().map(|s| json!(s))).collect();
                        if !hosts.is_empty() {
                            t.insert("host".into(), Json::Array(hosts));
                        }
                    } else if let Some(s) = host.as_str() {
                        t.insert("host".into(), json!([s]));
                    }
                }
            }
            Some(Json::Object(t))
        }
        _ => None,
    }
}

/// Clash proxy mapping → sing-box outbound JSON。
/// Ok(Some) = 成功; Ok(None) = 该节点无 name (理论不达); Err(reason) = 跳过该节点 (含原因)。
fn clash_proxy_to_singbox(m: &Mapping) -> Result<Option<Json>, String> {
    let name = match ystr(m, "name") {
        Some(n) => n,
        None => return Ok(None),
    };
    let ptype = ystr(m, "type").unwrap_or_default();
    let server = ystr(m, "server").unwrap_or_default();
    let port = yport(m).unwrap_or(0);

    // server 空 / port==0 会让 sing-box 启动失败, 跳过该节点。
    if server.trim().is_empty() || port == 0 {
        return Err(format!("missing-server-or-port:{name}"));
    }

    let mut ob = Map::new();
    let push_common = |ob: &mut Map<String, Json>| {
        ob.insert("tag".into(), json!(name.clone()));
        ob.insert("server".into(), json!(server.clone()));
        ob.insert("server_port".into(), json!(port));
    };

    match ptype.as_str() {
        "ss" => {
            ob.insert("type".into(), json!("shadowsocks"));
            push_common(&mut ob);
            if let Some(c) = ystr(m, "cipher") {
                ob.insert("method".into(), json!(c));
            }
            if let Some(pw) = ystr(m, "password") {
                ob.insert("password".into(), json!(pw));
            }
            apply_ss_plugin(m, &mut ob);
        }
        "vmess" => {
            ob.insert("type".into(), json!("vmess"));
            push_common(&mut ob);
            if let Some(u) = ystr(m, "uuid") {
                ob.insert("uuid".into(), json!(u));
            }
            // alterId: 整数或字符串。
            let aid = m
                .get(Yaml::String("alterId".into()))
                .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .unwrap_or(0);
            ob.insert("alter_id".into(), json!(aid));
            ob.insert(
                "security".into(),
                json!(ystr(m, "cipher").unwrap_or_else(|| "auto".into())),
            );
            if let Some(pe) = ypacket_encoding(m) {
                ob.insert("packet_encoding".into(), json!(pe));
            }
            if let Some(tls) = build_tls(m, false, &["servername", "sni", "server"]) {
                ob.insert("tls".into(), tls);
            }
            if let Some(t) = build_transport(m) {
                ob.insert("transport".into(), t);
            }
        }
        "vless" => {
            ob.insert("type".into(), json!("vless"));
            push_common(&mut ob);
            if let Some(u) = ystr(m, "uuid") {
                ob.insert("uuid".into(), json!(u));
            }
            if let Some(flow) = ystr(m, "flow") {
                if !flow.is_empty() {
                    ob.insert("flow".into(), json!(flow));
                }
            }
            if let Some(pe) = ypacket_encoding(m) {
                ob.insert("packet_encoding".into(), json!(pe));
            }
            if let Some(tls) = build_tls(m, false, &["servername", "sni", "server"]) {
                ob.insert("tls".into(), tls);
            }
            if let Some(t) = build_transport(m) {
                ob.insert("transport".into(), t);
            }
        }
        "trojan" => {
            ob.insert("type".into(), json!("trojan"));
            push_common(&mut ob);
            if let Some(pw) = ystr(m, "password") {
                ob.insert("password".into(), json!(pw));
            }
            // trojan 强制 TLS。
            if let Some(tls) = build_tls(m, true, &["sni", "servername", "server"]) {
                ob.insert("tls".into(), tls);
            }
            if let Some(t) = build_transport(m) {
                ob.insert("transport".into(), t);
            }
        }
        "hysteria2" => {
            ob.insert("type".into(), json!("hysteria2"));
            push_common(&mut ob);
            if let Some(pw) = ystr(m, "password") {
                ob.insert("password".into(), json!(pw));
            }
            // 带宽: 上游 up/down 可能是整数或 "50 Mbps" 字符串 → up_mbps/down_mbps。
            if let Some(up) = ymbps(m, "up") {
                ob.insert("up_mbps".into(), json!(up));
            }
            if let Some(down) = ymbps(m, "down") {
                ob.insert("down_mbps".into(), json!(down));
            }
            // obfs (salamander)。
            if let Some(obfs) = ystr(m, "obfs") {
                if !obfs.is_empty() {
                    let mut o = Map::new();
                    o.insert("type".into(), json!(obfs));
                    if let Some(opw) = ystr(m, "obfs-password") {
                        o.insert("password".into(), json!(opw));
                    }
                    ob.insert("obfs".into(), Json::Object(o));
                }
            }
            // hysteria2 强制 TLS。
            if let Some(tls) = build_tls(m, true, &["sni", "servername", "server"]) {
                ob.insert("tls".into(), tls);
            }
        }
        "tuic" => {
            // tuic v4 (仅 token, 无 uuid) → sing-box 仅支持 v5, 跳过。
            let has_uuid = ystr(m, "uuid").is_some();
            let has_token = ystr(m, "token").is_some();
            if !has_uuid && has_token {
                return Err(format!("tuic-v4:{name}"));
            }
            ob.insert("type".into(), json!("tuic"));
            push_common(&mut ob);
            if let Some(u) = ystr(m, "uuid") {
                ob.insert("uuid".into(), json!(u));
            }
            if let Some(pw) = ystr(m, "password") {
                ob.insert("password".into(), json!(pw));
            }
            if let Some(cc) = ystr(m, "congestion-controller") {
                ob.insert("congestion_control".into(), json!(cc));
            }
            if let Some(urm) = ystr(m, "udp-relay-mode") {
                ob.insert("udp_relay_mode".into(), json!(urm));
            }
            if let Some(true) = ybool(m, "reduce-rtt") {
                ob.insert("zero_rtt_handshake".into(), json!(true));
            }
            // tuic 强制 TLS。TUIC over QUIC 必须有 ALPN h3 才能握手 ——
            // 上游若未给 alpn, build_tls 不会 emit, 此处补默认 ["h3"]。
            if let Some(mut tls) = build_tls(m, true, &["sni", "servername", "server"]) {
                if let Some(obj) = tls.as_object_mut() {
                    if !obj.contains_key("alpn") {
                        obj.insert("alpn".into(), json!(["h3"]));
                    }
                }
                ob.insert("tls".into(), tls);
            }
        }
        "ssr" => {
            // sing-box 1.8+ 已移除 SSR。
            return Err(format!("ssr:{name}"));
        }
        other => {
            return Err(format!("{other}:{name}"));
        }
    }

    Ok(Some(Json::Object(ob)))
}

/// ss plugin (obfs / v2ray-plugin) → sing-box plugin / plugin_opts (分号分隔字符串)。
fn apply_ss_plugin(m: &Mapping, ob: &mut Map<String, Json>) {
    let Some(plugin) = ystr(m, "plugin") else { return };
    if plugin.is_empty() {
        return;
    }
    // mihomo "obfs" → sing-box "obfs-local"。
    let sb_plugin = match plugin.as_str() {
        "obfs" => "obfs-local",
        other => other,
    };
    ob.insert("plugin".into(), json!(sb_plugin));
    if let Some(opts) = ysub(m, "plugin-opts") {
        let mut parts: Vec<String> = Vec::new();
        // obfs 常见: mode / host。其余 key=val 原样拼。
        for (k, v) in opts {
            let Some(k) = k.as_str() else { continue };
            let val = match v {
                Yaml::String(s) => s.clone(),
                Yaml::Bool(b) => b.to_string(),
                Yaml::Number(n) => n.to_string(),
                _ => continue,
            };
            let key = match k {
                "mode" => "obfs".to_string(),
                "host" => "obfs-host".to_string(),
                other => other.to_string(),
            };
            parts.push(format!("{key}={val}"));
        }
        if !parts.is_empty() {
            ob.insert("plugin_opts".into(), json!(parts.join(";")));
        }
    }
}

// ------- group 映射 -------

/// 300 → "5m0s", 30 → "30s", 90 → "1m30s"。
fn secs_to_duration(secs: u32) -> String {
    let m = secs / 60;
    let s = secs % 60;
    if m == 0 {
        format!("{s}s")
    } else if s == 0 {
        format!("{m}m0s")
    } else {
        format!("{m}m{s}s")
    }
}

/// 渲染一个注入组为 sing-box outbound。`members` 是已过滤掉悬空成员的存活列表
/// (调用方保证非空), 用它而非 `g.proxies` 以避免引用被 skip 的 outbound。
fn inject_group_to_outbound(g: &InjectGroup, members: &[String]) -> Json {
    let outbounds: Vec<Json> = members.iter().map(|p| json!(p)).collect();
    match &g.kind {
        GroupKind::UrlTest { url, interval } => {
            json!({
                "type": "urltest",
                "tag": g.name,
                "outbounds": outbounds,
                "url": url,
                "interval": secs_to_duration(*interval),
                "tolerance": 50
            })
        }
        GroupKind::Select => {
            // default 必须在列表内: 取首项。
            let default = members.first().cloned();
            let mut obj = Map::new();
            obj.insert("type".into(), json!("selector"));
            obj.insert("tag".into(), json!(g.name));
            obj.insert("outbounds".into(), Json::Array(outbounds));
            if let Some(d) = default {
                obj.insert("default".into(), json!(d));
            }
            Json::Object(obj)
        }
    }
}

// ------- rule 映射 -------

/// RuleSpec → sing-box route.rule。返回 None 表示该类型无 sing-box 等价 (跳过)。
/// MATCH 由调用方单独处理为 route.final, 不会进这里。
fn rule_spec_to_singbox(rule_type: &RuleType, matcher: Option<&str>, target: &str) -> Option<Json> {
    let m = matcher?;
    let rule = match rule_type {
        RuleType::Domain => json!({ "domain": [m], "outbound": target }),
        RuleType::DomainSuffix => json!({ "domain_suffix": [m], "outbound": target }),
        RuleType::DomainKeyword => json!({ "domain_keyword": [m], "outbound": target }),
        RuleType::IpCidr | RuleType::IpCidr6 => json!({ "ip_cidr": [m], "outbound": target }),
        RuleType::Process => json!({ "process_name": [m], "outbound": target }),
        RuleType::DstPort => {
            let port: Option<u16> = m.parse().ok();
            json!({ "port": [port?], "outbound": target })
        }
        // GeoIp: sing-box 1.12+ 已移除 route rule 的 geoip 字段, emit 会让新版启动失败 → 跳过。
        // GeoSite / SrcPort / Other / Match: 无简单等价, 跳过。
        _ => return None,
    };
    Some(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn yaml_map(s: &str) -> Mapping {
        serde_yaml::from_str::<Yaml>(s).unwrap().as_mapping().unwrap().clone()
    }

    #[test]
    fn ss_basic() {
        let m = yaml_map("name: SS1\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["type"], json!("shadowsocks"));
        assert_eq!(ob["server_port"], json!(8388));
        assert_eq!(ob["method"], json!("aes-256-gcm"));
    }

    #[test]
    fn vless_reality() {
        let m = yaml_map(
            "name: V1\ntype: vless\nserver: 1.2.3.4\nport: 443\nuuid: abc\nflow: xtls-rprx-vision\ntls: true\nservername: www.ms.com\nclient-fingerprint: chrome\nreality-opts:\n  public-key: PK\n  short-id: '0123'",
        );
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["type"], json!("vless"));
        assert_eq!(ob["flow"], json!("xtls-rprx-vision"));
        let tls = &ob["tls"];
        assert_eq!(tls["enabled"], json!(true));
        assert_eq!(tls["server_name"], json!("www.ms.com"));
        assert_eq!(tls["utls"]["fingerprint"], json!("chrome"));
        assert_eq!(tls["reality"]["enabled"], json!(true));
        assert_eq!(tls["reality"]["public_key"], json!("PK"));
        assert_eq!(tls["reality"]["short_id"], json!("0123"));
    }

    #[test]
    fn vmess_ws() {
        let m = yaml_map(
            "name: VM1\ntype: vmess\nserver: a.com\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\ntls: true\nservername: a.com\nnetwork: ws\nws-opts:\n  path: /ray\n  headers:\n    Host: a.com",
        );
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["type"], json!("vmess"));
        assert_eq!(ob["alter_id"], json!(0));
        assert_eq!(ob["transport"]["type"], json!("ws"));
        assert_eq!(ob["transport"]["path"], json!("/ray"));
        assert_eq!(ob["transport"]["headers"]["Host"], json!("a.com"));
    }

    #[test]
    fn trojan_forced_tls() {
        let m = yaml_map("name: TJ\ntype: trojan\nserver: ex.com\nport: 443\npassword: p\nsni: ex.com");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["tls"]["enabled"], json!(true));
        assert_eq!(ob["tls"]["server_name"], json!("ex.com"));
    }

    #[test]
    fn hysteria2_obfs() {
        let m = yaml_map(
            "name: HY\ntype: hysteria2\nserver: 1.2.3.4\nport: 8443\npassword: pw\nsni: ex.com\nskip-cert-verify: true\nobfs: salamander\nobfs-password: ob",
        );
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["type"], json!("hysteria2"));
        assert_eq!(ob["obfs"]["type"], json!("salamander"));
        assert_eq!(ob["obfs"]["password"], json!("ob"));
        assert_eq!(ob["tls"]["insecure"], json!(true));
    }

    #[test]
    fn tuic_v5() {
        let m = yaml_map(
            "name: TU\ntype: tuic\nserver: h.com\nport: 443\nuuid: u\npassword: p\nsni: h.com\ncongestion-controller: bbr\nudp-relay-mode: native",
        );
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["congestion_control"], json!("bbr"));
        assert_eq!(ob["udp_relay_mode"], json!("native"));
        assert_eq!(ob["tls"]["enabled"], json!(true));
    }

    #[test]
    fn tuic_v4_skipped() {
        let m = yaml_map("name: TU4\ntype: tuic\nserver: h.com\nport: 443\ntoken: tok");
        let err = clash_proxy_to_singbox(&m).unwrap_err();
        assert!(err.starts_with("tuic-v4:"));
    }

    #[test]
    fn ssr_skipped() {
        let m = yaml_map("name: SSR1\ntype: ssr\nserver: h.com\nport: 443");
        let err = clash_proxy_to_singbox(&m).unwrap_err();
        assert!(err.starts_with("ssr:"));
    }

    #[test]
    fn duration_format() {
        assert_eq!(secs_to_duration(300), "5m0s");
        assert_eq!(secs_to_duration(30), "30s");
        assert_eq!(secs_to_duration(90), "1m30s");
    }

    #[test]
    fn rule_mapping() {
        let r = rule_spec_to_singbox(&RuleType::DomainSuffix, Some("ex.com"), "DIRECT").unwrap();
        assert_eq!(r["domain_suffix"], json!(["ex.com"]));
        assert_eq!(r["outbound"], json!("DIRECT"));
        let r2 = rule_spec_to_singbox(&RuleType::IpCidr, Some("10.0.0.0/8"), "REJECT").unwrap();
        assert_eq!(r2["ip_cidr"], json!(["10.0.0.0/8"]));
    }

    // ---- render() 级别测试 ----

    use crate::generator::model::{GroupKind, InjectGroup, RuleSpec};

    /// 构造一个最小 InjectModel: 一个上游节点 + Bridge-Exit selector 组。
    /// custom_rules / 上游 rules 由参数注入。
    fn make_model(custom_rules: Vec<RuleSpec>, upstream_yaml: &str) -> InjectModel {
        let root: Yaml = serde_yaml::from_str(upstream_yaml).unwrap();
        InjectModel {
            upstream_root: root,
            injected_proxies: Vec::new(),
            injected_groups: vec![InjectGroup {
                name: "Bridge-Exit".into(),
                kind: GroupKind::Select,
                proxies: vec!["UP1".into(), "DIRECT".into()],
            }],
            select_inject_target: "Bridge-Exit".into(),
            custom_rules,
            fallback_target: "Bridge-Exit".into(),
            upstream_count: 1,
            bridge_count: 0,
            chain_count: 0,
            missing_bridges: Vec::new(),
            has_relay_chain: false,
        }
    }

    const ONE_PROXY: &str = "proxies:\n  - name: UP1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";

    /// 收集 route.rules 里所有出现的 outbound tag。
    fn rule_outbound_tags(json: &Json) -> Vec<String> {
        json["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["outbound"].as_str().map(|s| s.to_string()))
            .collect()
    }

    /// 收集 outbounds 里所有 tag。
    fn outbound_tags(json: &Json) -> HashSet<String> {
        json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o["tag"].as_str().map(|s| s.to_string()))
            .collect()
    }

    #[test]
    fn custom_rule_dangling_upstream_group_skipped() {
        // target 指向上游 proxy-group 名 (sing-box 无此 outbound) → 跳过 + 记 skipped, 不产悬空。
        let specs = vec![
            RuleSpec { rule_type: RuleType::Domain, matcher: Some("a.com".into()), target: "UpstreamGroup".into() },
            RuleSpec { rule_type: RuleType::Domain, matcher: Some("b.com".into()), target: "DIRECT".into() },
        ];
        let model = make_model(specs, ONE_PROXY);
        let rendered = SingboxRenderer.render(&model).unwrap();
        let json: Json = serde_json::from_str(&rendered.body).unwrap();

        let tags = outbound_tags(&json);
        // 所有 route.rule 的 outbound 都必须在 outbounds tags 内 (含 final)。
        for ob in rule_outbound_tags(&json) {
            assert!(tags.contains(&ob), "悬空 outbound: {ob}");
        }
        assert!(tags.contains(json["route"]["final"].as_str().unwrap()));
        // UpstreamGroup 被跳过, DIRECT 保留。
        assert!(!rule_outbound_tags(&json).contains(&"UpstreamGroup".to_string()));
        assert!(rule_outbound_tags(&json).contains(&"DIRECT".to_string()));
        assert!(rendered.skipped.iter().any(|s| s == "rule-dangling-target:UpstreamGroup"));
    }

    #[test]
    fn custom_rule_geoip_skipped_and_recorded() {
        let specs = vec![RuleSpec {
            rule_type: RuleType::GeoIp,
            matcher: Some("CN".into()),
            target: "DIRECT".into(),
        }];
        let model = make_model(specs, ONE_PROXY);
        let rendered = SingboxRenderer.render(&model).unwrap();
        let json: Json = serde_json::from_str(&rendered.body).unwrap();
        // 不得 emit geoip 字段。
        let has_geoip = json["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.get("geoip").is_some());
        assert!(!has_geoip, "不应 emit 已移除的 geoip 字段");
        assert!(rendered.skipped.iter().any(|s| s == "rule-geoip-unsupported:CN"));
    }

    #[test]
    fn upstream_rules_not_migrated_recorded() {
        let upstream = "proxies:\n  - name: UP1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\nrules:\n  - DOMAIN-SUFFIX,a.com,DIRECT\n  - GEOIP,CN,DIRECT\n";
        let model = make_model(Vec::new(), upstream);
        let rendered = SingboxRenderer.render(&model).unwrap();
        assert!(rendered.skipped.iter().any(|s| s == "upstream-rules-not-migrated:2"));
    }

    #[test]
    fn tuic_no_alpn_gets_h3() {
        let m = yaml_map("name: TU\ntype: tuic\nserver: h.com\nport: 443\nuuid: u\npassword: p\nsni: h.com");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["tls"]["alpn"], json!(["h3"]));
    }

    #[test]
    fn tuic_keeps_explicit_alpn() {
        let m = yaml_map("name: TU\ntype: tuic\nserver: h.com\nport: 443\nuuid: u\npassword: p\nsni: h.com\nalpn:\n  - h3\n  - h2");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["tls"]["alpn"], json!(["h3", "h2"]));
    }

    #[test]
    fn tls_server_ip_not_used_as_sni() {
        // server 是 IP 且无显式 servername/sni → 不出现 server_name=IP。
        let m = yaml_map("name: TJ\ntype: trojan\nserver: 1.2.3.4\nport: 443\npassword: p");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["tls"]["enabled"], json!(true));
        assert!(ob["tls"].get("server_name").is_none(), "IP 不应作 SNI");
    }

    #[test]
    fn tls_explicit_sni_kept_even_when_server_is_ip() {
        let m = yaml_map("name: TJ\ntype: trojan\nserver: 1.2.3.4\nport: 443\npassword: p\nsni: real.example.com");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["tls"]["server_name"], json!("real.example.com"));
    }

    #[test]
    fn missing_server_or_port_skipped() {
        let m1 = yaml_map("name: P1\ntype: ss\nserver: 1.2.3.4\nport: 0\ncipher: aes-256-gcm\npassword: pw");
        assert!(clash_proxy_to_singbox(&m1).unwrap_err().starts_with("missing-server-or-port:"));
        let m2 = yaml_map("name: P2\ntype: ss\nserver: ''\nport: 8388\ncipher: aes-256-gcm\npassword: pw");
        assert!(clash_proxy_to_singbox(&m2).unwrap_err().starts_with("missing-server-or-port:"));
    }

    #[test]
    fn hysteria2_bandwidth_mapped() {
        let m = yaml_map("name: HY\ntype: hysteria2\nserver: ex.com\nport: 8443\npassword: pw\nup: 50\ndown: \"200 Mbps\"");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["up_mbps"], json!(50));
        assert_eq!(ob["down_mbps"], json!(200));
    }

    #[test]
    fn vmess_packet_encoding_forwarded() {
        let m = yaml_map("name: VM\ntype: vmess\nserver: a.com\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\npacket-encoding: xudp");
        let ob = clash_proxy_to_singbox(&m).unwrap().unwrap();
        assert_eq!(ob["packet_encoding"], json!("xudp"));
    }

    #[test]
    fn looks_like_ip_detection() {
        assert!(looks_like_ip("1.2.3.4"));
        assert!(looks_like_ip("2001:db8::1"));
        assert!(!looks_like_ip("example.com"));
        assert!(!looks_like_ip("a.b.c.d"));
    }

    fn ymap(s: &str) -> Mapping {
        serde_yaml::from_str::<Yaml>(s).unwrap().as_mapping().unwrap().clone()
    }

    /// 断言: 渲染结果里没有任何 outbound 引用了不存在的 tag (detour / group 成员 / rule)。
    fn assert_no_dangling(json: &Json) {
        let tags = outbound_tags(json);
        for ob in json["outbounds"].as_array().unwrap() {
            if let Some(d) = ob.get("detour").and_then(|d| d.as_str()) {
                assert!(tags.contains(d), "悬空 detour: {d}");
            }
            if let Some(members) = ob.get("outbounds").and_then(|m| m.as_array()) {
                assert!(!members.is_empty(), "空 outbounds 组: {:?}", ob["tag"]);
                for mm in members {
                    let mm = mm.as_str().unwrap();
                    assert!(tags.contains(mm), "悬空组成员: {mm}");
                }
            }
        }
        for ob in rule_outbound_tags(json) {
            assert!(tags.contains(&ob), "悬空 rule outbound: {ob}");
        }
        assert!(tags.contains(json["route"]["final"].as_str().unwrap()));
    }

    /// chain 的 detour 指向被 skip 的跳板 (ssr 跳板) → 该 chain 跳过, 不产悬空 detour。
    #[test]
    fn chain_with_dangling_detour_skipped() {
        // 上游含一个 ssr 跳板 (sing-box 不支持 → skip), chain 的 dialer-proxy 指向它。
        let upstream = "proxies:\n  - name: BR-SSR\n    type: ssr\n    server: h.com\n    port: 443\n";
        let root: Yaml = serde_yaml::from_str(upstream).unwrap();
        let chain = ymap("name: JP-via-BR-SSR\ntype: vmess\nserver: jp.com\nport: 443\nuuid: u\nalterId: 0\ncipher: auto\ndialer-proxy: BR-SSR");
        let model = InjectModel {
            upstream_root: root,
            injected_proxies: vec![chain],
            injected_groups: vec![InjectGroup {
                name: "Bridge-Exit".into(),
                kind: GroupKind::Select,
                proxies: vec!["JP-via-BR-SSR".into(), "DIRECT".into()],
            }],
            select_inject_target: "Bridge-Exit".into(),
            custom_rules: Vec::new(),
            fallback_target: "Bridge-Exit".into(),
            upstream_count: 1,
            bridge_count: 1,
            chain_count: 1,
            missing_bridges: Vec::new(),
            has_relay_chain: true,
        };
        let rendered = SingboxRenderer.render(&model).unwrap();
        let json: Json = serde_json::from_str(&rendered.body).unwrap();
        // chain 被跳过, 无悬空 detour; ssr 跳板 + chain 都记 skipped。
        let tags = outbound_tags(&json);
        assert!(!tags.contains("JP-via-BR-SSR"));
        assert!(rendered.skipped.iter().any(|s| s.starts_with("ssr:")));
        assert!(rendered.skipped.iter().any(|s| s == "chain-dangling-detour:JP-via-BR-SSR"));
        // Bridge-Exit 组的悬空成员 JP-via-BR-SSR 被过滤, 只剩 DIRECT, 组仍存活。
        assert_no_dangling(&json);
    }

    /// group 成员全部悬空 (唯一 chain 因出口不支持被 skip, 组只有它) → 整组跳过。
    #[test]
    fn group_all_members_dangling_skipped() {
        let upstream = "proxies: []\n";
        let root: Yaml = serde_yaml::from_str(upstream).unwrap();
        // 出口是 ssr → chain 渲染失败被 skip。
        let chain = ymap("name: DEAD-via-X\ntype: ssr\nserver: h.com\nport: 443\ndialer-proxy: X");
        let model = InjectModel {
            upstream_root: root,
            injected_proxies: vec![chain],
            injected_groups: vec![
                InjectGroup {
                    name: "X-auto".into(),
                    kind: GroupKind::UrlTest { url: "u".into(), interval: 300 },
                    proxies: vec!["DEAD-via-X".into()],
                },
                InjectGroup {
                    name: "Bridge-Exit".into(),
                    kind: GroupKind::Select,
                    proxies: vec!["X-auto".into(), "DIRECT".into()],
                },
            ],
            select_inject_target: "Bridge-Exit".into(),
            custom_rules: Vec::new(),
            fallback_target: "Bridge-Exit".into(),
            upstream_count: 0,
            bridge_count: 1,
            chain_count: 1,
            missing_bridges: Vec::new(),
            has_relay_chain: true,
        };
        let rendered = SingboxRenderer.render(&model).unwrap();
        let json: Json = serde_json::from_str(&rendered.body).unwrap();
        let tags = outbound_tags(&json);
        // X-auto 组成员全悬空 → 整组跳过; Bridge-Exit 过滤掉死组 X-auto, 仍有 DIRECT 存活。
        assert!(!tags.contains("X-auto"));
        assert!(tags.contains("Bridge-Exit"));
        assert!(rendered.skipped.iter().any(|s| s == "group-empty:X-auto"));
        assert_no_dangling(&json);
    }
}
