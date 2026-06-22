//! proxy mapping → 裸 URI 逆向序列化 (base64 通用订阅用)。
//!
//! 是 [`parser::uri`](crate::parser::uri) 正向解析 (URI → mapping) 的反向操作:
//! 把一个 Clash proxy Mapping 序列化回对应 scheme 的 URI 字符串。
//!
//! - ss://    `ss://base64url(method:password)@host:port?plugin=...#name`
//! - ssr://   `ssr://base64url(host:port:proto:method:obfs:base64url(pw)/?obfsparam=..&..)`
//! - vmess:// `vmess://base64std(json)` (v2rayN v=2)
//! - vless:// `vless://uuid@host:port?type=&security=&sni=&fp=&pbk=&sid=&path=&host=&flow=#name`
//! - trojan:// `trojan://password@host:port?sni=&type=&path=&host=&allowInsecure=1#name`
//! - hysteria2:// `hysteria2://password@host:port?sni=&insecure=1&obfs=&obfs-password=#name`
//! - tuic://  `tuic://uuid:password@host:port?sni=&congestion_control=&udp_relay_mode=&alpn=#name`
//!
//! 无法表达的字段尽力 / 跳过, **不 panic**。无法序列化的节点返回 `None` (调用方 skip)。

use serde_yaml::{Mapping, Value};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;

// ---------- 取值工具 ----------

fn ystr(m: &Mapping, key: &str) -> Option<String> {
    m.get(Value::String(key.into()))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn ybool(m: &Mapping, key: &str) -> Option<bool> {
    m.get(Value::String(key.into())).and_then(|v| v.as_bool())
}

/// port: Clash 可能是整数或字符串。
fn yport(m: &Mapping) -> Option<u64> {
    let v = m.get(Value::String("port".into()))?;
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn ysub<'a>(m: &'a Mapping, key: &str) -> Option<&'a Mapping> {
    m.get(Value::String(key.into())).and_then(|v| v.as_mapping())
}

/// alpn (Sequence) → 逗号拼接字符串。
fn yalpn_csv(m: &Mapping) -> Option<String> {
    let v = m.get(Value::String("alpn".into()))?;
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

/// host 写进 `host:port`: IPv6 加方括号。
fn fmt_host_port(host: &str, port: u64) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// percent-encode: 只保留 unreserved 字符, 其余按 %XX 编码 (RFC 3986)。
/// 用于 fragment (name) 与 query value。
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// 从 ws-opts / 顶层取 transport path / host。返回 (path, host)。
fn transport_path_host(m: &Mapping, network: &str) -> (Option<String>, Option<String>) {
    match network {
        "ws" => {
            let ws = ysub(m, "ws-opts");
            let path = ws.and_then(|w| ystr(w, "path"));
            let host = ws
                .and_then(|w| ysub(w, "headers"))
                .and_then(|h| ystr(h, "Host").or_else(|| ystr(h, "host")));
            (path, host)
        }
        "grpc" => {
            let svc = ysub(m, "grpc-opts").and_then(|g| ystr(g, "grpc-service-name"));
            (svc, None)
        }
        "h2" | "http" => {
            let h2 = ysub(m, "h2-opts");
            let path = h2.and_then(|h| ystr(h, "path"));
            let host = h2.and_then(|h| {
                h.get(Value::String("host".into())).and_then(|v| {
                    v.as_sequence()
                        .and_then(|seq| seq.iter().find_map(|x| x.as_str().map(|s| s.to_string())))
                        .or_else(|| v.as_str().map(|s| s.to_string()))
                })
            });
            (path, host)
        }
        _ => (None, None),
    }
}

// ---------- 入口 ----------

/// Clash proxy Mapping → 裸 URI。无法序列化 (缺 server/port、无名、不支持的协议) 返回 None。
pub fn proxy_to_uri(m: &Mapping) -> Option<String> {
    let ptype = ystr(m, "type")?;
    let server = ystr(m, "server")?;
    let port = yport(m)?;
    if server.trim().is_empty() || port == 0 {
        return None;
    }
    let name = ystr(m, "name").unwrap_or_else(|| format!("{server}:{port}"));
    match ptype.as_str() {
        "ss" => ss_uri(m, &server, port, &name),
        "ssr" => ssr_uri(m, &server, port, &name),
        "vmess" => vmess_uri(m, &server, port, &name),
        "vless" => vless_uri(m, &server, port, &name),
        "trojan" => trojan_uri(m, &server, port, &name),
        "hysteria2" => hysteria2_uri(m, &server, port, &name),
        "tuic" => tuic_uri(m, &server, port, &name),
        _ => None,
    }
}

// ---------- ss ----------

/// `ss://base64url(method:password)@host:port?plugin=...#name`
fn ss_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let cipher = ystr(m, "cipher")?;
    let password = ystr(m, "password").unwrap_or_default();
    if cipher.trim().is_empty() {
        return None;
    }
    let userinfo = URL_SAFE_NO_PAD.encode(format!("{cipher}:{password}").as_bytes());
    let mut uri = format!("ss://{userinfo}@{}", fmt_host_port(server, port));

    // plugin: mihomo plugin=obfs + plugin-opts → ?plugin=obfs-local;obfs=MODE;obfs-host=HOST
    if let Some(plugin) = ystr(m, "plugin").filter(|p| !p.is_empty()) {
        let sb_plugin = match plugin.as_str() {
            "obfs" => "obfs-local",
            other => other,
        };
        let mut parts: Vec<String> = vec![sb_plugin.to_string()];
        if let Some(opts) = ysub(m, "plugin-opts") {
            for (k, v) in opts {
                let Some(k) = k.as_str() else { continue };
                let key = match k {
                    "mode" => "obfs".to_string(),
                    "host" => "obfs-host".to_string(),
                    other => other.to_string(),
                };
                match v {
                    Value::String(s) => parts.push(format!("{key}={s}")),
                    Value::Bool(true) => parts.push(key),
                    Value::Bool(false) => {}
                    Value::Number(n) => parts.push(format!("{key}={n}")),
                    _ => {}
                }
            }
        }
        let plugin_str = pct_encode(&parts.join(";"));
        uri.push_str(&format!("?plugin={plugin_str}"));
    }

    uri.push_str(&format!("#{}", pct_encode(name)));
    Some(uri)
}

// ---------- ssr ----------

/// `ssr://base64url(host:port:protocol:method:obfs:base64url(password)/?obfsparam=..&protoparam=..&remarks=..)`
fn ssr_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let protocol = ystr(m, "protocol")?;
    let method = ystr(m, "cipher")?;
    let obfs = ystr(m, "obfs")?;
    let password = ystr(m, "password").unwrap_or_default();
    if protocol.trim().is_empty() || method.trim().is_empty() || obfs.trim().is_empty() {
        return None;
    }
    let pw_b64 = URL_SAFE_NO_PAD.encode(password.as_bytes());
    let mut inner = format!("{server}:{port}:{protocol}:{method}:{obfs}:{pw_b64}");

    let mut q: Vec<String> = Vec::new();
    if let Some(op) = ystr(m, "obfs-param").filter(|s| !s.is_empty()) {
        q.push(format!("obfsparam={}", URL_SAFE_NO_PAD.encode(op.as_bytes())));
    }
    if let Some(pp) = ystr(m, "protocol-param").filter(|s| !s.is_empty()) {
        q.push(format!("protoparam={}", URL_SAFE_NO_PAD.encode(pp.as_bytes())));
    }
    q.push(format!("remarks={}", URL_SAFE_NO_PAD.encode(name.as_bytes())));
    inner.push_str("/?");
    inner.push_str(&q.join("&"));

    Some(format!("ssr://{}", URL_SAFE_NO_PAD.encode(inner.as_bytes())))
}

// ---------- vmess ----------

/// `vmess://base64std(json)`, json 为 v2rayN v=2 格式。
fn vmess_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let uuid = ystr(m, "uuid")?;
    if uuid.trim().is_empty() {
        return None;
    }
    let net = ystr(m, "network").unwrap_or_else(|| "tcp".into());
    let net = if net.is_empty() { "tcp".to_string() } else { net };
    let aid = m
        .get(Value::String("alterId".into()))
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(0);
    let scy = ystr(m, "cipher").unwrap_or_else(|| "auto".into());

    let reality = ysub(m, "reality-opts");
    let tls_on = ybool(m, "tls").unwrap_or(false) || reality.is_some();
    let tls_field = if reality.is_some() {
        "reality"
    } else if tls_on {
        "tls"
    } else {
        ""
    };

    let (path, host_hdr) = transport_path_host(m, &net);
    let sni = ystr(m, "servername").or_else(|| ystr(m, "sni")).unwrap_or_default();

    let mut json = serde_json::Map::new();
    json.insert("v".into(), serde_json::json!("2"));
    json.insert("ps".into(), serde_json::json!(name));
    json.insert("add".into(), serde_json::json!(server));
    json.insert("port".into(), serde_json::json!(port.to_string()));
    json.insert("id".into(), serde_json::json!(uuid));
    json.insert("aid".into(), serde_json::json!(aid.to_string()));
    json.insert("scy".into(), serde_json::json!(scy));
    json.insert("net".into(), serde_json::json!(net));
    json.insert("type".into(), serde_json::json!("none"));
    if let Some(h) = &host_hdr {
        json.insert("host".into(), serde_json::json!(h));
    } else if net == "tcp" && !sni.is_empty() {
        json.insert("host".into(), serde_json::json!(""));
    }
    if let Some(p) = &path {
        json.insert("path".into(), serde_json::json!(p));
    }
    json.insert("tls".into(), serde_json::json!(tls_field));
    if !sni.is_empty() {
        json.insert("sni".into(), serde_json::json!(sni));
    }
    if let Some(fp) = ystr(m, "client-fingerprint").filter(|s| !s.is_empty()) {
        json.insert("fp".into(), serde_json::json!(fp));
    }
    if let Some(alpn) = yalpn_csv(m) {
        json.insert("alpn".into(), serde_json::json!(alpn));
    }
    if let Some(r) = reality {
        if let Some(pbk) = ystr(r, "public-key").filter(|s| !s.is_empty()) {
            json.insert("pbk".into(), serde_json::json!(pbk));
        }
        if let Some(sid) = ystr(r, "short-id") {
            json.insert("sid".into(), serde_json::json!(sid));
        }
    }

    let body = serde_json::to_string(&serde_json::Value::Object(json)).ok()?;
    Some(format!("vmess://{}", STANDARD.encode(body.as_bytes())))
}

// ---------- vless ----------

/// `vless://uuid@host:port?encryption=none&type=&security=&sni=&fp=&pbk=&sid=&flow=&path=&host=&serviceName=#name`
fn vless_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let uuid = ystr(m, "uuid")?;
    if uuid.trim().is_empty() {
        return None;
    }
    let net = ystr(m, "network").unwrap_or_else(|| "tcp".into());
    let net = if net.is_empty() { "tcp".to_string() } else { net };
    let reality = ysub(m, "reality-opts");
    let tls_on = ybool(m, "tls").unwrap_or(false) || reality.is_some();
    let security = if reality.is_some() {
        "reality"
    } else if tls_on {
        "tls"
    } else {
        "none"
    };

    let mut q: Vec<(String, String)> = vec![("encryption".into(), "none".into())];
    q.push(("type".into(), net.clone()));
    q.push(("security".into(), security.into()));
    if let Some(sni) = ystr(m, "servername").or_else(|| ystr(m, "sni")).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if let Some(fp) = ystr(m, "client-fingerprint").filter(|s| !s.is_empty()) {
        q.push(("fp".into(), fp));
    }
    if let Some(alpn) = yalpn_csv(m) {
        q.push(("alpn".into(), alpn));
    }
    if let Some(flow) = ystr(m, "flow").filter(|s| !s.is_empty()) {
        q.push(("flow".into(), flow));
    }
    if let Some(r) = reality {
        if let Some(pbk) = ystr(r, "public-key").filter(|s| !s.is_empty()) {
            q.push(("pbk".into(), pbk));
        }
        if let Some(sid) = ystr(r, "short-id").filter(|s| !s.is_empty()) {
            q.push(("sid".into(), sid));
        }
    }
    let (path, host_hdr) = transport_path_host(m, &net);
    match net.as_str() {
        "ws" | "h2" | "http" => {
            if let Some(p) = path {
                q.push(("path".into(), p));
            }
            if let Some(h) = host_hdr {
                q.push(("host".into(), h));
            }
        }
        "grpc" => {
            if let Some(svc) = path {
                q.push(("serviceName".into(), svc));
            }
        }
        _ => {}
    }

    let qs = q
        .iter()
        .map(|(k, v)| format!("{k}={}", pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    Some(format!(
        "vless://{uuid}@{}?{qs}#{}",
        fmt_host_port(server, port),
        pct_encode(name)
    ))
}

// ---------- trojan ----------

/// `trojan://password@host:port?sni=&allowInsecure=1&type=&path=&host=&fp=&pbk=&sid=#name`
fn trojan_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let password = ystr(m, "password")?;
    if password.trim().is_empty() {
        return None;
    }
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if ybool(m, "skip-cert-verify").unwrap_or(false) {
        q.push(("allowInsecure".into(), "1".into()));
    }
    if let Some(fp) = ystr(m, "client-fingerprint").filter(|s| !s.is_empty()) {
        q.push(("fp".into(), fp));
    }
    if let Some(alpn) = yalpn_csv(m) {
        q.push(("alpn".into(), alpn));
    }
    let net = ystr(m, "network").unwrap_or_default();
    if !net.is_empty() && net != "tcp" {
        q.push(("type".into(), net.clone()));
        let (path, host_hdr) = transport_path_host(m, &net);
        match net.as_str() {
            "ws" => {
                if let Some(p) = path {
                    q.push(("path".into(), p));
                }
                if let Some(h) = host_hdr {
                    q.push(("host".into(), h));
                }
            }
            "grpc" => {
                if let Some(svc) = path {
                    q.push(("serviceName".into(), svc));
                }
            }
            _ => {}
        }
    }
    if let Some(r) = ysub(m, "reality-opts") {
        q.push(("security".into(), "reality".into()));
        if let Some(pbk) = ystr(r, "public-key").filter(|s| !s.is_empty()) {
            q.push(("pbk".into(), pbk));
        }
        if let Some(sid) = ystr(r, "short-id").filter(|s| !s.is_empty()) {
            q.push(("sid".into(), sid));
        }
    }

    let qs = if q.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            q.iter()
                .map(|(k, v)| format!("{k}={}", pct_encode(v)))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    Some(format!(
        "trojan://{}@{}{qs}#{}",
        pct_encode(&password),
        fmt_host_port(server, port),
        pct_encode(name)
    ))
}

// ---------- hysteria2 ----------

/// `hysteria2://password@host:port?sni=&insecure=1&obfs=salamander&obfs-password=&pinSHA256=#name`
fn hysteria2_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let password = ystr(m, "password")?;
    if password.trim().is_empty() {
        return None;
    }
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if ybool(m, "skip-cert-verify").unwrap_or(false) {
        q.push(("insecure".into(), "1".into()));
    }
    if let Some(obfs) = ystr(m, "obfs").filter(|s| !s.is_empty()) {
        q.push(("obfs".into(), obfs));
        if let Some(opw) = ystr(m, "obfs-password").filter(|s| !s.is_empty()) {
            q.push(("obfs-password".into(), opw));
        }
    }
    if let Some(pin) = ystr(m, "fingerprint").filter(|s| !s.is_empty()) {
        q.push(("pinSHA256".into(), pin));
    }

    let qs = if q.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            q.iter()
                .map(|(k, v)| format!("{k}={}", pct_encode(v)))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    Some(format!(
        "hysteria2://{}@{}{qs}#{}",
        pct_encode(&password),
        fmt_host_port(server, port),
        pct_encode(name)
    ))
}

// ---------- tuic ----------

/// v5: `tuic://uuid:password@host:port?sni=&congestion_control=&udp_relay_mode=&alpn=#name`
/// v4: `tuic://token@host:port?sni=#name`
fn tuic_uri(m: &Mapping, server: &str, port: u64, name: &str) -> Option<String> {
    let mut q: Vec<(String, String)> = Vec::new();
    if let Some(sni) = ystr(m, "sni").or_else(|| ystr(m, "servername")).filter(|s| !s.is_empty()) {
        q.push(("sni".into(), sni));
    }
    if let Some(cc) = ystr(m, "congestion-controller").filter(|s| !s.is_empty()) {
        q.push(("congestion_control".into(), cc));
    }
    if let Some(urm) = ystr(m, "udp-relay-mode").filter(|s| !s.is_empty()) {
        q.push(("udp_relay_mode".into(), urm));
    }
    if let Some(alpn) = yalpn_csv(m) {
        q.push(("alpn".into(), alpn));
    }
    if ybool(m, "skip-cert-verify").unwrap_or(false) {
        q.push(("allow_insecure".into(), "1".into()));
    }
    if ybool(m, "disable-sni").unwrap_or(false) {
        q.push(("disable_sni".into(), "1".into()));
    }

    // userinfo: v5 = uuid:password; v4 = token。
    let userinfo = match (ystr(m, "uuid"), ystr(m, "password")) {
        (Some(u), Some(p)) if !u.is_empty() => {
            format!("{}:{}", pct_encode(&u), pct_encode(&p))
        }
        // uuid 存在但无 password: 输出裸 `tuic://uuid@...` (无 password 段)。
        // 注意往返语义: 解析回来会落到 parse_tuic 的 token 分支 (无 ':' → token),
        // 即把 uuid 当成 v4 token。这是有意的降级 (畸形 v5 节点缺 password 时退回 v4 形态),
        // 不在此处 early return None。
        (Some(u), None) if !u.is_empty() => pct_encode(&u),
        _ => {
            let token = ystr(m, "token")?;
            if token.trim().is_empty() {
                return None;
            }
            pct_encode(&token)
        }
    };

    let qs = if q.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            q.iter()
                .map(|(k, v)| format!("{k}={}", pct_encode(v)))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    Some(format!(
        "tuic://{userinfo}@{}{qs}#{}",
        fmt_host_port(server, port),
        pct_encode(name)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::uri;

    fn ymap(s: &str) -> Mapping {
        serde_yaml::from_str::<Value>(s)
            .unwrap()
            .as_mapping()
            .unwrap()
            .clone()
    }

    fn s<'a>(m: &'a Mapping, k: &str) -> Option<&'a str> {
        m.get(Value::String(k.into())).and_then(|v| v.as_str())
    }
    fn i(m: &Mapping, k: &str) -> Option<i64> {
        m.get(Value::String(k.into())).and_then(|v| v.as_i64())
    }
    fn nested<'a>(m: &'a Mapping, k: &str) -> Option<&'a Mapping> {
        m.get(Value::String(k.into())).and_then(|v| v.as_mapping())
    }

    // ---- 直接断言 URI 形态 ----
    #[test]
    fn ss_uri_shape() {
        let m = ymap("name: My Node\ntype: ss\nserver: 1.2.3.4\nport: 8388\ncipher: aes-256-gcm\npassword: pw");
        let uri = proxy_to_uri(&m).unwrap();
        assert!(uri.starts_with("ss://"));
        assert!(uri.ends_with("#My%20Node"));
    }

    #[test]
    fn vmess_uri_v2_json() {
        let m = ymap("name: VM\ntype: vmess\nserver: a.com\nport: 443\nuuid: u-123\nalterId: 0\ncipher: auto\ntls: true\nservername: a.com\nnetwork: ws\nws-opts:\n  path: /ray\n  headers:\n    Host: a.com");
        let uri = proxy_to_uri(&m).unwrap();
        let b64 = uri.strip_prefix("vmess://").unwrap();
        let decoded = String::from_utf8(STANDARD.decode(b64).unwrap()).unwrap();
        let j: serde_json::Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(j["v"], serde_json::json!("2"));
        assert_eq!(j["add"], serde_json::json!("a.com"));
        assert_eq!(j["net"], serde_json::json!("ws"));
        assert_eq!(j["path"], serde_json::json!("/ray"));
        assert_eq!(j["host"], serde_json::json!("a.com"));
        assert_eq!(j["tls"], serde_json::json!("tls"));
    }

    #[test]
    fn unsupported_type_none() {
        let m = ymap("name: X\ntype: snell\nserver: a.com\nport: 1");
        assert!(proxy_to_uri(&m).is_none());
    }

    #[test]
    fn missing_server_none() {
        let m = ymap("name: X\ntype: ss\nserver: ''\nport: 8388\ncipher: aes-256-gcm\npassword: pw");
        assert!(proxy_to_uri(&m).is_none());
    }

    // ---- 往返: URI → mapping (正向) → URI (逆向) → mapping (再正向), 关键字段一致 ----
    #[test]
    fn roundtrip_ss() {
        let orig = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#MyNode";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "type"), Some("ss"));
        assert_eq!(s(&m2, "server"), Some("1.2.3.4"));
        assert_eq!(i(&m2, "port"), Some(8388));
        assert_eq!(s(&m2, "cipher"), Some("aes-256-gcm"));
        assert_eq!(s(&m2, "password"), Some("password"));
        assert_eq!(s(&m2, "name"), Some("MyNode"));
    }

    #[test]
    fn roundtrip_vmess_ws_tls() {
        use base64::Engine;
        let json = r#"{"v":"2","ps":"vm-node","add":"a.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls","sni":"a.example.com"}"#;
        let orig = format!("vmess://{}", STANDARD.encode(json));
        let m1 = uri::parse_line_pub(&orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(s(&m2, "server"), Some("a.example.com"));
        assert_eq!(i(&m2, "port"), Some(443));
        assert_eq!(s(&m2, "network"), Some("ws"));
        assert_eq!(s(&m2, "servername"), Some("a.example.com"));
        let ws = nested(&m2, "ws-opts").unwrap();
        assert_eq!(s(ws, "path"), Some("/ray"));
        assert_eq!(s(nested(ws, "headers").unwrap(), "Host"), Some("a.example.com"));
    }

    #[test]
    fn roundtrip_vless_reality_grpc() {
        let orig = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=ABCDEF_publickey&sid=0123&type=grpc&serviceName=mygrpc#reality-node";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(s(&m2, "flow"), Some("xtls-rprx-vision"));
        assert_eq!(s(&m2, "servername"), Some("www.microsoft.com"));
        assert_eq!(s(&m2, "client-fingerprint"), Some("chrome"));
        assert_eq!(s(&m2, "network"), Some("grpc"));
        let r = nested(&m2, "reality-opts").unwrap();
        assert_eq!(s(r, "public-key"), Some("ABCDEF_publickey"));
        assert_eq!(s(r, "short-id"), Some("0123"));
        let g = nested(&m2, "grpc-opts").unwrap();
        assert_eq!(s(g, "grpc-service-name"), Some("mygrpc"));
    }

    #[test]
    fn roundtrip_trojan_ws() {
        let orig = "trojan://my%40pass@example.com:443?sni=example.com&allowInsecure=1&type=ws&host=example.com&path=%2Ftj#trojan-node";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "password"), Some("my@pass"));
        assert_eq!(s(&m2, "sni"), Some("example.com"));
        assert_eq!(s(&m2, "network"), Some("ws"));
        let ws = nested(&m2, "ws-opts").unwrap();
        assert_eq!(s(ws, "path"), Some("/tj"));
    }

    #[test]
    fn roundtrip_hysteria2() {
        let orig = "hysteria2://mypassword@1.2.3.4:8443?sni=example.com&insecure=1&obfs=salamander&obfs-password=ob_pw#hy2-node";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "type"), Some("hysteria2"));
        assert_eq!(s(&m2, "password"), Some("mypassword"));
        assert_eq!(s(&m2, "sni"), Some("example.com"));
        assert_eq!(s(&m2, "obfs"), Some("salamander"));
        assert_eq!(s(&m2, "obfs-password"), Some("ob_pw"));
    }

    #[test]
    fn roundtrip_tuic_v5() {
        let orig = "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@host.example.com:443?sni=x.example.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3#t-node";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(s(&m2, "password"), Some("pass"));
        assert_eq!(s(&m2, "sni"), Some("x.example.com"));
        assert_eq!(s(&m2, "congestion-controller"), Some("bbr"));
        assert_eq!(s(&m2, "udp-relay-mode"), Some("native"));
    }

    #[test]
    fn roundtrip_ssr() {
        let orig = "ssr://MS4yLjMuNDo4Mzg4Om9yaWdpbjphZXMtMjU2LWNmYjpwbGFpbjpiWGx3WVhOek1USXovP29iZnNwYXJhbT1iMkptYzJodmMzUXVZMjl0JnByb3RvcGFyYW09Y0hKdmRHOTJZV3cmcmVtYXJrcz1VMU5TSUU1dlpHVQ";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        assert!(back.starts_with("ssr://"));
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "type"), Some("ssr"));
        assert_eq!(s(&m2, "server"), Some("1.2.3.4"));
        assert_eq!(i(&m2, "port"), Some(8388));
        assert_eq!(s(&m2, "cipher"), Some("aes-256-cfb"));
        assert_eq!(s(&m2, "protocol"), Some("origin"));
        assert_eq!(s(&m2, "obfs"), Some("plain"));
        assert_eq!(s(&m2, "password"), Some("mypass123"));
        assert_eq!(s(&m2, "obfs-param"), Some("obfshost.com"));
        assert_eq!(s(&m2, "protocol-param"), Some("protoval"));
        assert_eq!(s(&m2, "name"), Some("SSR Node"));
    }

    #[test]
    fn roundtrip_ss_with_obfs_plugin() {
        let orig = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#p";
        let m1 = uri::parse_line_pub(orig).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = uri::parse_line_pub(&back).unwrap();
        assert_eq!(s(&m2, "plugin"), Some("obfs"));
        let po = nested(&m2, "plugin-opts").unwrap();
        assert_eq!(s(po, "mode"), Some("http"));
        assert_eq!(s(po, "host"), Some("www.bing.com"));
    }
}
