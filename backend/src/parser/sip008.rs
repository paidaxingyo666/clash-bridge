//! SIP008 JSON 订阅解析。
//!
//! 格式 (https://shadowsocks.org/doc/sip008.html):
//! `{ "version": 1, "servers": [ {server, server_port, password, method, remarks, plugin?, plugin_opts?}, ... ] }`
//! 每条 server 映射为 Clash `ss` proxy。

use serde::Deserialize;
use serde_yaml::{Mapping, Value};

use crate::error::{AppError, AppResult};

#[derive(Debug, Deserialize)]
struct Sip008Doc {
    #[allow(dead_code)]
    version: Option<i64>,
    servers: Vec<Sip008Server>,
}

#[derive(Debug, Deserialize)]
struct Sip008Server {
    server: String,
    server_port: u16,
    password: String,
    method: String,
    #[serde(default)]
    remarks: Option<String>,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    plugin_opts: Option<String>,
}

/// 解析 SIP008 JSON → Clash `{proxies: [...]}` YAML。
pub fn parse(raw: &str) -> AppResult<(String, usize)> {
    let doc: Sip008Doc = serde_json::from_str(raw.trim())
        .map_err(|e| AppError::BadRequest(format!("SIP008 JSON 解析失败: {e}")))?;

    let mut proxies: Vec<Mapping> = Vec::new();
    for (i, s) in doc.servers.into_iter().enumerate() {
        if s.server.trim().is_empty() || s.method.trim().is_empty() {
            continue;
        }
        let mut m = Mapping::new();
        let name = s
            .remarks
            .as_deref()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
            .map(|r| r.to_string())
            .unwrap_or_else(|| format!("{}:{}", s.server, s.server_port));
        ins(&mut m, "name", Value::String(name));
        ins(&mut m, "type", Value::String("ss".into()));
        ins(&mut m, "server", Value::String(s.server.clone()));
        ins(&mut m, "port", Value::Number(s.server_port.into()));
        ins(&mut m, "cipher", Value::String(s.method.clone()));
        ins(&mut m, "password", Value::String(s.password.clone()));
        ins(&mut m, "udp", Value::Bool(true));
        if let Some(plugin) = s.plugin.as_deref().filter(|p| !p.trim().is_empty()) {
            ins(&mut m, "plugin", Value::String(plugin.to_string()));
            if let Some(opts) = s.plugin_opts.as_deref().filter(|p| !p.trim().is_empty()) {
                if let Some(opts_map) = plugin_opts_to_mapping(opts) {
                    ins(&mut m, "plugin-opts", Value::Mapping(opts_map));
                }
            }
        }
        let _ = i;
        proxies.push(m);
    }

    if proxies.is_empty() {
        return Err(AppError::BadRequest("SIP008 里没有有效的 ss 节点".into()));
    }
    super::proxies_to_yaml(proxies)
}

/// 把 SIP008 的 plugin_opts 字符串 (如 `obfs=http;obfs-host=x.com`) 转成 Clash plugin-opts mapping。
/// Clash 对 obfs / v2ray-plugin 有结构化字段，这里做最常见的 obfs-local 映射；
/// 不认识的插件保留原串到 `__raw` 以免静默丢弃 (Clash 会忽略未知字段)。
fn plugin_opts_to_mapping(opts: &str) -> Option<Mapping> {
    let mut kv: Vec<(String, String)> = Vec::new();
    for part in opts.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            kv.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            kv.push((part.to_string(), String::new()));
        }
    }
    if kv.is_empty() {
        return None;
    }
    let mut m = Mapping::new();
    // obfs-local: obfs=http/tls, obfs-host=...
    for (k, v) in &kv {
        match k.as_str() {
            "obfs" => ins(&mut m, "mode", Value::String(v.clone())),
            "obfs-host" => ins(&mut m, "host", Value::String(v.clone())),
            _ => ins(&mut m, k, Value::String(v.clone())),
        }
    }
    Some(m)
}

fn ins(m: &mut Mapping, k: &str, v: Value) {
    m.insert(Value::String(k.into()), v);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies_of(yaml: &str) -> Vec<Mapping> {
        let v: Value = serde_yaml::from_str(yaml).unwrap();
        v.get("proxies")
            .and_then(|p| p.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_mapping().cloned())
            .collect()
    }

    fn s<'a>(m: &'a Mapping, k: &str) -> Option<&'a str> {
        m.get(Value::String(k.into())).and_then(|v| v.as_str())
    }

    #[test]
    fn parses_basic_sip008() {
        let raw = r#"{
            "version": 1,
            "servers": [
                {"server":"1.2.3.4","server_port":8388,"password":"pw1","method":"aes-256-gcm","remarks":"US-1"},
                {"server":"5.6.7.8","server_port":9999,"password":"pw2","method":"chacha20-ietf-poly1305"}
            ]
        }"#;
        let (yaml, n) = parse(raw).unwrap();
        assert_eq!(n, 2);
        let ps = proxies_of(&yaml);
        assert_eq!(s(&ps[0], "type"), Some("ss"));
        assert_eq!(s(&ps[0], "name"), Some("US-1"));
        assert_eq!(s(&ps[0], "server"), Some("1.2.3.4"));
        assert_eq!(
            ps[0].get(Value::String("port".into())).unwrap().as_i64(),
            Some(8388)
        );
        assert_eq!(s(&ps[0], "cipher"), Some("aes-256-gcm"));
        assert_eq!(s(&ps[0], "password"), Some("pw1"));
        // 无 remarks → server:port 兜底
        assert_eq!(s(&ps[1], "name"), Some("5.6.7.8:9999"));
    }

    #[test]
    fn parses_sip008_with_plugin() {
        let raw = r#"{
            "version": 1,
            "servers": [
                {"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm","remarks":"P","plugin":"obfs-local","plugin_opts":"obfs=http;obfs-host=www.bing.com"}
            ]
        }"#;
        let (yaml, n) = parse(raw).unwrap();
        assert_eq!(n, 1);
        let ps = proxies_of(&yaml);
        assert_eq!(s(&ps[0], "plugin"), Some("obfs-local"));
        let po = ps[0]
            .get(Value::String("plugin-opts".into()))
            .and_then(|v| v.as_mapping())
            .unwrap();
        assert_eq!(s(po, "mode"), Some("http"));
        assert_eq!(s(po, "host"), Some("www.bing.com"));
    }
}
