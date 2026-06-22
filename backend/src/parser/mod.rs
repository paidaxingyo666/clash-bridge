//! 多订阅格式归一化层。
//!
//! 统一中间表示 (IR) = Clash `proxies` 数组的 YAML 文本，即顶层 `{proxies: [...]}`。
//! 任意输入格式 (Clash YAML / base64 通用订阅 / 裸节点 URI 列表 / SIP008 JSON)
//! 在【拉取后、存库前】都先转成该 IR 再存 `last_upstream_yaml`，这样下游
//! generator / extract_nodes / count_proxies 一行都不用改 (它们硬要求 proxies 数组)。
//!
//! 安全假设 (SSRF): 本服务按"单租户可信自部署"模型处理，上游 URL 由部署者自己配置，
//! 因此本 MVP **不做内网 IP / SSRF 校验**。若改为多租户公开服务，必须在拉取层补内网网段拦截。

mod base64sub;
mod sip008;
pub(crate) mod uri;

use serde::Deserialize;
use serde_yaml::{Mapping, Value};

use crate::error::{AppError, AppResult};

/// 上游订阅输入格式。serde 小写，对应前端下拉与 DB 的 upstream_format 列。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubFormat {
    /// 自动探测 (默认)
    Auto,
    /// Clash / Mihomo YAML，原样使用
    Clash,
    /// base64 通用订阅 (整包解码后是裸节点 URI 列表)
    Base64,
    /// 裸节点 URI 列表 (逐行 ss:// vmess:// 等)
    Uri,
    /// SIP008 JSON
    Sip008,
}

impl SubFormat {
    /// 从 DB / 前端传入的字符串解析。未知值一律回落到 Auto (容错)。
    pub fn from_opt(s: Option<&str>) -> Self {
        match s.map(|x| x.trim().to_ascii_lowercase()).as_deref() {
            Some("clash") => SubFormat::Clash,
            Some("base64") => SubFormat::Base64,
            Some("uri") => SubFormat::Uri,
            Some("sip008") => SubFormat::Sip008,
            _ => SubFormat::Auto,
        }
    }
}

/// 把任意格式的上游订阅文本归一化成 Clash `{proxies: [...]}` 的 YAML 文本。
///
/// 返回 `(clash_yaml, node_count)`。
///
/// 关键安全约束（二次确认）：任何格式解析后【必须产出 ≥1 个有效节点】才算命中，
/// 否则继续回退 / 报错。这能防 Cloudflare challenge HTML、空订阅被误判成"成功但 0 节点"。
pub fn normalize_to_clash_yaml(raw: &str, hint: SubFormat) -> AppResult<(String, usize)> {
    match hint {
        SubFormat::Clash => parse_clash(raw),
        SubFormat::Sip008 => sip008::parse(raw),
        SubFormat::Base64 => parse_base64(raw),
        SubFormat::Uri => parse_uri_list(raw),
        SubFormat::Auto => auto_detect(raw),
    }
}

/// Auto 探测回退链：
/// (a) serde_yaml 成功且顶层 mapping 含非空 proxies 数组 → 原样;
/// (b) serde_json 成功且 version==1 + servers → SIP008;
/// (c) base64 整体解码后首个非空行匹配已知 scheme → Uri 列表;
/// (d) raw 直接逐行匹配 scheme → Uri 列表;
/// (e) 都不匹配 → BadRequest，错误带 raw 前 200 字符。
fn auto_detect(raw: &str) -> AppResult<(String, usize)> {
    // (a) Clash YAML
    if let Ok(res) = parse_clash(raw) {
        return Ok(res);
    }
    // (b) SIP008 JSON
    if looks_like_sip008(raw) {
        if let Ok(res) = sip008::parse(raw) {
            return Ok(res);
        }
    }
    // (c) base64 整包
    if base64sub::looks_like_base64_sub(raw) {
        if let Ok(res) = parse_base64(raw) {
            return Ok(res);
        }
    }
    // (d) 裸 URI 列表
    if uri::has_known_scheme_line(raw) {
        if let Ok(res) = parse_uri_list(raw) {
            return Ok(res);
        }
    }
    Err(AppError::BadRequest(format!(
        "无法识别的订阅格式 (尝试了 clash / sip008 / base64 / uri 均失败)。前 200 字符: {}",
        preview(raw)
    )))
}

/// Clash 分支：serde_yaml 解析成功 + 顶层 mapping 含非空 proxies 数组 → 原样返回。
fn parse_clash(raw: &str) -> AppResult<(String, usize)> {
    let v: Value = serde_yaml::from_str(raw)
        .map_err(|e| AppError::BadRequest(format!("Clash YAML 解析失败: {e}")))?;
    let m = v
        .as_mapping()
        .ok_or_else(|| AppError::BadRequest("Clash YAML 顶层不是 mapping".into()))?;
    let proxies = m
        .get(Value::String("proxies".into()))
        .and_then(|p| p.as_sequence())
        .ok_or_else(|| AppError::BadRequest("Clash YAML 缺少 proxies 数组".into()))?;
    // 二次确认：proxies 必须非空
    let count = proxies.len();
    if count == 0 {
        return Err(AppError::BadRequest("Clash YAML 的 proxies 数组为空".into()));
    }
    // 二次确认加固：至少一个元素是 mapping 且含 "type" 键，
    // 否则可能是 proxies:[null] 或 "结构合法但内容垃圾" 的 YAML 蒙混过关。
    let has_real_proxy = proxies.iter().any(|p| {
        p.as_mapping()
            .map(|pm| pm.contains_key(Value::String("type".into())))
            .unwrap_or(false)
    });
    if !has_real_proxy {
        return Err(AppError::BadRequest(
            "Clash YAML 的 proxies 数组无任何含 type 字段的有效节点 (疑似空/垃圾内容)".into(),
        ));
    }
    // 原样返回 (保留上游全部结构 — generator 需要 proxy-groups / rules 等)
    Ok((raw.to_string(), count))
}

/// base64 分支：整包 base64 解码后当作裸 URI 列表解析。
fn parse_base64(raw: &str) -> AppResult<(String, usize)> {
    let decoded = base64sub::decode_whole(raw)
        .ok_or_else(|| AppError::BadRequest("base64 订阅解码失败".into()))?;
    parse_uri_list(&decoded)
}

/// URI 列表分支：逐行解析裸节点 URI → proxy mapping，组装成 Clash IR。
///
/// 部分节点失败保护：若 "以已知 scheme 开头却解析失败" 的行数 ≥ 成功数 (failed >= proxies.len())，
/// 大概率是上游格式升级 / 不兼容，宁可整体报错走 yaml=None 分支 (COALESCE 保留旧缓存)，
/// 也不要用残缺结果覆盖好缓存，导致用户大面积掉节点。
fn parse_uri_list(raw: &str) -> AppResult<(String, usize)> {
    let (proxies, failed) = uri::parse_lines(raw);
    if proxies.is_empty() {
        return Err(AppError::BadRequest(format!(
            "URI 列表里没有解析出任何有效节点。前 200 字符: {}",
            preview(raw)
        )));
    }
    if failed > 0 && failed >= proxies.len() {
        return Err(AppError::BadRequest(format!(
            "URI 列表解析失败行数 ({failed}) ≥ 成功数 ({})，疑似上游格式不兼容/升级，\
             拒绝用残缺结果覆盖缓存。前 200 字符: {}",
            proxies.len(),
            preview(raw)
        )));
    }
    proxies_to_yaml(proxies)
}

/// 把一组 proxy Mapping 包成 `{proxies: [...]}` 的 Clash YAML 文本。
pub(crate) fn proxies_to_yaml(proxies: Vec<Mapping>) -> AppResult<(String, usize)> {
    let count = proxies.len();
    let mut root = Mapping::new();
    root.insert(
        Value::String("proxies".into()),
        Value::Sequence(proxies.into_iter().map(Value::Mapping).collect()),
    );
    let yaml = serde_yaml::to_string(&Value::Mapping(root))
        .map_err(|e| AppError::Internal(format!("序列化 Clash YAML 失败: {e}")))?;
    Ok((yaml, count))
}

/// 粗判是否像 SIP008 JSON：解析成 JSON 且 version==1 且有 servers 数组。
fn looks_like_sip008(raw: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_str(raw.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("version").and_then(|x| x.as_i64()) == Some(1)
        && v.get("servers").map(|s| s.is_array()).unwrap_or(false)
}

fn preview(s: &str) -> String {
    let trimmed = s.trim();
    let take: String = trimmed.chars().take(200).collect();
    if trimmed.chars().count() > 200 {
        format!("{take}…")
    } else {
        take
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxies_of(yaml: &str) -> Vec<serde_yaml::Mapping> {
        let v: Value = serde_yaml::from_str(yaml).unwrap();
        v.get("proxies")
            .and_then(|p| p.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|x| x.as_mapping().cloned())
            .collect()
    }

    #[test]
    fn auto_detects_clash_yaml_passthrough() {
        let raw = "proxies:\n  - {name: a, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}\n";
        let (yaml, n) = normalize_to_clash_yaml(raw, SubFormat::Auto).unwrap();
        assert_eq!(n, 1);
        // passthrough：原样返回
        assert_eq!(yaml, raw);
    }

    #[test]
    fn empty_clash_proxies_is_rejected() {
        let raw = "proxies: []\n";
        assert!(normalize_to_clash_yaml(raw, SubFormat::Clash).is_err());
    }

    #[test]
    fn clash_proxies_null_element_is_rejected() {
        // proxies 非空但元素是 null (无 type) → 二次确认加固应拒绝
        let raw = "proxies:\n  - null\n";
        assert!(normalize_to_clash_yaml(raw, SubFormat::Clash).is_err());
    }

    #[test]
    fn clash_proxies_garbage_without_type_is_rejected() {
        // 结构合法但每个元素都没有 type 键 → 拒绝
        let raw = "proxies:\n  - {foo: bar}\n  - {baz: 1}\n";
        assert!(normalize_to_clash_yaml(raw, SubFormat::Clash).is_err());
    }

    #[test]
    fn uri_list_mostly_failed_is_rejected() {
        // 5 行坏的 vless (已知 scheme 但解析失败) + 1 行好的 ss
        // failed(5) >= proxies.len()(1) → 拒绝, 不静默成功
        let raw = "vless://@:0?bad\nvless://@:0?bad\nvless://@:0?bad\nvless://@:0?bad\nvless://@:0?bad\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ok";
        let res = normalize_to_clash_yaml(raw, SubFormat::Uri);
        assert!(res.is_err(), "多数已知 scheme 行失败应被拒绝, 实际: {res:?}");
    }

    #[test]
    fn cf_challenge_html_is_rejected_not_empty_sub() {
        let html = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cf-ray</body></html>";
        // 既不是合法 clash，也不是 base64 节点，也没有 scheme 行 → 必须报错而非误判
        assert!(normalize_to_clash_yaml(html, SubFormat::Auto).is_err());
    }

    #[test]
    fn auto_detects_uri_list() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#node\ntrojan://pw@host.com:443#t";
        let (yaml, n) = normalize_to_clash_yaml(raw, SubFormat::Auto).unwrap();
        assert_eq!(n, 2);
        let ps = proxies_of(&yaml);
        assert_eq!(ps[0].get(Value::String("type".into())).unwrap().as_str(), Some("ss"));
        assert_eq!(ps[1].get(Value::String("type".into())).unwrap().as_str(), Some("trojan"));
    }

    /// 关键回归: 把各协议样本解析出的每个 proxy 单独序列化, 跑真实的 validate_proxy_yaml,
    /// 确保字段映射 (name/type/server/port + 协议字段/cipher 白名单/uuid 格式) 全部对齐, 不会静默连不上.
    #[test]
    fn parsed_proxies_pass_real_validator() {
        use base64::Engine;
        let vmess_json = r#"{"v":"2","ps":"vm","add":"a.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","host":"a.example.com","path":"/ray","tls":"tls"}"#;
        let vmess_uri = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(vmess_json)
        );
        let samples = vec![
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ss-node".to_string(),
            vmess_uri,
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=01ab&type=tcp#vless-reality".to_string(),
            "trojan://pw@example.com:443?sni=example.com#trojan-node".to_string(),
            "hysteria2://auth@1.2.3.4:8443?sni=example.com&obfs=salamander&obfs-password=op#hy2".to_string(),
            // ssr 双层 base64 (method=aes-256-cfb obfs=plain protocol=origin, 均在白名单内)
            "ssr://MS4yLjMuNDo4Mzg4Om9yaWdpbjphZXMtMjU2LWNmYjpwbGFpbjpiWGx3WVhOek1USXovP29iZnNwYXJhbT1iMkptYzJodmMzUXVZMjl0JnByb3RvcGFyYW09Y0hKdmRHOTJZV3cmcmVtYXJrcz1VMU5TSUU1dlpHVQ".to_string(),
            // tuic v5 (uuid + password)
            "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@1.2.3.4:443?sni=x&congestion_control=bbr&udp_relay_mode=native&alpn=h3#tuic-v5".to_string(),
        ];
        for uri in &samples {
            let (proxies, _failed) = super::uri::parse_lines(uri);
            assert_eq!(proxies.len(), 1, "解析失败: {uri}");
            let yaml = serde_yaml::to_string(&Value::Mapping(proxies[0].clone())).unwrap();
            crate::exit_node::service::validate_proxy_yaml(&yaml)
                .unwrap_or_else(|e| panic!("validate 失败 for {uri}: {e:?}\nyaml:\n{yaml}"));
        }
    }

    /// SIP008 解析产物也必须通过 validate_proxy_yaml.
    #[test]
    fn sip008_proxies_pass_real_validator() {
        let raw = r#"{"version":1,"servers":[{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm","remarks":"s1"}]}"#;
        let (yaml, _) = super::sip008::parse(raw).unwrap();
        for m in proxies_of(&yaml) {
            let py = serde_yaml::to_string(&Value::Mapping(m)).unwrap();
            crate::exit_node::service::validate_proxy_yaml(&py).unwrap();
        }
    }

    #[test]
    fn auto_detects_base64_whole_package() {
        use base64::Engine;
        let inner = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#node\nvless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?encryption=none&security=tls&type=ws&host=h.com&path=%2Fpath#vl";
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let (yaml, n) = normalize_to_clash_yaml(&b64, SubFormat::Auto).unwrap();
        assert_eq!(n, 2);
        let ps = proxies_of(&yaml);
        assert_eq!(ps[0].get(Value::String("type".into())).unwrap().as_str(), Some("ss"));
        assert_eq!(ps[1].get(Value::String("type".into())).unwrap().as_str(), Some("vless"));
    }
}
