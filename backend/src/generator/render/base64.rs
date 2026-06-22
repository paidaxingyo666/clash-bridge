//! Base64Renderer — base64 通用订阅 (URI 列表整体 base64)。
//!
//! 上游每个节点 → 裸 URI ([`uri_encode::proxy_to_uri`]), `\n` join, 整体 base64(STANDARD)。
//! 逆向失败 (不支持的协议 / 缺字段) 的节点跳过并记 `skipped`。
//!
//! base64 URI 列表无 relay/chain 概念 (`dialer-proxy` 是 mihomo 私有字段, 无 URI 等价),
//! 故 `supports_relay_chain()=false`; 含链路的 profile 由 service 层 415 拦截, 不会进到这里
//! 渲染链路节点 (injected_proxies 在此被忽略, 只渲染上游裸节点)。

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::error::AppResult;
use crate::generator::model::InjectModel;
use crate::generator::render::uri_encode::proxy_to_uri;
use crate::generator::render::{RenderedSub, Renderer};

pub struct Base64Renderer;

impl Renderer for Base64Renderer {
    fn render(&self, model: &InjectModel) -> AppResult<RenderedSub> {
        let mut skipped: Vec<String> = Vec::new();
        let mut uris: Vec<String> = Vec::new();

        let upstream_proxies = model
            .upstream_root
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .map(|s| s.as_slice())
            .unwrap_or(&[]);
        for p in upstream_proxies {
            let Some(m) = p.as_mapping() else { continue };
            match proxy_to_uri(m) {
                Some(uri) => uris.push(uri),
                None => {
                    let name = m
                        .get(serde_yaml::Value::String("name".into()))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let ptype = m
                        .get(serde_yaml::Value::String("type".into()))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    skipped.push(format!("uri-encode-failed:{ptype}:{name}"));
                }
            }
        }

        let joined = uris.join("\n");
        let body = STANDARD.encode(joined.as_bytes());
        let mut rendered = RenderedSub::new(body, "text/plain; charset=utf-8", "txt");
        rendered.skipped = skipped;
        Ok(rendered)
    }

    fn supports_relay_chain(&self) -> bool {
        false
    }

    fn format_id(&self) -> &'static str {
        "sub.txt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::model::{GroupKind, InjectGroup};
    use serde_yaml::Value as Yaml;

    fn make_model(upstream_yaml: &str) -> InjectModel {
        let root: Yaml = serde_yaml::from_str(upstream_yaml).unwrap();
        InjectModel {
            upstream_root: root,
            injected_proxies: Vec::new(),
            injected_groups: vec![InjectGroup {
                name: "Bridge-Exit".into(),
                kind: GroupKind::Select,
                proxies: vec!["DIRECT".into()],
            }],
            select_inject_target: "Bridge-Exit".into(),
            custom_rules: Vec::new(),
            fallback_target: "Bridge-Exit".into(),
            upstream_count: 0,
            bridge_count: 0,
            chain_count: 0,
            missing_bridges: Vec::new(),
            has_relay_chain: false,
        }
    }

    fn decode_body(body: &str) -> String {
        String::from_utf8(STANDARD.decode(body).unwrap()).unwrap()
    }

    #[test]
    fn renders_base64_of_uri_list() {
        let upstream = "proxies:\n  - name: SS1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n  - name: TJ1\n    type: trojan\n    server: ex.com\n    port: 443\n    password: tpw\n    sni: ex.com\n";
        let model = make_model(upstream);
        let rendered = Base64Renderer.render(&model).unwrap();
        assert_eq!(rendered.content_type, "text/plain; charset=utf-8");
        assert_eq!(rendered.filename_ext, "txt");
        let decoded = decode_body(&rendered.body);
        let lines: Vec<&str> = decoded.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("ss://"));
        assert!(lines[1].starts_with("trojan://"));
        assert!(rendered.skipped.is_empty());
    }

    #[test]
    fn unsupported_protocol_skipped() {
        // snell 不在 uri_encode 支持列表 → 跳过记 skipped, 其余节点照常。
        let upstream = "proxies:\n  - name: SNELL\n    type: snell\n    server: a.com\n    port: 1\n  - name: SS1\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
        let model = make_model(upstream);
        let rendered = Base64Renderer.render(&model).unwrap();
        let decoded = decode_body(&rendered.body);
        assert_eq!(decoded.lines().count(), 1);
        assert!(decoded.starts_with("ss://"));
        assert!(rendered.skipped.iter().any(|s| s.starts_with("uri-encode-failed:snell:")));
    }

    #[test]
    fn empty_proxies_yields_empty_base64() {
        let model = make_model("proxies: []\n");
        let rendered = Base64Renderer.render(&model).unwrap();
        assert_eq!(decode_body(&rendered.body), "");
    }
}
