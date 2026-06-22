//! base64 通用订阅解码工具。
//!
//! 机场常把"裸节点 URI 列表"整体 base64 编码后作为订阅返回。
//! 解码时容错：URL_SAFE_NO_PAD 优先、STANDARD 回退，并自动补 padding。

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;

/// 解码"整包" base64 订阅文本为 UTF-8 字符串。
/// 先剥掉所有空白 (机场会换行/加空格), 再依次尝试多种 alphabet + 自动补 padding。
pub fn decode_whole(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    decode_b64_flex(&cleaned)
}

/// 灵活 base64 解码：URL_SAFE_NO_PAD 优先、STANDARD 回退，自动补 padding。
/// 用于整包订阅，也用于 ss:// 的 userinfo 段。
pub fn decode_b64_flex(s: &str) -> Option<String> {
    let bytes = decode_b64_flex_bytes(s)?;
    String::from_utf8(bytes).ok()
}

/// 同 decode_b64_flex 但返回原始字节 (ss SIP002 userinfo 解码后还要按 ':' 拆，用字符串即可，
/// 但保留 bytes 版以防二进制；当前内部用字符串包装)。
pub fn decode_b64_flex_bytes(s: &str) -> Option<Vec<u8>> {
    // 去掉可能存在的 padding，统一由各引擎处理 (no_pad 引擎不接受 '=')
    let trimmed = s.trim_end_matches('=');

    // 1) URL_SAFE_NO_PAD —— 现代订阅最常见
    if let Ok(b) = URL_SAFE_NO_PAD.decode(trimmed) {
        return Some(b);
    }
    // 2) STANDARD_NO_PAD
    if let Ok(b) = STANDARD_NO_PAD.decode(trimmed) {
        return Some(b);
    }
    // 3) 补 padding 后用带 padding 的引擎
    let padded = pad(trimmed);
    if let Ok(b) = URL_SAFE.decode(&padded) {
        return Some(b);
    }
    if let Ok(b) = STANDARD.decode(&padded) {
        return Some(b);
    }
    None
}

/// 把 base64 补到 4 的倍数长度。
fn pad(s: &str) -> String {
    let rem = s.len() % 4;
    if rem == 0 {
        s.to_string()
    } else {
        let mut out = s.to_string();
        out.push_str(&"=".repeat(4 - rem));
        out
    }
}

/// 粗判 raw 是否像"整包 base64 订阅"：
/// 解码后首个非空行匹配已知 scheme，才算命中 (二次确认的前置判断)。
pub fn looks_like_base64_sub(raw: &str) -> bool {
    let decoded = match decode_whole(raw) {
        Some(d) => d,
        None => return false,
    };
    // 解码后逐行找第一个非空行，必须匹配已知 scheme
    decoded
        .lines()
        .map(|l| l.trim())
        .find(|l| !l.is_empty())
        .map(super::uri::is_known_scheme)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_url_safe_no_pad() {
        // "aes-256-gcm:password" url-safe no pad
        let s = "YWVzLTI1Ni1nY206cGFzc3dvcmQ";
        assert_eq!(decode_b64_flex(s).as_deref(), Some("aes-256-gcm:password"));
    }

    #[test]
    fn decode_standard_with_padding() {
        let s = "YWVzLTI1Ni1nY206cGFzc3dvcmQ=";
        assert_eq!(decode_b64_flex(s).as_deref(), Some("aes-256-gcm:password"));
    }

    #[test]
    fn whole_sub_with_newlines_decodes() {
        use base64::Engine;
        let inner = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#n";
        let b64 = STANDARD.encode(inner.as_bytes());
        // 插入换行模拟机场返回
        let withbreaks = format!("{}\n{}", &b64[..10], &b64[10..]);
        let out = decode_whole(&withbreaks).unwrap();
        assert!(out.starts_with("ss://"));
    }

    #[test]
    fn html_is_not_base64_sub() {
        let html = "<!DOCTYPE html><title>Just a moment</title>";
        assert!(!looks_like_base64_sub(html));
    }
}
