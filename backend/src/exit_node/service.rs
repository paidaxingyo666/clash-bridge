use crate::error::{AppError, AppResult};

/// 校验 proxy_yaml：必须是 mapping、含 name/type/server/port，按 type 做协议字段校验。
pub fn validate_proxy_yaml(yaml: &str) -> AppResult<()> {
    let v: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|e| AppError::BadRequest(format!("YAML 解析失败: {e}")))?;
    let m = v
        .as_mapping()
        .ok_or_else(|| AppError::BadRequest("proxy yaml 必须是 mapping".into()))?;

    let name = get_str(m, "name");
    if name.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(AppError::BadRequest("缺少 name 字段".into()));
    }
    let ty = get_str(m, "type").ok_or_else(|| AppError::BadRequest("缺少 type 字段".into()))?;
    let server = get_str(m, "server");
    if server.map(|s| s.trim().is_empty()).unwrap_or(true) {
        return Err(AppError::BadRequest("缺少 server 字段".into()));
    }
    let port = get_i64(m, "port").ok_or_else(|| AppError::BadRequest("port 必须是数字".into()))?;
    if !(1..=65535).contains(&port) {
        return Err(AppError::BadRequest("port 必须在 1-65535".into()));
    }

    match ty {
        "trojan" => {
            require_nonempty(m, "password", "trojan 缺少 password")?;
        }
        "ss" => {
            require_nonempty(m, "password", "ss 缺少 password")?;
            const SS_CIPHERS: &[&str] = &[
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "xchacha20-ietf-poly1305",
                "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm",
                "2022-blake3-chacha20-poly1305",
                "none",
            ];
            require_in(m, "cipher", SS_CIPHERS, "ss")?;
        }
        "ssr" => {
            require_nonempty(m, "password", "ssr 缺少 password")?;
            const SSR_CIPHERS: &[&str] = &[
                "aes-128-cfb",
                "aes-192-cfb",
                "aes-256-cfb",
                "aes-128-ctr",
                "aes-192-ctr",
                "aes-256-ctr",
                "aes-128-ofb",
                "aes-192-ofb",
                "aes-256-ofb",
                "chacha20-ietf",
                "rc4-md5",
                "none",
            ];
            const SSR_OBFS: &[&str] = &[
                "plain",
                "http_simple",
                "http_post",
                "random_head",
                "tls1.2_ticket_auth",
                "tls1.2_ticket_fastauth",
            ];
            const SSR_PROTOCOLS: &[&str] = &[
                "origin",
                "verify_sha1",
                "auth_sha1_v4",
                "auth_aes128_md5",
                "auth_aes128_sha1",
                "auth_chain_a",
                "auth_chain_b",
            ];
            require_in(m, "cipher", SSR_CIPHERS, "ssr")?;
            require_in(m, "obfs", SSR_OBFS, "ssr")?;
            require_in(m, "protocol", SSR_PROTOCOLS, "ssr")?;
        }
        "vmess" => {
            let uuid = get_str(m, "uuid")
                .ok_or_else(|| AppError::BadRequest("vmess 缺少 uuid".into()))?;
            check_uuid(uuid, "vmess")?;
        }
        "vless" => {
            let uuid = get_str(m, "uuid")
                .ok_or_else(|| AppError::BadRequest("vless 缺少 uuid".into()))?;
            check_uuid(uuid, "vless")?;
        }
        "hysteria2" => {
            require_nonempty(m, "password", "hysteria2 缺少 password")?;
        }
        "hysteria" => {
            // mihomo: auth_str (下划线) 或 auth-str
            let auth = get_str(m, "auth_str").or_else(|| get_str(m, "auth-str"));
            if auth.map(|s| s.trim().is_empty()).unwrap_or(true) {
                return Err(AppError::BadRequest("hysteria 缺少 auth_str".into()));
            }
            let up = get_i64(m, "up");
            let down = get_i64(m, "down");
            if up.unwrap_or(0) <= 0 {
                return Err(AppError::BadRequest("hysteria up 须为正数 (Mbps)".into()));
            }
            if down.unwrap_or(0) <= 0 {
                return Err(AppError::BadRequest("hysteria down 须为正数 (Mbps)".into()));
            }
        }
        "tuic" => {
            let uuid = get_str(m, "uuid")
                .ok_or_else(|| AppError::BadRequest("tuic 缺少 uuid".into()))?;
            check_uuid(uuid, "tuic")?;
            require_nonempty(m, "password", "tuic 缺少 password")?;
        }
        "snell" => {
            require_nonempty(m, "psk", "snell 缺少 psk")?;
        }
        "wireguard" => {
            require_nonempty(m, "private-key", "wireguard 缺少 private-key")?;
            require_nonempty(m, "public-key", "wireguard 缺少 public-key")?;
            require_nonempty(m, "ip", "wireguard 缺少 ip (本地隧道 IP)")?;
        }
        "anytls" => {
            require_nonempty(m, "password", "anytls 缺少 password")?;
        }
        "socks5" | "http" => {
            // 用户名密码均可选
        }
        _ => {
            // 其他协议放行
        }
    }

    Ok(())
}

/// 把 exit_node.proxy_yaml 转成 reqwest 能识别的 proxy URL.
/// 仅支持 socks5 / http / https 类型: 这是 reqwest 原生支持的两类 proxy.
/// vmess / trojan 等需要本地起 mihomo 才能用, 这里直接拒绝, 让前端把这类节点过滤掉.
pub fn proxy_url_from_yaml(yaml: &str) -> AppResult<reqwest::Url> {
    let v: serde_yaml::Value = serde_yaml::from_str(yaml)
        .map_err(|e| AppError::BadRequest(format!("exit_node yaml 解析失败: {e}")))?;
    let m = v
        .as_mapping()
        .ok_or_else(|| AppError::BadRequest("exit_node yaml 非 mapping".into()))?;

    let ty = get_str(m, "type").ok_or_else(|| AppError::BadRequest("exit_node 缺 type".into()))?;
    let server = get_str(m, "server")
        .ok_or_else(|| AppError::BadRequest("exit_node 缺 server".into()))?;
    let port = get_i64(m, "port")
        .ok_or_else(|| AppError::BadRequest("exit_node port 必须是数字".into()))?;

    let scheme = match ty {
        "socks5" => "socks5",
        "http" | "https" => "http",
        other => {
            return Err(AppError::BadRequest(format!(
                "节点类型 {other} 不可作为订阅拉取代理 (仅支持 socks5 / http)"
            )))
        }
    };

    let mut url: reqwest::Url = format!("{scheme}://{server}:{port}")
        .parse()
        .map_err(|e| AppError::Internal(format!("构造 proxy URL 失败: {e}")))?;
    if let Some(user) = get_str(m, "username") {
        url.set_username(user)
            .map_err(|_| AppError::Internal("set_username 失败".into()))?;
    }
    if let Some(pw) = get_str(m, "password") {
        url.set_password(Some(pw))
            .map_err(|_| AppError::Internal("set_password 失败".into()))?;
    }
    Ok(url)
}

fn get_str<'a>(m: &'a serde_yaml::Mapping, k: &str) -> Option<&'a str> {
    m.get(serde_yaml::Value::String(k.into()))
        .and_then(|v| v.as_str())
}
fn get_i64(m: &serde_yaml::Mapping, k: &str) -> Option<i64> {
    m.get(serde_yaml::Value::String(k.into())).and_then(|v| v.as_i64())
}
fn require_nonempty(m: &serde_yaml::Mapping, k: &str, msg: &str) -> AppResult<()> {
    match get_str(m, k) {
        Some(s) if !s.trim().is_empty() => Ok(()),
        _ => Err(AppError::BadRequest(msg.into())),
    }
}
fn require_in(
    m: &serde_yaml::Mapping,
    k: &str,
    allowed: &[&str],
    proto: &str,
) -> AppResult<()> {
    let v = get_str(m, k)
        .ok_or_else(|| AppError::BadRequest(format!("{proto} 缺少 {k}")))?;
    if !allowed.contains(&v) {
        return Err(AppError::BadRequest(format!(
            "{proto}: {k}={v} 不在支持列表里"
        )));
    }
    Ok(())
}

fn check_uuid(s: &str, proto: &str) -> AppResult<()> {
    let ok = s.len() == 36
        && s.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if ok {
        Ok(())
    } else {
        Err(AppError::BadRequest(format!(
            "{proto}: uuid 格式不合法 (应为 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )))
    }
}
