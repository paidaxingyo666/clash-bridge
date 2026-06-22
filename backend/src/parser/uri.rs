//! 裸节点 URI 列表解析。
//!
//! 每行一个节点 URI (ss:// vmess:// vless:// trojan:// hysteria2:// hy2://)。
//! 无法识别的 scheme 静默 skip，不报错。
//!
//! 字段映射以 mihomo (metacubex/mihomo) 的 Clash proxy schema 为准，
//! 并与 exit_node/service.rs 的 validate_proxy_yaml 保持一致。

use serde_yaml::{Mapping, Value};
use url::Url;

use super::base64sub::decode_b64_flex;

/// 已知 scheme 前缀。
const KNOWN_SCHEMES: &[&str] = &[
    "ss://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria2://",
    "hy2://",
];

/// 判断单行是否以已知 scheme 开头 (大小写不敏感)。
pub fn is_known_scheme(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
    KNOWN_SCHEMES.iter().any(|s| lower.starts_with(s))
}

/// 判断整段文本里是否存在至少一行已知 scheme (auto 探测用)。
pub fn has_known_scheme_line(raw: &str) -> bool {
    raw.lines().map(|l| l.trim()).any(is_known_scheme)
}

/// 逐行解析裸 URI → proxy Mapping 列表。无法识别的行静默跳过。
pub fn parse_lines(raw: &str) -> Vec<Mapping> {
    let mut out = Vec::new();
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(mut m) = parse_one(line) {
            // 名称去重 (Clash 节点名必须唯一，否则后续 dialer/group 引用混乱)
            dedup_name(&mut m, &mut seen_names);
            out.push(m);
        }
    }
    out
}

fn dedup_name(m: &mut Mapping, seen: &mut std::collections::HashSet<String>) {
    let key = Value::String("name".into());
    let base = m
        .get(&key)
        .and_then(|v| v.as_str())
        .unwrap_or("node")
        .to_string();
    let mut name = base.clone();
    let mut i = 2;
    while !seen.insert(name.clone()) {
        name = format!("{base}-{i}");
        i += 1;
    }
    m.insert(key, Value::String(name));
}

/// 解析单个 URI。识别失败 (含不支持的 scheme) 返回 None。
fn parse_one(uri: &str) -> Option<Mapping> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("ss://") {
        parse_ss(uri)
    } else if lower.starts_with("vmess://") {
        parse_vmess(uri)
    } else if lower.starts_with("vless://") {
        parse_vless(uri)
    } else if lower.starts_with("trojan://") {
        parse_trojan(uri)
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria2(uri)
    } else {
        None
    }
}

// ---------- 通用工具 ----------

fn ins(m: &mut Mapping, k: &str, v: Value) {
    m.insert(Value::String(k.into()), v);
}

fn ins_str(m: &mut Mapping, k: &str, v: impl Into<String>) {
    ins(m, k, Value::String(v.into()));
}

/// percent-decode (用于 fragment/password 等)。失败时返回原串。
fn pct_decode(s: &str) -> String {
    percent_decode(s)
}

/// 简易 percent-decode，避免再拉一个 crate。处理 %XX 与 '+' (query 场景 '+' 不当空格，这里保守不转)。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = hex_val(bytes[i + 1]);
            let l = hex_val(bytes[i + 2]);
            if let (Some(h), Some(l)) = (h, l) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 取 fragment 作为 name；无 fragment 时用 server:port 兜底。
fn name_from_fragment(fragment: Option<&str>, server: &str, port: i64) -> String {
    match fragment {
        Some(f) if !f.trim().is_empty() => {
            let n = pct_decode(f);
            let n = n.trim();
            if n.is_empty() {
                format!("{server}:{port}")
            } else {
                n.to_string()
            }
        }
        _ => format!("{server}:{port}"),
    }
}

/// 从 `url::Url` 收集 query 成 (key, value) map，value 已 percent-decode (url crate 自动 decode)。
fn collect_query(u: &Url) -> std::collections::HashMap<String, String> {
    u.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// 给 vless/trojan 共用：根据 network + query 构造 transport opts (ws-opts / grpc-opts)。
fn apply_transport(m: &mut Mapping, network: &str, q: &std::collections::HashMap<String, String>) {
    match network {
        "ws" => {
            let mut ws = Mapping::new();
            let path = q.get("path").map(|s| s.as_str()).unwrap_or("/");
            ins_str(&mut ws, "path", path);
            if let Some(host) = q.get("host").filter(|h| !h.is_empty()) {
                let mut headers = Mapping::new();
                ins_str(&mut headers, "Host", host.clone());
                ws.insert(Value::String("headers".into()), Value::Mapping(headers));
            }
            m.insert(Value::String("ws-opts".into()), Value::Mapping(ws));
        }
        "grpc" => {
            let mut grpc = Mapping::new();
            // vless/trojan 的 grpc serviceName 字段名为 serviceName；回退 path/host
            let svc = q
                .get("serviceName")
                .or_else(|| q.get("servicename"))
                .or_else(|| q.get("path"))
                .or_else(|| q.get("host"))
                .map(|s| s.as_str())
                .unwrap_or("");
            ins_str(&mut grpc, "grpc-service-name", svc);
            m.insert(Value::String("grpc-opts".into()), Value::Mapping(grpc));
        }
        _ => {}
    }
}

// ---------- ss ----------

/// 解析 `ss://`。两种形态:
/// - SIP002: `ss://base64url(method:password)@host:port?plugin=...#name`
/// - SIP022 / 明文: `ss://method:password@host:port#name`
///   (也有整体 base64 形态: `ss://base64(method:password@host:port)#name`)
fn parse_ss(uri: &str) -> Option<Mapping> {
    let rest = &uri[5..]; // 去掉 "ss://"

    // 拆出 fragment
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(f)),
        None => (rest, None),
    };

    // 拆出 query (?plugin=...)
    let (main, query) = match body.split_once('?') {
        Some((m, q)) => (m, Some(q)),
        None => (body, None),
    };

    // 形态判断：是否含 '@'
    let (userinfo, hostport) = if let Some((u, hp)) = main.rsplit_once('@') {
        // SIP002 / 明文带 @
        (u.to_string(), hp.to_string())
    } else {
        // 整体 base64: base64(method:password@host:port)
        let decoded = decode_b64_flex(main)?;
        let (u, hp) = decoded.rsplit_once('@')?;
        (u.to_string(), hp.to_string())
    };

    // userinfo 可能是 base64(method:password) 或明文 method:password
    let creds = if let Some((method, password)) = userinfo.split_once(':') {
        // 明文 (SIP022)
        (method.to_string(), password.to_string())
    } else {
        // base64url(method:password)
        let decoded = decode_b64_flex(&userinfo)?;
        let (method, password) = decoded.split_once(':')?;
        (method.to_string(), password.to_string())
    };
    let (method, password) = creds;
    if method.trim().is_empty() {
        return None;
    }

    // host:port (host 可能是 IPv6 [::1])
    let (host, port) = split_host_port(&hostport)?;
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name_from_fragment(fragment, &host, port));
    ins_str(&mut m, "type", "ss");
    ins_str(&mut m, "server", &host);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "cipher", &method);
    ins_str(&mut m, "password", &password);
    ins(&mut m, "udp", Value::Bool(true));

    // plugin (?plugin=obfs-local;obfs=http;obfs-host=...)
    if let Some(q) = query {
        let qmap = parse_query_str(q);
        if let Some(plugin_raw) = qmap.get("plugin").filter(|p| !p.is_empty()) {
            apply_ss_plugin(&mut m, plugin_raw);
        }
    }

    Some(m)
}

/// ss 的 plugin 串形如 `obfs-local;obfs=http;obfs-host=x.com` 或 `v2ray-plugin;mode=websocket;...`
fn apply_ss_plugin(m: &mut Mapping, plugin_raw: &str) {
    let decoded = pct_decode(plugin_raw);
    let mut parts = decoded.split(';');
    let plugin_name = match parts.next() {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return,
    };
    // mihomo 接受 obfs / v2ray-plugin / shadow-tls 等。obfs-local 归一为 "obfs"。
    let clash_plugin = match plugin_name.as_str() {
        "obfs-local" | "simple-obfs" => "obfs",
        other => other,
    };
    ins_str(m, "plugin", clash_plugin);

    let mut opts = Mapping::new();
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((k, v)) = part.split_once('=') {
            match k.trim() {
                "obfs" => ins_str(&mut opts, "mode", v.trim()),
                "obfs-host" => ins_str(&mut opts, "host", v.trim()),
                other => ins_str(&mut opts, other, v.trim()),
            }
        }
    }
    if !opts.is_empty() {
        m.insert(Value::String("plugin-opts".into()), Value::Mapping(opts));
    }
}

// ---------- vmess ----------

/// 解析 `vmess://base64(json)`。JSON 字段: v/ps/add/port/id/aid/scy/net/type/host/path/tls/sni/alpn/fp。
fn parse_vmess(uri: &str) -> Option<Mapping> {
    let b64 = &uri[8..]; // 去掉 "vmess://"
    // 可能含 fragment (少见)，先剥掉
    let b64 = b64.split('#').next().unwrap_or(b64);
    let decoded = decode_b64_flex(b64.trim())?;
    let json: serde_json::Value = serde_json::from_str(decoded.trim()).ok()?;
    let obj = json.as_object()?;

    let add = json_str(obj, "add")?;
    let port = json_port(obj, "port")?;
    let id = json_str(obj, "id")?;
    if add.trim().is_empty() || id.trim().is_empty() {
        return None;
    }

    let net = json_str(obj, "net").unwrap_or_else(|| "tcp".into());
    let net = if net.is_empty() { "tcp".to_string() } else { net };
    let tls_field = json_str(obj, "tls").unwrap_or_default();
    let host = json_str(obj, "host").unwrap_or_default();
    let sni = json_str(obj, "sni").unwrap_or_default();
    let path = json_str(obj, "path").unwrap_or_default();

    let ps = json_str(obj, "ps");
    let name = match ps {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => format!("{add}:{port}"),
    };

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name);
    ins_str(&mut m, "type", "vmess");
    ins_str(&mut m, "server", &add);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "uuid", &id);
    // alterId: aid 可能字符串/数字，默认 0
    let aid = json_port(obj, "aid").unwrap_or(0);
    ins(&mut m, "alterId", Value::Number(aid.into()));
    // cipher: scy 默认 auto
    let scy = json_str(obj, "scy").unwrap_or_default();
    let cipher = if scy.trim().is_empty() { "auto".to_string() } else { scy };
    ins_str(&mut m, "cipher", cipher);
    ins(&mut m, "udp", Value::Bool(true));
    ins_str(&mut m, "network", &net);

    let is_tls = tls_field == "tls" || tls_field == "reality";
    ins(&mut m, "tls", Value::Bool(is_tls));
    // servername: sni || host
    let servername = if !sni.is_empty() {
        sni.clone()
    } else {
        host.clone()
    };
    if is_tls && !servername.is_empty() {
        ins_str(&mut m, "servername", servername);
    }
    if let Some(fp) = json_str(obj, "fp").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "client-fingerprint", fp);
    }
    // alpn: 逗号分隔 → 数组
    if let Some(alpn) = json_str(obj, "alpn").filter(|s| !s.is_empty()) {
        let arr: Vec<Value> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect();
        if !arr.is_empty() {
            m.insert(Value::String("alpn".into()), Value::Sequence(arr));
        }
    }

    // transport
    match net.as_str() {
        "ws" => {
            let mut ws = Mapping::new();
            ins_str(&mut ws, "path", if path.is_empty() { "/".into() } else { path.clone() });
            if !host.is_empty() {
                let mut headers = Mapping::new();
                ins_str(&mut headers, "Host", host.clone());
                ws.insert(Value::String("headers".into()), Value::Mapping(headers));
            }
            m.insert(Value::String("ws-opts".into()), Value::Mapping(ws));
        }
        "grpc" => {
            let mut grpc = Mapping::new();
            let svc = if !path.is_empty() { path.clone() } else { host.clone() };
            ins_str(&mut grpc, "grpc-service-name", svc);
            m.insert(Value::String("grpc-opts".into()), Value::Mapping(grpc));
        }
        "h2" => {
            let mut h2 = Mapping::new();
            if !host.is_empty() {
                let hosts: Vec<Value> = host
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect();
                h2.insert(Value::String("host".into()), Value::Sequence(hosts));
            }
            if !path.is_empty() {
                ins_str(&mut h2, "path", path.clone());
            }
            if !h2.is_empty() {
                m.insert(Value::String("h2-opts".into()), Value::Mapping(h2));
            }
        }
        _ => {}
    }

    // reality (vmess 极少见，但按要求支持)
    if tls_field == "reality" {
        let mut reality = Mapping::new();
        if let Some(pbk) = json_str(obj, "pbk").filter(|s| !s.is_empty()) {
            ins_str(&mut reality, "public-key", pbk);
        }
        if let Some(sid) = json_str(obj, "sid") {
            ins_str(&mut reality, "short-id", sid);
        }
        if !reality.is_empty() {
            m.insert(Value::String("reality-opts".into()), Value::Mapping(reality));
        }
    }

    Some(m)
}

// ---------- vless ----------

/// 解析 `vless://uuid@host:port?...#name`。
fn parse_vless(uri: &str) -> Option<Mapping> {
    let u = Url::parse(uri).ok()?;
    let uuid = u.username();
    if uuid.is_empty() {
        return None;
    }
    let host = u.host_str()?.trim_matches(['[', ']']).to_string();
    let port = u.port()? as i64;
    if host.is_empty() {
        return None;
    }
    let q = collect_query(&u);

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name_from_fragment(u.fragment(), &host, port));
    ins_str(&mut m, "type", "vless");
    ins_str(&mut m, "server", &host);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "uuid", uuid);
    ins(&mut m, "udp", Value::Bool(true));

    if let Some(flow) = q.get("flow").filter(|f| !f.is_empty()) {
        ins_str(&mut m, "flow", flow.clone());
    }

    let network = q.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let network = if network.is_empty() { "tcp" } else { network };
    ins_str(&mut m, "network", network);

    let security = q.get("security").map(|s| s.as_str()).unwrap_or("");
    let is_tls = security == "tls" || security == "reality";
    ins(&mut m, "tls", Value::Bool(is_tls));

    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "servername", sni.clone());
    } else if let Some(host_q) = q.get("host").filter(|s| !s.is_empty()) {
        // 部分订阅把 sni 放 host
        if is_tls {
            ins_str(&mut m, "servername", host_q.clone());
        }
    }
    if let Some(fp) = q.get("fp").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "client-fingerprint", fp.clone());
    }
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        let arr: Vec<Value> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect();
        if !arr.is_empty() {
            m.insert(Value::String("alpn".into()), Value::Sequence(arr));
        }
    }

    // reality-opts (嵌套 mapping，不可扁平化)
    if security == "reality" {
        let mut reality = Mapping::new();
        if let Some(pbk) = q.get("pbk").filter(|s| !s.is_empty()) {
            ins_str(&mut reality, "public-key", pbk.clone());
        }
        if let Some(sid) = q.get("sid") {
            ins_str(&mut reality, "short-id", sid.clone());
        }
        if !reality.is_empty() {
            m.insert(Value::String("reality-opts".into()), Value::Mapping(reality));
        }
    }

    // transport (ws-opts / grpc-opts，嵌套 mapping)
    apply_transport(&mut m, network, &q);

    Some(m)
}

// ---------- trojan ----------

/// 解析 `trojan://password@host:port?...#name`。
fn parse_trojan(uri: &str) -> Option<Mapping> {
    let u = Url::parse(uri).ok()?;
    // password 在 userinfo，可能 percent-encoded
    let password = pct_decode(u.username());
    if password.is_empty() {
        return None;
    }
    let host = u.host_str()?.trim_matches(['[', ']']).to_string();
    let port = u.port()? as i64;
    if host.is_empty() {
        return None;
    }
    let q = collect_query(&u);

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name_from_fragment(u.fragment(), &host, port));
    ins_str(&mut m, "type", "trojan");
    ins_str(&mut m, "server", &host);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "password", password);
    ins(&mut m, "udp", Value::Bool(true));

    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "sni", sni.clone());
    } else if let Some(peer) = q.get("peer").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "sni", peer.clone());
    }
    // allowInsecure / insecure → skip-cert-verify
    let insecure = q
        .get("allowInsecure")
        .or_else(|| q.get("allowinsecure"))
        .or_else(|| q.get("insecure"))
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if insecure {
        ins(&mut m, "skip-cert-verify", Value::Bool(true));
    }
    if let Some(fp) = q.get("fp").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "client-fingerprint", fp.clone());
    }
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        let arr: Vec<Value> = alpn
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| Value::String(s.to_string()))
            .collect();
        if !arr.is_empty() {
            m.insert(Value::String("alpn".into()), Value::Sequence(arr));
        }
    }

    let network = q.get("type").map(|s| s.as_str()).unwrap_or("");
    if !network.is_empty() && network != "tcp" {
        ins_str(&mut m, "network", network);
        apply_transport(&mut m, network, &q);
    }

    // trojan over reality (有 pbk/sid)
    if q.get("security").map(|s| s.as_str()) == Some("reality")
        || q.contains_key("pbk")
    {
        let mut reality = Mapping::new();
        if let Some(pbk) = q.get("pbk").filter(|s| !s.is_empty()) {
            ins_str(&mut reality, "public-key", pbk.clone());
        }
        if let Some(sid) = q.get("sid") {
            ins_str(&mut reality, "short-id", sid.clone());
        }
        if !reality.is_empty() {
            m.insert(Value::String("reality-opts".into()), Value::Mapping(reality));
        }
    }

    Some(m)
}

// ---------- hysteria2 ----------

/// 解析 `hysteria2://auth@host:port?...#name` 或 `hy2://...`。
/// query: obfs / obfs-password / sni / insecure / pinSHA256。
fn parse_hysteria2(uri: &str) -> Option<Mapping> {
    let u = Url::parse(uri).ok()?;
    // auth 在 userinfo (可能 user 或 user:pass，统一取整段 userinfo 作 password)
    let auth = if u.password().is_some() {
        format!("{}:{}", u.username(), u.password().unwrap())
    } else {
        u.username().to_string()
    };
    let auth = pct_decode(&auth);
    let host = u.host_str()?.trim_matches(['[', ']']).to_string();
    let port = u.port().unwrap_or(443) as i64;
    if host.is_empty() {
        return None;
    }
    let q = collect_query(&u);

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name_from_fragment(u.fragment(), &host, port));
    ins_str(&mut m, "type", "hysteria2");
    ins_str(&mut m, "server", &host);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "password", auth);

    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "sni", sni.clone());
    }
    let insecure = q
        .get("insecure")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if insecure {
        ins(&mut m, "skip-cert-verify", Value::Bool(true));
    }
    // obfs: 仅 salamander
    if let Some(obfs) = q.get("obfs").filter(|s| !s.is_empty()) {
        // mihomo obfs 仅支持 salamander
        ins_str(&mut m, "obfs", obfs.clone());
        if let Some(opw) = q
            .get("obfs-password")
            .or_else(|| q.get("obfs_password"))
            .filter(|s| !s.is_empty())
        {
            ins_str(&mut m, "obfs-password", opw.clone());
        }
    }
    if let Some(pin) = q.get("pinSHA256").or_else(|| q.get("pinsha256")) {
        if !pin.is_empty() {
            ins_str(&mut m, "fingerprint", pin.clone());
        }
    }

    Some(m)
}

// ---------- host:port / query 工具 ----------

/// 拆 `host:port`，支持 IPv6 `[::1]:443`。
fn split_host_port(s: &str) -> Option<(String, i64)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // IPv6
        let (host, after) = rest.split_once(']')?;
        let port_str = after.strip_prefix(':')?;
        let port: i64 = port_str.trim().parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port_str) = s.rsplit_once(':')?;
    let port: i64 = port_str.trim().parse().ok()?;
    Some((host.to_string(), port))
}

/// 解析 raw query 串 (无前导 '?')，percent-decode value。供 ss 的 ?plugin= 用。
fn parse_query_str(q: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), pct_decode(v));
        } else {
            map.insert(pair.to_string(), String::new());
        }
    }
    map
}

// ---------- json 工具 (vmess) ----------

fn json_str(obj: &serde_json::Map<String, serde_json::Value>, k: &str) -> Option<String> {
    match obj.get(k) {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

/// port/aid 兼容字符串或数字。
fn json_port(obj: &serde_json::Map<String, serde_json::Value>, k: &str) -> Option<i64> {
    match obj.get(k) {
        Some(serde_json::Value::Number(n)) => n.as_i64(),
        Some(serde_json::Value::String(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s<'a>(m: &'a Mapping, k: &str) -> Option<&'a str> {
        m.get(Value::String(k.into())).and_then(|v| v.as_str())
    }
    fn i(m: &Mapping, k: &str) -> Option<i64> {
        m.get(Value::String(k.into())).and_then(|v| v.as_i64())
    }
    fn b(m: &Mapping, k: &str) -> Option<bool> {
        m.get(Value::String(k.into())).and_then(|v| v.as_bool())
    }
    fn nested<'a>(m: &'a Mapping, k: &str) -> Option<&'a Mapping> {
        m.get(Value::String(k.into())).and_then(|v| v.as_mapping())
    }

    // ---- ss ----
    #[test]
    fn ss_sip002_base64_userinfo() {
        // base64("aes-256-gcm:password") = YWVzLTI1Ni1nY206cGFzc3dvcmQ=
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#My%20Node";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("ss"));
        assert_eq!(s(&m, "server"), Some("1.2.3.4"));
        assert_eq!(i(&m, "port"), Some(8388));
        assert_eq!(s(&m, "cipher"), Some("aes-256-gcm"));
        assert_eq!(s(&m, "password"), Some("password"));
        assert_eq!(s(&m, "name"), Some("My Node"));
        assert_eq!(b(&m, "udp"), Some(true));
    }

    #[test]
    fn ss_sip022_plaintext() {
        // 明文 method:password (2022 系列常见明文形态)
        let uri = "ss://2022-blake3-aes-256-gcm:Sm+passwd@example.com:443#plain";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "cipher"), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(s(&m, "password"), Some("Sm+passwd"));
        assert_eq!(s(&m, "server"), Some("example.com"));
        assert_eq!(i(&m, "port"), Some(443));
    }

    #[test]
    fn ss_with_obfs_plugin() {
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#p";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "plugin"), Some("obfs"));
        let po = nested(&m, "plugin-opts").unwrap();
        assert_eq!(s(po, "mode"), Some("http"));
        assert_eq!(s(po, "host"), Some("www.bing.com"));
    }

    // ---- vmess ----
    #[test]
    fn vmess_ws_tls() {
        use base64::Engine;
        let json = r#"{"v":"2","ps":"vm-node","add":"a.example.com","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"a.example.com","path":"/ray","tls":"tls","sni":"a.example.com"}"#;
        let uri = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        let m = parse_vmess(&uri).unwrap();
        assert_eq!(s(&m, "type"), Some("vmess"));
        assert_eq!(s(&m, "server"), Some("a.example.com"));
        assert_eq!(i(&m, "port"), Some(443));
        assert_eq!(s(&m, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(i(&m, "alterId"), Some(0));
        assert_eq!(s(&m, "cipher"), Some("auto"));
        assert_eq!(s(&m, "network"), Some("ws"));
        assert_eq!(b(&m, "tls"), Some(true));
        assert_eq!(s(&m, "servername"), Some("a.example.com"));
        let ws = nested(&m, "ws-opts").unwrap();
        assert_eq!(s(ws, "path"), Some("/ray"));
        let headers = nested(ws, "headers").unwrap();
        assert_eq!(s(headers, "Host"), Some("a.example.com"));
    }

    #[test]
    fn vmess_numeric_port_and_aid() {
        use base64::Engine;
        // port/aid 为数字而非字符串
        let json = r#"{"v":2,"ps":"n","add":"1.1.1.1","port":8080,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":2,"net":"tcp","tls":""}"#;
        let uri = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        let m = parse_vmess(&uri).unwrap();
        assert_eq!(i(&m, "port"), Some(8080));
        assert_eq!(i(&m, "alterId"), Some(2));
        assert_eq!(b(&m, "tls"), Some(false));
    }

    // ---- vless + reality ----
    #[test]
    fn vless_reality_grpc() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=ABCDEF_publickey&sid=0123&type=grpc&serviceName=mygrpc#reality-node";
        let m = parse_vless(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("vless"));
        assert_eq!(s(&m, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(i(&m, "port"), Some(443));
        assert_eq!(s(&m, "flow"), Some("xtls-rprx-vision"));
        assert_eq!(b(&m, "tls"), Some(true));
        assert_eq!(s(&m, "servername"), Some("www.microsoft.com"));
        assert_eq!(s(&m, "client-fingerprint"), Some("chrome"));
        assert_eq!(s(&m, "network"), Some("grpc"));
        // 嵌套 reality-opts
        let r = nested(&m, "reality-opts").unwrap();
        assert_eq!(s(r, "public-key"), Some("ABCDEF_publickey"));
        assert_eq!(s(r, "short-id"), Some("0123"));
        // 嵌套 grpc-opts
        let g = nested(&m, "grpc-opts").unwrap();
        assert_eq!(s(g, "grpc-service-name"), Some("mygrpc"));
        assert_eq!(s(&m, "name"), Some("reality-node"));
    }

    #[test]
    fn vless_ws_tls() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.com:443?encryption=none&security=tls&type=ws&host=h.com&path=%2Fws&sni=h.com#vl-ws";
        let m = parse_vless(uri).unwrap();
        assert_eq!(s(&m, "network"), Some("ws"));
        assert_eq!(b(&m, "tls"), Some(true));
        let ws = nested(&m, "ws-opts").unwrap();
        assert_eq!(s(ws, "path"), Some("/ws"));
        let headers = nested(ws, "headers").unwrap();
        assert_eq!(s(headers, "Host"), Some("h.com"));
    }

    // ---- trojan ----
    #[test]
    fn trojan_basic() {
        let uri = "trojan://my%40pass@example.com:443?sni=example.com&allowInsecure=1&type=ws&host=example.com&path=%2Ftj#trojan-node";
        let m = parse_trojan(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("trojan"));
        assert_eq!(s(&m, "password"), Some("my@pass"));
        assert_eq!(s(&m, "server"), Some("example.com"));
        assert_eq!(i(&m, "port"), Some(443));
        assert_eq!(s(&m, "sni"), Some("example.com"));
        assert_eq!(b(&m, "skip-cert-verify"), Some(true));
        assert_eq!(s(&m, "network"), Some("ws"));
        let ws = nested(&m, "ws-opts").unwrap();
        assert_eq!(s(ws, "path"), Some("/tj"));
    }

    // ---- hysteria2 ----
    #[test]
    fn hysteria2_with_obfs() {
        let uri = "hysteria2://mypassword@1.2.3.4:8443?sni=example.com&insecure=1&obfs=salamander&obfs-password=ob_pw#hy2-node";
        let m = parse_hysteria2(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("hysteria2"));
        assert_eq!(s(&m, "password"), Some("mypassword"));
        assert_eq!(s(&m, "server"), Some("1.2.3.4"));
        assert_eq!(i(&m, "port"), Some(8443));
        assert_eq!(s(&m, "sni"), Some("example.com"));
        assert_eq!(b(&m, "skip-cert-verify"), Some(true));
        assert_eq!(s(&m, "obfs"), Some("salamander"));
        assert_eq!(s(&m, "obfs-password"), Some("ob_pw"));
    }

    #[test]
    fn hy2_alias_scheme() {
        let uri = "hy2://pw@host.net:443#h";
        let m = parse_hysteria2(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("hysteria2"));
        assert_eq!(s(&m, "server"), Some("host.net"));
        assert_eq!(i(&m, "port"), Some(443));
        assert_eq!(s(&m, "password"), Some("pw"));
    }

    // ---- 列表 / 容错 ----
    #[test]
    fn unknown_scheme_skipped_silently() {
        let raw = "ssr://garbage\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ok\ngarbageline";
        let ps = parse_lines(raw);
        assert_eq!(ps.len(), 1);
        assert_eq!(s(&ps[0], "type"), Some("ss"));
    }

    #[test]
    fn duplicate_names_deduped() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#dup\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@5.6.7.8:8388#dup";
        let ps = parse_lines(raw);
        assert_eq!(ps.len(), 2);
        assert_eq!(s(&ps[0], "name"), Some("dup"));
        assert_eq!(s(&ps[1], "name"), Some("dup-2"));
    }

    #[test]
    fn no_fragment_uses_server_port_fallback() {
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "name"), Some("1.2.3.4:8388"));
    }
}
