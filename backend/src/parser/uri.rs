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
    "ssr://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "tuic://",
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

/// 逐行解析裸 URI → proxy Mapping 列表。
///
/// 返回 `(proxies, failed)`。`failed` = "以已知 scheme 开头但解析失败" 的行数;
/// 非已知 scheme 的行 (未知协议/垃圾行) 继续静默跳过, 不计入 failed。
pub fn parse_lines(raw: &str) -> (Vec<Mapping>, usize) {
    let mut out = Vec::new();
    let mut failed = 0usize;
    let mut seen_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_one(line) {
            Some(mut m) => {
                // 名称去重 (Clash 节点名必须唯一，否则后续 dialer/group 引用混乱)
                dedup_name(&mut m, &mut seen_names);
                out.push(m);
            }
            None => {
                // 已知 scheme 却解析失败 → 计入 failed (疑似上游格式不兼容);
                // 非已知 scheme 的行静默跳过。
                if is_known_scheme(line) {
                    failed += 1;
                }
            }
        }
    }
    (out, failed)
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

/// 解析单个 URI 行 → proxy Mapping (公开包装, 供 render 层逆向序列化往返测试 / 复用)。
/// 识别失败 (含不支持的 scheme) 返回 None。
pub fn parse_line_pub(uri: &str) -> Option<Mapping> {
    parse_one(uri.trim())
}

/// 解析单个 URI。识别失败 (含不支持的 scheme) 返回 None。
fn parse_one(uri: &str) -> Option<Mapping> {
    let lower = uri.to_ascii_lowercase();
    // ssr:// 必须在 ss:// 之前判 (虽然 "ssr://".starts_with("ss://") 为 false, 保持显式更稳)
    if lower.starts_with("ssr://") {
        parse_ssr(uri)
    } else if lower.starts_with("ss://") {
        parse_ss(uri)
    } else if lower.starts_with("vmess://") {
        parse_vmess(uri)
    } else if lower.starts_with("vless://") {
        parse_vless(uri)
    } else if lower.starts_with("trojan://") {
        parse_trojan(uri)
    } else if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        parse_hysteria2(uri)
    } else if lower.starts_with("tuic://") {
        parse_tuic(uri)
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
        "h2" | "http" => {
            // h2/http transport → h2-opts: { path, host:[...] }。镜像 parse_vmess 的 h2 处理:
            // path 为字符串; host 按逗号 split 成 sequence。
            let mut h2 = Mapping::new();
            if let Some(host) = q.get("host").filter(|h| !h.is_empty()) {
                let hosts: Vec<Value> = host
                    .split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| Value::String(s.to_string()))
                    .collect();
                if !hosts.is_empty() {
                    h2.insert(Value::String("host".into()), Value::Sequence(hosts));
                }
            }
            if let Some(path) = q.get("path").filter(|p| !p.is_empty()) {
                ins_str(&mut h2, "path", path.clone());
            }
            if !h2.is_empty() {
                m.insert(Value::String("h2-opts".into()), Value::Mapping(h2));
            }
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
        // 明文 (SIP022)。password 可能含 %XX, 需 percent-decode。
        (method.to_string(), pct_decode(password))
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
        } else {
            // 裸 flag (如 v2ray-plugin 的 tls / mux) → bool true
            ins(&mut opts, part, Value::Bool(true));
        }
    }
    if !opts.is_empty() {
        m.insert(Value::String("plugin-opts".into()), Value::Mapping(opts));
    }
}

// ---------- ssr ----------

/// 解析 `ssr://` + 整体 URL-safe base64 (双层 base64)。
///
/// 外层解码后形如:
/// `host:port:protocol:method:obfs:base64url(password)/?obfsparam=..&protoparam=..&remarks=..&group=..`
/// 左半 (`/?` 之前) 按 `:` 切 6 段; 右半是 query, 其中 obfsparam/protoparam/remarks 的值也是 base64url。
/// password 段同样是 base64url, 故内层共有 4 处需再解一次 base64。
fn parse_ssr(uri: &str) -> Option<Mapping> {
    let rest = &uri[6..]; // 去掉 "ssr://"
    // 外层: 整体 URL-safe base64 (无 padding), 复用 decode_b64_flex 容错
    let decoded = decode_b64_flex(rest.trim())?;

    // 按第一个 "/?" 切左右; 兼容只有 "?" 或省略 "/" 的情况
    let (left, query) = if let Some(idx) = decoded.find("/?") {
        (&decoded[..idx], Some(&decoded[idx + 2..]))
    } else if let Some(idx) = decoded.find('?') {
        (&decoded[..idx], Some(&decoded[idx + 1..]))
    } else {
        // 去掉可能的尾部 '/'
        (decoded.trim_end_matches('/'), None)
    };

    // 左半按 ':' 切 6 段: host : port : protocol : method : obfs : base64url(password)
    // host 可能是 IPv6 (无方括号), 但 SSR 规范里 IPv6 也是裸 ':' 分隔的固定 6 段,
    // 故从右往左切 5 次, 剩下的全归 host。
    let parts: Vec<&str> = left.rsplitn(6, ':').collect();
    if parts.len() != 6 {
        return None;
    }
    // rsplitn 返回逆序: [password_b64, obfs, method, protocol, port, host]
    let password_b64 = parts[0];
    let obfs = parts[1];
    let method = parts[2];
    let protocol = parts[3];
    let port_str = parts[4];
    let host = parts[5];

    let port: i64 = port_str.trim().parse().ok()?;
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    // 与 validate_proxy_yaml 的 SSR 必填项对齐: cipher(method)/protocol/obfs 三者非空,
    // 否则是畸形节点(空 obfs/protocol 不在白名单), mihomo 静默连不上。归 None → 计入 failed → 走整体保护。
    if method.trim().is_empty() || protocol.trim().is_empty() || obfs.trim().is_empty() {
        return None;
    }

    // 内层: password 是 base64url, 再解一次
    let password = decode_b64_flex(password_b64.trim())?;
    // SSR password 空 = 畸形节点, 拒绝 (与 vmess 拒空 id / trojan 拒空 password 一致)。
    if password.trim().is_empty() {
        return None;
    }

    // query 里 obfsparam / protoparam / remarks 的值也是 base64url, 各自再解码
    let qmap = query.map(parse_query_str_raw).unwrap_or_default();
    let obfsparam = qmap
        .get("obfsparam")
        .and_then(|v| decode_b64_flex(v))
        .unwrap_or_default();
    let protoparam = qmap
        .get("protoparam")
        .and_then(|v| decode_b64_flex(v))
        .unwrap_or_default();
    let remarks = qmap
        .get("remarks")
        .and_then(|v| decode_b64_flex(v))
        .unwrap_or_default();

    let name = if remarks.trim().is_empty() {
        format!("{host}:{port}")
    } else {
        remarks.trim().to_string()
    };

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name);
    ins_str(&mut m, "type", "ssr");
    ins_str(&mut m, "server", host);
    ins(&mut m, "port", Value::Number(port.into()));
    ins_str(&mut m, "cipher", method);
    ins_str(&mut m, "password", password);
    ins_str(&mut m, "protocol", protocol);
    if !protoparam.is_empty() {
        ins_str(&mut m, "protocol-param", protoparam);
    }
    ins_str(&mut m, "obfs", obfs);
    if !obfsparam.is_empty() {
        ins_str(&mut m, "obfs-param", obfsparam);
    }
    ins(&mut m, "udp", Value::Bool(true));

    Some(m)
}

/// 解析 SSR query 串 (无前导 '?'), value **不** percent-decode (SSR 的 param 是 base64url, 交给调用方再解)。
fn parse_query_str_raw(q: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        } else {
            map.insert(pair.to_string(), String::new());
        }
    }
    map
}

// ---------- tuic ----------

/// 解析 `tuic://uuid:password@host:port?params#name` (主做 v5)。
///
/// userinfo 含 ':' → `uuid:password` (都 percent-decode); 不含 ':' → v4 token 形态, 映射 `token`。
/// query 用下划线 (congestion_control / udp_relay_mode), Clash YAML 用连字符。
fn parse_tuic(uri: &str) -> Option<Mapping> {
    let u = Url::parse(uri).ok()?;
    let host = u.host_str()?.trim_matches(['[', ']']).to_string();
    let port = u.port()? as i64;
    if host.is_empty() || !(1..=65535).contains(&port) {
        return None;
    }
    let q = collect_query(&u);

    let mut m = Mapping::new();
    ins_str(&mut m, "name", name_from_fragment(u.fragment(), &host, port));
    ins_str(&mut m, "type", "tuic");
    ins_str(&mut m, "server", &host);
    ins(&mut m, "port", Value::Number(port.into()));

    // userinfo: url crate 已把 username/password 拆好。
    // v5: uuid:password (有 password 段); v4: 只有 username = token。
    let username = pct_decode(u.username());
    match u.password() {
        Some(pw) => {
            // v5: uuid + password (都 percent-decode)
            ins_str(&mut m, "uuid", username);
            ins_str(&mut m, "password", pct_decode(pw));
        }
        None => {
            // v4 token 形态: 映射 token; 空 username = 既无 uuid 又无 token 的废节点, 拒绝
            if username.trim().is_empty() {
                return None;
            }
            ins_str(&mut m, "token", username);
        }
    }

    if let Some(sni) = q.get("sni").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "sni", sni.clone());
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
    if let Some(cc) = q.get("congestion_control").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "congestion-controller", cc.clone());
    }
    if let Some(urm) = q.get("udp_relay_mode").filter(|s| !s.is_empty()) {
        ins_str(&mut m, "udp-relay-mode", urm.clone());
    }
    if let Some(disable_sni) = q.get("disable_sni") {
        let b = disable_sni == "1" || disable_sni.eq_ignore_ascii_case("true");
        ins(&mut m, "disable-sni", Value::Bool(b));
    }
    if let Some(allow_insecure) = q.get("allow_insecure") {
        let b = allow_insecure == "1" || allow_insecure.eq_ignore_ascii_case("true");
        ins(&mut m, "skip-cert-verify", Value::Bool(b));
    }
    if let Some(reduce_rtt) = q.get("reduce_rtt") {
        let b = reduce_rtt == "1" || reduce_rtt.eq_ignore_ascii_case("true");
        ins(&mut m, "reduce-rtt", Value::Bool(b));
    }
    ins(&mut m, "udp", Value::Bool(true));

    Some(m)
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
    if add.trim().is_empty() || id.trim().is_empty() || !(1..=65535).contains(&port) {
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
    fn ss_sip022_password_percent_decoded() {
        // SIP022 明文 password 含 %XX (p%40ss → p@ss)
        let uri = "ss://2022-blake3-aes-256-gcm:p%40ss@h.example.com:443#enc";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "cipher"), Some("2022-blake3-aes-256-gcm"));
        assert_eq!(s(&m, "password"), Some("p@ss"));
        assert_eq!(s(&m, "server"), Some("h.example.com"));
        assert_eq!(i(&m, "port"), Some(443));
    }

    #[test]
    fn ss_v2ray_plugin_bare_tls_flag() {
        // v2ray-plugin 的裸 flag tls / mux 应转成 plugin-opts.tls=true / mux=true
        let uri = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Btls%3Bhost%3Dx.com#p";
        let m = parse_ss(uri).unwrap();
        assert_eq!(s(&m, "plugin"), Some("v2ray-plugin"));
        let po = nested(&m, "plugin-opts").unwrap();
        assert_eq!(b(po, "tls"), Some(true));
        assert_eq!(s(po, "mode"), Some("websocket"));
        assert_eq!(s(po, "host"), Some("x.com"));
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

    #[test]
    fn vmess_port_out_of_range_rejected() {
        use base64::Engine;
        // port=70000 越界 → parse_vmess 返回 None
        let json = r#"{"v":"2","ps":"n","add":"1.1.1.1","port":70000,"id":"b831381d-6324-4d53-ad4f-8cda48b30811","net":"tcp"}"#;
        let uri = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json));
        assert!(parse_vmess(&uri).is_none());
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

    #[test]
    fn vless_h2_parses_h2_opts() {
        // h2 transport: 正向解析应构造 h2-opts { path, host:[...] }。
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.com:443?encryption=none&security=tls&type=h2&host=a.com,b.com&path=%2Fh2&sni=h.com#vl-h2";
        let m = parse_vless(uri).unwrap();
        assert_eq!(s(&m, "network"), Some("h2"));
        let h2 = nested(&m, "h2-opts").unwrap();
        assert_eq!(s(h2, "path"), Some("/h2"));
        let hosts = h2
            .get(Value::String("host".into()))
            .and_then(|v| v.as_sequence())
            .unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].as_str(), Some("a.com"));
        assert_eq!(hosts[1].as_str(), Some("b.com"));
    }

    #[test]
    fn vless_h2_roundtrip_preserves_path_host() {
        // URI → mapping → URI → mapping: h2 的 path / host 应在往返后保留。
        use crate::generator::render::uri_encode::proxy_to_uri;
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h.com:443?encryption=none&security=tls&type=h2&host=a.com&path=%2Fh2&sni=h.com#vl-h2";
        let m1 = parse_vless(uri).unwrap();
        let back = proxy_to_uri(&m1).unwrap();
        let m2 = parse_vless(&back).unwrap();
        assert_eq!(s(&m2, "network"), Some("h2"));
        let h2 = nested(&m2, "h2-opts").unwrap();
        assert_eq!(s(h2, "path"), Some("/h2"));
        let hosts = h2
            .get(Value::String("host".into()))
            .and_then(|v| v.as_sequence())
            .unwrap();
        assert_eq!(hosts[0].as_str(), Some("a.com"));
    }

    #[test]
    fn trojan_h2_parses_h2_opts() {
        // trojan h2 transport 同样应构造 h2-opts。
        let uri = "trojan://pw@h.com:443?sni=h.com&type=h2&host=c.com&path=%2Ft#tj-h2";
        let m = parse_trojan(uri).unwrap();
        assert_eq!(s(&m, "network"), Some("h2"));
        let h2 = nested(&m, "h2-opts").unwrap();
        assert_eq!(s(h2, "path"), Some("/t"));
        let hosts = h2
            .get(Value::String("host".into()))
            .and_then(|v| v.as_sequence())
            .unwrap();
        assert_eq!(hosts[0].as_str(), Some("c.com"));
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

    // ---- ssr ----
    #[test]
    fn ssr_double_base64_full() {
        // 外层 ssr:// + 整体 url-safe base64; 内层 password / obfsparam / protoparam / remarks 各自再 base64url。
        // method=aes-256-cfb obfs=plain protocol=origin 均在 validate 白名单内。
        let uri = "ssr://MS4yLjMuNDo4Mzg4Om9yaWdpbjphZXMtMjU2LWNmYjpwbGFpbjpiWGx3WVhOek1USXovP29iZnNwYXJhbT1iMkptYzJodmMzUXVZMjl0JnByb3RvcGFyYW09Y0hKdmRHOTJZV3cmcmVtYXJrcz1VMU5TSUU1dlpHVQ";
        let m = parse_ssr(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("ssr"));
        assert_eq!(s(&m, "server"), Some("1.2.3.4"));
        assert_eq!(i(&m, "port"), Some(8388));
        assert_eq!(s(&m, "cipher"), Some("aes-256-cfb"));
        assert_eq!(s(&m, "protocol"), Some("origin"));
        assert_eq!(s(&m, "obfs"), Some("plain"));
        // 内层 base64 解出: password=mypass123, obfsparam=obfshost.com, protoparam=protoval, remarks=SSR Node
        assert_eq!(s(&m, "password"), Some("mypass123"));
        assert_eq!(s(&m, "obfs-param"), Some("obfshost.com"));
        assert_eq!(s(&m, "protocol-param"), Some("protoval"));
        assert_eq!(s(&m, "name"), Some("SSR Node"));
        assert_eq!(b(&m, "udp"), Some(true));
        // 必须通过真实 validate_proxy_yaml
        let yaml = serde_yaml::to_string(&Value::Mapping(m)).unwrap();
        crate::exit_node::service::validate_proxy_yaml(&yaml).unwrap();
    }

    // ---- tuic ----
    #[test]
    fn tuic_v5_full() {
        let uri = "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pass@host.example.com:443?sni=x.example.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3#t-node";
        let m = parse_tuic(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("tuic"));
        assert_eq!(s(&m, "server"), Some("host.example.com"));
        assert_eq!(i(&m, "port"), Some(443));
        assert_eq!(s(&m, "uuid"), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!(s(&m, "password"), Some("pass"));
        assert_eq!(s(&m, "sni"), Some("x.example.com"));
        assert_eq!(s(&m, "congestion-controller"), Some("bbr"));
        assert_eq!(s(&m, "udp-relay-mode"), Some("native"));
        assert_eq!(s(&m, "name"), Some("t-node"));
        let alpn = m.get(Value::String("alpn".into())).and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(alpn.len(), 1);
        assert_eq!(alpn[0].as_str(), Some("h3"));
        assert_eq!(b(&m, "udp"), Some(true));
        // 必须通过真实 validate_proxy_yaml (uuid 36 位 + password 非空)
        let yaml = serde_yaml::to_string(&Value::Mapping(m)).unwrap();
        crate::exit_node::service::validate_proxy_yaml(&yaml).unwrap();
    }

    #[test]
    fn tuic_v4_token_form() {
        // v4: userinfo 不含 ':' → 映射 token, 不设 uuid/password
        let uri = "tuic://sometoken@1.2.3.4:443?sni=x#v4";
        let m = parse_tuic(uri).unwrap();
        assert_eq!(s(&m, "type"), Some("tuic"));
        assert_eq!(s(&m, "token"), Some("sometoken"));
        assert!(m.get(Value::String("uuid".into())).is_none());
        assert!(m.get(Value::String("password".into())).is_none());
    }

    // ---- 列表 / 容错 ----
    #[test]
    fn unknown_scheme_skipped_silently() {
        // 注意: ssr:// 现已是已知 scheme, 这里换成真正未知的 wireguard:// 与裸 garbage 行。
        let raw = "wireguard://garbage\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#ok\ngarbageline";
        let (ps, failed) = parse_lines(raw);
        assert_eq!(ps.len(), 1);
        // wireguard:// / garbageline 都不是已知 scheme → 不计 failed
        assert_eq!(failed, 0);
        assert_eq!(s(&ps[0], "type"), Some("ss"));
    }

    #[test]
    fn duplicate_names_deduped() {
        let raw = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@1.2.3.4:8388#dup\nss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@5.6.7.8:8388#dup";
        let (ps, _failed) = parse_lines(raw);
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

    // ---- ssr/tuic 负向边界 (对抗审查建议固化) ----
    fn ssr_b64(inner: &str) -> String {
        use base64::Engine;
        format!(
            "ssr://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(inner)
        )
    }

    #[test]
    fn ssr_rejects_malformed() {
        use base64::Engine;
        let pw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("pw");
        // 段数 < 6
        assert!(parse_ssr(&ssr_b64("1.2.3.4:8388:origin")).is_none());
        // port 越界
        assert!(parse_ssr(&ssr_b64(&format!("1.2.3.4:70000:origin:aes-256-cfb:plain:{pw}"))).is_none());
        // protocol 空
        assert!(parse_ssr(&ssr_b64(&format!("1.2.3.4:8388::aes-256-cfb:plain:{pw}"))).is_none());
        // obfs 空
        assert!(parse_ssr(&ssr_b64(&format!("1.2.3.4:8388:origin:aes-256-cfb::{pw}"))).is_none());
        // password 空 (末段 base64 为空串)
        assert!(parse_ssr(&ssr_b64("1.2.3.4:8388:origin:aes-256-cfb:plain:")).is_none());
        // 合法对照: 全部就位则正常解析
        let ok = parse_ssr(&ssr_b64(&format!("1.2.3.4:8388:origin:aes-256-cfb:plain:{pw}"))).unwrap();
        assert_eq!(s(&ok, "type"), Some("ssr"));
        assert_eq!(s(&ok, "password"), Some("pw"));
        assert_eq!(s(&ok, "cipher"), Some("aes-256-cfb"));
        assert_eq!(s(&ok, "protocol"), Some("origin"));
        assert_eq!(s(&ok, "obfs"), Some("plain"));
    }

    #[test]
    fn tuic_empty_username_rejected() {
        // v4 空 username: 既无 uuid 又无 token 的废节点应拒
        assert!(parse_tuic("tuic://@host.net:443?sni=x#t").is_none());
    }
}
