// 固定出口节点的协议定义 + 表单 <-> YAML 互转 + 校验
import YAML from "yaml";

export type ProxyType =
  | "trojan"
  | "ss"
  | "vmess"
  | "vless"
  | "hysteria2"
  | "hysteria"
  | "tuic"
  | "snell"
  | "ssr"
  | "wireguard"
  | "anytls"
  | "socks5"
  | "http";

export const PROXY_TYPES: { value: ProxyType; label: string }[] = [
  { value: "trojan", label: "Trojan" },
  { value: "ss", label: "Shadowsocks" },
  { value: "ssr", label: "ShadowsocksR" },
  { value: "vmess", label: "VMess" },
  { value: "vless", label: "VLESS" },
  { value: "hysteria2", label: "Hysteria2" },
  { value: "hysteria", label: "Hysteria v1" },
  { value: "tuic", label: "TUIC" },
  { value: "snell", label: "Snell" },
  { value: "wireguard", label: "WireGuard" },
  { value: "anytls", label: "AnyTLS" },
  { value: "socks5", label: "SOCKS5" },
  { value: "http", label: "HTTP" },
];

export const SS_CIPHERS = [
  "aes-128-gcm",
  "aes-256-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
  "none",
] as const;

export const SSR_CIPHERS = [
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
] as const;

export const SSR_OBFS = [
  "plain",
  "http_simple",
  "http_post",
  "random_head",
  "tls1.2_ticket_auth",
  "tls1.2_ticket_fastauth",
] as const;

export const SSR_PROTOCOLS = [
  "origin",
  "verify_sha1",
  "auth_sha1_v4",
  "auth_aes128_md5",
  "auth_aes128_sha1",
  "auth_chain_a",
  "auth_chain_b",
] as const;

export const VMESS_CIPHERS = ["auto", "aes-128-gcm", "chacha20-poly1305", "none"] as const;
export const NETWORK_TYPES = ["tcp", "ws", "grpc", "h2"] as const;

export const TUIC_CC = ["bbr", "cubic", "new_reno"] as const;
export const TUIC_UDP_MODES = ["native", "quic"] as const;

export const HYSTERIA_PROTOCOLS = ["udp", "wechat-video", "faketcp"] as const;

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** 表单数据 — 宽 union, 字段按 type 不同有取舍 */
export interface ProxyForm {
  // 公共
  name: string;
  type: ProxyType;
  server: string;
  port: number | "";
  udp?: boolean;

  // TLS 系
  sni?: string;
  "skip-cert-verify"?: boolean;
  servername?: string;
  tls?: boolean;
  "client-fingerprint"?: string;

  // auth
  password?: string;
  username?: string;
  uuid?: string;

  // ss / ssr / vmess cipher 共用
  cipher?: string;

  // ssr
  obfs?: string;
  protocol?: string;
  "obfs-param"?: string;
  "protocol-param"?: string;

  // vmess
  alterId?: number | "";
  network?: string;

  // vless
  flow?: string;

  // hysteria(2)
  up?: string;
  down?: string;
  "auth-str"?: string; // hysteria v1

  // tuic
  "congestion-controller"?: string;
  "udp-relay-mode"?: string;
  version?: number | ""; // tuic / snell 共用
  "disable-sni"?: boolean;

  // snell
  psk?: string;

  // wireguard
  "private-key"?: string;
  "public-key"?: string;
  "preshared-key"?: string;
  ip?: string;
  ipv6?: string;
  mtu?: number | "";
}

export function emptyForm(type: ProxyType = "trojan"): ProxyForm {
  const base: ProxyForm = {
    name: "",
    type,
    server: "",
    port: 443,
    udp: true,
  };
  switch (type) {
    case "trojan":
      return { ...base, password: "", sni: "", "skip-cert-verify": false };
    case "ss":
      return { ...base, cipher: "aes-128-gcm", password: "" };
    case "ssr":
      return {
        ...base,
        cipher: "aes-256-cfb",
        password: "",
        obfs: "plain",
        protocol: "origin",
        "obfs-param": "",
        "protocol-param": "",
      };
    case "vmess":
      return {
        ...base,
        uuid: "",
        alterId: 0,
        cipher: "auto",
        network: "tcp",
        tls: false,
      };
    case "vless":
      return {
        ...base,
        uuid: "",
        network: "tcp",
        tls: false,
        servername: "",
        flow: "",
      };
    case "hysteria2":
      return {
        ...base,
        password: "",
        sni: "",
        "skip-cert-verify": false,
        up: "",
        down: "",
      };
    case "hysteria":
      return {
        ...base,
        "auth-str": "",
        up: "30",
        down: "200",
        sni: "",
        "skip-cert-verify": false,
        obfs: "",
        protocol: "udp",
      };
    case "tuic":
      return {
        ...base,
        uuid: "",
        password: "",
        sni: "",
        "skip-cert-verify": false,
        "congestion-controller": "bbr",
        "udp-relay-mode": "native",
        version: 5,
        "disable-sni": false,
      };
    case "snell":
      return { ...base, psk: "", version: 4 };
    case "wireguard":
      // wireguard 默认端口 51820
      return {
        ...base,
        port: 51820,
        "private-key": "",
        "public-key": "",
        "preshared-key": "",
        ip: "",
        ipv6: "",
        mtu: 1280,
      };
    case "anytls":
      return {
        ...base,
        password: "",
        sni: "",
        "skip-cert-verify": false,
        "client-fingerprint": "chrome",
      };
    case "socks5":
      return {
        ...base,
        port: 1080,
        username: "",
        password: "",
        tls: false,
        "skip-cert-verify": false,
      };
    case "http":
      return {
        ...base,
        port: 8080,
        udp: false,
        username: "",
        password: "",
        tls: false,
        "skip-cert-verify": false,
      };
  }
}

/** 表单 -> 简单 JS 对象 (再 YAML.stringify 出去) */
export function formToObject(f: ProxyForm): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: f.name,
    type: f.type,
    server: f.server,
    port: typeof f.port === "number" ? f.port : Number(f.port) || 0,
  };
  const putIf = (k: string, v: unknown) => {
    if (v !== undefined && v !== "" && v !== null) out[k] = v;
  };
  const putBoolIf = (k: string, v: boolean | undefined) => {
    if (v) out[k] = true;
  };

  switch (f.type) {
    case "trojan":
      putIf("password", f.password);
      putIf("sni", f.sni);
      putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      putBoolIf("udp", f.udp);
      break;
    case "ss":
      putIf("cipher", f.cipher);
      putIf("password", f.password);
      putBoolIf("udp", f.udp);
      break;
    case "ssr":
      putIf("cipher", f.cipher);
      putIf("password", f.password);
      putIf("obfs", f.obfs);
      putIf("protocol", f.protocol);
      putIf("obfs-param", f["obfs-param"]);
      putIf("protocol-param", f["protocol-param"]);
      putBoolIf("udp", f.udp);
      break;
    case "vmess":
      putIf("uuid", f.uuid);
      out.alterId = typeof f.alterId === "number" ? f.alterId : Number(f.alterId) || 0;
      putIf("cipher", f.cipher);
      if (f.network && f.network !== "tcp") out.network = f.network;
      if (f.tls) {
        out.tls = true;
        putIf("servername", f.servername);
        putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      }
      putBoolIf("udp", f.udp);
      break;
    case "vless":
      putIf("uuid", f.uuid);
      if (f.network && f.network !== "tcp") out.network = f.network;
      putIf("flow", f.flow);
      if (f.tls) {
        out.tls = true;
        putIf("servername", f.servername);
        putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      }
      putBoolIf("udp", f.udp);
      break;
    case "hysteria2":
      putIf("password", f.password);
      putIf("sni", f.sni);
      putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      putIf("up", f.up);
      putIf("down", f.down);
      break;
    case "hysteria":
      // mihomo 字段名是 auth_str (下划线), 输出时映射
      putIf("auth_str", f["auth-str"]);
      // up/down 数字 (Mbps)
      if (f.up) out.up = Number(f.up) || f.up;
      if (f.down) out.down = Number(f.down) || f.down;
      putIf("sni", f.sni);
      putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      putIf("obfs", f.obfs);
      putIf("protocol", f.protocol);
      break;
    case "tuic":
      putIf("uuid", f.uuid);
      putIf("password", f.password);
      putIf("sni", f.sni);
      putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      putIf("congestion-controller", f["congestion-controller"]);
      putIf("udp-relay-mode", f["udp-relay-mode"]);
      if (typeof f.version === "number") out.version = f.version;
      putBoolIf("disable-sni", f["disable-sni"]);
      break;
    case "snell":
      putIf("psk", f.psk);
      if (typeof f.version === "number") out.version = f.version;
      putBoolIf("udp", f.udp);
      break;
    case "wireguard":
      putIf("private-key", f["private-key"]);
      putIf("public-key", f["public-key"]);
      putIf("preshared-key", f["preshared-key"]);
      putIf("ip", f.ip);
      putIf("ipv6", f.ipv6);
      if (typeof f.mtu === "number" && f.mtu > 0) out.mtu = f.mtu;
      putBoolIf("udp", f.udp);
      break;
    case "anytls":
      putIf("password", f.password);
      putIf("sni", f.sni);
      putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      putIf("client-fingerprint", f["client-fingerprint"]);
      putBoolIf("udp", f.udp);
      break;
    case "socks5":
      putIf("username", f.username);
      putIf("password", f.password);
      if (f.tls) {
        out.tls = true;
        putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      }
      putBoolIf("udp", f.udp);
      break;
    case "http":
      putIf("username", f.username);
      putIf("password", f.password);
      if (f.tls) {
        out.tls = true;
        putBoolIf("skip-cert-verify", f["skip-cert-verify"]);
      }
      break;
  }
  return out;
}

export function formToYaml(f: ProxyForm): string {
  return YAML.stringify(formToObject(f));
}

function asStr(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asNum(v: unknown): number | "" {
  return typeof v === "number" ? v : v !== undefined && v !== null ? Number(v) || "" : "";
}

/** YAML 文本 -> 表单. 失败抛错 (含中文说明) */
export function yamlToForm(text: string): ProxyForm {
  let parsed: unknown;
  try {
    parsed = YAML.parse(text);
  } catch (e: any) {
    throw new Error(`YAML 解析失败: ${e?.message ?? e}`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("YAML 必须是单个对象 (mapping)");
  }
  const o = parsed as Record<string, unknown>;
  const type = String(o.type ?? "");
  if (!PROXY_TYPES.some((p) => p.value === type)) {
    throw new Error(
      `不支持的协议 type=${type || "(空)"}, 表单只支持 ${PROXY_TYPES.map((p) => p.value).join("/")}; ` +
        "其他协议请用 YAML 模式编辑.",
    );
  }
  const base = emptyForm(type as ProxyType);
  return {
    ...base,
    name: String(o.name ?? ""),
    server: String(o.server ?? ""),
    port: asNum(o.port),
    udp: !!o.udp,
    sni: asStr(o.sni) ?? base.sni,
    "skip-cert-verify": !!o["skip-cert-verify"],
    servername: asStr(o.servername) ?? base.servername,
    tls: !!o.tls,
    "client-fingerprint":
      asStr(o["client-fingerprint"]) ?? base["client-fingerprint"],

    password: asStr(o.password) ?? base.password,
    username: asStr(o.username) ?? base.username,
    uuid: asStr(o.uuid) ?? base.uuid,

    cipher: asStr(o.cipher) ?? base.cipher,
    obfs: asStr(o.obfs) ?? base.obfs,
    protocol: asStr(o.protocol) ?? base.protocol,
    "obfs-param": asStr(o["obfs-param"]) ?? base["obfs-param"],
    "protocol-param": asStr(o["protocol-param"]) ?? base["protocol-param"],

    alterId: asNum(o.alterId) || (base.alterId ?? 0),
    network: asStr(o.network) ?? base.network,

    flow: asStr(o.flow) ?? base.flow,

    up:
      typeof o.up === "number"
        ? String(o.up)
        : asStr(o.up) ?? base.up,
    down:
      typeof o.down === "number"
        ? String(o.down)
        : asStr(o.down) ?? base.down,
    "auth-str":
      asStr(o.auth_str) ?? asStr(o["auth-str"]) ?? base["auth-str"],

    "congestion-controller":
      asStr(o["congestion-controller"]) ?? base["congestion-controller"],
    "udp-relay-mode": asStr(o["udp-relay-mode"]) ?? base["udp-relay-mode"],
    version: asNum(o.version) || (base.version ?? ""),
    "disable-sni": !!o["disable-sni"],

    psk: asStr(o.psk) ?? base.psk,

    "private-key": asStr(o["private-key"]) ?? base["private-key"],
    "public-key": asStr(o["public-key"]) ?? base["public-key"],
    "preshared-key": asStr(o["preshared-key"]) ?? base["preshared-key"],
    ip: asStr(o.ip) ?? base.ip,
    ipv6: asStr(o.ipv6) ?? base.ipv6,
    mtu: asNum(o.mtu) || (base.mtu ?? ""),
  };
}

export type FieldErrors = Record<string, string>;

/** 校验表单, 返回 { field -> message }. 空对象 = 通过. */
export function validateForm(f: ProxyForm): FieldErrors {
  const e: FieldErrors = {};
  if (!f.name || !f.name.trim()) e.name = "不能为空";
  if (!f.server || !f.server.trim()) e.server = "不能为空";
  const p = typeof f.port === "number" ? f.port : Number(f.port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) e.port = "必须是 1-65535";

  switch (f.type) {
    case "trojan":
      if (!f.password) e.password = "不能为空";
      break;
    case "ss":
      if (!f.cipher || !(SS_CIPHERS as readonly string[]).includes(f.cipher))
        e.cipher = "不在支持的 cipher 列表";
      if (!f.password) e.password = "不能为空";
      break;
    case "ssr":
      if (!f.cipher || !(SSR_CIPHERS as readonly string[]).includes(f.cipher))
        e.cipher = "不在支持的 cipher 列表";
      if (!f.password) e.password = "不能为空";
      if (!f.obfs || !(SSR_OBFS as readonly string[]).includes(f.obfs))
        e.obfs = "不在支持的 obfs 列表";
      if (
        !f.protocol ||
        !(SSR_PROTOCOLS as readonly string[]).includes(f.protocol)
      )
        e.protocol = "不在支持的 protocol 列表";
      break;
    case "vmess":
      if (!f.uuid || !UUID_RE.test(f.uuid))
        e.uuid = "需要合法 UUID 格式 (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)";
      if (f.cipher && !(VMESS_CIPHERS as readonly string[]).includes(f.cipher))
        e.cipher = `须为 ${VMESS_CIPHERS.join("/")} 之一`;
      if (
        f.network &&
        !(NETWORK_TYPES as readonly string[]).includes(f.network)
      )
        e.network = `须为 ${NETWORK_TYPES.join("/")} 之一`;
      break;
    case "vless":
      if (!f.uuid || !UUID_RE.test(f.uuid))
        e.uuid = "需要合法 UUID 格式";
      if (
        f.network &&
        !(NETWORK_TYPES as readonly string[]).includes(f.network)
      )
        e.network = `须为 ${NETWORK_TYPES.join("/")} 之一`;
      if (f.tls && !f.servername)
        e.servername = "开启 tls 时建议填 servername (SNI)";
      break;
    case "hysteria2":
      if (!f.password) e.password = "不能为空";
      break;
    case "hysteria":
      if (!f["auth-str"]) e["auth-str"] = "不能为空";
      if (!f.up || !(Number(f.up) > 0)) e.up = "须为正数 (Mbps)";
      if (!f.down || !(Number(f.down) > 0)) e.down = "须为正数 (Mbps)";
      if (
        f.protocol &&
        !(HYSTERIA_PROTOCOLS as readonly string[]).includes(f.protocol)
      )
        e.protocol = `须为 ${HYSTERIA_PROTOCOLS.join("/")} 之一`;
      break;
    case "tuic":
      if (!f.uuid || !UUID_RE.test(f.uuid))
        e.uuid = "需要合法 UUID 格式";
      if (!f.password) e.password = "不能为空";
      if (
        f["congestion-controller"] &&
        !(TUIC_CC as readonly string[]).includes(f["congestion-controller"])
      )
        e["congestion-controller"] = `须为 ${TUIC_CC.join("/")} 之一`;
      if (
        f["udp-relay-mode"] &&
        !(TUIC_UDP_MODES as readonly string[]).includes(f["udp-relay-mode"])
      )
        e["udp-relay-mode"] = `须为 ${TUIC_UDP_MODES.join("/")} 之一`;
      break;
    case "snell":
      if (!f.psk) e.psk = "不能为空";
      if (typeof f.version === "number" && ![1, 2, 3, 4].includes(f.version))
        e.version = "一般为 3 或 4";
      break;
    case "wireguard":
      if (!f["private-key"]) e["private-key"] = "不能为空";
      if (!f["public-key"]) e["public-key"] = "不能为空";
      if (!f.ip) e.ip = "本地隧道 IP, 不能为空";
      break;
    case "anytls":
      if (!f.password) e.password = "不能为空";
      break;
    case "socks5":
    case "http":
      break;
  }
  return e;
}

