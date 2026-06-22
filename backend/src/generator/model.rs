//! generator 三层重构的中间模型 (parse → inject → render)。
//!
//! `InjectModel` 是纯数据载体, 不碰 IO / 不知道任何输出格式。
//! - `ClashRenderer` 走"在 clone 的 `upstream_root` 上原地注入"路径, 与历史 generate() 逐字节等价;
//! - `SingboxRenderer` 从 `InjectModel` 的补丁清单 (injected_proxies / injected_groups / custom_rules)
//!   从零构造 sing-box JSON, 不复用上游 proxy-groups。

use serde_yaml::{Mapping, Value};

/// 注入后的纯中间模型, 与具体输出格式无关。
#[derive(Debug, Clone)]
pub struct InjectModel {
    /// 上游原始 root (Clash 渲染走它原地注入保字节等价)。
    pub upstream_root: Value,
    /// 本次追加的链路节点 (每个 mapping 含 `dialer-proxy` 私有字段)。
    pub injected_proxies: Vec<Mapping>,
    /// 本次新增的组: per-exit url-test + Bridge-Exit-auto + Bridge-Exit(select)。
    pub injected_groups: Vec<InjectGroup>,
    /// 注入到所有原 type=select 组首位的目标 (= bridge_group_name)。
    pub select_inject_target: String,
    /// 用户自定义规则 (已软校验)。
    pub custom_rules: Vec<RuleSpec>,
    /// 兜底目标 (= bridge_group_name), MATCH 指向它。
    pub fallback_target: String,
    pub upstream_count: i32,
    pub bridge_count: i32,
    pub chain_count: i32,
    /// 用户勾选了但最新上游里找不到的 name。
    pub missing_bridges: Vec<String>,
    /// 是否含固定出口链路 (chain_count > 0)。
    pub has_relay_chain: bool,
}

/// 一个注入组的中性描述 (DSL-agnostic)。
#[derive(Debug, Clone)]
pub struct InjectGroup {
    pub name: String,
    pub kind: GroupKind,
    /// 组内成员 (节点名 / 其他组名 / DIRECT 等)。
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum GroupKind {
    /// 自动测速组。`interval` 为秒。
    UrlTest { url: String, interval: u32 },
    /// 手动选择组。
    Select,
}

/// 一条规则的中性描述。`matcher` 对 MATCH 为 None。
#[derive(Debug, Clone)]
pub struct RuleSpec {
    pub rule_type: RuleType,
    pub matcher: Option<String>,
    pub target: String,
}

/// Clash 规则类型。`Other` 保留原始 RULE-TYPE 字符串, 渲染时原样透传 (Clash) 或跳过 (sing-box)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
    IpCidr6,
    GeoIp,
    GeoSite,
    Process,
    DstPort,
    SrcPort,
    Match,
    /// 其他类型: 携带原始 RULE-TYPE 字符串 (如 RULE-SET / SRC-IP-CIDR 等)。
    Other(String),
}

impl RuleType {
    /// 由 Clash RULE-TYPE 字符串解析。大小写不敏感。
    pub fn parse(token: &str) -> Self {
        match token.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" => RuleType::Domain,
            "DOMAIN-SUFFIX" => RuleType::DomainSuffix,
            "DOMAIN-KEYWORD" => RuleType::DomainKeyword,
            "IP-CIDR" => RuleType::IpCidr,
            "IP-CIDR6" => RuleType::IpCidr6,
            "GEOIP" => RuleType::GeoIp,
            "GEOSITE" => RuleType::GeoSite,
            "PROCESS-NAME" => RuleType::Process,
            "DST-PORT" => RuleType::DstPort,
            "SRC-PORT" => RuleType::SrcPort,
            "MATCH" | "FINAL" => RuleType::Match,
            other => RuleType::Other(other.to_string()),
        }
    }

    /// 还原成 Clash RULE-TYPE 字符串 (用于 Clash 渲染原样输出)。
    pub fn as_clash_token(&self) -> &str {
        match self {
            RuleType::Domain => "DOMAIN",
            RuleType::DomainSuffix => "DOMAIN-SUFFIX",
            RuleType::DomainKeyword => "DOMAIN-KEYWORD",
            RuleType::IpCidr => "IP-CIDR",
            RuleType::IpCidr6 => "IP-CIDR6",
            RuleType::GeoIp => "GEOIP",
            RuleType::GeoSite => "GEOSITE",
            RuleType::Process => "PROCESS-NAME",
            RuleType::DstPort => "DST-PORT",
            RuleType::SrcPort => "SRC-PORT",
            RuleType::Match => "MATCH",
            RuleType::Other(s) => s.as_str(),
        }
    }

    /// 该类型是否要求 matcher 段 (MATCH 不要求)。
    pub fn needs_matcher(&self) -> bool {
        !matches!(self, RuleType::Match)
    }
}

impl RuleSpec {
    /// 渲染成 Clash 规则字符串 `RULE-TYPE,matcher,target` (MATCH 为 `MATCH,target`)。
    pub fn to_clash_line(&self) -> String {
        match &self.matcher {
            Some(m) => format!("{},{},{}", self.rule_type.as_clash_token(), m, self.target),
            None => format!("{},{}", self.rule_type.as_clash_token(), self.target),
        }
    }
}
