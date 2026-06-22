//! custom_rules 解析与校验。
//!
//! 字段语法: 每行一条 Clash 规则 `RULE-TYPE,matcher,target`(MATCH 例外: `MATCH,target` 两段)。
//! 空行 / `#` 注释行忽略。
//!
//! 两道校验:
//! 1. 写 profile 时 [`validate_syntax`] — 强语法校验 (段数 / RULE-TYPE / target 非空 / 静态白名单)。
//!    此时拿不到上游组名, 组名引用留生成时软校验。
//! 2. 生成时 [`parse_custom_rules`] — 软校验, 已知全部组名, 悬空 target 跳过 + warn,
//!    不让一条坏规则把整个订阅打挂。

use std::collections::HashSet;

use tracing::warn;

use crate::error::{AppError, AppResult};
use crate::generator::model::{RuleSpec, RuleType};

/// 写时强校验阶段已知的静态 target 白名单 (聚合组 / 内置策略)。
/// 上游组名 + 我们生成的组名在此阶段无法枚举, 留到生成时软校验。
const STATIC_TARGETS: &[&str] = &["Bridge-Exit", "DIRECT", "REJECT"];

/// mihomo 常见 RULE-TYPE 白名单 (大写)。`RuleType::parse` 把未识别的归到 `Other`,
/// 写时强校验只放行白名单内的类型, 明确拒绝拼写错误 (如 DOMAINSUFFIX)。
/// `RuleType` 枚举已显式覆盖的 (DOMAIN/IP-CIDR/GEOIP/MATCH 等) 在此列出, 高级/容器类型
/// (RULE-SET / SRC-IP-CIDR / IP-ASN 等) 一并放行, 生成时再按格式处理。
const KNOWN_RULE_TYPES: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-SUFFIX",
    "IP-ASN",
    "GEOIP",
    "GEOSITE",
    "SRC-GEOIP",
    "SRC-IP-CIDR",
    "SRC-IP-SUFFIX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-NAME-REGEX",
    "PROCESS-PATH-REGEX",
    "NETWORK",
    "DSCP",
    "UID",
    "RULE-SET",
    "SUB-RULE",
    "AND",
    "OR",
    "NOT",
    "MATCH",
    "FINAL",
];

/// 把一行原始文本拆成 (rule_type, matcher, target)。
/// 返回 None 表示该行是空行 / 注释 (应忽略)。
/// 返回 Err 表示语法非法。
fn parse_line(line: &str) -> AppResult<Option<(RuleType, Option<String>, String)>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }
    // 最多拆 3 段: RULE-TYPE,matcher,target
    let parts: Vec<&str> = trimmed.splitn(3, ',').map(|s| s.trim()).collect();
    let head = parts[0];
    if head.is_empty() {
        return Err(AppError::BadRequest(format!("custom_rules 行非法 (规则类型为空): {trimmed}")));
    }
    let rule_type = RuleType::parse(head);

    // RULE-TYPE 白名单校验: parse 把未识别类型归到 Other; 只放行白名单内的, 明确拒绝拼写错误
    // (如 DOMAINSUFFIX)。已被枚举的具体类型 (Domain/IpCidr/Match 等) 一定合法, 不必查表。
    if matches!(rule_type, RuleType::Other(_)) {
        let head_upper = head.trim().to_ascii_uppercase();
        if !KNOWN_RULE_TYPES.contains(&head_upper.as_str()) {
            return Err(AppError::BadRequest(format!(
                "custom_rules 行非法 (未知规则类型 '{head}'): {trimmed}"
            )));
        }
    }

    if rule_type.needs_matcher() {
        // 需要 3 段: RULE-TYPE,matcher,target
        if parts.len() != 3 {
            return Err(AppError::BadRequest(format!(
                "custom_rules 行非法 (应为 'RULE-TYPE,matcher,target'): {trimmed}"
            )));
        }
        let matcher = parts[1];
        let target = parts[2];
        if matcher.is_empty() {
            return Err(AppError::BadRequest(format!("custom_rules 行非法 (matcher 为空): {trimmed}")));
        }
        if target.is_empty() {
            return Err(AppError::BadRequest(format!("custom_rules 行非法 (target 为空): {trimmed}")));
        }
        Ok(Some((rule_type, Some(matcher.to_string()), target.to_string())))
    } else {
        // MATCH: 2 段 RULE-TYPE,target
        if parts.len() != 2 {
            return Err(AppError::BadRequest(format!(
                "custom_rules 行非法 (MATCH 应为 'MATCH,target'): {trimmed}"
            )));
        }
        let target = parts[1];
        if target.is_empty() {
            return Err(AppError::BadRequest(format!("custom_rules 行非法 (target 为空): {trimmed}")));
        }
        Ok(Some((rule_type, None, target.to_string())))
    }
}

/// 写 profile 时 (create / update) 的强语法校验。
/// - 每行能拆成合法 RULE-TYPE + 段数正确 + matcher/target 非空;
/// - target 在静态白名单内 (Bridge-Exit/DIRECT/REJECT) 才放行, 否则视为"可能的组名引用"——
///   组名引用此时无法验证, **不报错**, 留生成时软校验 (避免要求用户必须先 refresh)。
///
/// 语法错误返回 400。
pub fn validate_syntax(text: Option<&str>) -> AppResult<()> {
    let Some(text) = text else { return Ok(()) };
    if text.trim().is_empty() {
        return Ok(());
    }
    for line in text.lines() {
        // 仅做语法层校验; 组名引用 (非静态白名单 target) 不在此处拦截。
        let _ = parse_line(line)?;
    }
    Ok(())
}

/// 生成时软校验: 已知全部组名 (`known_groups` = 上游组名 + 我们生成的组名 + 静态白名单)。
/// - 每行翻成 [`RuleSpec`];
/// - 语法非法的行跳过 + warn (生成阶段不因一条坏规则整体失败);
/// - target 不在白名单的行跳过 + warn (悬空策略会让客户端报错)。
/// - 用户误写的 MATCH 行跳过 (我们自己会补兜底 MATCH)。
pub fn parse_custom_rules(text: &str, known_groups: &HashSet<String>) -> Vec<RuleSpec> {
    let mut out = Vec::new();
    for line in text.lines() {
        match parse_line(line) {
            Ok(None) => {}
            Ok(Some((rule_type, matcher, target))) => {
                if rule_type == RuleType::Match {
                    // 用户误写 MATCH: 跳过, 由我们统一补兜底。
                    warn!(line = %line.trim(), "custom_rules: 跳过用户 MATCH 行 (兜底由系统统一注入)");
                    continue;
                }
                let allowed = STATIC_TARGETS.contains(&target.as_str())
                    || known_groups.contains(&target);
                if !allowed {
                    warn!(
                        target = %target,
                        line = %line.trim(),
                        "custom_rules: target 不在已知组名 / 白名单内, 跳过该规则"
                    );
                    continue;
                }
                out.push(RuleSpec { rule_type, matcher, target });
            }
            Err(e) => {
                warn!(line = %line.trim(), error = ?e, "custom_rules: 行语法非法, 生成时跳过");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_syntax_accepts_valid() {
        let txt = "DOMAIN-SUFFIX,example.com,DIRECT\n# comment\n\nIP-CIDR,10.0.0.0/8,REJECT\nMATCH,Bridge-Exit";
        assert!(validate_syntax(Some(txt)).is_ok());
    }

    #[test]
    fn validate_syntax_accepts_group_ref() {
        // 组名引用 (非静态白名单) 在写时不报错, 留生成时校验
        assert!(validate_syntax(Some("DOMAIN,a.com,MyGroup")).is_ok());
    }

    #[test]
    fn validate_syntax_rejects_missing_target() {
        assert!(validate_syntax(Some("DOMAIN-SUFFIX,example.com")).is_err());
        assert!(validate_syntax(Some("DOMAIN-SUFFIX,example.com,")).is_err());
    }

    #[test]
    fn validate_syntax_rejects_empty_matcher() {
        assert!(validate_syntax(Some("DOMAIN-SUFFIX,,DIRECT")).is_err());
    }

    #[test]
    fn validate_syntax_rejects_match_three_segments() {
        // MATCH 必须两段
        assert!(validate_syntax(Some("MATCH,foo,bar")).is_err());
    }

    #[test]
    fn validate_syntax_rejects_unknown_rule_type() {
        // 拼写错误 (DOMAINSUFFIX 应为 DOMAIN-SUFFIX) → 400
        assert!(validate_syntax(Some("DOMAINSUFFIX,a.com,DIRECT")).is_err());
        assert!(validate_syntax(Some("FOOBAR,x,DIRECT")).is_err());
    }

    #[test]
    fn validate_syntax_accepts_whitelisted_advanced_types() {
        // RULE-SET / 大小写不敏感的高级类型放行
        assert!(validate_syntax(Some("RULE-SET,mylist,DIRECT")).is_ok());
        assert!(validate_syntax(Some("rule-set,mylist,Bridge-Exit")).is_ok());
        assert!(validate_syntax(Some("PROCESS-PATH,/usr/bin/foo,DIRECT")).is_ok());
    }

    #[test]
    fn validate_syntax_none_and_blank_ok() {
        assert!(validate_syntax(None).is_ok());
        assert!(validate_syntax(Some("   \n\n")).is_ok());
    }

    #[test]
    fn parse_custom_rules_skips_dangling_target() {
        let mut groups = HashSet::new();
        groups.insert("KnownGroup".to_string());
        let txt = "DOMAIN,a.com,KnownGroup\nDOMAIN,b.com,GhostGroup\nDOMAIN,c.com,DIRECT";
        let specs = parse_custom_rules(txt, &groups);
        // GhostGroup 被跳过
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].target, "KnownGroup");
        assert_eq!(specs[1].target, "DIRECT");
    }

    #[test]
    fn parse_custom_rules_skips_user_match() {
        let groups = HashSet::new();
        let specs = parse_custom_rules("MATCH,DIRECT", &groups);
        assert_eq!(specs.len(), 0);
    }

    #[test]
    fn parse_custom_rules_skips_invalid_line() {
        let groups = HashSet::new();
        // 非法行 (缺 target) 跳过, 不 panic
        let specs = parse_custom_rules("DOMAIN,a.com", &groups);
        assert_eq!(specs.len(), 0);
    }
}
