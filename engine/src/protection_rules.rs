//! Validated, opt-in protection rules for the kernel policy bridge.
//!
//! The rule file is intentionally not loaded implicitly.  Set
//! `EVERBLOOM_POLICY_RULES` to a JSON file to apply its enabled rules.  This
//! keeps packaged examples harmless while still giving deployments a single,
//! auditable source for process, file, and IPv4 network blocks.

use crate::driver_bridge::{DriverBridge, DriverBridgeError};
use crate::protection_state;
use log::{info, warn};
use serde::Deserialize;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;
use thiserror::Error;

const POLICY_VERSION: u32 = 1;
const MAX_RULES_PER_KIND: usize = 64;
const MAX_TARGET_UTF16_CHARS: usize = 259;

#[derive(Debug, Error)]
pub enum ProtectionRuleError {
    #[error("unable to read protection rule file: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid protection rule JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid protection rule: {0}")]
    Invalid(String),
    #[error("invalid Everbloom policy rule language: {0}")]
    Dsl(String),
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionRuleKind {
    #[serde(alias = "进程")]
    Process,
    #[serde(alias = "文件")]
    File,
    Registry,
    #[serde(alias = "mbr")]
    RawDisk,
    #[serde(alias = "网络")]
    Network,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionRuleAction {
    #[default]
    #[serde(alias = "阻断", alias = "拦截", alias = "禁止")]
    Block,
}

/// One policy rule.  Fields not relevant to the selected kind must be absent.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionRule {
    pub id: String,
    pub kind: ProtectionRuleKind,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub action: ProtectionRuleAction,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionRuleConfig {
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<ProtectionRule>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtectionRuleApplyReport {
    pub applied: usize,
    pub disabled: usize,
    pub unsupported: usize,
    pub failed: Vec<String>,
}

impl ProtectionRuleConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProtectionRuleError> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let config = match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| extension.eq_ignore_ascii_case("hpol"))
        {
            Some(true) => {
                let source = String::from_utf8(bytes).map_err(|error| {
                    ProtectionRuleError::Dsl(format!("rule file is not UTF-8: {error}"))
                })?;
                Self::from_hpol(&source)?
            }
            _ => serde_json::from_slice(&bytes)?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Parse the dependency-free Everbloom Policy Language (.hpol).
    ///
    /// Examples:
    /// `block process "C:\\ProgramData\\EverbloomSecurity\\quarantine\\sample.exe"`
    /// `阻断 网络 "192.0.2.1" 端口 443`
    pub fn from_hpol(source: &str) -> Result<Self, ProtectionRuleError> {
        let mut version = None;
        let mut rules = Vec::new();

        for (line_index, raw_line) in source.lines().enumerate() {
            let line_number = line_index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let tokens = tokenize_hpol_line(line).map_err(|error| {
                ProtectionRuleError::Dsl(format!("line {line_number}: {error}"))
            })?;
            if tokens.is_empty() {
                continue;
            }

            if is_keyword(&tokens[0], &["version", "版本"]) {
                if tokens.len() != 2 || version.is_some() {
                    return Err(ProtectionRuleError::Dsl(format!(
                        "line {line_number}: expected one version declaration"
                    )));
                }
                version = Some(tokens[1].parse::<u32>().map_err(|_| {
                    ProtectionRuleError::Dsl(format!(
                        "line {line_number}: version must be an integer"
                    ))
                })?);
                continue;
            }

            if tokens.len() < 3 || !is_keyword(&tokens[0], &["block", "阻断", "拦截", "禁止"])
            {
                return Err(ProtectionRuleError::Dsl(format!(
                    "line {line_number}: expected block/阻断 <kind> <target>"
                )));
            }
            let kind = parse_hpol_kind(&tokens[1]).ok_or_else(|| {
                ProtectionRuleError::Dsl(format!(
                    "line {line_number}: unknown rule kind {:?}",
                    tokens[1]
                ))
            })?;
            let mut rule = ProtectionRule {
                id: format!("hpol-line-{line_number}"),
                kind,
                target: None,
                address: None,
                port: None,
                action: ProtectionRuleAction::Block,
                enabled: true,
            };

            match kind {
                ProtectionRuleKind::Process
                | ProtectionRuleKind::File
                | ProtectionRuleKind::Registry
                | ProtectionRuleKind::RawDisk => {
                    rule.target = Some(tokens[2].clone());
                }
                ProtectionRuleKind::Network => {
                    rule.address = Some(tokens[2].clone());
                }
            }

            let mut index = 3;
            while index < tokens.len() {
                if is_keyword(&tokens[index], &["port", "端口"]) {
                    if kind != ProtectionRuleKind::Network || index + 1 >= tokens.len() {
                        return Err(ProtectionRuleError::Dsl(format!(
                            "line {line_number}: port is valid only for network rules"
                        )));
                    }
                    rule.port = Some(tokens[index + 1].parse::<u16>().map_err(|_| {
                        ProtectionRuleError::Dsl(format!(
                            "line {line_number}: port must be an integer"
                        ))
                    })?);
                    index += 2;
                } else if is_keyword(&tokens[index], &["id", "标识", "规则名"]) {
                    if index + 1 >= tokens.len() {
                        return Err(ProtectionRuleError::Dsl(format!(
                            "line {line_number}: id is missing"
                        )));
                    }
                    rule.id = tokens[index + 1].clone();
                    index += 2;
                } else {
                    return Err(ProtectionRuleError::Dsl(format!(
                        "line {line_number}: unknown option {:?}",
                        tokens[index]
                    )));
                }
            }
            rules.push(rule);
        }

        let config = Self {
            version: version.unwrap_or(1),
            rules,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ProtectionRuleError> {
        if self.version != POLICY_VERSION {
            return Err(ProtectionRuleError::Invalid(format!(
                "unsupported version {}, expected {}",
                self.version, POLICY_VERSION
            )));
        }

        let mut ids = HashSet::with_capacity(self.rules.len());
        let mut process_count = 0;
        let mut file_count = 0;
        let mut network_count = 0;
        let mut registry_count = 0;
        let mut raw_disk_count = 0;

        for rule in &self.rules {
            let id = rule.id.trim();
            if id.is_empty() || id.len() > 64 || !ids.insert(id.to_string()) {
                return Err(ProtectionRuleError::Invalid(format!(
                    "rule id must be unique and contain 1-64 characters: {:?}",
                    rule.id
                )));
            }
            if rule.action != ProtectionRuleAction::Block {
                return Err(ProtectionRuleError::Invalid(format!(
                    "rule {} uses an unsupported action",
                    rule.id
                )));
            }

            match rule.kind {
                ProtectionRuleKind::Process => {
                    process_count += 1;
                    validate_count(process_count, "process", &rule.id)?;
                    validate_path_target(rule, "process")?;
                }
                ProtectionRuleKind::File => {
                    file_count += 1;
                    validate_count(file_count, "file", &rule.id)?;
                    validate_path_target(rule, "file")?;
                }
                ProtectionRuleKind::Registry => {
                    registry_count += 1;
                    validate_count(registry_count, "registry", &rule.id)?;
                    validate_path_target(rule, "registry")?;
                }
                ProtectionRuleKind::RawDisk => {
                    raw_disk_count += 1;
                    validate_count(raw_disk_count, "raw_disk", &rule.id)?;
                    validate_path_target(rule, "raw_disk")?;
                }
                ProtectionRuleKind::Network => {
                    network_count += 1;
                    validate_count(network_count, "network", &rule.id)?;
                    if rule.target.is_some() {
                        return Err(ProtectionRuleError::Invalid(format!(
                            "network rule {} must not contain target",
                            rule.id
                        )));
                    }
                    let address = rule.address.as_deref().ok_or_else(|| {
                        ProtectionRuleError::Invalid(format!(
                            "network rule {} is missing address",
                            rule.id
                        ))
                    })?;
                    let parsed = address.parse::<Ipv4Addr>().map_err(|_| {
                        ProtectionRuleError::Invalid(format!(
                            "network rule {} has invalid IPv4 address {:?}",
                            rule.id, address
                        ))
                    })?;
                    if parsed.is_unspecified() || parsed.is_multicast() || parsed.is_broadcast() {
                        return Err(ProtectionRuleError::Invalid(format!(
                            "network rule {} cannot target unspecified, multicast, or broadcast IPv4",
                            rule.id
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn apply_enabled(&self, bridge: &DriverBridge) -> ProtectionRuleApplyReport {
        let mut report = ProtectionRuleApplyReport::default();
        for rule in &self.rules {
            if !rule.enabled {
                report.disabled += 1;
                continue;
            }

            let result = match rule.kind {
                ProtectionRuleKind::Process => bridge.block_process(
                    rule.target
                        .as_deref()
                        .expect("validated process rule target"),
                ),
                ProtectionRuleKind::File => {
                    bridge.block_file(rule.target.as_deref().expect("validated file rule target"))
                }
                ProtectionRuleKind::Registry => bridge.block_registry(
                    rule.target
                        .as_deref()
                        .expect("validated registry rule target"),
                ),
                ProtectionRuleKind::RawDisk => bridge.block_raw_disk(
                    rule.target
                        .as_deref()
                        .expect("validated raw disk rule target"),
                ),
                ProtectionRuleKind::Network => {
                    let address = rule
                        .address
                        .as_deref()
                        .expect("validated network rule address")
                        .parse::<Ipv4Addr>()
                        .expect("validated network rule IPv4 address");
                    bridge.block_network(address, rule.port)
                }
            };

            match result {
                Ok(_) => report.applied += 1,
                Err(error) if error.is_unavailable() => {
                    protection_state::set_driver_enabled(false);
                    report.unsupported += 1;
                }
                Err(DriverBridgeError::Unsupported) => report.unsupported += 1,
                Err(error) => report.failed.push(format!("{}: {}", rule.id, error)),
            }
        }
        report
    }
}

/// Load and apply the explicitly configured policy file, if one was supplied.
pub fn apply_configured_protection_rules(
) -> Result<Option<ProtectionRuleApplyReport>, ProtectionRuleError> {
    let Some(path) = std::env::var_os("EVERBLOOM_POLICY_RULES") else {
        return Ok(None);
    };

    let path = Path::new(&path);
    let config = ProtectionRuleConfig::load(path)?;
    let report = config.apply_enabled(&DriverBridge::new());
    if !report.failed.is_empty() {
        for failure in &report.failed {
            warn!("protection rule was not applied: {}", failure);
        }
    }
    info!(
        "protection rules loaded from {}: applied={}, disabled={}, unsupported={}, failed={}",
        path.display(),
        report.applied,
        report.disabled,
        report.unsupported,
        report.failed.len()
    );
    Ok(Some(report))
}

fn validate_count(count: usize, kind: &str, id: &str) -> Result<(), ProtectionRuleError> {
    if count > MAX_RULES_PER_KIND {
        return Err(ProtectionRuleError::Invalid(format!(
            "{} rule limit ({}) exceeded at {}",
            kind, MAX_RULES_PER_KIND, id
        )));
    }
    Ok(())
}

fn validate_path_target(rule: &ProtectionRule, kind: &str) -> Result<(), ProtectionRuleError> {
    if rule.address.is_some() || rule.port.is_some() {
        return Err(ProtectionRuleError::Invalid(format!(
            "{} rule {} must not contain network fields",
            kind, rule.id
        )));
    }
    let target = rule.target.as_deref().ok_or_else(|| {
        ProtectionRuleError::Invalid(format!("{} rule {} is missing target", kind, rule.id))
    })?;
    let trimmed = target.trim();
    if trimmed.is_empty()
        || trimmed.len() != target.len()
        || trimmed.encode_utf16().count() > MAX_TARGET_UTF16_CHARS
        || trimmed.chars().any(|character| character.is_control())
        || trimmed.contains('*')
        || trimmed.contains('?')
    {
        return Err(ProtectionRuleError::Invalid(format!(
            "{} rule {} has an invalid exact target",
            kind, rule.id
        )));
    }
    Ok(())
}

fn is_keyword(value: &str, keywords: &[&str]) -> bool {
    keywords
        .iter()
        .any(|keyword| value.eq_ignore_ascii_case(keyword))
}

fn parse_hpol_kind(value: &str) -> Option<ProtectionRuleKind> {
    if is_keyword(value, &["registry"]) {
        return Some(ProtectionRuleKind::Registry);
    }
    if is_keyword(value, &["process", "进程"]) {
        Some(ProtectionRuleKind::Process)
    } else if is_keyword(value, &["file", "文件"]) {
        Some(ProtectionRuleKind::File)
    } else if is_keyword(value, &["network", "网络"]) {
        Some(ProtectionRuleKind::Network)
    } else if is_keyword(value, &["raw_disk", "raw-disk", "mbr", "磁盘"]) {
        Some(ProtectionRuleKind::RawDisk)
    } else if is_keyword(value, &["network"]) {
        Some(ProtectionRuleKind::Network)
    } else {
        None
    }
}

fn tokenize_hpol_line(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in line.chars() {
        match character {
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if quoted {
        return Err("unterminated quoted value".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> ProtectionRuleConfig {
        serde_json::from_str(
            r#"{
                "version": 1,
                "rules": [
                    {"id":"process-test","kind":"process","target":"C:\\Temp\\EverbloomSecurity\\blocked.exe","enabled":true},
                    {"id":"file-test","kind":"file","target":"C:\\Temp\\EverbloomSecurity\\blocked.exe","enabled":false},
                    {"id":"network-test","kind":"network","address":"192.0.2.1","port":443,"enabled":true}
                ]
            }"#,
        )
        .expect("sample JSON should parse")
    }

    #[test]
    fn validates_process_file_and_network_rules() {
        sample_config().validate().expect("sample should validate");
    }

    #[test]
    fn rejects_wildcards_because_driver_matching_is_exact() {
        let mut config = sample_config();
        config.rules[0].target = Some(String::from(r"C:\Temp\*.exe"));
        assert!(config.validate().is_err());
    }

    #[test]
    fn disabled_rules_are_not_applied() {
        let mut config = sample_config();
        config.rules[0].enabled = false;
        config.rules[2].enabled = false;
        let report = config.apply_enabled(&DriverBridge::new());
        assert_eq!(report.applied, 0);
        assert_eq!(report.disabled, 3);
    }

    #[test]
    fn repository_safe_policy_profile_is_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("data");
        let config = ProtectionRuleConfig::load(root.join("policy_rules.json"))
            .expect("safe JSON policy profile should load");
        assert_eq!(config.rules.len(), 3);
        assert!(config.rules.iter().all(|rule| rule.enabled));

        let hpol = ProtectionRuleConfig::load(root.join("policy_rules.hpol"))
            .expect("safe HPOL policy profile should load");
        assert_eq!(hpol.rules.len(), 3);
    }

    #[test]
    fn parses_english_and_simplified_chinese_hpol_rules() {
        let config = ProtectionRuleConfig::from_hpol(
            r#"
                version 1
                block process "C:\ProgramData\EverbloomSecurity\quarantine\sample.exe" id "english-process"
                阻断 文件 "C:\ProgramData\EverbloomSecurity\quarantine\sample.exe" 规则名 "中文文件"
                禁止 网络 "192.0.2.1" 端口 443
            "#,
        )
        .expect("English and Chinese policy syntax should parse");
        assert_eq!(config.rules.len(), 3);
        assert_eq!(config.rules[1].id, "中文文件");
        assert_eq!(config.rules[2].port, Some(443));
    }

    #[test]
    fn accepts_simplified_chinese_json_aliases() {
        let config: ProtectionRuleConfig = serde_json::from_str(
            r#"{
                "version": 1,
                "rules": [{
                    "id": "中文规则",
                    "kind": "进程",
                    "target": "C:\\Temp\\EverbloomSecurity\\sample.exe",
                    "action": "阻断",
                    "enabled": true
                }]
            }"#,
        )
        .expect("localized JSON aliases should parse");
        config
            .validate()
            .expect("localized JSON aliases should validate");
    }
}
