//! User-mode infostealer correlation and response.
//!
//! This module correlates privacy-preserving HIPS/ETW labels by PID. It never
//! reads browser database rows or cookie values. A firewall rule is only added
//! after a high-confidence, multi-signal correlation for a non-browser process.

use crate::hips::HipsEvent;
use crate::layers::behavior::{BehaviorEvent, BehaviorEventKind};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use thiserror::Error;

const STATE_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_STATES: usize = 1024;
const MAX_ACTION_EVENTS: usize = 256;
const FIREWALL_RULE_PREFIX: &str = "EverbloomSecurity-Stealer-";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum StealerSignal {
    BrowserStore,
    Dpapi,
    CredentialAccess,
    Collection,
    Archive,
    Exfiltration,
    Network,
    ProcessInjection,
}

impl StealerSignal {
    fn label(self) -> &'static str {
        match self {
            Self::BrowserStore => "browser_store",
            Self::Dpapi => "dpapi",
            Self::CredentialAccess => "credential_access",
            Self::Collection => "collection",
            Self::Archive => "archive",
            Self::Exfiltration => "exfiltration",
            Self::Network => "network",
            Self::ProcessInjection => "process_injection",
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessEvidence {
    signals: HashSet<StealerSignal>,
    process_path: Option<String>,
    last_seen: Instant,
    action_applied: bool,
}

#[derive(Debug, Clone)]
struct PendingAction {
    pid: u32,
    process_path: String,
    score: f32,
    indicators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealerProtectionEvent {
    pub pid: u32,
    pub process_path: String,
    pub score_percent: u8,
    pub indicators: Vec<String>,
    pub firewall_rule: Option<String>,
    pub firewall_applied: bool,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("system firewall integration is only available on Windows")]
    Unsupported,
    #[error("firewall program path is not absolute: {0}")]
    NonAbsolutePath(String),
    #[error("firewall program path is not a regular file: {0}")]
    NotAFile(String),
    #[error("unable to start netsh: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("netsh firewall command failed with exit code {0:?}")]
    CommandFailed(Option<i32>),
}

lazy_static! {
    static ref PROCESS_EVIDENCE: Mutex<HashMap<u32, ProcessEvidence>> = Mutex::new(HashMap::new());
    static ref PROTECTION_EVENTS: Mutex<VecDeque<StealerProtectionEvent>> =
        Mutex::new(VecDeque::new());
    static ref ACTIVE_FIREWALL_RULES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

/// Observe a privacy-preserving HIPS event. Only stable indicator labels are
/// consumed; no browser database content is opened or returned.
pub fn observe_hips_event(event: &HipsEvent) {
    let (pid, process_path, signals): (u32, Option<String>, Vec<StealerSignal>) = match event {
        HipsEvent::CookieTheftSuspected {
            pid,
            process_path,
            indicators,
        } => (
            *pid,
            Some(process_path.clone()),
            indicators_to_signals(indicators),
        ),
        HipsEvent::CtfHijackDllLoad {
            pid, process_path, ..
        } => (
            *pid,
            Some(process_path.clone()),
            vec![StealerSignal::ProcessInjection],
        ),
        HipsEvent::WhiteBlackSideLoad {
            pid, process_path, ..
        } => (
            *pid,
            Some(process_path.clone()),
            vec![StealerSignal::ProcessInjection],
        ),
        HipsEvent::SuspiciousProcessChain { pid, .. }
        | HipsEvent::SuspiciousApcInjection { pid, .. }
        | HipsEvent::SuspiciousThreadPoolInjection { pid, .. }
        | HipsEvent::SuspiciousReflectivePe { pid, .. } => {
            (*pid, None, vec![StealerSignal::ProcessInjection])
        }
        _ => return,
    };

    observe_signals(pid, process_path, signals);
}

/// Observe ETW/kernel behavior labels. Details remain telemetry-only and are
/// not parsed as secrets.
pub fn observe_behavior_event(event: &BehaviorEvent) {
    let Some(pid) = event.process_id else {
        return;
    };
    let signal = match event.kind {
        BehaviorEventKind::NetworkConnect | BehaviorEventKind::DnsQuery => {
            Some(StealerSignal::Network)
        }
        BehaviorEventKind::CredentialAccess => Some(StealerSignal::CredentialAccess),
        BehaviorEventKind::ProcessInject => Some(StealerSignal::ProcessInjection),
        BehaviorEventKind::FileWrite => Some(StealerSignal::Collection),
        _ => None,
    };
    if let Some(signal) = signal {
        observe_signals(pid, None, vec![signal]);
    }
}

/// Drain response events for NDJSON/GUI delivery.
pub fn drain_protection_events() -> Vec<StealerProtectionEvent> {
    let mut queue = PROTECTION_EVENTS.lock().unwrap();
    queue.drain(..).collect()
}

/// Remove firewall rules created by this engine instance. This is intended
/// for an explicit user action, not automatic cleanup on engine exit.
pub fn clear_active_firewall_rules() -> Vec<String> {
    let names = ACTIVE_FIREWALL_RULES
        .lock()
        .map(|mut rules| rules.drain().collect::<Vec<_>>())
        .unwrap_or_default();
    let mut removed = Vec::new();
    for name in names {
        if delete_firewall_rule(&name).is_ok() {
            removed.push(name);
        }
    }
    removed
}

fn observe_signals(pid: u32, process_path: Option<String>, signals: Vec<StealerSignal>) {
    if !crate::protection_state::r3_enabled() || signals.is_empty() {
        return;
    }

    let action = {
        let mut states = match PROCESS_EVIDENCE.lock() {
            Ok(states) => states,
            Err(_) => return,
        };
        let now = Instant::now();
        states.retain(|_, state| now.duration_since(state.last_seen) <= STATE_TTL);
        if states.len() >= MAX_STATES && !states.contains_key(&pid) {
            if let Some(oldest_pid) = states
                .iter()
                .min_by_key(|(_, state)| state.last_seen)
                .map(|(pid, _)| *pid)
            {
                states.remove(&oldest_pid);
            }
        }

        let state = states.entry(pid).or_insert_with(|| ProcessEvidence {
            signals: HashSet::new(),
            process_path: None,
            last_seen: now,
            action_applied: false,
        });
        state.last_seen = now;
        if let Some(path) = process_path {
            state.process_path = Some(path);
        }
        state.signals.extend(signals);
        if state.action_applied {
            None
        } else {
            let score = score_signals(&state.signals);
            if qualifies_for_protection(&state.signals, score) {
                let path = state.process_path.clone();
                state.action_applied = true;
                path.filter(|path| !path.trim().is_empty())
                    .map(|path| PendingAction {
                        pid,
                        process_path: path,
                        score,
                        indicators: sorted_labels(&state.signals),
                    })
            } else {
                None
            }
        }
    };

    if let Some(action) = action {
        apply_protection(action);
    }
}

fn indicators_to_signals(indicators: &[String]) -> Vec<StealerSignal> {
    let mut signals = Vec::new();
    for indicator in indicators {
        let normalized = indicator.to_ascii_lowercase();
        let signal = if normalized.contains("store")
            || normalized.contains("cookie")
            || normalized.contains("login")
            || normalized.contains("web_data")
            || normalized.contains("local_state")
        {
            Some(StealerSignal::BrowserStore)
        } else if normalized.contains("dpapi") {
            Some(StealerSignal::Dpapi)
        } else if normalized.contains("credential") {
            Some(StealerSignal::CredentialAccess)
        } else if normalized.contains("collection") || normalized.contains("cookie_collection") {
            Some(StealerSignal::Collection)
        } else if normalized.contains("archive") || normalized.contains("compress") {
            Some(StealerSignal::Archive)
        } else if normalized.contains("exfil") {
            Some(StealerSignal::Exfiltration)
        } else {
            None
        };
        if let Some(signal) = signal {
            signals.push(signal);
        }
    }
    signals
}

fn score_signals(signals: &HashSet<StealerSignal>) -> f32 {
    let weights = [
        (StealerSignal::BrowserStore, 0.30),
        (StealerSignal::Dpapi, 0.25),
        (StealerSignal::CredentialAccess, 0.20),
        (StealerSignal::Collection, 0.15),
        (StealerSignal::Archive, 0.12),
        (StealerSignal::Exfiltration, 0.25),
        (StealerSignal::Network, 0.20),
        (StealerSignal::ProcessInjection, 0.18),
    ];
    weights
        .iter()
        .filter(|(signal, _)| signals.contains(signal))
        .map(|(_, weight)| *weight)
        .sum::<f32>()
        .min(1.0)
}

fn qualifies_for_protection(signals: &HashSet<StealerSignal>, score: f32) -> bool {
    let browser_store = signals.contains(&StealerSignal::BrowserStore);
    let credential = signals.contains(&StealerSignal::Dpapi)
        || signals.contains(&StealerSignal::CredentialAccess);
    let collection = signals.contains(&StealerSignal::Collection)
        || signals.contains(&StealerSignal::Archive)
        || signals.contains(&StealerSignal::ProcessInjection);
    let outbound =
        signals.contains(&StealerSignal::Exfiltration) || signals.contains(&StealerSignal::Network);
    browser_store && credential && collection && outbound && score >= 0.82
}

fn sorted_labels(signals: &HashSet<StealerSignal>) -> Vec<String> {
    let mut labels = signals
        .iter()
        .map(|signal| signal.label().to_string())
        .collect::<Vec<_>>();
    labels.sort();
    labels
}

fn apply_protection(action: PendingAction) {
    let firewall_result = if firewall_enabled() {
        add_program_firewall_rule(&action.process_path)
    } else {
        Err(FirewallError::Unsupported)
    };

    let (firewall_rule, firewall_applied, message) = match firewall_result {
        Ok(rule) => {
            log::warn!(
                "StealerGuard blocked outbound traffic for pid={} program={} rule={}",
                action.pid,
                action.process_path,
                rule
            );
            (
                Some(rule),
                true,
                "high-confidence infostealer correlation; outbound program firewall block applied"
                    .to_string(),
            )
        }
        Err(error) => {
            log::error!(
                "StealerGuard detected high-confidence infostealer pid={} program={} score={:.2}; firewall action unavailable: {}",
                action.pid,
                action.process_path,
                action.score,
                error
            );
            (
                None,
                false,
                format!(
                    "high-confidence infostealer correlation; firewall action unavailable: {}",
                    error
                ),
            )
        }
    };

    let event = StealerProtectionEvent {
        pid: action.pid,
        process_path: action.process_path,
        score_percent: (action.score * 100.0).round().clamp(0.0, 100.0) as u8,
        indicators: action.indicators,
        firewall_rule,
        firewall_applied,
        message,
    };
    let mut queue = PROTECTION_EVENTS.lock().unwrap();
    if queue.len() >= MAX_ACTION_EVENTS {
        queue.pop_front();
    }
    queue.push_back(event);
}

fn firewall_enabled() -> bool {
    std::env::var("EVERBLOOM_STEALER_FIREWALL")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(true)
}

fn add_program_firewall_rule(path: &str) -> Result<String, FirewallError> {
    let (canonical_path, rule_name) = validate_program_path(path)?;
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={rule_name}"),
        "dir=out",
        "action=block",
        &format!("program={}", canonical_path.display()),
        "enable=yes",
        "profile=any",
    ])?;
    ACTIVE_FIREWALL_RULES
        .lock()
        .map_err(|_| FirewallError::CommandFailed(None))?
        .insert(rule_name.clone());
    Ok(rule_name)
}

fn delete_firewall_rule(name: &str) -> Result<(), FirewallError> {
    run_netsh(&[
        "advfirewall",
        "firewall",
        "delete",
        "rule",
        &format!("name={name}"),
    ])?;
    Ok(())
}

fn validate_program_path(path: &str) -> Result<(PathBuf, String), FirewallError> {
    let original = Path::new(path);
    if !original.is_absolute() {
        return Err(FirewallError::NonAbsolutePath(path.to_string()));
    }
    let canonical = fs::canonicalize(original).unwrap_or_else(|_| original.to_path_buf());
    if !canonical.is_file() {
        return Err(FirewallError::NotAFile(canonical.display().to_string()));
    }
    let normalized = canonical.to_string_lossy().replace('/', "\\");
    let mut hasher = Sha256::new();
    hasher.update(normalized.to_ascii_lowercase().as_bytes());
    let digest = hex::encode(hasher.finalize());
    Ok((
        canonical,
        format!("{FIREWALL_RULE_PREFIX}{}", &digest[..16]),
    ))
}

fn run_netsh(args: &[&str]) -> Result<(), FirewallError> {
    #[cfg(windows)]
    {
        let status = Command::new("netsh.exe").args(args).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(FirewallError::CommandFailed(status.code()))
        }
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        Err(FirewallError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::{qualifies_for_protection, score_signals, validate_program_path, StealerSignal};
    use std::collections::HashSet;

    #[test]
    fn stealer_requires_correlated_signals() {
        let mut signals = HashSet::new();
        signals.insert(StealerSignal::BrowserStore);
        signals.insert(StealerSignal::Dpapi);
        assert!(!qualifies_for_protection(&signals, score_signals(&signals)));

        signals.insert(StealerSignal::Collection);
        signals.insert(StealerSignal::Network);
        assert!(qualifies_for_protection(&signals, score_signals(&signals)));
    }

    #[test]
    fn injection_can_be_an_independent_collection_context() {
        let mut signals = HashSet::new();
        signals.insert(StealerSignal::BrowserStore);
        signals.insert(StealerSignal::CredentialAccess);
        signals.insert(StealerSignal::ProcessInjection);
        signals.insert(StealerSignal::Exfiltration);
        assert!(qualifies_for_protection(&signals, score_signals(&signals)));
    }

    #[test]
    fn firewall_rule_name_is_deterministic_for_a_file() {
        let path = std::env::current_exe().expect("test executable path");
        let (_, first) = validate_program_path(path.to_str().expect("utf8 path")).expect("file");
        let (_, second) = validate_program_path(path.to_str().expect("utf8 path")).expect("file");
        assert_eq!(first, second);
        assert!(first.starts_with("EverbloomSecurity-Stealer-"));
    }
}
