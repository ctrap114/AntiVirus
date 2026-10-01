use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BehaviorEventKind {
    FileWrite,
    RegistryWrite,
    ProcessCreate,
    NetworkConnect,
    SuspiciousApiCall,
    DnsQuery,
    ProcessInject,
    PersistenceChange,
    CredentialAccess,
    ServiceTampering,
    BackupDeletion,
    RansomwareEncryption,
    SuspiciousPersistence,
    /// An anomalous module (DLL) load or protected-process baseline
    /// violation. Distinct from PersistenceChange: this marks code execution
    /// through an unexpected module rather than an autostart authoring step.
    SuspiciousModuleLoad,
}

impl BehaviorEventKind {
    /// Stable lowercase label shared by Display and the attack-chain frame.
    pub fn as_str(&self) -> &'static str {
        match self {
            BehaviorEventKind::FileWrite => "file_write",
            BehaviorEventKind::RegistryWrite => "registry_write",
            BehaviorEventKind::ProcessCreate => "process_create",
            BehaviorEventKind::NetworkConnect => "network_connect",
            BehaviorEventKind::SuspiciousApiCall => "suspicious_api_call",
            BehaviorEventKind::DnsQuery => "dns_query",
            BehaviorEventKind::ProcessInject => "process_inject",
            BehaviorEventKind::PersistenceChange => "persistence_change",
            BehaviorEventKind::CredentialAccess => "credential_access",
            BehaviorEventKind::ServiceTampering => "service_tampering",
            BehaviorEventKind::BackupDeletion => "backup_deletion",
            BehaviorEventKind::RansomwareEncryption => "ransomware_encryption",
            BehaviorEventKind::SuspiciousPersistence => "suspicious_persistence",
            BehaviorEventKind::SuspiciousModuleLoad => "suspicious_module_load",
        }
    }
}

impl fmt::Display for BehaviorEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Aggressive,
    Normal,
    Relaxed,
}

impl SecurityLevel {
    pub fn threshold(&self) -> f32 {
        match self {
            SecurityLevel::Aggressive => 0.55,
            SecurityLevel::Normal => 0.7,
            SecurityLevel::Relaxed => 0.85,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BehaviorEvent {
    pub kind: BehaviorEventKind,
    pub detail: String,
    pub process_id: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct BehaviorScoreResult {
    pub process_id: Option<u32>,
    pub score: f32,
    pub matched_indicators: Vec<String>,
}

pub struct BehavioralScorer {
    weights: HashMap<BehaviorEventKind, f32>,
    pub threshold: f32,
    pub security_level: SecurityLevel,
}

impl BehavioralScorer {
    pub fn new(weights: HashMap<BehaviorEventKind, f32>, threshold: f32) -> Self {
        Self {
            weights,
            threshold,
            security_level: SecurityLevel::Normal,
        }
    }
}

impl Default for BehavioralScorer {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert(BehaviorEventKind::ProcessInject, 0.25);
        weights.insert(BehaviorEventKind::SuspiciousApiCall, 0.40);
        weights.insert(BehaviorEventKind::RegistryWrite, 0.20);
        weights.insert(BehaviorEventKind::FileWrite, 0.15);
        weights.insert(BehaviorEventKind::NetworkConnect, 0.12);
        weights.insert(BehaviorEventKind::PersistenceChange, 0.15);
        weights.insert(BehaviorEventKind::DnsQuery, 0.10);
        weights.insert(BehaviorEventKind::CredentialAccess, 0.22);
        weights.insert(BehaviorEventKind::ServiceTampering, 0.18);
        weights.insert(BehaviorEventKind::BackupDeletion, 0.16);
        weights.insert(BehaviorEventKind::RansomwareEncryption, 0.30);
        weights.insert(BehaviorEventKind::SuspiciousPersistence, 0.18);
        weights.insert(BehaviorEventKind::SuspiciousModuleLoad, 0.12);
        Self {
            weights,
            threshold: SecurityLevel::Normal.threshold(),
            security_level: SecurityLevel::Normal,
        }
    }
}

impl BehavioralScorer {
    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.threshold = level.threshold();
        self.security_level = level;
        self
    }

    pub fn score_events(&self, events: &[BehaviorEvent]) -> BehaviorScoreResult {
        let mut total = 0.0;
        let mut matched = Vec::new();
        let mut seen_kinds = HashSet::new();

        for event in events {
            // A noisy process can emit the same operation many times. Count
            // each behavior family once per scoring window so repeated file
            // writes or network callbacks cannot manufacture a high score.
            if seen_kinds.insert(event.kind.clone()) {
                if let Some(weight) = self.weights.get(&event.kind) {
                    total += *weight;
                    matched.push(format!("{}:{}", event.kind, event.detail));
                }
            }
        }

        // Correlation bonuses reward behavior combinations while keeping
        // repeated events bounded. A lone API or network event remains weak.
        let has_injection = seen_kinds.contains(&BehaviorEventKind::ProcessInject);
        let has_credential_access = seen_kinds.contains(&BehaviorEventKind::CredentialAccess);
        let has_collection = seen_kinds.contains(&BehaviorEventKind::FileWrite)
            || seen_kinds.contains(&BehaviorEventKind::RegistryWrite);
        let has_network = seen_kinds.contains(&BehaviorEventKind::NetworkConnect)
            || seen_kinds.contains(&BehaviorEventKind::DnsQuery);
        if has_injection && has_collection {
            total += 0.18;
            matched.push("correlation:injection_plus_collection".to_string());
        }
        if has_credential_access && has_network {
            total += 0.18;
            matched.push("correlation:credential_plus_network".to_string());
        }
        if seen_kinds.contains(&BehaviorEventKind::BackupDeletion)
            && seen_kinds.contains(&BehaviorEventKind::RansomwareEncryption)
        {
            total += 0.24;
            matched.push("correlation:backup_destruction_plus_encryption".to_string());
        }
        if total > 1.0 {
            total = 1.0;
        }

        BehaviorScoreResult {
            process_id: None,
            score: total,
            matched_indicators: matched,
        }
    }

    pub fn score_events_by_process(&self, events: &[BehaviorEvent]) -> Vec<BehaviorScoreResult> {
        let mut process_scores: HashMap<Option<u32>, BehaviorScoreResult> = HashMap::new();
        let mut seen_kinds: HashMap<Option<u32>, HashSet<BehaviorEventKind>> = HashMap::new();

        for event in events {
            let entry =
                process_scores
                    .entry(event.process_id)
                    .or_insert_with(|| BehaviorScoreResult {
                        process_id: event.process_id,
                        score: 0.0,
                        matched_indicators: Vec::new(),
                    });

            let kinds = seen_kinds.entry(event.process_id).or_default();
            if kinds.insert(event.kind.clone()) {
                if let Some(weight) = self.weights.get(&event.kind) {
                    entry.score += *weight;
                    entry
                        .matched_indicators
                        .push(format!("{}:{}", event.kind, event.detail));
                }
            }
        }

        for (process_id, entry) in &mut process_scores {
            let Some(kinds) = seen_kinds.get(process_id) else {
                continue;
            };
            let has_injection = kinds.contains(&BehaviorEventKind::ProcessInject);
            let has_credential_access = kinds.contains(&BehaviorEventKind::CredentialAccess);
            let has_collection = kinds.contains(&BehaviorEventKind::FileWrite)
                || kinds.contains(&BehaviorEventKind::RegistryWrite);
            let has_network = kinds.contains(&BehaviorEventKind::NetworkConnect)
                || kinds.contains(&BehaviorEventKind::DnsQuery);
            if has_injection && has_collection {
                entry.score += 0.18;
                entry
                    .matched_indicators
                    .push("correlation:injection_plus_collection".to_string());
            }
            if has_credential_access && has_network {
                entry.score += 0.18;
                entry
                    .matched_indicators
                    .push("correlation:credential_plus_network".to_string());
            }
            if kinds.contains(&BehaviorEventKind::BackupDeletion)
                && kinds.contains(&BehaviorEventKind::RansomwareEncryption)
            {
                entry.score += 0.24;
                entry
                    .matched_indicators
                    .push("correlation:backup_destruction_plus_encryption".to_string());
            }
            entry.score = entry.score.min(1.0);
        }

        process_scores.into_values().collect()
    }
    pub fn is_malicious(&self, score: f32) -> bool {
        score >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_behavioral_scoring() {
        let scorer = BehavioralScorer::default();
        let events = vec![
            BehaviorEvent {
                kind: BehaviorEventKind::RegistryWrite,
                detail: "HKCU\\Software\\Test".into(),
                process_id: None,
            },
            BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousApiCall,
                detail: "NtWriteVirtualMemory".into(),
                process_id: None,
            },
            BehaviorEvent {
                kind: BehaviorEventKind::NetworkConnect,
                detail: "192.168.1.1:80".into(),
                process_id: None,
            },
        ];
        let result = scorer.score_events(&events);
        assert!(result.score > 0.0);
        assert_eq!(result.matched_indicators.len(), 3);
        assert!(scorer.is_malicious(result.score));
    }

    #[test]
    fn test_per_process_behavioral_scoring() {
        let scorer = BehavioralScorer::default();
        let events = vec![
            BehaviorEvent {
                kind: BehaviorEventKind::RegistryWrite,
                detail: "HKCU\\Software\\Test".into(),
                process_id: Some(1001),
            },
            BehaviorEvent {
                kind: BehaviorEventKind::SuspiciousApiCall,
                detail: "CreateRemoteThread".into(),
                process_id: Some(1001),
            },
            BehaviorEvent {
                kind: BehaviorEventKind::NetworkConnect,
                detail: "10.0.0.1:443".into(),
                process_id: Some(2002),
            },
        ];

        let results = scorer.score_events_by_process(&events);
        assert_eq!(results.len(), 2);
        let first = results.iter().find(|r| r.process_id == Some(1001)).unwrap();
        assert!(first.score > 0.0);
        assert_eq!(first.matched_indicators.len(), 2);
    }

    #[test]
    fn repeated_behavior_family_is_counted_once() {
        let scorer = BehavioralScorer::default();
        let events = vec![
            BehaviorEvent {
                kind: BehaviorEventKind::FileWrite,
                detail: "a.exe".into(),
                process_id: Some(1001),
            },
            BehaviorEvent {
                kind: BehaviorEventKind::FileWrite,
                detail: "b.exe".into(),
                process_id: Some(1001),
            },
        ];

        let result = scorer.score_events_by_process(&events);
        assert_eq!(result.len(), 1);
        assert!((result[0].score - 0.15).abs() < f32::EPSILON);
        assert_eq!(result[0].matched_indicators.len(), 1);
    }
}
